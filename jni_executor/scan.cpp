// scan.cpp — rblx_Module introspection + ARM64 signature scanner.
//
// Self-contained resolver: parses /proc/self/maps to locate a lib*, then
// reads the in-memory ELF headers to recover the .text/.data/.bss layouts
// and finally scans the executable segment for caller-specified byte patterns.
// No libelf / libunwind / link.h dependencies — pure POSIX + elf(3) types.
//
// Compile: arm64-v8a, NDK r26+, -O2 -fPIC.
//
#include "scan.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <errno.h>

#include <android/log.h>
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "ScanH", __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  "ScanH", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "ScanH", __VA_ARGS__)

/*
 * ---- /proc/self/maps parsing -------------------------------------------------
 * We scan every file-backed anonymous/ELF mapping whose "pathname" column
 * ends with the lib name, keep the lowest base address, then aggregate the
 * remaining adjacent mappings to compute total module size.
 */
static int parse_maps_line(char *line,
                           void **base_out, void **end_out,
                           unsigned *prot_out, char **path_out) {
	char *p = line;
	char *dash = strchr(line, '-');
	if (!dash) return -1;
	*dash = '\0';
	*base_out   = (void*)strtoul(line, NULL, 16);
	*end_out    = (void*)strtoul(dash + 1, &p, 16);
	*prot_out   = 0;
	char *perm  = p;
	for (char *c = perm; c < perm + 4 && *c; c++) {
		switch (*c) {
			case 'r': *prot_out |= PROT_READ;  break;
			case 'w': *prot_out |= PROT_WRITE; break;
			case 'x': *prot_out |= PROT_EXEC;  break;
			case 'p': case 's':                break;
			default: break;
		}
	}
	while (*p && *p != ' ') p++;   // skip perms tail -> offset field
	// fields: offset dev inode pathname  (skip 4 space-separated tokens)
	for (int fields = 0; fields < 4; ) {
		while (*p == ' ') p++;            // skip blanks between fields
		while (*p && *p != ' ') p++;      // consume field
		if (fields < 4) fields++;
	}
	// remaining token is the pathname (or "" / NULL)
	*path_out = (*p) ? p : NULL;
	return 0;
}

static const char *basename_of(const char *p) {
	const char *b = strrchr(p, '/');
	return b ? b + 1 : p;
}

int rblx_find_module(const char *basename, rblx_Module *out) {
	if (!out || !basename) return -1;
	FILE *f = fopen("/proc/self/maps", "r");
	if (!f) return -11;

	char line[1024 + NAME_MAX + 16];
	void *first_base = NULL, *last_end = NULL;
	rblx_Module tmp{};
	int matched = 0;

	while (fgets(line, sizeof(line) - 1, f)) {
		void *base = NULL, *endp = NULL; unsigned prot = 0; char *path = NULL;
		line[strcspn(line, "\n")] = '\0';
		if (parse_maps_line(line, &base, &endp, &prot, &path) != 0) continue;
		if (!path) continue;
		const char *b = basename_of(path);
		if (strcmp(b, basename) != 0) continue;
		// Accept RX or RWX segments (executable image + loader writable parts)
		if (!(prot & PROT_READ)) continue;
		(void)0;
		if (!first_base) first_base = base;
		last_end = endp;
		// Capture the earliest region's base as the module bias:
		if (!tmp.base) tmp.base = base;
		tmp.size = (size_t)((uint8_t*)endp - (uint8_t*)tmp.base);
		matched = 1;
	}
	fclose(f);

	if (!matched) return -2;                  // no such module mapped
	if (!first_base) return -3;

	tmp.base   = first_base;
	tmp.end    = last_end;
	tmp.size   = (size_t)((uint8_t*)last_end - (uint8_t*)first_base);
	strncpy(tmp.name, basename, sizeof(tmp.name) - 1);

	/* Parse ELF PROGRAM headers straight from memory to recover layout.
	 * Deliberately NOT the section header table: on this engine the shdr
	 * table lands in the zero-filled tail of the last PT_LOAD, so reading
	 * it yields garbage string-table pointers and strcmp(".text") SIGSEGVs.
	 * PT_LOAD segments are what the kernel actually mapped — always valid. */
	Elf64_Ehdr *ehdr = (Elf64_Ehdr*)tmp.base;
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
		LOGE("module %s: bad elf magic @ %p (not pure ELF map?)",
		     tmp.name, tmp.base);
		memcpy(out, &tmp, sizeof(*out));
		return 0;  // still useful: base/size only
	}
	size_t msize = tmp.size;
	if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0 || ehdr->e_phnum > 256 ||
	    ehdr->e_phoff >= msize ||
	    (size_t)ehdr->e_phnum * sizeof(Elf64_Phdr) > msize - ehdr->e_phoff) {
		LOGW("module %s: phdr out of range, using base/size only", tmp.name);
		memcpy(out, &tmp, sizeof(*out));
		return 0;
	}
	const Elf64_Phdr *ph =
		(const Elf64_Phdr*)((uint8_t*)tmp.base + ehdr->e_phoff);

	/* load bias: runtime addr = bias + link-time p_vaddr */
	uintptr_t bias = (uintptr_t)tmp.base;
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (ph[i].p_type == PT_LOAD && ph[i].p_offset == 0) {
			bias = (uintptr_t)tmp.base - (uintptr_t)ph[i].p_vaddr;
			break;
		}
	}
	/* first RX LOAD = .text ; first RW LOAD = .data ; .bss = RW memsz tail */
	uintptr_t bss_va = 0;
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (ph[i].p_type != PT_LOAD) continue;
		uintptr_t va = bias + ph[i].p_vaddr;
		if (ph[i].p_flags & PF_X) {
			if (!tmp.text_off) {
				tmp.text_off  = va - (uintptr_t)tmp.base;
				tmp.text_size = ph[i].p_filesz;
			}
		}
		if (ph[i].p_flags & PF_W) {
			if (!tmp.data_off) tmp.data_off = va - (uintptr_t)tmp.base;
			if (ph[i].p_memsz > ph[i].p_filesz)
				bss_va = va + ph[i].p_filesz;   /* last RW tail wins */
		}
	}
	if (bss_va) tmp.bss_off = bss_va - (uintptr_t)tmp.base;
	LOGI("module %-20s base=%p end=%p  text@%#zx/%#zx  data@%#zx  bss@%#zx",
	     tmp.name, tmp.base, tmp.end,
	     tmp.text_off, tmp.text_size, tmp.data_off, tmp.bss_off);
	memcpy(out, &tmp, sizeof(*out));
	return 0;
}

/*
 * ---- Signature matcher ----------------------------------------------------
 * mask semantics per byte position:
 *   'x'  — must equal pat->bytes[idx]
 *   '?'  — anything allowed (wildcard)
 *   '!'  — MUST NOT equal pat->bytes[idx]   (negative wildcard)
 *   '\0' — stop (patterns are not required to be NUL but we treat EOL too)
 */
void *rblx_scan_range(void *start_in, size_t len, const rblx_Pattern *pat) {
	if (!pat || !pat->bytes || !pat->mask || !len || pat->len == 0)
		return NULL;

	/* Normalise the effective match width — prefer explicit mask length,
	 * fall back to pat->len when only a length prefix is provided. */
	size_t mlen = strnlen(pat->mask, 4096);
	if (mlen == 0 || mlen > pat->len)
		mlen = pat->len;                 // byte-pattern length drives loop

	uint8_t *s = (uint8_t*)start_in;
	if (len < mlen) return NULL;

	for (size_t i = 0; i + mlen <= len; i++) {
		size_t k;
		int hit = 1;
		for (k = 0; k < mlen; k++) {
			unsigned char b  = s[i + k];
			unsigned char want = pat->bytes[k];
			switch (pat->mask[k]) {
				case 'x': if (b != want) { hit = 0; } break;
				case '!': if (b == want) { hit = 0; } break;
				case '?':                            break;
				default:  /* treat unknown mask char as match-any */
				                hit = 1;
			}
			if (!hit) break;
		}
		if (hit) return s + i;
	}
	return NULL;
}

void *rblx_scan_module(const rblx_Module *mod, const rblx_Pattern *pat) {
	if (!mod || !mod->text_size)
		return NULL;
	uint8_t *text = (uint8_t*)mod->base + mod->text_off;
	if (text == (uint8_t*)mod->base)
		text = (uint8_t*)mod->base;      // module not parsed as ELF → scan whole base
	size_t span = mod->text_size ? mod->text_size : mod->size;
	return rblx_scan_range(text, span, pat);
}

/*
 * ---- In-memory dynamic symbol resolution (namespace-safe) ----------------
 * dlsym(RTLD_DEFAULT) cannot see libs that were loaded into a private linker
 * namespace, and plain dlopen("libroblox.so", ...) may *load a second copy*
 * of the engine (huge RAM spike on this device → LMK kill). Instead we walk
 * the already-mapped module's PT_DYNAMIC → DT_SYMTAB/DT_STRTAB directly.
 */
bool rblx_addr_in_module(const rblx_Module *mod, const void *addr) {
	if (!mod || !mod->base || !mod->end || !addr) return false;
	uintptr_t a = (uintptr_t)addr;
	return a >= (uintptr_t)mod->base && a < (uintptr_t)mod->end;
}

void *rblx_dlsym_module(const rblx_Module *mod, const char *name) {
	if (!mod || !mod->base || !name) return NULL;
	uint8_t *base = (uint8_t*)mod->base;
	size_t msize = mod->size ? mod->size
	              : (size_t)((uint8_t*)mod->end - base);
	Elf64_Ehdr *ehdr = (Elf64_Ehdr*)base;
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) return NULL;
	if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0 || ehdr->e_phnum > 256 ||
	    ehdr->e_phoff >= msize ||
	    (size_t)ehdr->e_phnum * sizeof(Elf64_Phdr) > msize - ehdr->e_phoff)
		return NULL;

	Elf64_Phdr *ph = (Elf64_Phdr*)(base + ehdr->e_phoff);

	/* load bias: runtime address = bias + link-time VA.
	 * Android .so files usually map file offset 0 at p_vaddr 0 (bias = base). */
	uintptr_t bias = (uintptr_t)base;
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (ph[i].p_type == PT_LOAD && ph[i].p_offset == 0) {
			bias = (uintptr_t)base - (uintptr_t)ph[i].p_vaddr;
			break;
		}
	}
	uintptr_t lo = (uintptr_t)base, hi = lo + msize;

	const Elf64_Dyn *dyn = NULL;
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (ph[i].p_type == PT_DYNAMIC) {
			uintptr_t da = bias + ph[i].p_vaddr;
			if (da >= lo && da < hi)
				dyn = (const Elf64_Dyn*)da;
			break;
		}
	}
	if (!dyn) return NULL;

	uintptr_t symtab = 0, strtab = 0, hash = 0, gnu_hash = 0;
	size_t syment = sizeof(Elf64_Sym);
	for (const Elf64_Dyn *d = dyn, *dend = dyn + 4096;
	     d->d_tag != DT_NULL && d < dend; d++) {
		switch (d->d_tag) {
			case DT_SYMTAB: symtab  = d->d_un.d_ptr; break;
			case DT_STRTAB: strtab  = d->d_un.d_ptr; break;
			case DT_HASH:   hash    = d->d_un.d_ptr; break;
			case DT_GNU_HASH: gnu_hash = d->d_un.d_ptr; break;
			case DT_SYMENT: syment  = d->d_un.d_val; break;
			default: break;
		}
	}
	if (!symtab || !strtab || syment == 0) return NULL;
	/* only trust in-module pointers */
	if (bias + symtab < lo || bias + symtab >= hi) return NULL;
	if (bias + strtab < lo || bias + strtab >= hi) return NULL;
	if (hash && (bias + hash < lo || bias + hash >= hi)) hash = 0;
	if (gnu_hash && (bias + gnu_hash < lo || bias + gnu_hash >= hi)) gnu_hash = 0;

	/* symbol count: SysV hash nchain, else walk GNU hash buckets, else cap */
	size_t nsyms = 0;
	if (hash) {
		const uint32_t *h = (const uint32_t*)(bias + hash);
		nsyms = h[1];                                  /* nchain */
	} else if (gnu_hash) {
		const uint32_t *gh = (const uint32_t*)(bias + gnu_hash);
		uint32_t nbuckets = gh[0], symoffset = gh[1], bloom_size = gh[2];
		const uint64_t *bloom  = (const uint64_t*)(gh + 4);
		const uint32_t *buckets = (const uint32_t*)(bloom + bloom_size);
		const uint32_t *chain   = buckets + nbuckets;
		uint32_t maxidx = symoffset;
		uint64_t guard = 0;
		for (uint32_t b = 0; b < nbuckets && guard < (1u<<20); b++) {
			uint32_t idx = buckets[b];
			if (idx == 0) continue;
			uint32_t si = idx;
			for (;;) {
				guard++;
				if (si > maxidx) maxidx = si;
				uint32_t cur = chain[si - symoffset];
				if (cur & 1) break;
				si++;
			}
		}
		nsyms = maxidx + 1;
	}
	if (nsyms == 0) nsyms = (1u<<20);                  /* safety cap */
	if (nsyms > (1u<<20)) nsyms = (1u<<20);

	const Elf64_Sym *syms = (const Elf64_Sym*)(bias + symtab);
	const char *strs = (const char*)(bias + strtab);
	for (size_t i = 0; i < nsyms; i++) {
		const Elf64_Sym *s = &syms[i];
		if (s->st_name == 0 || s->st_value == 0) continue;
		unsigned t = ELF64_ST_TYPE(s->st_info);
		if (t != STT_FUNC && t != STT_OBJECT) continue;
		const char *nm = strs + s->st_name;
		if ((uintptr_t)nm < lo || (uintptr_t)nm >= hi) continue;  /* guard */
		if (strcmp(nm, name) == 0)
			return (void*)(bias + s->st_value);
	}
	return NULL;
}

/*
 * ---- raw R/W -------------------------------------------------------------- */
static int page_protect_ok(void *addr, size_t n) {
	return mprotect((void*)((uintptr_t)addr & ~(0xFFFull)),
	                (((uintptr_t)addr & 0xFFF) + n + 0xFFF) & ~0xFFFull,
	                PROT_READ|PROT_WRITE|PROT_EXEC) == 0 ? 0 : -1;
}

int rblx_readmem(void *addr, void *out, size_t n) {
	if (!addr || !out) return -1;
	/* /proc/self/mem is in-proc so memcpy is safe; only probe RO regions. */
	memcpy(out, addr, n);
	return 0;
}

int rblx_writemem(void *addr, const void *in, size_t n) {
	if (!addr || !in || !n) return -1;
	page_protect_ok(addr, n);
	memcpy((void*)addr, in, n);
	__builtin___clear_cache((char*)addr, (char*)addr + n);
	return 0;
}

uint32_t rblx_read_u32(void *addr) {
	uint32_t v = 0; rblx_readmem(addr, &v, sizeof(v)); return v;
}
uint64_t rblx_read_u64(void *addr) {
	uint64_t v = 0; rblx_readmem(addr, &v, sizeof(v)); return v;
}
void rblx_write_u32(void *addr, uint32_t v) { rblx_writemem(addr, &v, sizeof(v)); }
void rblx_write_u64(void *addr, uint64_t v) { rblx_writemem(addr, &v, sizeof(v)); }

/*
 * ADRP/ADD pair resolution (ARM64 PC-relative addressing).
 * insn -> points at the ADRP instruction (the pair: ADRP then ADD).
 */
void *rblx_adrp_add_resolve(void *insn) {
	if (!insn) return NULL;
	uint32_t adrp_raw = rblx_read_u32(insn);
	uint32_t add_raw  = rblx_read_u32((uint8_t*)insn + 4);

	/* ADRP encoding: 1 x 1 immlo[2] 10000 immhi[19] 0d000 DTPD? */
	/* mask for ADRP (opcode 0x90, with top bit set): bits[31:28]=100x */
	if ((adrp_raw & 0x9FC00000) != 0x90000000 &&
	    ((adrp_raw >> 24) & 0x1F) != 0x12)      // tolerate ADRP variant
		return NULL;

	/* imm = (immhi:immlo) sign-extended, × pagesize */
	int64_t immhi = (int64_t)((adrp_raw >> 5) & 0x7FFFF);   // 19-bit hi
	uint32_t immlo = (adrp_raw >> 29) & 0x3;                // 2-bit lo
	int64_t imm    = (immhi << 2) | immlo;                  // 21-bit signed
	imm = (imm << 21) >> 21;                                // arithmetic sign-extend
	imm <<= 12;                                              // × 4096

	uintptr_t pc = (uintptr_t)insn & ~(uintptr_t)0xFFFull; // page aligned
	uintptr_t page = pc + (uintptr_t)imm;

	uintptr_t off = 0;
	// ADD (immediate, 64-bit): op=0, real encoding bits[31:23]=1001000
	if ((add_raw & 0xFF800300) == 0x91000000 ||
	    (add_raw & 0xFF800300) == 0x91040000) {            // LSL #? variants too
		off = add_raw & 0xFFF;     // imm12 (12-bit)
		uint32_t sh = (add_raw >> 22) & 0x1;              // shift (12 => LSL12)
		if (sh) off <<= 12;
	}
	return (void*)(page + off);
}

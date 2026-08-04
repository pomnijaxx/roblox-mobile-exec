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

	/* Parse ELF section tables straight from memory to recover sections     */
	Elf64_Ehdr *ehdr = (Elf64_Ehdr*)tmp.base;
	if (ehdr->e_ident[EI_MAG0] != ELFMAG0) {
		LOGE("module %s: bad elf magic @ %p (not pure ELF map?)",
		     tmp.name, tmp.base);
		memcpy(out, &tmp, sizeof(*out));
		return 0;  // still useful: base/size only
	}
	Elf64_Shdr *sh = (Elf64_Shdr*)((uint8_t*)tmp.base + ehdr->e_shoff);
	const char *strtab = (const char*)tmp.base +
		sh[ehdr->e_shstrndx].sh_offset;
	for (int i = 0; i < ehdr->e_shnum; i++) {
		const char *name = strtab + sh[i].sh_name;
		size_t runtime_off = sh[i].sh_addr;   // sh_addr is file VA w/ bias
		if (strcmp(name, ".text") == 0)      { tmp.text_off  = runtime_off;
		                                      tmp.text_size = sh[i].sh_size; }
		else if (strcmp(name, ".data") == 0){ tmp.data_off   = runtime_off;
		                                      tmp.data_size  = sh[i].sh_size; }
		else if (strcmp(name, ".bss") == 0)  { tmp.bss_off    = runtime_off;
		                                      /* size implicit */ }
	}
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

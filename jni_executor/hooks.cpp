// hooks.cpp — inline ARM64 trampoline hooks with a REAL prologue relocator.
//
// A naive 16-byte prologue copy is broken for any function whose first
// instructions contain PC-relative branches (b/bl/b.cond/cbz/cbnz/tbz/tbnz)
// or literal loads (adr/adrp + ldr/ldrsw literal). Copying them into a
// separate RWX page changes their PC → they resolve to the WRONG target:
// the result is an infinite loop (e.g. a "b" that now targets garbage) or a
// SIGILL one call later.
//
// Tombstone_19 proved this exact failure on Roblox: signal 4 (SIGILL,
// ILL_ILLOPC) with pc==x16 (branched to non-code) inside
// librobloxexec.so detour_pc_entry+1092 with a repeated frame loop. There
// was NO watchdog thread — our own trampoline was executing relocated
// garbage (pcall is called thousands of times/sec → crash in seconds;
// tolstring rarely → the old "slow freeze"). The relocator below emits
// every PC-relative instruction against the trampoline's address so those
// targets keep working from the separate page.
#include "hooks.h"
#include "scan.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <android/log.h>

#define LOGI(fmt, ...) __android_log_print(ANDROID_LOG_INFO,  "HookH", fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) __android_log_print(ANDROID_LOG_WARN,  "HookH", fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, "HookH", fmt, ##__VA_ARGS__)

/* 16-byte ARM64 indirect-jump stub:
 *      ldr  x16, [pc, #8]   = 0x58000050   (64-bit LDR literal, imm19=2)
 *      br   x16             = 0xD61F0200
 *      <u64 target>         (placed at pc+8 from the ldr)            */
static const uint32_t INST_LDR_X16 = 0x58000050u;
static const uint32_t INST_BR_X16  = 0xD61F0200u;

static size_t pg_size(void){
	static long p=0;
	if(!p) p = sysconf(_SC_PAGESIZE);
	return (size_t)(p<=0?4096:p);
}

static int mprotn(void *addr, size_t n, int prot){
	uintptr_t pg=pg_size();
	uintptr_t s=(uintptr_t)addr & ~(pg-1);
	uintptr_t e=((uintptr_t)addr + n + pg - 1) & ~(pg-1);
	return mprotect((void*)s,(size_t)(e-s),prot)==0?0:-errno;
}

/* ---------- emit helpers ---------- */
static void putw(uint8_t **p,uint32_t v){ memcpy(*p,&v,4); *p+=4; }

/* full-range indirect branch: 16 bytes */
static void emit_branch(uint8_t **p,uint64_t tgt){
	putw(p,INST_LDR_X16); putw(p,INST_BR_X16);
	memcpy(*p,&tgt,8); *p+=8;
}
/* full-range call (BL): ldr x16,[pc,#8]; blr x16; <u64 tgt>; 16 bytes.
 * The ldr literal target address is at pc+8 (bl can't reach beyond ±128MB
 * from the trampoline), so we load the absolute address into x16 and blr.
 * The callee returns to *p — the next relocated instruction.          */
static void emit_call(uint8_t **p,uint64_t tgt){
	uint32_t *w=(uint32_t*)*p;
	/* ldr x16,[pc,#8] ; blr x16 ; u64 tgt */
	w[0]=INST_LDR_X16; w[1]=0xD63F0200u; /* blr x16 */
	memcpy(w+2,&tgt,8);
	*p+=16;
}
/* load <imm> into x/w reg with movz/movk (4..16 bytes). Returns bytes used. */
static int emit_mov64(uint8_t **p,int rd,uint64_t v){
	uint8_t *s=*p;
	putw(p,0xD2800000u | ((v&0xFFFF)<<5) | (uint32_t)rd);              /* movz xr,#lo16 */
	if(v & 0xFFFF0000ull)      putw(p,0xF2800000u | (1u<<21) | (((v>>16)&0xFFFF)<<5) | (uint32_t)rd);
	if(v & 0xFFFFFFFF00000000ull) putw(p,0xF2800000u | (2u<<21) | (((v>>32)&0xFFFF)<<5) | (uint32_t)rd);
	if(v & 0xFFFF000000000000ull) putw(p,0xF2800000u | (3u<<21) | (((v>>48)&0xFFFF)<<5) | (uint32_t)rd);
	return (int)(*p-s);
}

/* ---------- instruction decoders ---------- */
static inline uint32_t bh(uint32_t v,int hi,int lo){ return (v>>lo)&((1u<<(hi-lo+1))-1u); }
static inline int64_t sgn(int64_t v,int bits_sz){
	int64_t m=1LL<<(bits_sz-1);
	return (v ^ m)-m;
}

/* ---------- single-instruction relocator ----------
 * Re-emit `ins` (word at ORIGINAL pc == ipc) into *p. Returns bytes
 * written, or -1 on unrelocatable input. The original pc is needed to
 * recompute PC-relative targets.                                     */
static int reloc_one(uint8_t **p, uint32_t ins, uint64_t ipc){
	uint64_t tgt;
	int cond, bit, rt, rd, op;
	int64_t off;

	/* B  (0x14000000) / BL (0x94000000): imm26<<2 */
	if((ins & 0x7C000000u)==0x14000000u){
		off = sgn((int64_t)bh(ins,25,0),26) << 2;      /* imm26 sign-ext */
		tgt = (uint64_t)(ipc + off);
		if(ins & 0x80000000u) emit_call(p,tgt);
		else                  emit_branch(p,tgt);
		return 16;
	}
	/* B.cond (0x54000000) : imm19<<2, cond 4:0 */
	if((ins & 0xFF000010u)==0x54000000u){
		cond=(int)bh(ins,3,0);
		off=sgn((int64_t)bh(ins,23,5),19)<<2;
		tgt=(uint64_t)(ipc+off);
		cond=((cond^1)&0xF);                        /* inverted condition */
		putw(p,0x54000000u|(uint32_t)cond|(5u<<5));  /* b.<nc> +20B (skip 16B jump +4B) */
		emit_branch(p,tgt);
		return 20;
	}
	/* CBZ (0x34000000) / CBNZ (0x35000000): imm19<<2 */
	if((ins & 0x7E000000u)==0x34000000u || (ins & 0x7E000000u)==0x35000000u){
		rt=ins&31; op=(ins>>24)&1;
		off=sgn((int64_t)bh(ins,23,5),19)<<2;
		tgt=(uint64_t)(ipc+off);
		putw(p,0x34000000u|((uint32_t)(op^1)<<24)|(5u<<5)|(uint32_t)rt); /* inverted → skip +20B */
		emit_branch(p,tgt);
		return 20;
	}
	/* TBZ / TBNZ (0x36000000 / 0x37000000): imm14<<2  */
	if((ins & 0x7E000000u)==0x36000000u || (ins & 0x7E000000u)==0x37000000u){
		op=(ins>>24)&1; rt=ins&31;
		bit=(int)(((ins>>31)&1) * 64 + bh(ins,23,19));
		off=sgn((int64_t)bh(ins,18,5),14)<<2;
		tgt=(uint64_t)(ipc+off);
		/* invert op, skip 20B */
		putw(p,0x36000000u|((uint32_t)(op^1)<<24)|(5u<<5)
		           |((uint32_t)((bit&0x1F)<<19))|((uint32_t)(((bit>>5)&1)<<31))|(uint32_t)rt);
		emit_branch(p,tgt);
		return 20;
	}
	/* ADRP (0x90000000): immhi<<2|immlo, page */
	if((ins&0x9F000000u)==0x90000000u){
		rd=(int)ins&31;
		int64_t immhi=sgn((int64_t)bh(ins,23,5),19);
		int64_t immlo=bh(ins,30,29);
		int64_t off=(immhi<<2)|immlo;
		uint64_t base=ipc & ~0xFFFull;
		uint64_t page=(off<0)? base-((uint64_t)(-off)<<12) : base+((uint64_t)off<<12);
		return emit_mov64(p,rd,page);
	}
	/* ADR (0x10000000): immhi<<2|immlo */
	if((ins&0x9F000000u)==0x10000000u){
		rd=(int)ins&31;
		int64_t immhi=sgn((int64_t)bh(ins,23,5),19);
		int64_t immlo=bh(ins,30,29);
		int64_t off=(immhi<<2)|immlo;
		tgt=(uint64_t)((int64_t)ipc+off);
		return emit_mov64(p,rd,tgt);
	}
	/* LDR literal: forms 0x18xxxxxx (w32), 0x58xxxxxx (x64), 0x98xxxxxx (ldrsw),
	 * 0xD8xxxxxx (prfm). The opc bits 31:30 give size: 00→ldr32, 01→ldr64,
	 * 10→ldrsw, 11→prfm. Literal address = pc + imm19*8 for ldr64,
	 * imm19*4 otherwise. */
	{
		uint32_t by1 = (ins >> 24) & 0xFFu;   /* top byte of the opcode */
		if(by1 == 0x18u || by1 == 0x58u || by1 == 0x98u || by1 == 0xD8u){
			int opc = (int)(ins >> 30) & 3;   /* 00 w, 01 x, 10 ldrsw, 11 prfm */
			if(opc == 3){ putw(p,ins); return 4; }  /* PRFM: copy */
			rt = (int)(ins & 31);
			int64_t imm19 = sgn((int64_t)bh(ins,23,5),19);
			int64_t scale = (opc == 1) ? 8 : 4;
			uint64_t addr = (uint64_t)((int64_t)ipc + imm19*scale);
			int n = emit_mov64(p,rt,addr);
			uint32_t front;
			if(opc == 0)      front = 0xB9400000u; /* ldr w  */
			else if(opc == 1) front = 0xF9400000u; /* ldr x  */
			else              front = 0xB9800000u; /* ldrsw x */
			putw(p, front | ((uint32_t)rt<<5) | (uint32_t)rt);
			return n + 4;
		}
	}
	/* default: copy */
	putw(p,ins);
	return 4;
}

/* ---------- public install ---------- */
int rblx_hook_install(rblx_Hook *h, void *target, void *detour, int min_bytes){
	if(!h||!target||!detour) return -1;
	memset(h,0,sizeof(*h));
	h->target=target; h->detour=detour; h->active=false;
	h->name="?";
	/* ARM64: 16-byte patch (>=4 instrs, aligned & reloc-safe).
	 * The stub layout is fixed: [ldr x16,[pc,#8]; br x16; u64 detour]
	 * = 16 bytes + an 8-byte pointer at target+8. The trampoline resume
	 * lands on target+patch, so patch MUST be 16+ — an 8-byte patch makes
	 * the resume jump INTO the pointer slot (SIGILL on the data bytes).   */
	int patch=16;
	if(min_bytes>patch) patch=(min_bytes+3)&~3;
	if(patch<16) patch=16;                    /* never below the 16B stub   */
	if((size_t)patch>sizeof(h->patch)) patch=(int)sizeof(h->patch);
	h->backup_len=patch;

	uint8_t backup[320]; memset(backup,0,sizeof backup);
	if(rblx_readmem(target,backup,patch)!=0)
		LOGW("backup read err for %p",target);

	/* allocate a RWX trampoline page */
	size_t pgs=pg_size();
	void*tramp=mmap(nullptr,pgs,PROT_READ|PROT_WRITE|PROT_EXEC,
	                 MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
	if(tramp==MAP_FAILED){ LOGE("tramp mmap: %s",strerror(errno)); return -3; }
	h->trampoline=tramp;

	/* copy + relocate the patched prefix, word by word */
	uint8_t *t=(uint8_t*)tramp;
	uint64_t base=(uint64_t)(uintptr_t)target;
	for(int i=0;i<patch/4;i++){
		uint32_t wb; memcpy(&wb, backup+i*4, 4);
		int32_t n=reloc_one(&t, wb, base+i*4);
		if(n<=0){ LOGW("reloc fail at %p (n=%d)",(void*)(base+i*4),(int)n); break; }
	}
	/* append resume jump to the untouched original body */
	emit_branch(&t,(uint64_t)((uint8_t*)target+patch));
	__builtin___clear_cache((char*)tramp,(char*)tramp+pgs);
	memcpy(h->backup,backup,patch);

	/* make target writable, write the patch, flush icache */
	int wp=mprotn(target,patch,PROT_READ|PROT_WRITE|PROT_EXEC);
	if(wp) LOGW("target %p not W (rc=%d) — forcing",target,wp);
	uint8_t full[16]; memset(full,0,sizeof full);
	((uint32_t*)full)[0]=INST_LDR_X16; ((uint32_t*)full)[1]=INST_BR_X16;
	((uint64_t*)(full+8))[0]=(uint64_t)detour;
	memcpy(h->patch,full,patch);
	/* race-safe order: constant first, then instructions */
	if(rblx_writemem((uint8_t*)target + 8, full + 8, 8)!=0){
		LOGE("patch const write failed"); return -5;
	}
	if(rblx_writemem(target, full, 8)!=0){ LOGE("patch write failed"); return -5; }
	__builtin___clear_cache((char*)target,(char*)target+patch);

	/* verify the patch actually landed before declaring success */
	uint8_t chk[16]; memset(chk,0,sizeof chk);
	if(rblx_readmem(target,chk,patch)!=0 || memcmp(chk,full,patch)!=0){
		LOGE("hook verify FAILED — restoring original bytes");
		rblx_writemem(target, backup, patch);
		__builtin___clear_cache((char*)target,(char*)target+patch);
		return -6;
	}

	h->active=true;
	LOGI("hook OK  target=%p detour=%p tramp=%p resume@%p",
	     target,detour,tramp,(void*)((uint8_t*)target+patch));
	return 0;
}

int rblx_hook_remove(rblx_Hook *h){
	if(!h) return -1;
	if(h->trampoline && h->trampoline!=MAP_FAILED){
		munmap(h->trampoline,pg_size());
	}
	if(h->target && h->backup_len<=sizeof(h->backup)&& h->backup[0]!=0){
		rblx_writemem(h->target, h->backup, h->backup_len);
		__builtin___clear_cache((char*)h->target,(char*)h->target+h->backup_len);
	}
	memset(h,0,sizeof(*h));
	return 0;
}

void *rblx_resolve_detour(const char *sym, void **tr){
	(void)sym;
	if(tr) *tr=nullptr;
	return nullptr;
}
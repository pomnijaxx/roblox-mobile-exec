// hooks.cpp — inline ARM64 trampoline hooks (clean build).
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
/* NOTE: 0x18400040 was WRONG — that decodes as 32-bit `ldr w0,[pc,#+0x80008]`
 * (top byte 0x18, Rt=0, imm19=131074) so x16 was never loaded and `br x16`
 * branched to garbage → deterministic crash on the first live pcall even
 * though the hook "verified" (verify only checks bytes landed, not that the
 * instruction stream is valid). 0x58000050 = `ldr x16,[pc,#8]` (opc=01
 * 64-bit, imm19=2, Rt=16), which pairs with the constant at +8.          */
static const uint32_t INST_LDR_X16 = 0x58000050u;
static const uint32_t INST_BR_X16  = 0xD61F0200u;

static size_t pg_size(){
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

static void emit_stub(void *dst, uint64_t target){
	uint32_t *p=(uint32_t*)dst;
	uint64_t *c=(uint64_t*)((uint8_t*)dst+8);    // constant at pc+8 of the ldr
	p[0]=INST_LDR_X16; p[1]=INST_BR_X16; p[2]=0; p[3]=0;
	c[0]=target;
}

int rblx_hook_install(rblx_Hook *h, void *target, void *detour, int min_bytes){
	if(!h||!target||!detour) return -1;
	memset(h,0,sizeof(*h));
	h->target=target; h->detour=detour; h->active=false;

	/* ARM64: use a 16-byte patch (>=4 instrs; aligned & reloc-safe) */
	int patch=16;
	if(min_bytes>patch) patch=(min_bytes+3)&~3;
	if((size_t)patch>sizeof(h->patch)) patch=(int)sizeof(h->patch);
	h->backup_len=patch;

	uint8_t backup[24]; memset(backup,0,sizeof backup);
	if(rblx_readmem(target,backup,patch)!=0)
		LOGW("backup read err for %p",target);

	/* allocate a RWX trampoline page */
	size_t pgs=pg_size();
	void*tramp=mmap(nullptr,pgs,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
	if(tramp==MAP_FAILED){ LOGE("tramp mmap: %s",strerror(errno)); return -3; }
	h->trampoline=tramp;

	/* copy original prefix into trampoline, then append resume stub → tgt+patch*/
	uint8_t *t=(uint8_t*)tramp;
	memcpy(t,backup,patch);
	emit_stub(t+patch, (uint64_t)((uint8_t*)target + patch));
	__builtin___clear_cache((char*)tramp,(char*)tramp+pgs);
	memcpy(h->backup,backup,patch);

	/* make target writable, write the patch, flush icache */
	int wp=mprotn(target,patch,PROT_READ|PROT_WRITE|PROT_EXEC);
	if(wp) LOGW("target %p not W (rc=%d) — forcing",target,wp);
	uint8_t full[16]; memset(full,0,sizeof full);
	((uint32_t*)full)[0]=INST_LDR_X16; ((uint32_t*)full)[1]=INST_BR_X16;
	((uint64_t*)(full+8))[0]=(uint64_t)detour;
	memcpy(h->patch,full,patch);
	/* race-safe order: write the u64 constant (bytes 8-15) FIRST so any
	 * core that fetches the new LDR always reads the complete detour addr,
	 * then write the instruction pair (bytes 0-7) back-to-back. A reader
	 * therefore sees: original prologue, or new-LDR + constant (no branch
	 * taken — harmless x16 clobber), or the full new entry. The residual
	 * torn case (old instr0 + new BR) is a few-ns window, same as
	 * Substrate/And64 accept.                                         */
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
	LOGI("hook OK  target=%p detour=%p tramp=%p resume@%p  insns=%08x,%08x",
	     target,detour,tramp,(void*)((uint8_t*)target+patch),
	     ((uint32_t*)full)[0],((uint32_t*)full)[1]);
	return 0;
}

int rblx_hook_remove(rblx_Hook *h){
	if(!h) return -1;
	if(h->trampoline && h->trampoline!=MAP_FAILED){
		munmap(h->trampoline,pg_size());
	}
	/* re-install the original bytes (full restore) */
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

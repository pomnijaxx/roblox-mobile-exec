/*
 * scan.h — Process-module introspection + ARM64 signature scanner.
 *
 * libRoblox.so on Android ships with its own symbols and is often partly or
 * wholly stripped (no useful libc exports). Instead of `dlsym` on Lua symbols
 * we scan the target module's executable segments for ARM64 bytecode patterns
 * and resolve candidate `lua_CFunction` / data-pointer offsets ourselves. This
 * is what real Roblox execs (Delta, EvonX, Kram, etc.) depend on for
 * cross-version stability.
 *
 * The scanner deliberately does NOT link libproc or libunwind — it reads
 * /proc/self/maps directly and walks section headers of the ELF in-process.
 */
#ifndef RBLX_SCAN_H
#define RBLX_SCAN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A loaded ELF module handle resolved from /proc/self/maps */
typedef struct {
    void   *base;     /* module load bias                       */
    void   *end;      /* module end                             */
    size_t  size;     /* module total size                      */
    size_t  text_off; /* offset of .text from base              */
    size_t  text_size;/* size of .text                            */
    size_t  data_off; /* offset of .data from base              */
    size_t  data_size;/* size of .data                           */
    size_t  bss_off;  /* offset of .bss from base (runtime)      */
    char    name[256];/* module path (/proc/self/maps basename)  */
} rblx_Module;

/* Pattern matcher token */
typedef struct {
    const uint8_t *bytes;
    const char   *mask;   /* 'x' = match byte, '?' = wildcard, '!' =
                            * negated wildcard (must NOT match)              */
    size_t len;
} rblx_Pattern;

/*
 * Find a loaded module by *basename* match against /proc/self/maps.
 * Example: "libRoblox.so" -> fills out->base with ASLR-bias base address.
 * On failure returns -1 and leaves the struct untouched.
 */
int rblx_find_module(const char *basename, rblx_Module *out);

/*
 * Scan the module's readable+executable regions (typically .text) for the
 * given pattern, returning a *runtime pointer* (base + offset) to the first
 * hit or NULL.
 */
void *rblx_scan_module(const rblx_Module *mod, const rblx_Pattern *pat);

/*
 * Generic in-process heap scanner (scans a given address range for a byte
 * pattern). Used to resolve relative pointers / lua_State data references.
 */
void *rblx_scan_range(void *start, size_t len, const rblx_Pattern *pat);

/* Read raw memory; returns bytes copied into out (0 == ok, else err). */
int rblx_readmem(void *addr, void *out, size_t n);

/* Write raw memory (uses /proc/self/mem + mprotect); 0 == ok. */
int rblx_writemem(void *addr, const void *in, size_t n);

/* Convenience: 4/8/16-bit reads + writes through /proc/self/mem. */
uint32_t rblx_read_u32(void *addr);
uint64_t rblx_read_u64(void *addr);
void     rblx_write_u32(void *addr, uint32_t v);
void     rblx_write_u64(void *addr, uint64_t v);

/* ARM64-specific: follow a 2-operand ADRP/ADD pair to recover a data pointer. */
void *rblx_adrp_add_resolve(void *insn); /* insn points @ the ADRP            */

/*
 * Resolve a symbol by walking the in-memory ELF dynamic symbol table of a
 * module found via rblx_find_module(). Works even when the lib was loaded
 * into a private linker namespace where dlsym(RTLD_DEFAULT) cannot see it,
 * and NEVER triggers a new load of the module (no OOM risk on the device).
 * Returns the runtime address or NULL.
 */
void *rblx_dlsym_module(const rblx_Module *mod, const char *name);

/* True if addr lies inside the module's mapped range [base, end). */
bool rblx_addr_in_module(const rblx_Module *mod, const void *addr);

#ifdef __cplusplus
}
#endif
#endif /* RBLX_SCAN_H */

/*
 * memops.h — Lua-level memory read/write primitives.
 * Implements UNC `readfile` style byte primitives plus the Roblox-native
 * memory functions (readpointer, writefloat, readstring…) used by
 * delta/arceusx scripts targeting the engine's data models.
 */
#ifndef RBLX_MEMOPS_H
#define RBLX_MEMOPS_H

#include "lua_compat.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Register the full memory primitive family onto `L`:
 *   readpointer(addr)      -> int    (Luau-style pointer-as-int)
 *   writepointer(addr,v)   -> void
 *   readdouble(addr)       -> number
 *   writedouble(addr,v)    -> void
 *   readstring(addr,n)     -> string | nil (on fault)
 *   writestring(addr,s)    -> int
 *   readvector3(addr)      -> Vector3 table
 *   freeregion(addr,len)   -> int
 *   allocate(len)          -> addr pointer
 */
int rblx_memops_init(rblx_lua_State *L);

/* Direct C entry for injectors wanting to bypass Lua parsing. */
int   rblx_mem_readstring(char *dst, size_t dstlen, void *addr, size_t n);
size_t rblx_mem_writestring(void *addr, const char *s, size_t maxn);
int   rblx_mem_read_double(double *out, void *addr);
int   rblx_mem_write_double(void *addr, double v);
int   rblx_get_process_map(const char **maps_out, void *addr);

#ifdef __cplusplus
}
#endif
#endif /* RBLX_MEMOPS_H */

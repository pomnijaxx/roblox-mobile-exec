/*
 * lua_compat.h — Minimal Lua C ABI shim.
 * Roblox runs a fork of Lua 5.3 (Luau on mobile). We do NOT link liblua;
 * instead we resolve the engine symbols from libRoblox.so at runtime and
 * call them through typed function pointers. This header defines only the
 * types/structs the API requires so that <no> upstream lua headers are needed
 * and the library stays self-contained for cross-compilation.
 *
 * The layout below mirrors upstream Lua 5.3 / Luau public ABI so it can
 * drive BOTH a freshly-bootstrapped state and the real Roblox lua_State once
 * its symbols are hooked.
 */
#ifndef RBLX_LUA_COMPAT_H
#define RBLX_LUA_COMPAT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef ptrdiff_t rblx_LuaInteger;     /* lu_Int    (>=32bit)              */
typedef double    rblx_LuaNumber;      /* lua_Num                         */

/*
 * Value is opaque to us — Roblox keeps the real definition. We only ever
 * touch *lua_State* pointers; never dereference the body.
 */
typedef struct rblx_lua_State rblx_lua_State;
typedef int (*rblx_lua_CFunction)(rblx_lua_State *L,
                                  void *dbgfr, void *ctx, int nresults);

/* Lua type enum (matches upstream 5.3 / Luau subset) */
enum rblx_LuaType {
    RBLX_LUA_TNONE      = -1,
    RBLX_LUA_TNIL       = 0,
    RBLX_LUA_TBOOLEAN   = 1,
    RBLX_LUA_TLIGHTUSERDATA = 2,
    RBLX_LUA_TNUMBER    = 3,
    RBLX_LUA_TSTRING    = 4,
    RBLX_LUA_TTABLE     = 5,
    RBLX_LUA_TFUNCTION  = 6,
    RBLX_LUA_TUSERDATA  = 7,
    RBLX_LUA_TTHREAD    = 8,
};

/* ----------------------------------------------------------------------- */
/* Runtime-resolved signatures (dlopen'd from libRoblox.so)                */
/* ----------------------------------------------------------------------- */
typedef rblx_lua_State *      (*rblx_luaL_newstate_t)(void);
typedef void                  (*rblx_lua_close_t)(rblx_lua_State *);
typedef void                  (*rblx_luaL_openlibs_t)(rblx_lua_State *);
typedef int                   (*rblx_luaL_loadstring_t)(rblx_lua_State *,
                                                        const char *,
                                                        const char *);
/* Roblox's engine `loadstring` is registered as a plain C closure:
 * int luaB_loadstring(lua_State* L) — reads arg 1 (source) from the stack,
 * returns 1 (compiled chunk on top) or 2 (nil, err on top).               */
typedef int                   (*rblx_luaB_loadstring_t)(rblx_lua_State *);
typedef int                   (*rblx_luaL_loadbuffer_t)(rblx_lua_State *,
                                                        const char *, size_t,
                                                        const char *);
typedef int                   (*rblx_luaL_loadbufferx_t)(rblx_lua_State *,
                                                         const char *, size_t,
                                                         const char *,
                                                         const char *);
/* Roblox fork of pushcclosure carries EXTRA state vs stock Lua:
 * (L, fn, const char* debugname, int nup, void* extra) — debugname and
 * extra accept NULL. Confirmed by disasm @0x2229450: x2 goes through
 * strlen (cbz NULL skip), w3 is the upvalue count, x4 is stored into
 * the closure at +0x30.                                                  */
typedef void                  (*rblx_lua_pushcclosure_t)(rblx_lua_State *,
                                                         rblx_lua_CFunction,
                                                         const char *,
                                                         int,
                                                         void *);
typedef int                   (*rblx_lua_pcall_t)(rblx_lua_State *,
                                                  int nargs, int nresults,
                                                  int errfunc);
typedef int                   (*rblx_lua_call_t)(rblx_lua_State *,
                                                 int nargs, int nresults);
typedef void                  (*rblx_lua_setglobal_t)(rblx_lua_State *,
                                                      const char *);
typedef void                  (*rblx_lua_getglobal_t)(rblx_lua_State *,
                                                      const char *);
typedef int                   (*rblx_lua_gettop_t)(rblx_lua_State *);
typedef void                  (*rblx_lua_settop_t)(rblx_lua_State *, int);
typedef void                  (*rblx_lua_pushnil_t)(rblx_lua_State *);
typedef void                  (*rblx_lua_pushstring_t)(rblx_lua_State *,
                                                       const char *);
typedef void                  (*rblx_lua_pushnumber_t)(rblx_lua_State *,
                                                       rblx_LuaNumber);
typedef void                  (*rblx_lua_pushinteger_t)(rblx_lua_State *,
                                                        rblx_LuaInteger);
typedef const char *          (*rblx_lua_tostring_t)(rblx_lua_State *,
                                                     int);
typedef const char *          (*rblx_lua_tolstring_t)(rblx_lua_State *,
                                                      int, size_t *);
typedef rblx_LuaInteger       (*rblx_lua_tointeger_t)(rblx_lua_State *,
                                                      int);
typedef int                   (*rblx_lua_isnumber_t)(rblx_lua_State *,
                                                     int);
typedef int                   (*rblx_lua_type_t)(rblx_lua_State *,
                                                 int);
typedef void                  (*rblx_lua_createtable_t)(rblx_lua_State *,
                                                        int, int);
typedef void                  (*rblx_lua_settable_t)(rblx_lua_State *,
                                                     int);
typedef int                   (*rblx_lua_next_t)(rblx_lua_State *, int);
typedef size_t                (*rblx_lua_objlen_t)(rblx_lua_State *,
                                                   int);
typedef void                  (*rblx_lua_pushvalue_t)(rblx_lua_State *, int);
typedef void                  (*rblx_lua_replace_t)(rblx_lua_State *, int);
typedef void *                (*rblx_lua_newuserdata_t)(rblx_lua_State *,
                                                        size_t);
typedef void                  (*rblx_lua_pushlightuserdata_t)(rblx_lua_State*,
                                                              void *);
typedef int                   (*rblx_lua_requiref_t)(rblx_lua_State *,
                                                     const char *modname,
                                                     rblx_lua_CFunction openf,
                                                     int glberr0);
typedef int                   (*rblx_luaL_ref_t)(rblx_lua_State *, int);
typedef void                  (*rblx_lua_rawseti_t)(rblx_lua_State *, int,
                                                    rblx_LuaInteger);
typedef rblx_LuaInteger       (*rblx_lua_tointegerx_t)(rblx_lua_State *, int,
                                                       int *);
typedef int                   (*rblx_lua_error_t)(rblx_lua_State *);
typedef int                   (*rblx_lua_load_t)(rblx_lua_State *,
                                                 void *reader, void *dt,
                                                 const char *name);
typedef const char *          (*rblx_lua_pushf_string_t)(rblx_lua_State *,
                                                          const char *, ...);
typedef const char *          (*rblx_lua_pushlstring_t)(rblx_lua_State *,
                                                        const char *, size_t);

/* Roblox/Luau specific token */
#define RBLX_LUA_OK    0
#define RBLX_LUA_TK_FLOAT    0x00
#define RBLX_LUA_TK_EOS        0xFF

/* Standard Lua status codes (stock Lua 5.3 values) */
#define RBLX_LUA_ERRRUN      2
#define RBLX_LUA_ERRSYNTAX   3
#define RBLX_LUA_ERRMEM      4
#define RBLX_LUA_ERRERR      5

#define RBLX_LUA_GLOBALS_ID    "globals"

/* RBLX_API calling convention shim for callbacks */
#define RBLX_API(r) r

#ifdef __cplusplus
}
#endif
#endif /* RBLX_LUA_COMPAT_H */

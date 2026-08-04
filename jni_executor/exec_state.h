/*
 * exec_state.h — shared cross-translation-unit handle to the resolved Roblox
 * symbol table + Lua-API accessor inlines. Included by every .cpp in the
 * executor so UNC handlers, memops and the engine itself talk the same live
 * lua_State through one typed pointer table (not the real liblua link set).
 */
#ifndef RBLX_EXEC_STATE_H
#define RBLX_EXEC_STATE_H

#include "lua_compat.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Full resolved-symbol table (defined in roblox_exec.cpp). We expose it
 * through a function accessor instead of a bare global so dlinit ordering
 * across translation units is deterministic (the table is fully zero-init
 * until bind_symbols() runs, which always happens before any UNC fn fires). */
typedef struct RobloxSymbols RobloxSymbols;
struct RobloxSymbols {
    void    *module_base;
    size_t   module_size;
    void    *lua_state_ptr;

    rblx_luaL_newstate_t          luaL_newstate;
    rblx_lua_close_t              lua_close;
    rblx_luaL_openlibs_t          luaL_openlibs;
    rblx_luaL_loadstring_t        luaL_loadstring;
    rblx_luaL_loadbuffer_t        luaL_loadbuffer;
    rblx_luaL_loadbufferx_t       luaL_loadbufferx;
    rblx_lua_pushcclosure_t       lua_pushcclosure;
    rblx_lua_pcall_t              lua_pcall;
    rblx_lua_call_t               lua_call;
    rblx_lua_setglobal_t          lua_setglobal;
    rblx_lua_getglobal_t          lua_getglobal;
    rblx_lua_gettop_t             lua_gettop;
    rblx_lua_settop_t             lua_settop;
    rblx_lua_pushnil_t            lua_pushnil;
    rblx_lua_pushstring_t         lua_pushstring;
    rblx_lua_pushnumber_t         lua_pushnumber;
    rblx_lua_pushinteger_t        lua_pushinteger;
    rblx_lua_tostring_t           lua_tostring;
    rblx_lua_tointeger_t          lua_tointeger;
    rblx_lua_tointegerx_t         lua_tointegerx;
    rblx_lua_isnumber_t           lua_isnumber;
    rblx_lua_type_t               lua_type;
    rblx_lua_createtable_t        lua_createtable;
    rblx_lua_settable_t           lua_settable;
    rblx_lua_next_t               lua_next;
    rblx_lua_objlen_t             lua_objlen;
    rblx_lua_pushvalue_t          lua_pushvalue;
    rblx_lua_replace_t            lua_replace;
    rblx_lua_newuserdata_t        lua_newuserdata;
    rblx_lua_pushlightuserdata_t  lua_pushlightuserdata;
    rblx_lua_requiref_t           lua_requiref;
rblx_luaL_ref_t              luaL_ref;
    rblx_lua_rawseti_t            lua_rawseti;
    rblx_lua_pushlstring_t       lua_pushlstring;
    rblx_lua_error_t              lua_error;
    rblx_lua_load_t               lua_load;
    rblx_lua_pushf_string_t       lua_pushf_string;
};

extern RobloxSymbols g_sym;

/* Convenience: a live lua_State* fetched from the resolved pointer or a
 * caller-supplied one. Returns NULL if the engine has not bootstrapped.   */
rblx_lua_State *rblx_state_current(void);   /* live lua_State* (g_cur or resolved) */

/* Trampoline accessors for the inline hooks so callers can chain into the
 * ORIGINAL luaL_loadstring/lua_pcall bodies without re-entering the patch
 * (avoids recursion). Returns NULL when the hook was not installed.       */
void *rblx_trampoline_loadstring(void);
void *rblx_trampoline_pcall(void);
bool  rblx_in_trusted_loader(void);        /* true iff sUNC loader-frame armed*/

#ifdef __cplusplus
}
#endif

/* C-callable Lua accessors — these dereference g_sym at inline speed and
 * double-check NULL for robustness (so any UNC fn stays crash-safe even if
 * the engine partially init'd).                              */
#ifdef RBLX_NO_MACROS
#else
#define L_GETTOP()      (g_sym.lua_gettop          ? g_sym.lua_gettop(g_cur)          : 0)
#define L_PUSHCC(fn,n)  (g_sym.lua_pushcclosure    ? g_sym.lua_pushcclosure(g_cur,fn,n)    : (void)0)
#define L_SETGLOBAL(k)  (g_sym.lua_setglobal       ? g_sym.lua_setglobal(g_cur,k)       : (void)0)
#define L_PUSHNIL()     (g_sym.lua_pushnil         ? g_sym.lua_pushnil(g_cur)           : (void)0)
#define L_PUSHS(s)      (g_sym.lua_pushstring      ? g_sym.lua_pushstring(g_cur,s)      : (void)0)
#define L_PUSHN(n)      (g_sym.lua_pushnumber      ? g_sym.lua_pushnumber(g_cur,n)      : (void)0)
#define L_PUSHI(i)      (g_sym.lua_pushinteger     ? g_sym.lua_pushinteger(g_cur,(rblx_LuaInteger)i)     : (void)0)
#define L_PUSHLSTR(s,n) (g_sym.lua_pushlstring     ? g_sym.lua_pushlstring(g_cur,(s),(size_t)(n)) : L_PUSHS(s))
#define L_CREATETABLE(a,b) (g_sym.lua_createtable    ? g_sym.lua_createtable(g_cur,a,b)  : (void)0)
#define L_RAWSETI(i)    (g_sym.lua_rawseti         ? g_sym.lua_rawseti(g_cur,i)         : (void)0)
#define L_NEXT(i)       (g_sym.lua_next            ? g_sym.lua_next(g_cur,i)            : 0)
#define L_TYPE(i)       (g_sym.lua_type            ? g_sym.lua_type(g_cur,i)            : RBLX_LUA_TNONE)
#define L_TOSTRING(i)   (g_sym.lua_tostring        ? g_sym.lua_tostring(g_cur,i)        : "")
#define L_TOINT(i)      (g_sym.lua_tointeger       ? g_sym.lua_tointeger(g_cur,i)       : 0)
#define L_OBJLEN(i)     (g_sym.lua_objlen          ? g_sym.lua_objlen(g_cur,i)          : 0)
#define L_PUSHVALUE(i)  (g_sym.lua_pushvalue        ? g_sym.lua_pushvalue(g_cur,i)       : (void)0)
#define L_REF(t)        (g_sym.luaL_ref            ? g_sym.luaL_ref(g_cur,t)             : 0)
#define L_TOINTEGERX(i,o) (g_sym.lua_tointegerx     ? g_sym.lua_tointegerx(g_cur,i,o)    : 0)
#endif

/* g_cur is the lua_State the active UNC handler runs on (thread-local). */
#ifdef __cplusplus
extern "C" rblx_lua_State *g_cur;
#endif

#endif /* RBLX_EXEC_STATE_H */

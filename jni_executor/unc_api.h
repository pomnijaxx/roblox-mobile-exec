/*
 * unc_api.h — Universal Naming Convention + Secure-UNC surface.
 * Declares the Roblox-standard environment functions exposed to bootstrapped
 * scripts and the sUNC security-gated entry points. The implementation lives
 * in jni/lib/..../unc_api/c via runtime lua_State symbol binding.
 */
#ifndef RBLX_UNC_API_H
#define RBLX_UNC_API_H

#include "lua_compat.h"
#include "hooks.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UNC feature matrix advertised to scripts (read-only global `getfidelity`). */
typedef struct {
    const char *version;        /* e.g.  "0.857.4-Delta-Rev5"       */
    const char *universe;       /* executor brand / codename        */
    const char *scriptcontext;  /* script container id               */
    int        fidelity;        /* numeric fidelity level (0-3)     */
    int        sandbox_flags;   /* bitmask of permitted UNC verbs   */
    int        secure;          /* 1 == sUNC active (cookie gating) */
} rblx_ExecEnv;

/*
 * Initialize the full UNC + sUNC namespace into a freshly-resolved lua_State.
 * Called once after symbols are bound, before any game loop frames tick.
 *
 * `env` supplies branding + the fidelity bitmask that drives
 * `getfidelity()` / `--[[ syn.environment ]] `.
 *
 * Side effects:
 *   - pushes cfunctions under `_G` & `syn.*`, `crypt.*` etc.
 *   - arms the anti-tamper cookie (if secure==1) — sUNC gate installed.
 */
int rblx_unc_init(rblx_lua_State *L, const rblx_ExecEnv *env);

/* sUNC: mark the live lua_State as bootstrap-trusted (call on init). */
void rblx_sunc_register_state(rblx_lua_State *L);
/* Thread-local "we are inside our own loader frame" flag the detour hooks
 * set right before they chain into Roblox's luaL_loadstring so the in-engine
 * hook can prove the bytecode came from a sanctioned path. */
bool rblx_sunc_active_loader(void);        /* true iff inside g_in_trusted_loader */
void rblx_sunc_enter(void);                /* set  */
void rblx_sunc_leave(void);                /* clear */
bool rblx_is_trusted_state(rblx_lua_State *L);

#ifdef __cplusplus
} /* closes extern "C" opened at top */
#endif

/* Java VM handle accessor (kept opaque: `struct JavaVM` is typedef'd by jni.h
 * into `JavaVM`; exposing it as `void*` sidesteps host/NDK header clashes). */
#ifdef __cplusplus
extern "C" {
#endif
extern void *rblx_jvm_handle(void);        /* actual JavaVM* returned opaque    */
extern void *rblx_loader_callback_ref(void);
#ifdef __cplusplus
}
#endif

/* Register a single global cfunction under both _G and syn namespace. */
void rblx_unc_bind_global(rblx_lua_State *L,
                          const char *gname,
                          rblx_lua_CFunction fn,
                          const char *synname);

/* Push a (optionally encrypted-at-rest) config blob read from APK assets. */
void rblx_unc_load_asset(rblx_lua_State *L, const char *assetpath);

#ifdef __cplusplus
namespace rblxec {
/* Build a Lua table [{k1=v1},{},...] on the current g_cur using a variadic,
 * type-dispatching helper. Handy while constructing UNC result objects.     */
void push_config_table(rblx_lua_State *L);
}
#endif

#endif /* RBLX_UNC_API_H */

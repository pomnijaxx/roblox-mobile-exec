/*
 * hooks.h — Thumb2/ARM64-inlined trampoline hooking + detour registry.
 *
 * We hijack hot call-sites inside libRoblox.so (specifically
 * luaL_loadstring / lua_pcallk / lua_pushcclosure) by overwriting their first
 * few bytes with a `B <ours>` or `BR <xn>` and parking a relocated trampoline
 * under a separate page so calls to the *original* implementation still land.
 *
 * ARM64 patcher used here supports two strategies:
 *   (A) B <imm26>          — +/- 128MiiB range, minimal 4-byte patch
 *   (B) LDR Xt,#imm; BR Xt — 8-byte patch, unbounded range (always-safe)
 *
 * The trampoline copies the overwritten bytes, optionally fixing up relative
 * operands (branches/loads) whose targets are now invalid, and appends a jump
 * to the real function body+backup_len. This implements `I/x86_86`'s
 * "push original / jmp remainder" technique on ARM64.
 */
#ifndef RBLX_HOOKS_H
#define RBLX_HOOKS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RBLX_HOOK_TRAMP_MAX 128   /* max trampoline byte budget            */
#define RBLX_HOOK_PATCH_SIZE 8    /* minimum patchable region on ARM64     */

typedef struct {
    void *target;          /* runtime address being hooked                */
    void *detour;          /* our interceptor function                    */
    uint8_t backup[RBLX_HOOK_TRAMP_MAX];
    size_t  backup_len;    /* bytes stolen/relocated                      */
    uint8_t patch[RBLX_HOOK_PATCH_SIZE];
    void *trampoline;      /* relocated stub -> original rest             */
    bool active;
    const char *name;
} rblx_Hook;

/*
 * Install (or refresh) an inline hook. `detour` is invoked with the same
 * register/state the real target would see; it MUST call through
 * `rblx_Hook.trampoline` to chain to the original. The trampoline is filled
 * in place.
 */
int rblx_hook_install(rblx_Hook *h, void *target, void *detour,
                      int min_bytes);

/* Remove a hook (restores original bytes). Safe to call on an inactive hook. */
int rblx_hook_remove(rblx_Hook *h);

/* Convenience: resolve a function pointer at runtime via our own hook table. */
void *rblx_resolve_detour(const char *sym, void **trampoline_out);

#ifdef __cplusplus
}
#endif
#endif /* RBLX_HOOKS_H */

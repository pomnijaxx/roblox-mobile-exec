// roblox_exec.cpp — Roblox Mobile executor engine (main JNI module).
//
// Lifecycle:
//   Dalvik loads librobloxexec.so (patched APK) → JNI_OnLoad captures VM.
//   Java_roblox_executor_Executor_nativeInit():
//     1. locate libRoblox.so via /proc/self/maps (rblx_find_module)
//     2. resolve the live lua_C API symbols (dlsym + arm64 sig fallbacks)
//     3. discover the live lua_State* (the engine keeps one in .bss)
//     4. install inline ARM64 hooks routing lua_loadstring/lua_pcall through
//        the sUNC gate
//     5. inject the UNC + memops + sUNC global families
//   Java_Executor_nativeExec("SCRIPT_SRC") then compiles+execs user Lua.
//
#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <stdarg.h>

#include "lua_compat.h"
#include "scan.h"
#include "hooks.h"
#include "unc_api.h"
#include "memops.h"
#include "exec_state.h"

// HOOK INSTALL MODE:
//   0 = normal (loadstring + pcall detours)
//   1 = diagnostic — no hooks at all (proved .text patch triggers tamper)
//   2 = probe — hook lua_tolstring ONLY (chain-only). If the game survives,
//       the anti-tamper scanner is watching pcall/loadstring specifically and
//       we can execute via raw pcall pointer from a non-critical detour.
#ifndef RBLX_HOOK_MODE
#define RBLX_HOOK_MODE 1
#endif
#define LOG_TAG "RobloxExec"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)

/* ---- continuous tamper-scanner capture (RBLX_SCANLOG) -----------------
 * A background thread snapshots EVERY thread's cpu ticks every 250ms and
 * appends one line to /sdcard/Download/tscan_log.txt. When the game's
 * anti-tamper freezes us ~2s after .text patching, the tail of this file
 * shows WHICH thread spiked (and whether a new thread appeared) right
 * before the freeze — that's the scanner, caught in the act.
 * Enabled by default; harmless on no-hook builds (no freeze, log idle). */
#ifndef RBLX_SCANLOG
#define RBLX_SCANLOG 1
#endif
#define RBLX_TSLOG_PATH "/storage/emulated/0/Download/tscan_log.txt"
/* Fallback copies: app-internal path (no storage permission needed to WRITE,
 * but needs run-as/adb to read) and a path guessed from our own package. */
static const char *tslog_internal_path(void) {
	static char buf[160];
	static int  done = 0;
	if (!done) {
		done = 1;
		char pkg[96] = "com.roblox.client";
		FILE *f = fopen("/proc/self/cmdline", "r");
		if (f) {
			size_t n = fread(pkg, 1, sizeof(pkg) - 1, f);
			fclose(f);
			if (n) pkg[n] = '\0';   /* cmdline is NUL-terminated */
		}
		char *slash = strchr(pkg, '/');
		if (slash) *slash = '\0';
		/* 1) app-private: needs adb root/unroot to read */
		snprintf(buf, sizeof(buf), "/data/data/%s/files/tscan_log.txt", pkg);
	}
	return buf;
}

/* Path every app can write on Android 11+ WITHOUT storage permission, and
 * one the Termux shell can read directly: Android/data/<pkg>/files/.        */
static const char *tslog_android_data_path(void) {
	static char buf[192];
	static int  done = 0;
	if (!done) {
		done = 1;
		char pkg[96] = "com.roblox.client";
		FILE *f = fopen("/proc/self/cmdline", "r");
		if (f) {
			size_t n = fread(pkg, 1, sizeof(pkg) - 1, f);
			fclose(f);
			if (n) pkg[n] = '\0';
		}
		char *slash = strchr(pkg, '/');
		if (slash) *slash = '\0';
		snprintf(buf, sizeof(buf),
		         "/storage/emulated/0/Android/data/%s/files/tscan_log.txt",
		         pkg);
	}
	return buf;
}
#define RBLX_TS_INTERVAL_MS  250
#define RBLX_TS_MAX_THREADS  512
#define RBLX_SPIKE_TICKS 20 /* ~80% of one core per 250ms window (100Hz ticks) */

static pthread_mutex_t g_tslog_mu = PTHREAD_MUTEX_INITIALIZER;
static volatile long g_pcall_calls = 0;   /* counted in detour_pc_entry */

static void tslog(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	char line[1024];
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	int h = snprintf(line, sizeof(line), "[%ld.%03ld] ",
	                 (long)ts.tv_sec, ts.tv_nsec / 1000000);
	vsnprintf(line + h, sizeof(line) - (size_t)h, fmt, ap);
	va_end(ap);
	__android_log_print(ANDROID_LOG_INFO, "RobloxTScan", "%s", line);
	pthread_mutex_lock(&g_tslog_mu);
	/* 1) external: /storage/emulated/0/Download (readable by Termux) */
	FILE *f = fopen(RBLX_TSLOG_PATH, "a");
	if (f) {
		fputs(line, f);
		fputc('\n', f);
		fflush(f);
		fclose(f);
	}
	/* 1b) Android/data/<pkg>/files — writeable w/o permission, readable by Termux */
	const char *jd = tslog_android_data_path();
	if (jd) {
		FILE *h = fopen(jd, "a");
		if (h) {
			fputs(line, h);
			fputc('\n', h);
			fflush(h);
			fclose(h);
		}
	}
	/* 3) internal: app-private files dir (readable via adb run-as) */
	const char *ip = tslog_internal_path();
	if (ip) {
		FILE *g = fopen(ip, "a");
		if (g) {
			fputs(line, g);
			fputc('\n', g);
			fflush(g);
			fclose(g);
		}
	}
	pthread_mutex_unlock(&g_tslog_mu);
}

/* Definitions of externs declared in exec_state.h */
RobloxSymbols  g_sym{};
rblx_lua_State *g_cur           = nullptr;
static JavaVM *g_jvm            = nullptr;
static jobject  g_loader_cb      = nullptr;     /* global ref on ScriptLoader   */
static bool      g_hooks_active  = false;
static bool      g_unc_injected  = false;       /* UNC family injected at least once */
static pthread_mutex_t g_lock    = PTHREAD_MUTEX_INITIALIZER;

/* Last engine module resolved from /proc/self/maps; used to validate that a
 * dlsym'd symbol actually lives INSIDE the engine before we hook it.        */
static rblx_Module g_mod{};
static bool        g_mod_valid = false;

/* Native-side JNI handles reached by the UNC/HTTP surface in adjacent TUs.
 * Declared extern "C" so the C++ (and future C) object layout stays ABI-wide
 * one symbol, and to avoid forcing every caller to know about jni.h. */
extern "C" JNIEXPORT void *rblx_jvm_handle(void)          { return (void*)g_jvm; }
extern "C" JNIEXPORT void *rblx_loader_callback_ref(void) { return (void*)g_loader_cb; }

static rblx_Hook g_hook_loadstring{};
static rblx_Hook g_hook_pcall{};
static rblx_Hook g_hook_tolstring{};
static rblx_ExecEnv g_env{};

extern "C" void *rblx_trampoline_loadstring(void){ return g_hook_loadstring.active ? g_hook_loadstring.trampoline : nullptr; }
extern "C" void *rblx_trampoline_pcall(void){ return g_hook_pcall.active ? g_hook_pcall.trampoline : nullptr; }
extern "C" void *rblx_trampoline_tolstring(void){ return g_hook_tolstring.active ? g_hook_tolstring.trampoline : nullptr; }

/* ---- queued user script ------------------------------------------------
 * jni_exec() (UI thread) only BINDS the engine + enqueues the source. The
 * script itself is executed by pump_pending() from inside the lua_pcall
 * detour, i.e. ON ROBLOX'S OWN SCRIPT THREAD with its real live lua_State.
 * Calling lua_pcall on the live game state from a foreign thread races with
 * the VM and corrupts it (delayed crash) — this design eliminates that.   */
#define RBLX_QUEUE_MAX (1u<<16)
static pthread_mutex_t g_queue_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_queue_cv = PTHREAD_COND_INITIALIZER;
static char    g_pending[RBLX_QUEUE_MAX];
static size_t  g_pending_len   = 0;
static int     g_pending_rc    = RBLX_LUA_OK;
static bool    g_pending_done  = false;

static void pump_pending(rblx_lua_State *L);   /* defined after do_inject_unc */

/* thread-local call depth: protects the sUNC detour path from re-entry */
static __thread int g_unc_depth;

/* live lua_State* either from g_cur (explicitly set) or resolved by us */
rblx_lua_State *rblx_state_current(void) {
	if (g_cur) return g_cur;
	if (g_sym.lua_state_ptr) {
		void **slot = (void**)g_sym.lua_state_ptr;
		if (slot && *slot) return (rblx_lua_State*)(*slot);
	}
	return nullptr;
}

/* ---- detours (placed via inline ARM64 hooks; real ARM64 prototypes) ----
 *   luaL_loadstring(L, source, name)   — x0:L, x1:src, x2:name
 *   lua_pcall (L, nargs, nresults, ef) — x0:L, x1:nargs, x2:nres, x3:ef
 * Roblox reaches them as plain C fns (no lua_CFunction calling shim here
 * because these symbols are NOT the task-dispatch form — they are the core
 * engine entry points). We chain through the trampoline (relocated original
 * bytes) so the Lua VM semantics survive.
 * sUNC: only `_G.load` (registered in unc_api.cpp) may arm the per-thread
 * loader-frame token via rblx_sunc_enter before reaching here — a pure Lua
 * sandbox script cannot forge that without a native handle.            */
typedef int (*ls_orig_t)(rblx_lua_State*, const char*, const char*);
typedef int (*pc_orig_t)(rblx_lua_State*, int, int, int);
typedef const char* (*ts_orig_t)(rblx_lua_State*, int, size_t*);

static int unc_load_dispatcher(rblx_lua_State *L, int nargs, int nres, int ef){
	pc_orig_t tramp = reinterpret_cast<pc_orig_t>(rblx_trampoline_pcall());
	return tramp ? tramp(L,nargs,nres,ef) : 0;
}
static int unc_load_dispatcher_loadstring(rblx_lua_State *L, rblx_lua_State*, int nargs, int nres){
	(void)L;(void)nargs;(void)nres;
	(void)unc_load_dispatcher;
	return 0;
}

/* install-time detour that Roblox actually branches into ------------------- */
static int detour_ls_entry(rblx_lua_State *L, const char* src, const char* name){
	g_cur=L; (void)src;(void)name;
	int armed = rblx_in_trusted_loader();
	LOGV("luaL_loadstring detour: src=%p armed=%d", (const void*)src, armed);
	ls_orig_t tramp = reinterpret_cast<ls_orig_t>(rblx_trampoline_loadstring());
	return tramp ? tramp(L, src, name) : 0;   // propagate original status
}
static int detour_pc_entry(rblx_lua_State *L, int nargs, int nresults, int errf){	g_cur=L;
	__sync_add_and_fetch(&g_pcall_calls, 1);
	pump_pending(L);                     // run queued user script on the game thread
	g_unc_depth++;                      // block re-entrant UNC dispatch
	pc_orig_t tramp=reinterpret_cast<pc_orig_t>(rblx_trampoline_pcall());
	int r = tramp ? tramp(L,nargs,nresults,errf) : 0;
	g_unc_depth--;
	if (r && r<=5) LOGV("lua_pcall => %d (L=%p)", r, (void*)L);
	return r;
}
/* PROBE detour: lua_tolstring chain-only (no pump yet). If this survives
 * in-game, the tamper scanner watches pcall/loadstring specifically.      */
static const char* detour_ts_entry(rblx_lua_State *L, int idx, size_t *len){
	g_cur=L;
	ts_orig_t tramp = reinterpret_cast<ts_orig_t>(rblx_trampoline_tolstring());
	return tramp ? tramp(L, idx, len) : nullptr;
}

/* ---- inline-hook installer ---- */
static int install_hooks(void) {
	int rc = 0;
#if RBLX_HOOK_MODE == 1
	LOGI("DIAGNOSTIC BUILD: hook patching SKIPPED by design (RBLX_HOOK_MODE=1)");
	tslog("HOOKS SKIPPED mode=1");
	return 0;
#elif RBLX_HOOK_MODE == 2
	LOGI("PROBE BUILD: hooking lua_tolstring ONLY (RBLX_HOOK_MODE=2)");
	if (g_sym.lua_tolstring) {
		if (g_mod_valid && !rblx_addr_in_module(&g_mod, (void*)g_sym.lua_tolstring)) {
			LOGE("tolstring %p outside module — refusing to hook (poisoned symbol)",
			     (void*)g_sym.lua_tolstring);
			g_sym.lua_tolstring = nullptr;
		} else {
			int z = rblx_hook_install(&g_hook_tolstring,
			                          (void*)g_sym.lua_tolstring,
			                          (void*)detour_ts_entry, 16);
			if (z == 0) { g_hooks_active = true; tslog("HOOKS tolstring installed"); }
			else { rc--; LOGE("tolstring hook fail %d", z); }
		}
	}
	LOGI("install_hooks(PROBE tolstring) rc=%d hooks_active=%d", rc, (int)g_hooks_active);
	tslog("HOOKS done mode=2 rc=%d active=%d", rc, (int)g_hooks_active);
	return rc;  // 0 == all good (or none present)
#else
	LOGI("NORMAL BUILD: hooking loadstring + pcall (RBLX_HOOK_MODE=0)");
	if (g_sym.luaL_loadstring) {
		if (g_mod_valid && !rblx_addr_in_module(&g_mod, (void*)g_sym.luaL_loadstring)) {
			LOGE("loadstring %p outside module — refusing to hook (poisoned symbol)",
			     (void*)g_sym.luaL_loadstring);
			g_sym.luaL_loadstring = nullptr;
		} else {
			int z = rblx_hook_install(&g_hook_loadstring,
			                          (void*)g_sym.luaL_loadstring,
			                          (void*)detour_ls_entry, 16);
			if (z == 0) { g_hooks_active = true; tslog("HOOKS loadstring installed"); }
			else { rc--; LOGE("loadstring hook fail %d", z); }
		}
	}
	if (g_sym.lua_pcall) {
		if (g_mod_valid && !rblx_addr_in_module(&g_mod, (void*)g_sym.lua_pcall)) {
			LOGE("pcall %p outside module — refusing to hook (poisoned symbol)",
			     (void*)g_sym.lua_pcall);
			g_sym.lua_pcall = nullptr;
		} else {
			int z = rblx_hook_install(&g_hook_pcall,
			                          (void*)g_sym.lua_pcall,
			                          (void*)detour_pc_entry, 16);
			if (z == 0) { g_hooks_active = true; tslog("HOOKS pcall installed"); }
			else { rc--; LOGE("pcall hook fail %d", z); }
		}
	}
	LOGI("install_hooks rc=%d hooks_active=%d", rc, (int)g_hooks_active);
	tslog("HOOKS done mode=0 rc=%d active=%d", rc, (int)g_hooks_active);
	return rc;  // 0 == all good (or none present)
#endif
}

/* ---- symbol resolution (in-memory ELF dynsym walk; NO dlopen) ---- */
static int bind_symbols(const rblx_Module *mod) {
	if (!mod || !mod->base) return -101;

	/* Never dlopen the engine by name here: dlopen("libroblox.so", ...)
	 * without RTLD_NOLOAD can LOAD A SECOND COPY of the 200MB+ engine into
	 * the default namespace (the original lives in Roblox's private linker
	 * namespace) → RAM spike → LMK kill seconds later. We resolve straight
	 * from the already-mapped module instead.                            */
	bool any = false;
#define R(NAME) do {                                                       \
		void *p = rblx_dlsym_module(mod, #NAME);                       \
		if (p) { *(void **)&g_sym.NAME = p; any = true; }              \
	} while (0)

	R(luaL_newstate);
	R(lua_close);
	R(luaL_openlibs);
	R(luaL_loadstring);
	R(luaL_loadbufferx);                    /* alias fallback */
	R(lua_pushcclosure);
	R(lua_pcall);
	R(lua_call);
	R(lua_setglobal);
	R(lua_getglobal);
	R(lua_gettop);
	R(lua_settop);
	R(lua_pushnil);
	R(lua_pushstring);
	R(lua_pushnumber);
	R(lua_pushinteger);
	R(lua_tostring);
	R(lua_tointeger);
	R(lua_createtable);
	R(lua_settable);
	R(lua_next);
	R(lua_objlen);
	R(lua_pushvalue);
	R(lua_replace);
	R(luaL_ref);
	R(lua_rawseti);
	R(lua_error);
	R(lua_newuserdata);
	R(lua_pushlightuserdata);
	R(lua_requiref);
	R(lua_load);
	R(lua_pushf_string);
	R(lua_type);
	R(lua_pushlstring);
#undef R

	/* Engine-version-pinned fallback: this APK's libroblox.so exports NO
	 * lua_* symbols (hidden visibility / stripped Luau), so the dynsym walk
	 * above finds nothing. The offsets below are the link-time VAs recovered
	 * by offline RE of the EXACT same binary (fix3_build/elf_check). Runtime
	 * address = module load bias + link VA: the off-0 PT_LOAD of this .so
	 * has p_vaddr 0, so bias == mod->base. Fallbacks only fill what dlsym
	 * already resolved (they never overwrite a live symbol).               */
#define FB(NAME, OFF) do {                                                    \
	if (!g_sym.NAME && mod->base) {                                          \
		g_sym.NAME = (decltype(g_sym.NAME))((uint8_t*)mod->base + (OFF));   \
		any = true;                                                        \
		LOGI("fb " #NAME " <- base+0x%llx = %p",                            \
		     (unsigned long long)(OFF), (void*)g_sym.NAME);                \
	}                                                                        \
} while (0)
	FB(lua_pcall,         0x5b4f2cc);   /* luaB_pcall → luaD_pcall          */
	FB(lua_pushstring,    0x2229bf0);
	FB(lua_pushlstring,   0x5b4d6c8);
	FB(lua_pushcclosure,  0x2229450);   /* (L, fn, debugname, nup, ctx)     */
	FB(lua_pushnil,       0x222a0dc);
	FB(lua_gettop,        0x223ca6c);
	FB(lua_settop,        0x2228e68);
	FB(lua_next,          0x224f768);
	FB(lua_type,          0x2228e00);
	FB(lua_tolstring,     0x223d140);   /* NULL-len safe (cbz x19)           */
	FB(luaB_loadstring,   0x3a53f8c);   /* engine global loadstring closure  */
#undef FB

	/* alias fixup: some builds name loadstring differently */
	if (!g_sym.luaL_loadstring) {
		g_sym.luaL_loadstring =
		  (rblx_luaL_loadstring_t)g_sym.luaL_loadbuffer; /* heuristic alias */
	}
	if (g_sym.luaL_loadbufferx && !g_sym.luaL_loadbuffer)
		g_sym.luaL_loadbuffer = (rblx_luaL_loadbuffer_t)g_sym.luaL_loadbufferx;

	LOGI("bind: load=%p loadbuffer=%p ls_ro=%p pcall=%p tolstring=%p type=%p "
	     "top=%p settop=%p cc=%p pushstr=%p",
	     (void*)g_sym.luaL_loadstring, (void*)g_sym.luaL_loadbuffer,
	     (void*)g_sym.luaB_loadstring, (void*)g_sym.lua_pcall,
	     (void*)g_sym.lua_tolstring, (void*)g_sym.lua_type,
	     (void*)g_sym.lua_gettop, (void*)g_sym.lua_settop,
	     (void*)g_sym.lua_pushcclosure, (void*)g_sym.lua_pushstring);

	g_sym.module_base = mod->base;
	g_sym.module_size = mod->size;

	LOGI("symbols: load=%p ls_ro=%p pcall=%p newstate=%p type=%p tolstr=%p",
	     g_sym.luaL_loadstring, g_sym.luaB_loadstring, g_sym.lua_pcall,
	     g_sym.luaL_newstate, g_sym.lua_type, g_sym.lua_tolstring);
	return any ? 0 : -102;
}

/*
 * Discover Roblox's persistent lua_State pointer slot.
 * Luau stores `lua_State *gL` (or equivalent script-context field) in .bss.
 * We locate it by scanning .bss for an in-module pointer whose target lies
 * inside libRoblox's executable region (the state's vtable region).
 */
static int resolve_lua_state(const rblx_Module *mod) {
	if (!mod || (!g_sym.luaL_loadstring && !g_sym.luaB_loadstring &&
	             !g_sym.lua_pcall)) return -1;
	if (!mod->bss_off) return -1;
	void **scan = (void**)((uint8_t*)mod->base + mod->bss_off);
	size_t ents = (mod->size > mod->bss_off)
	              ? (mod->size - mod->bss_off) / sizeof(void*) : 0;
	if (ents > (1u<<22)) ents = (1u<<22);          /* cap scan time */
	uintptr_t lo = (uintptr_t)mod->base;
	uintptr_t hi = (uintptr_t)mod->end;
	for (size_t i = 0; i < ents; i++) {
		void *cand = scan[i];
		if (((uintptr_t)cand & 0x7) != 0) continue;
		if ((uintptr_t)cand < lo || (uintptr_t)cand >= hi) continue;
		usleep(1000);
		if (scan[i] != cand) continue;             /* unstable → skip */
		g_sym.lua_state_ptr = &scan[i];            // store slot address
		LOGI("found lua_State slot @ %p -> candidate %p", &scan[i], cand);
		return 0;
	}
	LOGW("lua_State slot not auto-located; hooks deliver the live state");
	return -1;
}

/* ---- UNC + memops injection into live L ---- */
static int do_inject_unc(void) {
	rblx_ExecEnv env{};
	env.version       = "0.830.5-rc.7";   /* mimic shipped build tag             */
	env.universe      = "ArceusRevo-x64-android";
	env.scriptcontext = "LuauRuntime-Android";
	env.fidelity      = 3;
	env.sandbox_flags = 0xFFFFFFFFu;
	env.secure        = 1;                /* sUNC engaged */
	memcpy(&g_env, &env, sizeof(env));

	rblx_lua_State *L = rblx_state_current();
	if (!L) { LOGE("no live lua_State to inject UNC into"); return -1; }
	/* NOTE: we deliberately do NOT call luaL_openlibs(L) here. Re-opening the
	 * standard libraries on Roblox's LIVE global state would replace their
	 * customized globals and corrupt the running game. The state already has
	 * everything it needs; we only add our own globals below.             */

	int rc = rblx_unc_init(L, &env);
	if (rc) LOGE("unc_init failed (%d)", rc);
	rc |= rblx_memops_init(L);
	if (rc) LOGE("memops init failed (%d)", rc);
	g_hooks_active = true;
	return rc;
}

/* ---- queued-script pump (runs ON the game's script thread) -------------- */
static void pump_pending(rblx_lua_State *L) {
	if (!L) return;

	/* FAST PATH FIRST: with an idle queue the detour must do ZERO work —
	 * no UNC injection, no state probing. The previous order ran
	 * do_inject_unc() on the very first pcall after hook install (even
	 * with no script queued), re-entrantly mutating the game's live Lua
	 * state inside its own in-flight pcall → freeze then crash.          */
	pthread_mutex_lock(&g_queue_mu);
	if (!g_pending_len) { pthread_mutex_unlock(&g_queue_mu); return; }
	pthread_mutex_unlock(&g_queue_mu);

	/* one-time UNC surface install — only reached when a script is pending */
	if (!g_unc_injected) {
		pthread_mutex_lock(&g_lock);
		if (!g_unc_injected) {
			if (do_inject_unc() == 0) g_unc_injected = true;
		}
		pthread_mutex_unlock(&g_lock);
	}

	pthread_mutex_lock(&g_queue_mu);
	if (!g_pending_len) { pthread_mutex_unlock(&g_queue_mu); return; }
	char src[RBLX_QUEUE_MAX];
	size_t n = g_pending_len < RBLX_QUEUE_MAX - 1
	           ? g_pending_len : RBLX_QUEUE_MAX - 1;
	memcpy(src, g_pending, n);
	src[n] = '\0';
	g_pending_len = 0;                    /* dequeue */
	pthread_mutex_unlock(&g_queue_mu);

	/* Run through the ORIGINAL bodies (trampolines) to avoid re-entering
	 * the detours while the game is already inside them. */
	int rc = RBLX_LUA_ERRRUN;
	ls_orig_t ls = reinterpret_cast<ls_orig_t>(rblx_trampoline_loadstring());
	pc_orig_t pc = reinterpret_cast<pc_orig_t>(rblx_trampoline_pcall());
	/* Preferred path: the engine's OWN `loadstring` C function, wrapped in a
	 * FRESH C closure and driven through lua_pcall. Calling the raw engine
	 * function directly with the game's stack was WRONG: loadstring reads
	 * ARG 1 of the current frame, which inside the game's in-flight
	 * lua_pcall is the GAME's function, not our pushed string — the type
	 * check failed, luaL_error did a longjmp through our detour frames and
	 * corrupted the live state (crash seconds later). Driving it through
	 * lua_pcall makes the VM build a correct frame (arg1 = src) and
	 * captures compile/runtime errors cleanly (status return, no longjmp). */
	if (g_sym.luaB_loadstring && g_sym.lua_pushstring &&
	    g_sym.lua_pushcclosure && pc) {
		int top = g_sym.lua_gettop ? g_sym.lua_gettop(L) : 0;
		g_sym.lua_pushcclosure(L, (rblx_lua_CFunction)g_sym.luaB_loadstring,
		                      nullptr, 0, nullptr);
		g_sym.lua_pushstring(L, src);
		int n = pc(L, 1, 1, 0);      /* loadstring(src) → chunk | nil */
		if (n == RBLX_LUA_OK) {
			/* engine loadstring contract: 1 result = chunk (function) on
			 * top, or nil on compile failure. Check the type — calling
			 * nil blindly yields "attempt to call a nil value" instead
			 * of a contained syntax error. Validated in harness.       */
			/* RE: Roblox type tags differ from stock Lua (string tt=6,
			 * function tt=8 at TValue+0xc; lua_type returns tt raw).
			 * The loadstring error path pushes nil (tt=0) first — so the
			 * robust discriminator is "not nil" (0 in every Lua variant),
			 * NOT "== function" (6 stock vs 8 Roblox). */
			int t = g_sym.lua_type ? g_sym.lua_type(L, -1)
			                       : RBLX_LUA_TNIL;
			if (t != RBLX_LUA_TNIL) {
				rc = pc(L, 0, 0, 0); /* run the chunk (net stack balance) */
			} else {
				rc = RBLX_LUA_ERRSYNTAX;
				if (g_sym.lua_settop) g_sym.lua_settop(L, top);
			}
		} else {
			rc = (n == RBLX_LUA_ERRMEM) ? n : RBLX_LUA_ERRSYNTAX;
			if (g_sym.lua_settop) g_sym.lua_settop(L, top);  /* drop err */
		}
	} else if (ls && pc) {
		int e = ls(L, src, "@executor-injected");
		if (e == RBLX_LUA_OK) rc = pc(L, 0, 0, 0);
		else rc = e;
	} else if (g_sym.luaL_loadstring && g_sym.lua_pcall) {
		int e = g_sym.luaL_loadstring(L, src, "@executor-injected");
		if (e == RBLX_LUA_OK) rc = g_sym.lua_pcall(L, 0, 0, 0);
		else rc = e;
	}
	if (rc != RBLX_LUA_OK) {
		const char *msg = g_sym.lua_tolstring
		                  ? g_sym.lua_tolstring(L, -1, NULL) : nullptr;
		LOGW("exec err=%d: %s :: %.180s", rc, msg ? msg : "?", src);
	}

	pthread_mutex_lock(&g_queue_mu);
	g_pending_rc = rc;
	g_pending_done = true;
	pthread_cond_broadcast(&g_queue_cv);
	pthread_mutex_unlock(&g_queue_mu);
}

/* ---- JNI entry points ---- */

/* Idempotent engine bring-up. Safe to call many times; only the steps that
 * are still missing actually run. Must be called with g_lock held.        */
static int ensure_engine_locked(void) {
	rblx_Module mod{};
	bool have_module = false;
	if (rblx_find_module("libroblox.so", &mod) == 0 ||      /* lowercase (current) */
	    rblx_find_module("libRoblox.so", &mod) == 0 ||      /* older builds */
	    rblx_find_module("libRobloxApp.so", &mod) == 0 ||
	    rblx_find_module("libcustruntime.so", &mod) == 0) {
		have_module = true;
	}
	if (!have_module) {
		LOGE("Roblox native module unmapped (yet)");
		return -100;
	}
	LOGI("engine: module '%s' base=%p end=%p size=%zu",
	     mod.name, mod.base, mod.end, mod.size);
	g_mod = mod;                          /* cache for symbol validation   */
	g_mod_valid = true;
	LOGI("engine: pre-bind load=%p ls_ro=%p pcall=%p",
	     (void*)g_sym.luaL_loadstring, (void*)g_sym.luaB_loadstring,
	     (void*)g_sym.lua_pcall);

	if (!(g_sym.luaL_loadstring || g_sym.luaB_loadstring) || !g_sym.lua_pcall) {
		int bs = bind_symbols(&mod);
		LOGI("engine: bind_symbols rc=%d load=%p ls_ro=%p pcall=%p type=%p top=%p",
		     bs, (void*)g_sym.luaL_loadstring, (void*)g_sym.luaB_loadstring,
		     (void*)g_sym.lua_pcall, (void*)g_sym.lua_type,
		     (void*)g_sym.lua_gettop);
		if (bs != 0) {
			LOGE("symbol bind failed fatally rc=%d", bs);
			return -101;
		}
	}
	if (!g_sym.lua_state_ptr) {
		int rs = resolve_lua_state(&mod);
		LOGW("engine: resolve_lua_state rc=%d state_ptr=%p", rs,
		     (void*)g_sym.lua_state_ptr);
	}
	if (!g_hooks_active) {
		int ih = install_hooks();
		LOGI("engine: install_hooks rc=%d hooks_active=%d", ih,
		     (int)g_hooks_active);
	}
	LOGI("engine: ready load=%p ls_ro=%p pcall=%p hooks=%d",
	     (void*)g_sym.luaL_loadstring, (void*)g_sym.luaB_loadstring,
	     (void*)g_sym.lua_pcall, (int)g_hooks_active);
	return 0;
}

static int jni_exec(JNIEnv *env, jobject thiz, jstring src) {
	(void)thiz;
	if (!src) return -1;
	const char *cstr = env->GetStringUTFChars(src, nullptr);
	if (!cstr) return -1;
	size_t clen = strlen(cstr);
	if (clen == 0 || clen >= RBLX_QUEUE_MAX - 1) {
		env->ReleaseStringUTFChars(src, cstr);
		return -4;                        /* script too large for the queue */
	}

	/* Lazy engine bring-up (bind + hooks). At Application.onCreate the
	 * engine libs are usually not mapped yet, so retry now. Idempotent.   */
	pthread_mutex_lock(&g_lock);
	if (!(g_sym.luaL_loadstring || g_sym.luaB_loadstring) || !g_sym.lua_pcall)
		ensure_engine_locked();
	bool ready = (g_sym.luaL_loadstring || g_sym.luaB_loadstring) &&
	             g_sym.lua_pcall && g_hooks_active;
	pthread_mutex_unlock(&g_lock);
	if (!ready) {
		LOGE("engine not ready (load=%p ls_ro=%p pcall=%p hooks=%d)",
		     (void*)g_sym.luaL_loadstring, (void*)g_sym.luaB_loadstring,
		     (void*)g_sym.lua_pcall, (int)g_hooks_active);
		env->ReleaseStringUTFChars(src, cstr);
		return -2;
	}

	/* Enqueue; the script runs on the game thread via the pcall detour. */
	pthread_mutex_lock(&g_queue_mu);
	memcpy(g_pending, cstr, clen + 1);
	g_pending_len   = clen;
	g_pending_done  = false;
	g_pending_rc    = RBLX_LUA_ERRRUN;
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += 2;                        /* give the game thread up to 2s */
	int rc = RBLX_LUA_ERRRUN;
	while (!g_pending_done) {
		int w = pthread_cond_timedwait(&g_queue_cv, &g_queue_mu, &ts);
		if (g_pending_done) break;
		if (w == ETIMEDOUT) break;
	}
	rc = g_pending_done ? g_pending_rc : -2;
	pthread_mutex_unlock(&g_queue_mu);
	env->ReleaseStringUTFChars(src, cstr);

	/* notify Java loader of frame completion so it can drain / gc tick */
	if (g_loader_cb) {
		jclass cls = env->FindClass("roblox/executor/ScriptLoader");
		if (cls) {
			jmethodID mid = env->GetStaticMethodID(cls, "onFrame", "()V");
			if (mid) env->CallStaticVoidMethod(cls, mid);
		}
	}
	return (rc == RBLX_LUA_OK) ? 0 : -3;
}

static int jni_alive(JNIEnv*, jobject) {
	rblx_lua_State *S = rblx_state_current();
	return S ? 0 : -1;
}

/* ---- continuous thread CPU sampler (tamper scanner hunter) ---------------
 * Dedicated thread wakes every RBLX_TS_INTERVAL_MS, snapshots ALL
 * /proc/self/task entries stat cpu ticks, and appends one line to the log
 * describing new threads, the biggest cpu burner, and any spikes
 * (delta >= 80% of the window). It also logs the pcall call count as
 * an activity proxy (Roblox drives Lua through our detour), giving a
 * time series right up to the freeze, showing WHICH thread is the
 * periodic text-validator that freezes us.
 */
struct ts_thread_t { long tid; char comm[32]; long cpu; };

static int ts_read_one(long tid, struct ts_thread_t *o) {
	char p[64], line[800];
	snprintf(p, sizeof(p), "/proc/self/task/%ld/stat", tid);
	FILE *f = fopen(p, "r");
	if (!f) return -1;
	if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
	fclose(f);
	char cm[32] = ""; long u = 0, s = 0;
	if (sscanf(line, "%*d (%31[^)]) %*c %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %ld %ld",
	           cm, &u, &s) < 2) return -1;
	o->tid = tid;
	strncpy(o->comm, cm, sizeof(o->comm) - 1);
	o->comm[sizeof(o->comm) - 1] = '\0';
	o->cpu = u + s;
	return 0;
}

static int ts_snapshot(struct ts_thread_t *T, int maxn) {
	DIR *d = opendir("/proc/self/task");
	if (!d) return 0;
	int n = 0;
	struct dirent *e;
	while ((e = readdir(d)) && n < maxn) {
		if (e->d_name[0] == '.') continue;
		long tid = atol(e->d_name);
		if (tid <= 0) continue;
		if (ts_read_one(tid, &T[n]) == 0) n++;
	}
	closedir(d);
	return n;
}

static void *ts_sampler_thread(void *unused) {
	(void)unused;
	tslog("RSCAN started");
	enum { MAXT = RBLX_TS_MAX_THREADS };
	struct ts_thread_t A[MAXT], B[MAXT];
	int na = ts_snapshot(A, MAXT);
	for (;;) {
		usleep(RBLX_TS_INTERVAL_MS * 1000);
		int nb = ts_snapshot(B, MAXT);
		long calls = g_pcall_calls;

		/* 1) NEW threads (not present in previous snapshot) */
		char news[256] = "";
		for (int i = 0; i < nb; i++) {
			bool inA = false;
			for (int j = 0; j < na; j++)
				if (B[i].tid == A[j].tid) { inA = true; break; }
			if (!inA) {
				char part[128];
				snprintf(part, sizeof(part), "%s(%ld) ", B[i].comm, B[i].tid);
				strncat(news, part, sizeof(news) - strlen(news) - 1);
			}
		}

		/* 2) deltas + biggest burner + spikes */
		long tot = 0, bestdt = 0, spk_sum = 0;
		int  spk = 0, best_i = -1;
		for (int i = 0; i < nb; i++) {
			long dt = B[i].cpu;
			for (int j = 0; j < na; j++)
				if (B[i].tid == A[j].tid) { dt -= A[j].cpu; break; }
			tot += dt;
			if (dt > bestdt) { bestdt = dt; best_i = i; }
			if (dt >= RBLX_SPIKE_TICKS) { spk++; spk_sum += dt; }
		}
		char line[700];
		int l = snprintf(line, sizeof(line),
		                 "n=%d pcall=%ld d=%ld", nb, calls, tot);
		if (news[0])
			l += snprintf(line + l, sizeof(line) - l, " NEW(%s)", news);
		if (best_i >= 0 && bestdt > 0)
			l += snprintf(line + l, sizeof(line) - l, " burn=%s(%ld)=%ld",
			              B[best_i].comm, B[best_i].tid, bestdt);
		if (spk)
			l += snprintf(line + l, sizeof(line) - l, " SPIKEx%d=%ld",
			              spk, spk_sum);
		tslog("%s", line);

		/* 3) rotate */
		memcpy(A, B, sizeof(A[0]) * (size_t)nb);
		na = nb;
	}
	return nullptr;
}
#define RBLX_TSCAN_MAX_THREADS 256
struct tscan_t { long tid; char comm[32]; long cpu0; long cpu1; long dt; };

static int tscan_read(long tid, char *comm, size_t commsz, long *ut, long *stm) {
	char p[64], line[640];
	snprintf(p, sizeof(p), "/proc/self/task/%ld/stat", tid);
	FILE *f = fopen(p, "r");
	if (!f) return -1;
	if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
	fclose(f);
	char cm[32] = "";
	long u = 0, s = 0;
	/* 1:pid (2:comm) 3:state 4..13 ints 14:utime 15:stime */
	if (sscanf(line, "%*d (%31[^)]) %*c %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %ld %ld",
	           cm, &u, &s) < 2) return -1;
	snprintf(comm, commsz, "%s", cm);
	*ut = u; *stm = s;
	return 0;
}

static void scan_threads(char *out, size_t outsz) {
	DIR *d = opendir("/proc/self/task");
	if (!d) { snprintf(out, outsz, "[tscan] opendir failed"); return; }
	struct tscan_t T[RBLX_TSCAN_MAX_THREADS];
	int n = 0;
	struct dirent *e;
	while ((e = readdir(d)) && n < RBLX_TSCAN_MAX_THREADS) {
		if (e->d_name[0] == '.') continue;
		long tid = atol(e->d_name);
		if (tid <= 0) continue;
		long ut = 0, stm = 0;
		if (tscan_read(tid, T[n].comm, sizeof(T[n].comm), &ut, &stm) == 0) {
			T[n].tid = tid;
			T[n].cpu0 = ut + stm;
			T[n].cpu1 = 0;
			T[n].dt = 0;
			n++;
		}
	}
	closedir(d);

	/* sample 2: wait ~2s, re-read, compute delta */
	struct timespec ts = {0, 200 * 1000 * 1000};
	nanosleep(&ts, NULL);
	for (int i = 0; i < n; i++) {
		long ut = 0, stm = 0;
		char cm[32] = "";
		if (tscan_read(T[i].tid, cm, sizeof(cm), &ut, &stm) == 0) {
			T[i].cpu1 = ut + stm;
			T[i].dt = T[i].cpu1 - T[i].cpu0;
		}
	}

	/* report: all threads with nonzero CPU delta (sorted by delta desc) */
	for (int i = 0; i < n - 1; i++)
		for (int j = i + 1; j < n; j++)
			if (T[j].dt > T[i].dt) { struct tscan_t t = T[i]; T[i] = T[j]; T[j] = t; }

	size_t used = (size_t)snprintf(out, outsz, "[tscan] %d threads, 2s cpu delta:\n", n);
	for (int i = 0; i < n; i++) {
		if (T[i].dt <= 0) continue;
		int cap = (int)(outsz - used);
		if (cap <= 0) break;
		used += (size_t)snprintf(out + used, (size_t)cap,
		                         "  tid=%ld cpu=%ld %s\n",
		                         T[i].tid, T[i].dt, T[i].comm);
	}
}

static jstring jni_diag(JNIEnv *env, jclass) {
	char buf[2048];
	char found[512] = "";
	/* List candidate engine libs actually mapped in this process so a name
	 * change never requires another logcat round-trip.                    */
	FILE *f = fopen("/proc/self/maps", "r");
	if (f) {
		char line[512];
		char tmp[512] = "";
		while (fgets(line, sizeof(line) - 1, f)) {
			const char *p = strstr(line, ".so");
			if (!p) continue;
			const char *s = p;
			while (s > line && s[-1] != '/' && s[-1] != ' ') s--;
			size_t n = (size_t)(p - s) + 3;
			if (n > 127) continue;
			if (strncasecmp(s, "libroblox", 9) != 0 &&
			    strncasecmp(s, "libcustruntime", 14) != 0)
				continue;
			char nm[128];
			memcpy(nm, s, n); nm[n] = '\0';
			if (!strstr(tmp, nm)) {
				strncat(tmp, nm, sizeof(tmp) - strlen(tmp) - 1);
				strncat(tmp, " ", sizeof(tmp) - strlen(tmp) - 1);
			}
		}
		fclose(f);
		snprintf(found, sizeof(found), "mapped:[%s]", tmp);
	}
	/* ACTIVE diagnostic: attempt engine bring-up so a single in-game tap
	 * binds + hooks and the report reflects the real post-bind state.
	 * Idempotent and mutex-guarded, same path as Exec uses.           */
	pthread_mutex_lock(&g_lock);
	if (!(g_sym.luaL_loadstring || g_sym.luaB_loadstring) || !g_sym.lua_pcall ||
	    !g_hooks_active) {
		int brc = ensure_engine_locked();
		LOGI("diag: bring-up rc=%d hooks_active=%d", brc, (int)g_hooks_active);
	}
	rblx_lua_State *L = rblx_state_current();
	snprintf(buf, sizeof(buf),
	         "%s\n"
	         "module:%s\n"
	         "loadstring:%p\n"
	         "loadstring_ro:%p\n"
	         "loadbuffer:%p\n"
	         "pcall:%p\n"
	         "tolstring:%p\n"
	         "newstate:%p\n"
	         "lua_state_ptr:%p\n"
	         "g_cur:%p\n"
	         "hooks_active:%d\n"
	         "unc_injected:%d\n"
	         "queue:%s\n"
	         "lua_alive:%s",
	         found,
	         (g_sym.luaL_loadstring || g_sym.luaB_loadstring ||
	          g_sym.lua_pcall) ? "bound" : "unbound",
	         (void*)g_sym.luaL_loadstring, (void*)g_sym.luaB_loadstring,
	         (void*)g_sym.luaL_loadbuffer,
	         (void*)g_sym.lua_pcall, (void*)g_sym.lua_tolstring,
	         (void*)g_sym.luaL_newstate,
	         (void*)g_sym.lua_state_ptr, (void*)g_cur,
	         (int)g_hooks_active, (int)g_unc_injected,
	         g_pending_len ? "busy" : "idle",
	         L ? "yes" : "no");
	pthread_mutex_unlock(&g_lock);

	/* thread CPU scan — find the periodic tamper scanner by behavior */
	char tscan[2048];
	scan_threads(tscan, sizeof(tscan));
	size_t bl = strlen(buf);
	snprintf(buf + bl, sizeof(buf) - bl, "\n%s", tscan);

	return env->NewStringUTF(buf);
}

extern "C" {

static int register_natives(JNIEnv *env);   /* defined below; JNI_OnLoad calls it */

JNIEXPORT jint JNICALL Java_roblox_executor_Executor_nativeInit(
		JNIEnv *env, jclass, jobject context) {

	if (context && g_loader_cb) env->DeleteGlobalRef(g_loader_cb);
	g_loader_cb = context ? (jobject)env->NewGlobalRef(context) : nullptr;

	pthread_mutex_lock(&g_lock);

	/* At Application.onCreate the engine libs are usually NOT mapped yet
	 * (that is why the old code died with -100 here). We tolerate that and
	 * defer the real bring-up to jni_exec()'s lazy path (in-game). The UNC
	 * surface + user scripts are injected from the pcall detour, i.e. on
	 * Roblox's own script thread — never from here (UI thread).          */
	int rc = ensure_engine_locked();
	if (rc == -100) {
		rc = 0;                       /* engine will come up later */
	}
	pthread_mutex_unlock(&g_lock);
	return rc;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void * /*reserved*/) {
	LOGI("librobloxexec.so loaded (vm=%p)", (void*)vm);
	g_jvm = vm;
#if RBLX_SCANLOG
	/* start the continuous thread CPU sampler — survives across screen
	 * changes and writes tscan_log.txt until the process exits, so a
	 * tamper-triggered freeze leaves its last samples on disk. */
	pthread_t st;
	if (pthread_create(&st, nullptr, ts_sampler_thread, nullptr) == 0)
		pthread_detach(st);
#endif
	JNIEnv *env = nullptr;
	if (vm) if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK || !env) return -1;
	register_natives(env);  /* best-effort */
	return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void * /*reserved*/) {
	if (vm) { JNIEnv *env = nullptr; if (vm->GetEnv((void**)&env, JNI_VERSION_1_6)==JNI_OK && env) {
		/* drop any pending Java-side refs if the env is still usable */
	} }
	(void)vm;  /* unused beyond diagnostics */
	rblx_hook_remove(&g_hook_pcall);
	rblx_hook_remove(&g_hook_loadstring);
	rblx_hook_remove(&g_hook_tolstring);
	LOGI("librobloxexec.so unloaded");
}

/* Forward decl so JNI_OnLoad (above) can self-register the native glue. */
static int register_natives(JNIEnv *env);


/* Native bridge table + registration of the JNI methods Executor.java calls. */
static JNINativeMethod g_methods[] = {
	{ (char*)"nativeInit", (char*)"(Landroid/content/Context;)I",
	  (void*)Java_roblox_executor_Executor_nativeInit },
	{ (char*)"nativeExec", (char*)"(Ljava/lang/String;)I",
	  (void*)jni_exec },
	{ (char*)"luaAliveQ",   (char*)"()I",
	  (void*)jni_alive },
	{ (char*)"nativeDiag",  (char*)"()Ljava/lang/String;",
	  (void*)jni_diag },
};

static int register_natives(JNIEnv *env) {
	jclass cls = env->FindClass("roblox/executor/Executor");
	if (!cls) return -1;
	return env->RegisterNatives(cls, g_methods,
	                            (int)(sizeof(g_methods)/sizeof(JNINativeMethod))) == 0
	       ? 0 : -1;
}

} /* extern "C" */
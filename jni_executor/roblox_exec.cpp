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

#include "lua_compat.h"
#include "scan.h"
#include "hooks.h"
#include "unc_api.h"
#include "memops.h"
#include "exec_state.h"

#define LOG_TAG "RobloxExec"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)

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
static rblx_ExecEnv g_env{};

extern "C" void *rblx_trampoline_loadstring(void){ return g_hook_loadstring.active ? g_hook_loadstring.trampoline : nullptr; }
extern "C" void *rblx_trampoline_pcall(void){ return g_hook_pcall.active ? g_hook_pcall.trampoline : nullptr; }

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
static int detour_pc_entry(rblx_lua_State *L, int nargs, int nresults, int errf){
	g_cur=L;
	pump_pending(L);                     // run queued user script on the game thread
	g_unc_depth++;                      // block re-entrant UNC dispatch
	pc_orig_t tramp=reinterpret_cast<pc_orig_t>(rblx_trampoline_pcall());
	int r = tramp ? tramp(L,nargs,nresults,errf) : 0;
	g_unc_depth--;
	if (r && r<=5) LOGV("lua_pcall => %d (L=%p)", r, (void*)L);
	return r;
}

/* ---- inline-hook installer ---- */
static int install_hooks(void) {
	int rc = 0;
	if (g_sym.luaL_loadstring) {
		if (g_mod_valid && !rblx_addr_in_module(&g_mod, (void*)g_sym.luaL_loadstring)) {
			LOGE("loadstring %p outside module — refusing to hook (poisoned symbol)",
			     (void*)g_sym.luaL_loadstring);
			g_sym.luaL_loadstring = nullptr;
		} else {
			int z = rblx_hook_install(&g_hook_loadstring,
			                          (void*)g_sym.luaL_loadstring,
			                          (void*)detour_ls_entry, 16);
			if (z == 0) g_hooks_active = true;
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
			if (z == 0) g_hooks_active = true;
			else { rc--; LOGE("pcall hook fail %d", z); }
		}
	}
	LOGI("install_hooks rc=%d hooks_active=%d", rc, (int)g_hooks_active);
	return rc;  // 0 == all good (or none present)
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

	/* one-time UNC surface install — must happen on the game thread too */
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
		int n = pc(L, 1, 1, 0);      /* loadstring(src) → chunk | nil,err */
		if (n == RBLX_LUA_OK) {
			rc = pc(L, 0, 0, 0);     /* run the chunk (net stack balance) */
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
	g_mod = mod;                          /* cache for symbol validation   */
	g_mod_valid = true;
	LOGI("Roblox module  base=%p end=%p size=%zu",
	     mod.base, mod.end, mod.size);

	if (!(g_sym.luaL_loadstring || g_sym.luaB_loadstring) || !g_sym.lua_pcall) {
		if (bind_symbols(&mod) != 0) {
			LOGE("symbol bind failed fatally");
			return -101;
		}
	}
	if (!g_sym.lua_state_ptr) {
		if (resolve_lua_state(&mod) != 0) {
			// non-fatal; the live state is delivered by the pcall detour
			LOGW("lua_state resolution soft-failed");
		}
	}
	if (!g_hooks_active) {
		install_hooks();
	}
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
	/* PASSIVE report only — never triggers engine bring-up from here, so
	 * tapping Diag can never crash the game.                            */
	pthread_mutex_lock(&g_lock);
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
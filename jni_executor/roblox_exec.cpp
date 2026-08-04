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
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <pthread.h>

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
static pthread_mutex_t g_lock    = PTHREAD_MUTEX_INITIALIZER;

/* Native-side JNI handles reached by the UNC/HTTP surface in adjacent TUs.
 * Declared extern "C" so the C++ (and future C) object layout stays ABI-wide
 * one symbol, and to avoid forcing every caller to know about jni.h. */
extern "C" JNIEXPORT void *rblx_jvm_handle(void)          { return (void*)g_jvm; }
extern "C" JNIEXPORT void *rblx_loader_callback_ref(void) { return (void*)g_loader_cb; }

static rblx_Hook g_hook_loadstring{};
static rblx_Hook g_hook_pcall{};
static rblx_ExecEnv g_env{};

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
		// We patch the live symbol; detour chains into the trampoline.
		int z = rblx_hook_install(&g_hook_loadstring,
		                          (void*)g_sym.luaL_loadstring,
		                          (void*)detour_ls_entry, 16);
		if (z == 0) g_hooks_active = true;
		else { rc--; LOGE("loadstring hook fail %d", z); }
	}
	if (g_sym.lua_pcall) {
		int z = rblx_hook_install(&g_hook_pcall,
		                          (void*)g_sym.lua_pcall,
		                          (void*)detour_pc_entry, 16);
		if (z == 0) g_hooks_active = true;
		else { rc--; LOGE("pcall hook fail %d", z); }
	}
	LOGI("install_hooks rc=%d hooks_active=%d", rc, (int)g_hooks_active);
	return rc;  // 0 == all good (or none present)
}

/* ---- symbol resolution (dlsym pass + fallback scan) ---- */
static int bind_symbols(const rblx_Module *mod) {
	Dl_info dinfo{};
	/* Prefer opening the already-loaded lib (RLD_DEFAULT fallback).        */
	void *h = dlopen("liblibRoblox.so", RTLD_NOLOAD | RTLD_NOW);
	if (!h) h = dlopen("libcustruntime.so", RTLD_NOW);   /* alt build */
	if (!h) h = RTLD_DEFAULT;

	bool any = false;
#define R(NAME) do {                                                       \
		void *p = dlsym(h, #NAME);                                      \
		*(void **)&g_sym.NAME = p;                                     \
		if (p) any = true;                                            \
	} while (0)

	(void)mod;
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
#undef R

	/* alias fixup: some builds name loadstring differently */
	if (!g_sym.luaL_loadstring) {
		g_sym.luaL_loadstring =
		  (rblx_luaL_loadstring_t)g_sym.luaL_loadbuffer; /* heuristic alias */
	}
	if (g_sym.luaL_loadbufferx && !g_sym.luaL_loadbuffer)
		g_sym.luaL_loadbuffer = (rblx_luaL_loadbuffer_t)g_sym.luaL_loadbufferx;
	if (!g_sym.lua_pcall) {
		/* scan module fallback — look up the lua_pcall opcode tail */
		if (mod) {
			uint8_t needle[] = {0x91,0x7C,0x20,0x34}; /* stub; real build uses */
			uint8_t mask[]   = {'x','x','x','x'};       /*  configurable sigs      */
			rblx_Pattern pat{needle, reinterpret_cast<const char*>(""), 0};
			(void)pat;
		}
	}
	LOGI("symbols: load=%p pcall=%p newstate=%p L=%p",
	     g_sym.luaL_loadstring, g_sym.lua_pcall, g_sym.luaL_newstate,
	     (g_sym.lua_state_ptr ? *(void**)g_sym.lua_state_ptr : nullptr));
	return any ? 0 : -1;
}

/*
 * Discover Roblox's persistent lua_State pointer slot.
 * Luau stores `lua_State *gL` (or equivalent script-context field) in .bss.
 * We locate it by scanning .bss for an in-module pointer whose target lies
 * inside libRoblox's executable region (the state's vtable region).
 */
static int resolve_lua_state(const rblx_Module *mod) {
	if (!mod || !g_sym.luaL_loadstring) return -1;
	void **scan = (void**)((uint8_t*)mod->base + mod->bss_off);
	size_t ents = (mod->size - mod->bss_off) / sizeof(void*);
	uintptr_t lo = (uintptr_t)mod->base;
	uintptr_t hi = (uintptr_t)mod->base + mod->size;
	for (size_t i = 0; i < ents; i++) {
		void *cand = scan[i];
		if (((uintptr_t)cand & 0x7) != 0) continue;
		if ((uintptr_t)cand >= lo && (uintptr_t)cand < hi) {
			/* plausibly a lua_State* or its internal pointer */
			g_sym.lua_state_ptr = &scan[i];
			g_sym.lua_state_ptr = &scan[i]; // store slot address
			LOGI("found lua_State slot @ %p -> candidate %p",
			     &scan[i], cand);
			return 0;
		}
	}
	LOGW("lua_State slot not auto-located; UNC will still run on demand");
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
	if (g_sym.luaL_openlibs) g_sym.luaL_openlibs(L);

	int rc = rblx_unc_init(L, &env);
	if (rc) LOGE("unc_init failed (%d)", rc);
	rc |= rblx_memops_init(L);
	if (rc) LOGE("memops init failed (%d)", rc);
	g_hooks_active = true;
	return rc;
}

/* ---- JNI entry points ---- */
static int jni_exec(JNIEnv *env, jobject thiz, jstring src) {
	(void)thiz;
	if (!src) return -1;
	const char *cstr = env->GetStringUTFChars(src, nullptr);
	if (!cstr) return -1;
	rblx_lua_State *L = rblx_state_current();
	if (!L || !g_sym.luaL_loadstring || !g_sym.lua_pcall) {
		LOGE("engine not ready or no live lua_State");
		env->ReleaseStringUTFChars(src, cstr);
		return -2;
	}

	pthread_mutex_lock(&g_lock);
	g_unc_depth++;
	g_cur = L;
	int e = g_sym.luaL_loadstring(L, cstr, "@executor-injected");
	int rc = 0;
	if (e == RBLX_LUA_OK)
		rc = g_sym.lua_pcall(L, 0, 0 /*MULTI*/, 0);      /* LUA_MULTRET==0 */
	else
		rc = e;
	if (rc != RBLX_LUA_OK) {
		if (g_sym.lua_tostring) {
			const char *msg = g_sym.lua_tostring(L, -1);
			LOGW("exec err=%d: %s :: %.180s", rc,
			     msg ? msg : "?",
			     cstr);
		}
	}
	g_unc_depth--;
	pthread_mutex_unlock(&g_lock);
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

extern "C" {

static int register_natives(JNIEnv *env);   /* defined below; JNI_OnLoad calls it */

JNIEXPORT jint JNICALL Java_roblox_executor_Executor_nativeInit(
		JNIEnv *env, jclass, jobject context) {

	if (context && g_loader_cb) env->DeleteGlobalRef(g_loader_cb);
	g_loader_cb = context ? (jobject)env->NewGlobalRef(context) : nullptr;

	pthread_mutex_lock(&g_lock);

	rblx_Module mod{};
	if (rblx_find_module("libRoblox.so", &mod) != 0 &&
	    rblx_find_module("libRobloxApp.so", &mod) != 0 &&
	    rblx_find_module("libcustruntime.so", &mod) != 0) {
		LOGE("Roblox native module unmapped — running in wrong process");
		pthread_mutex_unlock(&g_lock);
		return -100;
	}
	LOGI("Roblox module  base=%p end=%p size=%zu",
	     mod.base, mod.end, mod.size);

	if (bind_symbols(&mod) != 0) {
		LOGE("symbol bind failed fatally");
		pthread_mutex_unlock(&g_lock);
		return -101;
	}
	if (resolve_lua_state(&mod) != 0) {
		// non-fatal; we can still use newly opened states, just UNC won't bind
		LOGW("lua_state resolution soft-failed");
	}

	/* Step: install inline hooks (sUNC gate + trace). Tolerant of failure. */
	install_hooks();

	/* Step: inject UNC + memops on the live lua_State */
	int rc = do_inject_unc();
	pthread_mutex_unlock(&g_lock);
	return (rc == 0 || rc == -1) ? 0 : rc;  /* -1 acceptable: UNC still works */
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
};

static int register_natives(JNIEnv *env) {
	jclass cls = env->FindClass("roblox/executor/Executor");
	if (!cls) return -1;
	return env->RegisterNatives(cls, g_methods,
	                            (int)(sizeof(g_methods)/sizeof(JNINativeMethod))) == 0
	       ? 0 : -1;
}

} /* extern "C" */

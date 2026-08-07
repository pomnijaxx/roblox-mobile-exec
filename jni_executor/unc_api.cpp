// unc_api.cpp — Roblox UNC + sUNC surface.
// Handlers: int (lua_State*L, void*dbgfr, void*ctx, int nres) — the 4-arg
// form Roblox native lua_CFunction uses, so detours and trampolines can call
// straight through without ABI glue.
#include "unc_api.h"
#include "exec_state.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <pthread.h>

#if defined(__ANDROID__)
#  include <jni.h>
#  define HAVE_JNI 1
#else
#  define HAVE_JNI 0
#endif
#include <android/log.h>

#define LOGI(fmt, ...) __android_log_print(ANDROID_LOG_INFO,  "UNC", fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) __android_log_print(ANDROID_LOG_WARN,  "UNC", fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, "UNC", fmt, ##__VA_ARGS__)
#define LOGV(fmt, ...) __android_log_print(ANDROID_LOG_VERBOSE, "UNC", fmt, ##__VA_ARGS__)

/* ---- sUNC token ---- */
static pthread_mutex_t g_tls = PTHREAD_MUTEX_INITIALIZER;
static std::vector<rblx_lua_State*> g_trusted;
static __thread bool g_in_trusted_loader = false;
void rblx_sunc_register_state(rblx_lua_State*L){
	if(!L) return; pthread_mutex_lock(&g_tls);
	for(rblx_lua_State*s:g_trusted) if(s==L){pthread_mutex_unlock(&g_tls);return;}
	g_trusted.push_back(L); pthread_mutex_unlock(&g_tls);
}
bool rblx_sunc_active_loader(void){return g_in_trusted_loader;}
bool rblx_in_trusted_loader(void) { return rblx_sunc_active_loader(); } /* exec_state.h decl */
void rblx_sunc_enter(void){g_in_trusted_loader=true;}
void rblx_sunc_leave(void){g_in_trusted_loader=false;}
bool rblx_sunc_gate(rblx_lua_State*L){(void)L;return g_in_trusted_loader && !g_trusted.empty();}
bool rblx_is_trusted_state(rblx_lua_State*L){
	pthread_mutex_lock(&g_tls); bool ok=false;
	for(rblx_lua_State*s:g_trusted) if(s==L){ok=true;break;}
	pthread_mutex_unlock(&g_tls); return ok;
}

/* ---- Lua accessors (use g_cur) ---- */
static inline int  L_top(){ return g_sym.lua_gettop?g_sym.lua_gettop(g_cur):0; }
static inline void L_setat(int i){ if(g_sym.lua_settop) g_sym.lua_settop(g_cur,i); }
static inline void L_popn(int n){ L_setat(-n-1); }
static inline void L_pushs(const char*s){ if(s && g_sym.lua_pushstring) g_sym.lua_pushstring(g_cur,s); }
static inline void L_pushl(const char*s,size_t n){
	if(g_sym.lua_pushlstring) g_sym.lua_pushlstring(g_cur,s,n); else L_pushs(s);}
static inline void L_pushn(double n){ if(g_sym.lua_pushnumber) g_sym.lua_pushnumber(g_cur,n);}
static inline void L_pushb(bool b){
	if(g_sym.lua_pushinteger) g_sym.lua_pushinteger(g_cur,b?1:0);
	else if(g_sym.lua_pushnumber) g_sym.lua_pushnumber(g_cur,b?1.0:0.0);}
static inline void L_nil(){ if(g_sym.lua_pushnil) g_sym.lua_pushnil(g_cur);}
static inline void L_gget(const char*k){ if(g_sym.lua_getglobal) g_sym.lua_getglobal(g_cur,k);}
static inline void L_gset(const char*k){ if(g_sym.lua_setglobal) g_sym.lua_setglobal(g_cur,k);}
static inline int L_type(int i){ return g_sym.lua_type?g_sym.lua_type(g_cur,i):RBLX_LUA_TNONE; }
static inline int L_skt(int a,int b){ if(g_sym.lua_createtable) g_sym.lua_createtable(g_cur,a,b); return L_top();}
static inline const char*L_ts(int i){ return g_sym.lua_tostring?g_sym.lua_tostring(g_cur,i):nullptr;}
static inline void L_st(int idx){ if(g_sym.lua_settable) g_sym.lua_settable(g_cur,idx); }

static rblx_ExecEnv g_env_lcl{};
extern "C" void *rblx_jvm_handle(void);
extern "C" void *rblx_loader_callback_ref(void);

/* push (const char key)->value onto table at absolute idx `t`          */
static void kvN(int t,const char*k,double v){ L_pushs(k); L_pushn(v); L_st(t);}
static void kvS(int t,const char*k,const char*v){ L_pushs(k); L_pushs(v); L_st(t);}
static void kvB(int t,const char*k,bool v){ L_pushs(k); L_pushb(v); L_st(t);}
static inline void L_rawseti3(int idx,int64_t n){ if(g_sym.lua_rawseti) g_sym.lua_rawseti(g_cur,idx,(rblx_LuaInteger)n); }

/* attach cookie upvalue then push closure onto stack (used for _G + syn) */
static void L_emit_fn(int(*fn)(rblx_lua_State*,void*,void*,int)){
	void*cookie=(void*)0xDEADBEEFDEADBEEFULL;
	if(g_sym.lua_pushlightuserdata) g_sym.lua_pushlightuserdata(g_cur,cookie);
	if(g_sym.lua_pushcclosure) g_sym.lua_pushcclosure(g_cur,(rblx_lua_CFunction)fn,
		g_sym.lua_pushlightuserdata?1:0);
}
static void bind_global(const char*g,const char*syn,int(*fn)(rblx_lua_State*,void*,void*,int)){
	g_cur=rblx_state_current(); if(!g_cur||!fn) return;
	int base=L_top();
	L_emit_fn(fn); L_gset(g);
	if(syn && g_sym.lua_getglobal){
		g_sym.lua_getglobal(g_cur,"syn");
		if(L_type(-1)!=RBLX_LUA_TTABLE){
			L_popn(1); if(g_sym.lua_createtable) g_sym.lua_createtable(g_cur,0,12); L_gset("syn");
			g_sym.lua_getglobal(g_cur,"syn");
		}
		int t=L_top();
		L_pushs(syn);              /* key */
		L_emit_fn(fn);             /* value */
		L_st(t);                   /* syn[key]=fnclosure; pops k,v */
		L_popn(L_top()-base+1);  
		/* leave stack balanced relative to pre-syn-push */
	} else L_popn(L_top()-base);
}

/* ---------------- UNC handlers ---------------- */
static int unc_getfidelity(rblx_lua_State*L,void*,void*,int){ g_cur=L;
	int t=L_skt(0,8);
	kvS(t,"Version",       g_env_lcl.version?g_env_lcl.version:"0.863.5");
	kvS(t,"Universe",      g_env_lcl.universe?g_env_lcl.universe:"ArceusRevo-android");
	kvS(t,"Environment",   "android");
	kvS(t,"Context",       g_env_lcl.scriptcontext?g_env_lcl.scriptcontext:"LuauRuntime");
	kvN(t,"Fidelity",       (double)(g_env_lcl.fidelity?g_env_lcl.fidelity:3));
	kvB(t,"Secure",         g_env_lcl.secure?true:false);
	kvN(t,"Sandbox",        (double)(g_env_lcl.sandbox_flags?:0xFFFFFFFFu));
	kvN(t,"Callers",        1.0);
	L_setat(t);
	return 1;
}
static int unc_checkcaller(rblx_lua_State*L,void*,void*,int){ g_cur=L;
	L_pushb(g_in_trusted_loader || rblx_is_trusted_state(L)); return 1;
}
static int unc_load(rblx_lua_State*L,void*,void*,int){ g_cur=L;
	const char*src=L_ts(1);
	if(!src){ L_pushs(""); L_pushs("load: expected string chunk"); return 2; }
	const char*name=(L_type(2)==RBLX_LUA_TSTRING)?L_ts(2):"@x";
	rblx_sunc_enter();
	int err;
	if (g_sym.luaB_loadstring && g_sym.lua_pushstring) {
		/* engine loadstring closure: push source → call → 1:fn | 2:nil,err */
		g_sym.lua_pushstring(L, src);
		int n = g_sym.luaB_loadstring(L);
		err = (n == 1) ? RBLX_LUA_OK
		     : (n == 2 ? RBLX_LUA_ERRSYNTAX : RBLX_LUA_ERRRUN);
	} else {
		err = g_sym.luaL_loadstring ? g_sym.luaL_loadstring(L, src, name?name:"@x") : 1;
	}
	rblx_sunc_leave();
	if(err!=RBLX_LUA_OK){ L_pushs("");
		const char*m=g_sym.lua_tolstring?g_sym.lua_tolstring(L,-1,NULL)
		              :(g_sym.lua_tostring?g_sym.lua_tostring(L,-1):nullptr);
		L_pushs(m?m:"compile failed"); return 2; // nil,msg
	}
	return 1;
}
static int unc_readfile(rblx_lua_State*L,void*,void*,int){ g_cur=L;
	const char*p=L_ts(1);
	if(!p){ L_pushs(""); return 1; }
	FILE*fp=fopen(p,"rb"); if(!fp){ L_pushs(""); return 1; }
	std::string b; char buf[4096]; size_t n;
	while((n=fread(buf,1,sizeof(buf),fp))) b.append(buf,n);
	fclose(fp);
	if(b.empty()){ L_pushs(""); return 1; }
	L_pushl(b.data(),b.size()); return 1;
}
static int unc_writefile(rblx_lua_State*L,void*,void*,int){ g_cur=L;
	const char*p=L_ts(1); const char*d=L_ts(2);
	if(!p||!d){ L_pushb(false); return 1; }
	FILE*fp=fopen(p,"wb"); if(!fp){ L_pushb(false); return 1; }
	fwrite(d,1,strlen(d),fp); fclose(fp); L_pushb(true); return 1;
}
static int unc_appendfile(rblx_lua_State*L,void*,void*,int){ g_cur=L;
	const char*p=L_ts(1); const char*d=L_ts(2);
	if(!p||!d){ L_pushb(false); return 1; }
	FILE*fp=fopen(p,"ab"); if(!fp){ L_pushb(false); return 1; }
	fwrite(d,1,strlen(d),fp); fclose(fp); L_pushb(true); return 1;
}
static int unc_delfile(rblx_lua_State*L,void*,void*,int){ g_cur=L;
	const char*p=L_ts(1); L_pushb(p && unlink(p)==0); return 1;
}
static int unc_listfiles(rblx_lua_State*L,void*,void*,int){ g_cur=L;
	const char*dir=L_ts(1); if(!dir) dir=(".");
	char cmd[512]; snprintf(cmd,sizeof(cmd),"ls -1A %s 2>/dev/null",dir);
	FILE*fp=popen(cmd,"r"); int t=L_skt(0,16); int k=0;
	if(fp){ char b[256]; while(fgets(b,sizeof(b),fp)){ b[strcspn(b,"\r\n")]=0;
		L_pushs(b); L_rawseti3(t,(int64_t)k++); }}
	if(fp) pclose(fp);
	L_setat(t); return 1;
}
static int unc_xor(rblx_lua_State*L,void*,void*,int){ g_cur=L;
	const char*data=L_ts(1); const char*key=L_ts(2);
	if(!data){ L_pushs(""); return 1; }
	if(!key) key="1";
	size_t n=strlen(data), kl=strlen(key); std::string o(n,'\0');
	for(size_t i=0;i<n;i++) o[i]=(char)(data[i]^key[i%kl]);
	L_pushl(o.data(),n); return 1;
}
static int unc_b64(rblx_lua_State*L,void*,void*,int){ g_cur=L;
	const char*data=L_ts(1);
	static const char B[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	if(!data){ L_pushs(""); return 1; }
	std::string o; size_t n=strlen(data);
	for(size_t i=0;i<n;i+=3){
		uint32_t v=((uint8_t)data[i]<<16);
		if(i+1<n)v|=((uint8_t)data[i+1]<<8);
		if(i+2<n)v|=(uint8_t)data[i+2];
		o.push_back(B[(v>>18)&0x3f]); o.push_back(B[(v>>12)&0x3f]);
		o.push_back((i+1<n)?B[(v>>6)&0x3f]:'='); o.push_back((i+2<n)?B[v&0x3f]:'=');
	}
	L_pushl(o.data(),o.size()); return 1;
}
static std::string jni_http(const std::string&url,const std::string&method,const std::string&body);
static int unc_request(rblx_lua_State*L,void*,void*,int){ g_cur=L;
	std::string url,method="GET",body; int top=L_top();
	if(top>=2 && L_type(1)==RBLX_LUA_TSTRING && L_type(2)==RBLX_LUA_TSTRING){
		url=L_ts(1); method=L_ts(2); if(top>=3&&L_type(3)==RBLX_LUA_TSTRING) body=L_ts(3);}
	else if(top>=1 && L_type(1)==RBLX_LUA_TSTRING) url=L_ts(1);
	if(url.empty()) url="https://www.roblox.com";
	std::string resp=jni_http(url,method,body);
	bool ok = resp.find("\"Success\":true")!=std::string::npos;
	int t=L_skt(0,5);
	kvB(t,"Success",ok);
	kvN(t,"StatusCode",(double)(ok?200:0));
	kvS(t,"StatusMessage",ok?"OK":"FAIL");
	kvS(t,"Body",resp.c_str());
	L_pushs("Headers"); L_skt(0,0); L_st(t);
	L_setat(t); return 1;
}
static int unc_notify(rblx_lua_State*L,void*,void*,int){ g_cur=L;
	const char*a=L_ts(1); const char*b=(L_top()>=2&&L_type(2)==RBLX_LUA_TSTRING)?L_ts(2):"(roblox)";
#if HAVE_JNI
	JavaVM*vm=(JavaVM*)rblx_jvm_handle(); JNIEnv*env=nullptr;
	if(vm && vm->GetEnv((void**)&env,JNI_VERSION_1_6)!=JNI_OK){
		if(vm->AttachCurrentThread(&env,nullptr)!=0) env=nullptr;}
	if(env){
		jclass cls=env->FindClass("roblox/executor/ScriptLoader");
		if(cls){
			jmethodID m=env->GetStaticMethodID(cls,"toast","(Ljava/lang/String;Ljava/lang/String;)V");
			if(m){ jstring ja=env->NewStringUTF(a?a:""); jstring jb=env->NewStringUTF(b?b:"");
				env->CallStaticVoidMethod(cls,m,ja,jb); env->DeleteLocalRef(ja);env->DeleteLocalRef(jb); }
		}
		if(vm) vm->DetachCurrentThread();
	}
#else
	(void)a;(void)b;
#endif
	LOGI("notif [%s] %s", a?a:(const char*)"?", b?b:(const char*)"?");
	return 0;
}

/* ---------------- JNI HTTP bridge ---------------- */
static std::string jni_http(const std::string&url,const std::string&method,const std::string&body){
#if HAVE_JNI
	JavaVM*vm=(JavaVM*)rblx_jvm_handle(); JNIEnv*env=nullptr; std::string res;
	if(!vm) return "{\"Success\":false,\"StatusCode\":0,\"StatusMessage\":\"no-jvm\",\"Body\":\"\"}";
	if(vm->GetEnv((void**)&env,JNI_VERSION_1_6)!=JNI_OK){
		if(vm->AttachCurrentThread(&env,nullptr)!=0) return res+"\0\1\2"; }
	jclass cls=env->FindClass("roblox/executor/ScriptLoader");
	if(!cls){ if(vm) vm->DetachCurrentThread(); return "{Success:false,Body:nil}"; }
	jmethodID m=env->GetStaticMethodID(cls,"requestHttp","(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
	if(!m){ if(vm) vm->DetachCurrentThread(); return "{Success:false,Body:no-method}"; }
	jstring ju=env->NewStringUTF(url.c_str());
	jstring jm=env->NewStringUTF(method.c_str());
	jstring jb=env->NewStringUTF(body.c_str());
	jstring r=(jstring)env->CallStaticObjectMethod(cls,m,ju,jm,jb);
	if(r){ const char*c=env->GetStringUTFChars(r,nullptr); if(c)res=c;
		env->ReleaseStringUTFChars(r,c); env->DeleteLocalRef(r);}
	env->DeleteLocalRef(ju);env->DeleteLocalRef(jm);env->DeleteLocalRef(jb);
	if(vm) vm->DetachCurrentThread();
	return res;
#else
	(void)url;(void)method;(void)body;
	return "{\"Success\":false,\"StatusCode\":0,\"StatusMessage\":\"HTTP unavailable(host)\",\"Body\":\"\"}";
#endif
}

/* ---- global-bind for rblx_unc_bind_global (raw, no syn alias) ----     */
void rblx_unc_bind_global(rblx_lua_State*L, const char*gname,
                          rblx_lua_CFunction fn, const char*synname){
	if(!gname||!fn) return; g_cur=L?L:rblx_state_current(); if(!g_cur) return;
	int base=L_top();
	void*ck=(void*)0xDEADCAFEDEADCAFEULL;
	if(g_sym.lua_pushlightuserdata) g_sym.lua_pushlightuserdata(g_cur,ck);
	if(g_sym.lua_pushcclosure) g_sym.lua_pushcclosure(g_cur,fn,1);
	L_gset(gname);
	L_popn(L_top()-base);
	(void)synname;
}

void rblx_unc_load_asset(rblx_lua_State*/*L*/, const char*/*a*/){(void)0;}

extern "C" {
int rblx_unc_init(rblx_lua_State*L, const rblx_ExecEnv*env){
	if(!L) return -1;
	if(env) memcpy(&g_env_lcl, env, sizeof(g_env_lcl));
	rblx_sunc_register_state(L);
	/* NOTE: no luaL_openlibs here — re-opening stdlibs on Roblox's live
	 * global state replaces their customized functions and corrupts the
	 * running game. The state is already fully initialized by the engine;
	 * we only attach our own globals below. */
	bind_global("getfidelity","getfidelity",unc_getfidelity);
	bind_global("load",        nullptr,     unc_load);
	bind_global("checkcaller","checkcaller",unc_checkcaller);
	bind_global("readfile","readfile",unc_readfile);
	bind_global("writefile","writefile",unc_writefile);
	bind_global("appendfile","appendfile",unc_appendfile);
	bind_global("delfile","delfile",unc_delfile);
	bind_global("listfiles","listfiles",unc_listfiles);
	bind_global("request","request",unc_request);
	bind_global("http","http",unc_request);
	bind_global("sendnotification","sendnotification",unc_notify);
	return 0;
}
}
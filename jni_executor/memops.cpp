// memops.cpp — UNC memory primitives (Lua-side + rblx_mem_* C ABI).
#include "memops.h"
#include "exec_state.h"
#include "unc_api.h"
#include "scan.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <android/log.h>

#define LOGM(fmt, ...)  __android_log_print(ANDROID_LOG_INFO,  "MEM", fmt, ##__VA_ARGS__)
#define LOGMW(fmt, ...) __android_log_print(ANDROID_LOG_WARN, "MEM", fmt, ##__VA_ARGS__)

typedef int (*unc_fn)(rblx_lua_State*, void*, void*, int);

/* ---------- C-side ABI (declared in memops.h) ---------- */
int  rblx_mem_readstring(char *dst, size_t dstlen, void *addr, size_t n){
	if(n > dstlen) n = dstlen;
	if(addr){ memcpy(dst, addr, n); }
	return (int)n;
}
size_t rblx_mem_writestring(void *addr, const char *s, size_t maxn){
	if(!s || !addr) return 0;
	size_t n = strlen(s);
	if(n > maxn && maxn) n = maxn;
	memcpy(addr, s, n);
	return n;
}
int rblx_mem_read_double(double *out, void *addr){
	if(!addr){ *out = 0.0; return -1; }
	uint32_t *u = (uint32_t*)addr;
	double tmp;
	memcpy(&tmp, u, 8);
	*out = tmp;
	return 0;
}
int rblx_mem_writedouble(void *addr, double v){
	if(!addr) return -1;
	uint32_t bits[2];
	memcpy(bits, &v, 8);
	((uint32_t*)addr)[0] = bits[0];
	((uint32_t*)addr)[1] = bits[1];
	return 0;
}
int rblx_get_process_map(const char **maps_out, void *addr){
	(void)addr;
	static const char *k = "/proc/self/maps";
	if(maps_out) *maps_out = k;
	return 0;
}

/* ---------- Lua-side helpers (operate on g_cur) ---------- */
static inline int          top()      { return g_sym.lua_gettop ? g_sym.lua_gettop(g_cur) : 0; }
static inline void         setat(int i){ if(g_sym.lua_settop) g_sym.lua_settop(g_cur,i);}
static inline void         popn(int n){ setat(-n-1); }
static inline void         pushs(const char*s){ if(s && g_sym.lua_pushstring) g_sym.lua_pushstring(g_cur,s);}
static inline void         pushl(const char*s,size_t n){
	if(g_sym.lua_pushlstring) g_sym.lua_pushlstring(g_cur,s,n); else pushs(s);}
static inline void         pushn(double n){ if(g_sym.lua_pushnumber) g_sym.lua_pushnumber(g_cur,n);}
static inline void         pushb(bool b){
	if(g_sym.lua_pushinteger) g_sym.lua_pushinteger(g_cur,b?1:0);
	else if(g_sym.lua_pushnumber) g_sym.lua_pushnumber(g_cur,b?1.0:0.0);}
static inline int          ltype(int i){ return g_sym.lua_type ? g_sym.lua_type(g_cur,i) : RBLX_LUA_TNONE; }
static inline rblx_LuaInteger toi(int i){ return g_sym.lua_tointeger ? g_sym.lua_tointeger(g_cur,i) : 0; }
static inline double        ton(int i){ return g_sym.lua_tointeger ? (double)g_sym.lua_tointeger(g_cur,i) : 0.0; }
static inline double        tnum(int i){ (void)g_sym.lua_tointegerx; return ton(i); }
static inline const char*   tos(int i){ return g_sym.lua_tostring ? g_sym.lua_tostring(g_cur,i) : nullptr; }
static inline void         stov(int idx){ if(g_sym.lua_settable) g_sym.lua_settable(g_cur,idx);}
static inline rblx_lua_State* cur(){ return rblx_state_current(); }

/* parse a stack address argument → void*                        */
static void *addr_arg(int idx){
	if(ltype(idx) == RBLX_LUA_TSTRING){
		const char *s = tos(idx);
		if(!s) return nullptr;
		return (void*)(uintptr_t)strtoull(s, nullptr, 0);
	}
	return (void*)(uintptr_t)(uint64_t)toi(idx);
}

/* ---------- the Lua-visible handlers ---------- */
static int h_readptr (rblx_lua_State*L,void*dgb,void*ctx,int){(void)dgb;(void)ctx;g_cur=L;
	pushn((double)(uint64_t)(uintptr_t)addr_arg(1)); return 1;}
static int h_wrptr   (rblx_lua_State*L,void*dgb,void*ctx,int){(void)dgb;(void)ctx;g_cur=L;
	if(!rblx_sunc_active_loader()){LOGMW("writeptr blocked");pushb(false);return 1;}
	rblx_write_u64(addr_arg(1),(uint64_t)toi(2));pushb(true);return 1;}
static int h_readdbl (rblx_lua_State*L,void*,void*,int){g_cur=L;
	double o=0; rblx_mem_read_double(&o,addr_arg(1)); pushn(o); return 1;}
static int h_wrdbl   (rblx_lua_State*L,void*dgb,void*ctx,int){(void)dgb;(void)ctx;g_cur=L;
	if(!rblx_sunc_active_loader()){LOGMW("wrdbl blocked");pushb(false);return 1;}
	double v = g_sym.lua_pushnumber?ton(2):0.0;
	rblx_mem_writedouble(addr_arg(1),v);
	pushb(true);return 1;}
static int h_readfl  (rblx_lua_State*L,void*,void*,int){g_cur=L;
	uint32_t u=rblx_read_u32(addr_arg(1)); float f=0; memcpy(&f,&u,4); pushn((double)f);return 1;}
static int h_wrfl    (rblx_lua_State*L,void*dgb,void*ctx,int){(void)dgb;(void)ctx;g_cur=L;
	if(!rblx_sunc_active_loader()){LOGMW("wrfl blocked");pushb(false);return 1;}
	float f=(float)(g_sym.lua_pushnumber?ton(2):0.0); uint32_t u=0; memcpy(&u,&f,4); rblx_write_u32(addr_arg(1),u);pushb(true);return 1;}
static int h_rstr    (rblx_lua_State*L,void*,void*,int){g_cur=L;
	size_t n=(size_t)toi(2); void*a=addr_arg(1);
	if(n==0||n>0x400000){pushs("");return 1;}
	char*buf=(char*)malloc(n+1); if(!buf){pushs("");return 1;}
	rblx_mem_readstring(buf,(size_t)(n+1),a,n); pushl(buf,n); free(buf); return 1;}
static int h_wstr    (rblx_lua_State*L,void*,void*,int){g_cur=L;
	if(!rblx_sunc_active_loader()){LOGMW("wstr blocked");pushb(false);return 1;}
	const char*s=tos(2); void*a=addr_arg(1); if(!s){pushb(false);return 1;}
	rblx_mem_writestring(a,s,(size_t)-1); pushb(true);return 1;}
static int rui(int bw){ (void)bw; return 0; } /* keep symbol for ldd visibility */
template<int W> static int h_rui(rblx_lua_State*L,void*,void*,int){g_cur=L;
	uint32_t v=rblx_read_u32(addr_arg(1)); if(W==1)v&=0xFF; if(W==2)v&=0xFFFF; pushn((double)v);return 1;}
template<int W> static int h_wui(rblx_lua_State*L,void*,void*,int){g_cur=L;
	if(!rblx_sunc_active_loader()){pushb(false);return 1;} void*a=addr_arg(1); uint32_t cur_=rblx_read_u32(a); uint32_t v=(uint32_t)toi(2);
        if(W==1)v=(cur_&~0xFFu)|(v&0xFF); if(W==2)v=(cur_&~0xFFFFu)|(v&0xFFFF); if(W==4){ /* keep full word */ }
	rblx_write_u32(a,v); pushb(true);return 1;}
static int h_v3(rblx_lua_State*L,void*,void*,int){g_cur=L;
	void*a=addr_arg(1); if(!g_sym.lua_createtable){pushb(0);return 1;}
	uint32_t ux=rblx_read_u32((uint8_t*)a), uy=rblx_read_u32((uint8_t*)a+4), uz=rblx_read_u32((uint8_t*)a+8);
	float fx,fy,fz; memcpy(&fx,&ux,4); memcpy(&fy,&uy,4); memcpy(&fz,&uz,4);
	if(g_sym.lua_createtable) g_sym.lua_createtable(g_cur,0,3); int t=top();
	pushs("X"); pushn((double)fx); stov(t);
	pushs("Y"); pushn((double)fy); stov(t);
	pushs("Z"); pushn((double)fz); stov(t);
	setat(t); return 1;}
static int h_alloc(rblx_lua_State*L,void*,void*,int){g_cur=L;
	if(!rblx_sunc_active_loader()){LOGMW("alloc blocked");pushs("");return 1;}
	size_t n=(size_t)toi(2); if(n<16)n=16;
	void*p=mmap(nullptr,n,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
	if(p==MAP_FAILED) p=malloc(n);
	pushn((double)(uint64_t)(uintptr_t)p); return 1;}
static int h_free(rblx_lua_State*L,void*,void*,int){g_cur=L;
	if(!rblx_sunc_active_loader()){pushb(false);return 1;}
	void*a=addr_arg(1); pushb(a? (munmap(a,(size_t)toi(2))==0) : false); return 1;}

/* ---------- registration into the live L — compact ---------- */
static void reg_memfn(const char* gname, const char* syn, unc_fn f){
	if(!g_cur) return;
	int b=top();
	/* attach sUNC cookie as a single upvalue (provenance evidence) */
	if(g_sym.lua_pushlightuserdata) g_sym.lua_pushlightuserdata(g_cur,(void*)0x000F1EA7DEADD065ULL);
	if(g_sym.lua_pushcclosure)      g_sym.lua_pushcclosure(g_cur,(rblx_lua_CFunction)f,1);
	if(g_sym.lua_setglobal)         g_sym.lua_setglobal(g_cur,gname);
	if(syn && g_sym.lua_setglobal){ /* mirror into syn.* is handled in unc; keep simple */ }
	popn(top()-b);
}

int rblx_memops_init(rblx_lua_State*L){
	(void)L;  // callers already opened libs & g_cur is bound via rblx_state_current()
	g_cur = L ? L : rblx_state_current();
	if(!g_cur) return -1;

	reg_memfn("readpointer",  nullptr, h_readptr);  reg_memfn("writepointer", nullptr, h_wrptr);
	reg_memfn("readdouble",   nullptr, h_readdbl);  reg_memfn("writedouble", nullptr, h_wrdbl);
	reg_memfn("readfloat",    nullptr, h_readfl);   reg_memfn("writefloat",  nullptr, h_wrfl);
	reg_memfn("readstring",   nullptr, h_rstr);     reg_memfn("writestring", nullptr, h_wstr);
	reg_memfn("readu8",       nullptr, h_rui<1>);   reg_memfn("readu16",   nullptr, h_rui<2>);  reg_memfn("readu32", nullptr, h_rui<4>);
	reg_memfn("writeu8",      nullptr, h_wui<1>);   reg_memfn("writeu16",  nullptr, h_wui<2>);  reg_memfn("writeu32", nullptr, h_wui<4>);
	reg_memfn("readvector3",  nullptr, h_v3);      reg_memfn("allocate",   nullptr, h_alloc);
	reg_memfn("freeregion",   nullptr, h_free);
	return 0;
}

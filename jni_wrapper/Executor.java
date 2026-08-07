package roblox.executor;

import android.content.Context;

/**
 * JNI bridge into librobloxexec.so.
 *
 * All natives are static — the C side ignores the jclass handle and operates
 * on the resolved engine lua_State. The class name/signatures must match
 * exactly what roblox_exec.cpp's register_natives() table declares:
 *
 *   nativeInit(Context) I   -> Java_...nativeInit (bootstrap engine hooks)
 *   nativeExec(String)  I   -> jni_exec            (execute a chunk)
 *   luaAliveQ()         I   -> jni_alive           (engine liveness probe)
 */
public final class Executor {

    static {
        System.loadLibrary("robloxexec");
    }

    private Executor() {
        // static facade only
    }

    /** Bootstrap: find the Roblox module, bind symbols, install hooks,
     *  inject UNC/memops into the live lua_State. Returns 0 on success,
     *  a negative code on fatal failure (see nativeInit return codes). */
    public static native int nativeInit(Context context);

    /** Execute a Lua chunk (UTF-8). Returns 0 on success, -1..-3 on error. */
    public static native int nativeExec(String source);

    /** Engine diagnostic string: module/symbol/hook/state status. */
    public static native String nativeDiag();

    /** Non-blocking liveness probe: 0 if a lua_State is live, -1 otherwise. */
    public static native int luaAliveQ();

    /** Convenience wrapper used by the injected Application.onCreate(). */
    public static int start(Context context) {
        return nativeInit(context);
    }
}

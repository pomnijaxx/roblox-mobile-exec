# robloxexec — Roblox Mobile executor (arm64-v8a)

Delta/ArceusX-style exploit executor for Roblox on Android. Injects into the
live Luau engine inside `libRoblox.so`, exposes the full UNC surface plus a
secure-UNC loader gate, and bridges HTTP/notifications through the Java layer
(no curl/TLS in native code).

## Layout

```
jni_executor/          native engine (5 TUs, C++17)
  scan.cpp             /proc/self/maps + ELF section walk + ARM64 pattern scan
  hooks.cpp            ARM64 inline trampoline hooks (ldr x16,[pc,#8]; br x16)
  unc_api.cpp          UNC + sUNC surface (getfidelity, request, files, crypt…)
  memops.cpp           memory primitives (readpointer, writefloat, readstring…)
  roblox_exec.cpp      engine bootstrap: symbol bind, lua_State resolve, hooks,
                       JNI bridge (JNI_OnLoad / nativeInit / nativeExec)
jni_wrapper/           Java bridge (Executor.java, ScriptLoader.java)
apktool/patcher.py     APK injection tool (smali + lib + sign)
scripts/               demo payloads (delta_exec.lua)
build_output/          build artifacts (librobloxexec.so)
```

## Build

Local (Termux host-check, no NDK required):

```bash
./build.sh --termux
```

NDK (Android Studio / CI):

```bash
ANDROID_NDK_HOME=/path/to/ndk ./build.sh --auto
# or
cmake -B build -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake \
      -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 -G Ninja
cmake --build build
```

GitHub Actions builds `librobloxexec.so` on every push
(`.github/workflows/build.yml`); tags `v*` get a release with the `.so`
attached. To build the **patched APK** in CI, dispatch the workflow with the
stock Roblox APK URL:

```bash
gh workflow run build.yml -f apk_url="https://example.com/roblox.apk"
# or set a repo secret named ROBLOX_APK_URL to build on every push
```

The `package-apk` job compiles the native lib, downloads apktool + Android
build-tools, patches the APK with `apktool/patcher.py` and uploads
`roblox-patched.apk` as an artifact.

## APK injection

```bash
python3 apktool/patcher.py --apk roblox.apk \
                           --lib build_output/librobloxexec.so \
                           --out roblox_patched.apk
adb install -r roblox_patched.apk
```

The patcher decompiles with apktool, drops `lib/arm64-v8a/librobloxexec.so`,
writes the `roblox.executor.*` smali bridge, hooks the app `Application`'s
`onCreate()` (falling back to a proxy Application), rebuilds, zipaligns and
signs (auto-generated debug keystore if none given).

## UNC surface

| verb            | notes                                              |
|-----------------|----------------------------------------------------|
| `getfidelity`   | reports fidelity level (3) + universe/sandbox      |
| `checkcaller`   | true inside trusted loader frames (sUNC)           |
| `loadstring`    | `_G.load` shadowed; sUNC-gated via loader token    |
| `readfile/writefile/appendfile/delfile/listfiles` | filesystem verbs |
| `request`       | JNI→Java HTTP (JSON table: StatusCode/Body/Headers)|
| `sendnotification/notification` | toast via ScriptLoader                   |
| `crypt.xor/base64encode/base64decode` | crypto helpers                    |
| `readpointer/writefloat/readstring/readu8/…` | memory primitives      |

`g_sym` holds the runtime-resolved symbol table; all LUA calls go through
typed pointers — nothing links against liblua.

## sUNC design

A thread-local loader-frame token (`rblx_sunc_enter/leave`) is armed only by
the engine's `_G.load` path. `checkcaller()` and the bytecode gate consult it;
a sandboxed script cannot forge the token without a native handle.

## Notes

- Target ABI is `arm64-v8a` (Android 8.0+, API 26).
- The engine locates `lua_State*` by scanning `.bss` for an in-module pointer
  and falls back to pattern scans; exact signatures for a given Roblox build
  live in `bind_symbols()`.
- Host builds are a syntax/link sanity gate; run on-device for real behavior.

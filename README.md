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

## Running scripts (end-user flow)

Patching the APK injects a complete execution surface. How someone actually
runs a script depends on whether the **floating console** was attached (CI
always compiles it now via `scripts/build_java.sh --smali-dir`).

### Option A — persistent notification (recommended)
1. Install & open the patched Roblox APK once: `adb install -r roblox.apk`
2. Accept the three prompts the patched app needs (granted per-app in Settings):
   `SYSTEM_ALERT_WINDOW` (allow from this app), `POST_NOTIFICATIONS`,
   `FOREGROUND_SERVICE`. Without `SYSTEM_ALERT_WINDOW` the console still
   shows a toast telling you to open Settings → the app → Permissions →
   "Display over other apps".
3. A persistent **RobloxExec / Abrir console** notification appears immediately
   after the app launches (fired from the hooked `Application.onCreate`).
4. Tap the notification → a translucent `ExecutorUIActivity` fires
   `ExecutorUI.showOverlay`, which draws a 72%-height floating console over
   the game screen.
5. Paste your Lua (UNC-enabled) into the `EditText`, hit **Execute** → the text
   is handed to `Executor.nativeExec` and runs on a worker thread in the live
   `lua_State`. Output / error codes appear in the `Log` field (green text).
   **Clear** wipes the editor; **Close** dismisses the window and the
   notification is auto-cleared if you also tap Close (window destroy calls
   `hideOverlay`).

The console is built with framework APIs only (no AndroidX), so there's no
extra dependency: `NotificationChannel` (API 26+/FINE for newer Android) and
`TYPE_APPLICATION_OVERLAY` (API 26+, else `TYPE_PHONE`) are guarded by
version checks.

### Option B — auto-exec file (no UI interaction at all)
Drop a Lua script at

```
/data/user/0/com.roblox.client/files/robloxexec/autoload.lua
```

On the *next* process start, `ExecutorBridge.start → ScriptLoader.autoExec`
opens `robloxexec/autoload.lua`, feeds it to `nativeExec`, and prints the code
(`[autoload] executing ... / [autoload] done (0)`) to the console log if the
UI is attached (silent otherwise). This is the path Delta users reach with by
"dropping the file in the folder".

`config.json.example` is a hint for what a richer config might carry (executor
name, version, default fidelity) — it's metadata only and not hot-loaded today.

### Option C — in-game (the UNC surface is already live)
Because `luaL_loadstring` is hooked and `_G.load`/`loadstring` are shadowed on
the resident `lua_State`, *any* script executing inside Roblox can simply do
```lua
local t = request({Url="https://...";}) 
loadstring(t.Body)()   -- sUNC gate is satisfied inside engine frames
```
The end-user doesn't start the console there; they just call Lua that calls
back into a script they already fetched. The console (A) / file (B) are how a
person *initially* gets their script onto the device.

## APK injection

```bash
# native lib + handwritten bridge (sUNC core only, no UI)
python3 apktool/patcher.py --apk roblox.apk \
                           --lib build_output/librobloxexec.so \
                           --out roblox_patched.apk

# plus the floating console: compile the UI classes to smali, then pass them in
bash scripts/build_java.sh -o smali_out                  # javac + d8 + baksmali
python3 apktool/patcher.py --apk roblox.apk \
                           --lib build_output/librobloxexec.so \
                           --smali-dir smali_out \
                           --out roblox_with_ui.apk
adb install -r roblox_with_ui.apk
```

The patcher (`apktool/patcher.py`) decompiles with apktool, drops
`lib/arm64-v8a/librobloxexec.so`, writes `roblox.executor.*` smali bridge
(or uses your `--smali-dir`), **injects `android.permission.SYSTEM_ALERT_WINDOW`,
`POST_NOTIFICATIONS`, `FOREGROUND_SERVICE` and a transparent
`ExecutorUIActivity` into `AndroidManifest.xml`** when the console is present),
hooks the app `Application.onCreate()` → `ExecutorBridge.start()` (falling
back to a generated `ProxyApplication`), rebuilds, `zipalign`s and signs
(auto debug keystore unless `--ks` given). Run on-device; the console needs
its runtime permission grants from Settings.

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

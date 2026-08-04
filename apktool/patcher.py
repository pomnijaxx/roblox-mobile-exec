#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patcher.py — inject librobloxexec.so + JNI bridge into a Roblox APK.

Pipeline (needs `apktool` on PATH; zipalign/apksigner optional but recommended):

    1. apktool d -f      decompile the target APK
    2. copy librobloxexec.so -> lib/arm64-v8a/
    3. write smali bridge classes (roblox/executor/*)
    4. hook the app's Application.onCreate() -> ExecutorBridge.start()
       (falls back to a proxy Application if the app has none)
    5. apktool b          rebuild
    6. zipalign + apksigner (or debug keystore auto-generated)

Usage:
    python3 patcher.py --apk roblox.apk --lib build_output/librobloxexec.so \
                       --out roblox_patched.apk [--keep] [--ks debug.keystore]
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

# --------------------------------------------------------------------------
# Embedded smali templates
# --------------------------------------------------------------------------

EXECUTOR_SMALI = """\
.class public final Lroblox/executor/Executor;
.super Ljava/lang/Object;

# static natives: must match register_natives() in jni_executor/roblox_exec.cpp
.method static constructor <clinit>()V
    .registers 1

    const-string v0, "robloxexec"

    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    return-void
.end method

.method public static native nativeInit(Landroid/content/Context;)I
.end method

.method public static native nativeExec(Ljava/lang/String;)I
.end method

.method public static native luaAliveQ()I
.end method
"""

SCRIPTLOADER_SMALI = """\
.class public final Lroblox/executor/ScriptLoader;
.super Ljava/lang/Object;

.field private static volatile appContext:Landroid/content/Context;

.method public constructor <init>()V
    .registers 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static attach(Landroid/content/Context;)V
    .registers 2

    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v0

    sput-object v0, Lroblox/executor/ScriptLoader;->appContext:Landroid/content/Context;

    return-void
.end method

.method public static toast(Ljava/lang/String;Ljava/lang/String;)V
    .registers 6

    sget-object v0, Lroblox/executor/ScriptLoader;->appContext:Landroid/content/Context;

    if-eqz v0, :cond_ret

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    if-eqz p1, :cond_nomsg

    const-string v2, "\\n"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_nomsg
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    const/4 v3, 0x1

    invoke-static {v0, v2, v3}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object v4

    invoke-virtual {v4}, Landroid/widget/Toast;->show()V

    :cond_ret
    return-void
.end method

.method private static readAll(Ljava/io/InputStream;)Ljava/lang/String;
    .registers 5

    new-instance v0, Ljava/io/ByteArrayOutputStream;

    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    const/16 v1, 0x2000

    new-array v1, v1, [B

    :loop
    invoke-virtual {p0, v1}, Ljava/io/InputStream;->read([B)I

    move-result v2

    if-gez v2, :done

    const/4 v3, 0x0

    invoke-virtual {v0, v1, v3, v2}, Ljava/io/ByteArrayOutputStream;->write([BII)V

    goto :loop

    :done
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toString()Ljava/lang/String;

    move-result-object v3

    return-object v3
.end method

.method public static requestHttp(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .registers 15

    :try_start
    new-instance v0, Ljava/net/URL;

    if-eqz p0, :url_default

    move-object v4, p0

    goto :url_ok

    :url_default
    const-string v4, "https://www.roblox.com"

    :url_ok
    invoke-direct {v0, v4}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    move-result-object v5

    check-cast v5, Ljava/net/HttpURLConnection;

    move-object v0, v5

    if-eqz p1, :m_default

    move-object v6, p1

    goto :m_ok

    :m_default
    const-string v6, "GET"

    :m_ok
    invoke-virtual {v6}, Ljava/lang/String;->toUpperCase()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v0, v6}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    const/16 v7, 0x1f40

    invoke-virtual {v0, v7}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V

    invoke-virtual {v0, v7}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V

    if-eqz p2, :nobody

    const-string v7, "GET"

    invoke-virtual {v6, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :nobody

    const/4 v7, 0x1

    invoke-virtual {v0, v7}, Ljava/net/HttpURLConnection;->setDoOutput(Z)V

    invoke-virtual {p2}, Ljava/lang/String;->getBytes()[B

    move-result-object v7

    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;

    move-result-object v8

    invoke-virtual {v8, v7}, Ljava/io/OutputStream;->write([B)V

    invoke-virtual {v8}, Ljava/io/OutputStream;->close()V

    :nobody
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getResponseCode()I

    move-result v1

    const/16 v7, 0x190

    if-lt v1, v7, :stream_ok

    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getErrorStream()Ljava/io/InputStream;

    move-result-object v7

    goto :stream_got

    :stream_ok
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;

    move-result-object v7

    :stream_got
    if-eqz v7, :stream_skip

    invoke-static {v7}, Lroblox/executor/ScriptLoader;->readAll(Ljava/io/InputStream;)Ljava/lang/String;

    move-result-object v8

    goto :stream_body

    :stream_skip
    const-string v8, ""

    :stream_body
    new-instance v9, Ljava/lang/StringBuilder;

    invoke-direct {v9}, Ljava/lang/StringBuilder;-><init>()V

    const-string v10, "{\\"Success\\":"

    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v10, 0xc8

    if-lt v1, v10, :succ_fail

    const/16 v10, 0x12c

    if-ge v1, v10, :succ_fail

    const-string v10, "true"

    goto :succ_done

    :succ_fail
    const-string v10, "false"

    :succ_done
    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v10, ",\\"StatusCode\\":"

    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v9, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v10, ",\\"StatusMessage\\":\\"OK\\",\\"Headers\\":\\"\\",\\"Body\\":\\""

    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v9, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v10, "\\"}"

    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->disconnect()V

    :try_end
    return-object v3

    :catch
    move-exception v11

    const-string v0, "{\\"Success\\":false,\\"StatusCode\\":0,\\"StatusMessage\\":\\"ERR\\",\\"Headers\\":\\"\\",\\"Body\\":\\"\\"}"

    return-object v0
.end method

.method public static onFrame()V
    .registers 1

    return-void
.end method
"""

BRIDGE_SMALI = """\
.class public Lroblox/executor/ExecutorBridge;
.super Ljava/lang/Object;

# Called from the injected Application.onCreate().
.method public static start(Landroid/content/Context;)V
    .registers 2

    invoke-static {p0}, Lroblox/executor/ScriptLoader;->attach(Landroid/content/Context;)V

    invoke-static {p0}, Lroblox/executor/Executor;->nativeInit(Landroid/content/Context;)I

    move-result v0
__UI_HOOK__

    return-void
.end method
"""

# Hook lines appended to ExecutorBridge.start() when the console UI classes
# were provided via --smali-dir.
UI_HOOK_SMALI = """\
    invoke-static {p0}, Lroblox/executor/ExecutorUI;->ensureNotification(Landroid/content/Context;)V

    invoke-static {p0}, Lroblox/executor/ScriptLoader;->autoExec(Landroid/content/Context;)V
"""

PROXY_APP_SMALI = """\
.class public Lroblox/executor/ProxyApplication;
.super Landroid/app/Application;

.method public onCreate()V
    .registers 2

    invoke-super {p0}, Landroid/app/Application;->onCreate()V

    invoke-static {p0}, Lroblox/executor/ExecutorBridge;->start(Landroid/content/Context;)V

    return-void
.end method
"""

# Permissions injected when the console UI is present.
UI_PERMISSIONS = [
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.FOREGROUND_SERVICE",
]

UI_ACTIVITY = (
    '<activity android:name="roblox.executor.ExecutorUIActivity"'
    ' android:exported="false"'
    ' android:theme="@android:style/Theme.Translucent.NoTitleBar"/>'
)

# --------------------------------------------------------------------------
# Tooling helpers
# --------------------------------------------------------------------------

def run(cmd, **kw):
    print("[patcher] $ " + " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def which(name):
    return shutil.which(name)


def patch_application_oncreate(smali_path):
    """Insert ExecutorBridge.start(p0) right after the first invoke-super
    inside the Application's onCreate()V method. Returns True if patched."""
    with open(smali_path, "r", encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    hook = "\n\n    invoke-static {p0}, Lroblox/executor/ExecutorBridge;->start(Landroid/content/Context;)V"

    out = []
    in_oncreate = False
    patched = False
    for line in lines:
        out.append(line)
        if not in_oncreate:
            m = re.match(r"^\.method (?:public|protected) onCreate\(\)V", line)
            if m:
                in_oncreate = True
            continue
        # inside onCreate: after the first invoke-super we inject our call
        if re.search(r"invoke-super\s*\{p0\}", line):
            out.append(hook)
            patched = True
            in_oncreate = False
            continue
        if line.startswith(".end method"):
            in_oncreate = False

    if patched:
        with open(smali_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
    return patched


def find_application_class(manifest_path):
    """Return the android:name of the <application> element or None."""
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = fh.read()
    m = re.search(r"<application\b[^>]*>", manifest)
    if not m:
        return None
    tag = m.group(0)
    n = re.search(r'android:name="([^"]+)"', tag)
    return n.group(1) if n else None


def smali_class_path(class_name):
    """'com.foo.App' -> smali/com/foo/App.smali (handles leading dot)."""
    name = class_name.lstrip(".")
    return "smali/" + name.replace(".", "/") + ".smali"


def find_existing_smali(root, class_name):
    """Some apps put classes in smali_classes2/..; search all smali dirs."""
    for entry in sorted(os.listdir(root)):
        if not entry.startswith("smali"):
            continue
        p = os.path.join(root, entry, class_name.lstrip(".").replace(".", "/") + ".smali")
        if os.path.isfile(p):
            return p
    return None


def write_smali(root, rel, content):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    print("[patcher] wrote " + rel)
    return path


def copy_smali_dir(work_apk, smali_dir):
    """Copy javac/d8/baksmali output (e.g. roblox/executor/*.smali) into the
    decompiled APK's smali/ tree. Returns True if any classes were copied."""
    if not smali_dir or not os.path.isdir(smali_dir):
        return False
    n = 0
    for root, _dirs, files in os.walk(smali_dir):
        for fn in files:
            if not fn.endswith(".smali"):
                continue
            src = os.path.join(root, fn)
            rel = os.path.relpath(src, smali_dir)  # roblox/executor/ExecutorUI.smali
            dst = os.path.join(work_apk, "smali", rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            n += 1
    if n:
        print("[patcher] copied %d smali classes from %s" % (n, smali_dir))
    return n > 0


def inject_manifest(work_apk, has_ui):
    """Add overlay/notification permissions + the console activity when the
    UI classes are present. Roblox already declares most perms; we only add
    what is missing."""
    manifest = os.path.join(work_apk, "AndroidManifest.xml")
    with open(manifest, "r", encoding="utf-8") as fh:
        text = fh.read()

    changed = False
    if has_ui:
        for perm in UI_PERMISSIONS:
            needle = '<uses-permission android:name="%s"' % perm
            if needle not in text:
                text = text.replace("</manifest>",
                                    '    %s/>\n</manifest>' % needle)
                changed = True
        if UI_ACTIVITY.split('"')[1] not in text:
            m = re.search(r"<application\b[^>]*>", text)
            if m:
                text = text[:m.end()] + "\n        " + UI_ACTIVITY + text[m.end():]
                changed = True

    if changed:
        with open(manifest, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("[patcher] AndroidManifest.xml updated (perms/activity)")
    return changed


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Inject Roblox executor into APK")
    ap.add_argument("--apk", required=True, help="input (stock Roblox) APK")
    ap.add_argument("--lib", required=True, help="librobloxexec.so")
    ap.add_argument("--out", default="roblox_patched.apk", help="output APK")
    ap.add_argument("--keep", action="store_true", help="keep workdir on exit")
    ap.add_argument("--ks", default=None, help="keystore (auto-generates if unset)")
    ap.add_argument("--ks-pass", default="android", help="keystore password")
    ap.add_argument("--ks-alias", default="exec", help="keystore alias")
    ap.add_argument("--smali-dir", default=None,
                    help="dir with compiled UI classes (javac+d8+baksmali output)")
    args = ap.parse_args()

    if not which("apktool"):
        sys.exit("[patcher] error: apktool not found on PATH")

    work = tempfile.mkdtemp(prefix="robloxexec_patch_")
    print("[patcher] workdir: " + work)
    work_apk = os.path.join(work, "apk")

    # 1. decompile (full decode incl. manifest; needs a recent apktool (3.x)
    #    that can decode modern compileSdk resource tables)
    r = run(["apktool", "d", "-f", "-o", work_apk, args.apk])
    if r.returncode != 0:
        sys.exit("[patcher] apktool d failed:\n" + r.stderr[-2000:])
    if not os.path.isdir(work_apk):
        sys.exit("[patcher] apktool produced no output dir")

    # 2. native lib
    libdir = os.path.join(work_apk, "lib", "arm64-v8a")
    os.makedirs(libdir, exist_ok=True)
    shutil.copy2(args.lib, os.path.join(libdir, "librobloxexec.so"))
    print("[patcher] copied librobloxexec.so -> lib/arm64-v8a/")

    # 3. bridge smali — Java-compiled UI classes may already cover
    #    Executor/ScriptLoader when --smali-dir was supplied; only write
    #    the handwritten fallback templates where the class is missing.
    has_ui = copy_smali_dir(work_apk, args.smali_dir)

    cls_rel = lambda c: "smali/roblox/executor/%s.smali" % c
    if not os.path.exists(os.path.join(work_apk, cls_rel("Executor"))):
        write_smali(work_apk, cls_rel("Executor"), EXECUTOR_SMALI)
    if not os.path.exists(os.path.join(work_apk, cls_rel("ScriptLoader"))):
        write_smali(work_apk, cls_rel("ScriptLoader"), SCRIPTLOADER_SMALI)
    bridge_body = BRIDGE_SMALI.replace("__UI_HOOK__",
                                      UI_HOOK_SMALI if has_ui else "")
    write_smali(work_apk, cls_rel("ExecutorBridge"), bridge_body)

    # 4. hook the app's Application.onCreate() -> ExecutorBridge.start()
    #    (falls back to our ProxyApplication when it has none)
    manifest = os.path.join(work_apk, "AndroidManifest.xml")
    app_cls = find_application_class(manifest)
    if app_cls:
        smali = find_existing_smali(work_apk, app_cls)
        if smali and patch_application_oncreate(smali):
            print("[patcher] hooked Application.onCreate() in " + smali)
        else:
            print("[patcher] app class '%s' not patched (not found); using ProxyApplication"
                  % app_cls)
            app_cls = None
    else:
        app_cls = None
    if not app_cls:
        proxy = cls_rel("ProxyApplication")
        if not os.path.exists(os.path.join(work_apk, proxy)):
            write_smali(work_apk, proxy, PROXY_APP_SMALI)
        r = run(["sed", "-i", 's|<application |<application android:name="roblox.executor.ProxyApplication" |',
                 manifest])
        if r.returncode != 0:
            sys.exit("[patcher] could not set ProxyApplication in manifest")
        print("[patcher] manifest now points at roblox.executor.ProxyApplication")

    # 4b. when UI classes are present, inject permissions + launcher activity
    #    (idempotent: skipped if the app already declares them).
    inject_manifest(work_apk, has_ui)

    # 5. rebuild
    out_apk = args.out
    if os.path.exists(out_apk):
        os.remove(out_apk)
    r = run(["apktool", "b", work_apk, "-o", out_apk])
    if r.returncode != 0:
        sys.exit("[patcher] apktool b failed:\n" + r.stderr[-2000:])

    # 6. align + sign
    aligned = out_apk + ".aligned"
    za = which("zipalign")
    if za:
        run([za, "-f", "4", out_apk, aligned])
        os.replace(aligned, out_apk)
    else:
        print("[patcher] warning: zipalign not found; skipping alignment")

    signer = which("apksigner")
    ks = args.ks
    if signer:
        if not ks:
            ks = os.path.join(work, "debug.keystore")
            if not os.path.exists(ks):
                keytool = which("keytool")
                if keytool:
                    run([keytool, "-genkeypair", "-v", "-keystore", ks,
                         "-storepass", args.ks_pass, "-alias", args.ks_alias,
                         "-keypass", args.ks_pass, "-keyalg", "RSA",
                         "-keysize", "2048", "-validity", "10000",
                         "-dname", "CN=RobloxExec, OU=Mobile, O=exec, C=US"])
        r = run([signer, "sign", "--ks", ks, "--ks-pass", "pass:" + args.ks_pass,
                 "--key-pass", "pass:" + args.ks_pass, "--out", out_apk + ".signed",
                 out_apk])
        if r.returncode == 0:
            os.replace(out_apk + ".signed", out_apk)
        else:
            print("[patcher] warning: apksigner failed:\n" + r.stderr[-800:])
    else:
        print("[patcher] warning: apksigner not found; APK is unsigned")

    if not args.keep:
        shutil.rmtree(work, ignore_errors=True)

    print("[patcher] done -> " + os.path.abspath(out_apk))
    print("[patcher] install: adb install -r " + os.path.abspath(out_apk))


if __name__ == "__main__":
    main()

#!/usr/bin/env bash
# build_java.sh — compile jni_wrapper/*.java -> smali for patcher.py
#
# Pipeline:  javac (against android.jar) -> d8 (classes.dex) -> baksmali (smali/)
#
# Environment (or flags):
#   ANDROID_JAR    android.jar path           (default: $ANDROID_HOME/platforms/android-34/android.jar)
#   D8             d8 binary path             (default: $ANDROID_HOME/build-tools/34.0.0/d8)
#   BAKSMALI_JAR   baksmali jar path          (default: /opt/baksmali.jar)
#
# Usage:
#   bash scripts/build_java.sh -o smali_out
set -euo pipefail

OUT=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) OUT="$2"; shift 2 ;;
        -h|--help)
            echo "usage: build_java.sh -o <smali_out_dir>"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done
[[ -n "$OUT" ]] || { echo "error: -o required" >&2; exit 2; }

ANDROID_JAR="${ANDROID_JAR:-${ANDROID_HOME:-}/platforms/android-34/android.jar}"
D8="${D8:-${ANDROID_HOME:-}/build-tools/34.0.0/d8}"
BAKSMALI_JAR="${BAKSMALI_JAR:-/opt/baksmali.jar}"

for t in "$ANDROID_JAR" "$D8" "$BAKSMALI_JAR" javac java; do
    if [[ "$t" == "javac" || "$t" == "java" ]]; then
        command -v "$t" >/dev/null || { echo "error: $t not found" >&2; exit 2; }
    else
        [[ -f "$t" ]] || { echo "error: $t not found" >&2; exit 2; }
    fi
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "[build_java] javac -> classes/"
javac -nowarn -proc:none \
    -bootclasspath "$ANDROID_JAR" \
    -source 8 -target 8 \
    -d "$WORK/classes" \
    "$ROOT"/jni_wrapper/*.java

echo "[build_java] d8 -> classes.dex"
mkdir -p "$WORK/dex"
"$D8" --release --lib "$ANDROID_JAR" --min-api 21 \
    --output "$WORK/dex" \
    "$WORK"/classes/roblox/executor/*.class

echo "[build_java] baksmali -> $OUT"
rm -rf "$OUT"
java -jar "$BAKSMALI_JAR" d "$WORK/dex/classes.dex" -o "$OUT"

echo "[build_java] done ($(find "$OUT" -name '*.smali' | wc -l) smali files)"

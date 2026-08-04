#!/usr/bin/env bash
# build.sh — build librobloxexec.so for arm64-v8a.
#
# Usage:
#   ./build.sh                     # NDK toolchain (ANDROID_NDK_HOME) or CMake
#   ./build.sh --termux            # host-check build with Termux clang (no NDK)
#   ./build.sh --cmake <toolchain> # explicit android.toolchain.cmake path
#
# Output: build_output/librobloxexec.so
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/build_output"
mkdir -p "$OUT"

MODE="${1:---auto}"

# ---------------------------------------------------------------- helpers
die() { echo "error: $*" >&2; exit 1; }

build_termux() {
  echo "[build.sh] Termux host-check build (NOT android-linked; uses Termux jni.h)"
  # NOTE: no -isystem $PREFIX/include — Termux clang already resolves its own
  # sysroot; adding -isystem first reorders C headers before libc++ and breaks
  # the C++ standard library headers (cerrno/cstdio 'header not found' errors).
  local inc="-I$ROOT/jni_executor -std=c++17 -D__ANDROID__ -fno-strict-aliasing -fPIC"
  local objs=()
  for f in scan hooks unc_api memops roblox_exec; do
    echo "  cc jni_executor/$f.cpp"
    clang++ -c $inc "$ROOT/jni_executor/$f.cpp" -o "$OUT/$f.o"
    objs+=("$OUT/$f.o")
  done
  echo "  ld librobloxexec.so (-Bsymbolic)"
  clang++ -shared -fPIC -Wl,-Bsymbolic "${objs[@]}" \
      -o "$OUT/librobloxexec.so" -llog -landroid
  echo "  => $OUT/librobloxexec.so"
}

build_ndk() {
  local tc="$1"
  [ -f "$tc" ] || die "toolchain file not found: $tc"
  echo "[build.sh] NDK CMake build via $tc"
  cmake -S "$ROOT" -B "$OUT/cmake" \
      -DCMAKE_TOOLCHAIN_FILE="$tc" \
      -DANDROID_ABI=arm64-v8a \
      -DANDROID_PLATFORM=android-26 \
      -DCMAKE_BUILD_TYPE=Release \
      -G Ninja
  cmake --build "$OUT/cmake" -j"$(nproc 2>/dev/null || echo 4)"
  cp "$OUT/cmake/librobloxexec.so" "$OUT/librobloxexec.so"
  echo "  => $OUT/librobloxexec.so"
}

find_ndk_toolchain() {
  local ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK:-}}"
  if [ -z "$ndk" ] && [ -n "${ANDROID_HOME:-}" ]; then
    # Android Studio's bundled NDK (latest)
    ndk="$(ls -d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1 || true)"
  fi
  if [ -n "$ndk" ]; then
    local tc="$ndk/build/cmake/android.toolchain.cmake"
    [ -f "$tc" ] && echo "$tc" && return 0
  fi
  return 1
}

# ------------------------------------------------------------------ main
case "$MODE" in
  --termux) build_termux ;;
  --cmake)
    [ $# -ge 2 ] || die "--cmake <android.toolchain.cmake>"
    build_ndk "$2"
    ;;
  --auto)
    if tc="$(find_ndk_toolchain)"; then
      build_ndk "$tc"
    elif command -v clang++ >/dev/null 2>&1; then
      echo "[build.sh] NDK not found; falling back to Termux host-check build"
      build_termux
    else
      die "no compiler and no NDK available"
    fi
    ;;
  *) die "unknown mode: $MODE (try --termux | --cmake <path> | --auto)" ;;
esac

ls -la "$OUT/librobloxexec.so"

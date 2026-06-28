#!/usr/bin/env bash
# Cross-compile the sk-pqc-rs Rust core (hybrid X25519 + ML-KEM-768, --features
# dart) for the three common Android ABIs and drop the resulting libsk_pqc.so
# into android/app/src/main/jniLibs/ so `flutter build apk` bundles it and the
# on-device round-trip can load it.
#
# Prereqs: Android NDK + a Rust toolchain WITH the Android std targets. Arch
# system rust (no rustup) ships only host + wasm std, so this uses rustup-managed
# targets. Install them once:
#   rustup target add aarch64-linux-android x86_64-linux-android armv7-linux-androideabi
#
# Env:
#   ANDROID_NDK_HOME  path to an installed NDK (e.g. $ANDROID_HOME/ndk/<ver>)
#   SK_PQC_RS         path to the sibling sk-pqc-rs checkout (default ../../../sk-pqc-rs)
set -euo pipefail

API=21
SK_PQC_RS="${SK_PQC_RS:-$(cd "$(dirname "$0")/../../../sk-pqc-rs" && pwd)}"
NDK="${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to your installed NDK}"
TOOL="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
APP="$(cd "$(dirname "$0")" && pwd)"
JNI="$APP/android/app/src/main/jniLibs"

build() { # <rust-target> <clang-prefix> <abi-dir>
  local tgt="$1" clang="$2" abi="$3"
  local up; up="$(echo "$tgt" | tr "a-z-" "A-Z_")"
  export "CARGO_TARGET_${up}_LINKER=$TOOL/${clang}${API}-clang"
  export "CC_${tgt//-/_}=$TOOL/${clang}${API}-clang"
  export "AR_${tgt//-/_}=$TOOL/llvm-ar"
  ( cd "$SK_PQC_RS" && cargo build --release --features dart --target "$tgt" )
  mkdir -p "$JNI/$abi"
  cp "$SK_PQC_RS/target/$tgt/release/libsk_pqc.so" "$JNI/$abi/"
}

build aarch64-linux-android      aarch64-linux-android      arm64-v8a
build x86_64-linux-android       x86_64-linux-android       x86_64
build armv7-linux-androideabi    armv7a-linux-androideabi   armeabi-v7a

echo "Bundled libsk_pqc.so for: arm64-v8a, x86_64, armeabi-v7a"

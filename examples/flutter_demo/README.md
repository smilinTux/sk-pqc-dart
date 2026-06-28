# sk_pqc Flutter demo — hybrid X25519 + ML-KEM-768 round-trip

Minimal Flutter app that proves the **mobile story** for
[`sk_pqc`](../../): one button runs a hybrid post-quantum KEM
**keygen → encapsulate → decapsulate** round-trip through the `sk-pqc-rs`
**pure-Rust core** over `flutter_rust_bridge`, then displays that the sender and
recipient derived the **same 32-byte shared secret**.

* Suite: `x25519-mlkem768` — X25519 (`x25519-dalek`) + ML-KEM-768 (RustCrypto
  `ml-kem`, **FIPS 203**), combined with HKDF-SHA256.
* **Hybrid**, not "quantum-proof": the secret holds as long as **either** the
  classical X25519 leg **or** the ML-KEM-768 leg is unbroken. **KEM-only** (no
  signatures).
* Wire sizes: public 1216 B, private 2432 B, ciphertext 1120 B, secret 32 B.

## Run the headless proof (host)

```sh
# 1. Build the host Rust core (x86_64) with the dart feature:
( cd ../../../sk-pqc-rs && cargo build --release --features dart )
# 2. Point the loader at it and run the widget test:
SK_PQC_RS_LIB=$(pwd)/../../../sk-pqc-rs/target/release/libsk_pqc.so \
  flutter test
```

The widget test taps the button and asserts `SHARED SECRETS MATCH`.

## Build the Android APK (on-device)

```sh
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/<version>
./build_android_libs.sh          # cross-compiles libsk_pqc.so into jniLibs/
flutter build apk --release
```

`build_android_libs.sh` cross-compiles the Rust core for `arm64-v8a`, `x86_64`
and `armeabi-v7a` and places each `libsk_pqc.so` under
`android/app/src/main/jniLibs/`, which `flutter build apk` bundles so the
on-device round-trip can load the native core.

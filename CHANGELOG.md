# Changelog

## Unreleased

### Added
- **`package:sk_pqc/rust_core.dart`** (optional) — backs the Dart API with the shared
  `sk-pqc-rs` Rust core (ML-KEM-768 via RustCrypto `ml-kem`, FIPS 203; X25519 via
  `x25519-dalek`) over flutter_rust_bridge — the Dart twin of that crate's PyO3 binding.
  `SkPqcRustCore` exposes `generateKeyPair` / `encapsulate` / `decapsulate` /
  `deriveDmMessageKey` returning the same Dart types. Separate import: the default
  `sk_pqc.dart` (liboqs / noble backends) stays Rust-free.
- Committed frb glue under `lib/src/rust/`; `flutter_rust_bridge` runtime dependency
  (used only by `rust_core.dart`).
- `test/rust_frb_parity_test.dart` (tag `frb`) — proves the Rust-via-frb core matches the
  pure-Dart implementation **byte-for-byte** on the shared DM-key KAT vectors, with
  hybrid-KEM cross-decapsulation in both directions; self-skips when the cdylib is absent.
  Native binding; web/wasm is future work. No wire change.

## 0.1.0

Initial release — **published to pub.dev** as
[`sk_pqc`](https://pub.dev/packages/sk_pqc) (`dart pub add sk_pqc`). Companion
packages: PyPI [`sk-pqc`](https://pypi.org/project/sk-pqc/) and crates.io
[`sk-pqc`](https://crates.io/crates/sk-pqc) — all import as `sk_pqc`.

- Hybrid post-quantum KEM with suite id `x25519-mlkem768` (X25519 + ML-KEM-768,
  FIPS 203).
- One `HybridKem` Dart API with two backends behind a conditional import:
  - **native** (`dart:ffi`) → liboqs `OQS_KEM` ML-KEM-768.
  - **web** (`dart:js_interop`) → `@noble/post-quantum` ml_kem768.
  - X25519 on both via `package:cryptography`.
- HKDF-SHA256 hybrid combiner (`HKDF-SHA256(X25519_ss ‖ MLKEM768_ss, salt, info)`),
  the only original cryptographic code, tested against RFC 5869 and hand-computed
  vectors.
- Documented wire format (1216-B public key, 2432-B private key, 1120-B
  ciphertext, 32-B shared secret) as the cross-implementation interop contract.
- Test coverage: combiner KATs, ML-KEM-768 KAT vs NIST ACVP FIPS 203 keyGen,
  cross-backend (noble ↔ liboqs both directions), round-trips, malformed-input
  handling, and a JSON interop test vector verified by Dart, liboqs, noble, and
  Python (`tool/verify_vector.py`).

### Known limitations

- KEM only — no signatures (ML-DSA / SLH-DSA are future work).
- v1 ships and tests the FFI path on Linux desktop. Per-arch liboqs binaries for
  Android/iOS/macOS/Windows are a documented CI follow-up.
- The web backend's assurance depends on `@noble/post-quantum`.

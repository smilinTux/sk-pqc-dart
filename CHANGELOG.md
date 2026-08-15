# Changelog

## Unreleased

### Documentation

- **Fixed a broken standards citation (HTTP 404).** `SOP.md`, `SECURITY.md` and
  `CONTRIBUTING.md` all cited the CRYPTOGRAPHY_STANDARD at
  `github.com/smilinTux/skstacks/blob/main/docs/CRYPTOGRAPHY_STANDARD.md`, which
  returns **404** (that repo is private and contains no such file). All three now cite
  the canonical `github.com/smilinTux/sk-standards/blob/main/standards/CRYPTOGRAPHY_STANDARD.md`
  (HTTP 200). This repo is public, so a reader checking the crypto-compliance claim was
  hitting a dead link.
- `SOP.md` restructured to the 9 canonical SK_REPO_DOC_STANDARD sections, in order.
  Added an explicit **Overview**, split **Release / Deploy** out of "Build / Deploy",
  and added a **Maturity-tier + Version reference** section. **Test** now precedes
  **API**, which was previously reversed.
- **Stated the maturity tier in `README.md`**, which previously stated none. The only
  "tier" it mentioned was the FIPS 203 ML-KEM-768 parameter set, a different scale;
  both files now say so explicitly.
- **Said plainly that there is no self-report.** The old tier table marked T1 as met.
  `sk_pqc` exposes only `kSuiteId` / `HybridKem.suiteId`; it is a stateless KEM with no
  channel or peer, so the self-report obligation sits with the **consumer**. T1 is now
  recorded as **partial**.
- `SECURITY.md`: added the **experimental / unaudited posture statement** required by
  SECURITY_DISCLOSURE_STANDARD section 2.
- **Documented the duplicate checkout hazard** in Troubleshooting: this remote is
  cloned locally to both `skcapstone-repos/sk-pqc-dart` and `skcapstone-repos/sk_pqc`
  (the repo's former name, still redirected by GitHub), and both were seen behind
  `origin/main`.
- Added a `docs-evidence` block (9 hermetic checks) pinning the suite id, the
  **combiner ordering invariant** (X25519 first), the HKDF-SHA256 + 32-byte output, the
  default info label, the ML-KEM-768 wire sizes, the `SK_PQC_LIBOQS` override, and the
  `flutter_rust_bridge` pin. Added an "Unverified / needs an operator pass" section.
- Added `.github/workflows/docs-check.yml` (tiers 1,2).

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

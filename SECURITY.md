# Security Policy — sk_pqc

`sk_pqc` is a **hybrid post-quantum key-encapsulation** library (suite
`x25519-mlkem768`: X25519 + ML-KEM-768, FIPS 203). Because it is cryptographic
infrastructure, please read both the **honest-claim posture** and the **threat model**
below before relying on it or reporting an issue.

---

## Honest claims (what this library does and does NOT promise)

Per the SKStacks
[CRYPTOGRAPHY_STANDARD](https://github.com/smilinTux/skstacks/blob/main/docs/CRYPTOGRAPHY_STANDARD.md),
every security claim is scoped to **surface + FIPS number + hybrid-vs-classical**.

- ✅ **Quantum-resistant / post-quantum key encapsulation.** The 32-byte derived
  secret is secure if **either** the X25519 leg **or** the ML-KEM-768 leg holds.
- ✅ Targets the **FIPS 203 ML-KEM-768** tier (internet default; matches TLS
  `X25519MLKEM768` and Signal PQXDH).
- ✅ Neutralises **Harvest-Now-Decrypt-Later (HNDL)** for any key wrapped through the
  combiner — this is **maturity tier T2 (Hybrid KEM)**.
- ❌ **Not** "quantum-proof," "quantum-safe," or "unbreakable." Lattice cryptography
  is young; these words are never used.
- ❌ **Not** a signature scheme. It is **KEM-only** — it authenticates **nothing** by
  itself. ML-DSA / SLH-DSA (FIPS 204/205, tier T3) are **future work**. Pair `sk_pqc`
  with a signature scheme for authenticated key exchange, or you are exposed to a
  man-in-the-middle.
- ❌ **Not** the CNSA-2.0 ceiling (ML-KEM-1024) — that tier is reserved for a
  sovereign root.
- ❌ **No web client may claim it is E2E post-quantum.** WebCrypto has no PQC API in
  any browser (2026); the web leg's assurance is *disclosed* as resting on the audited
  pure-JS `@noble/post-quantum`.

---

## Threat model

### In scope (what the hybrid KEM defends)

- **HNDL on the key-exchange secret.** A future cryptographically-relevant quantum
  computer (CRQC) that records today's ciphertext cannot recover the shared secret
  without breaking **both** legs (X25519 *and* ML-KEM-768). By Mosca's Inequality,
  long-shelf-life secrets are already past the migration threshold — hence T2 now.
- **Classical break of one primitive.** A future cryptanalytic break of X25519 alone
  leaves ML-KEM-768 standing, and vice-versa.
- **Wire tampering / corrupt ciphertext.** ML-KEM-768 uses **implicit rejection** — a
  tampered ciphertext yields a pseudo-random secret that simply won't match; the
  library does **not** crash. Malformed lengths raise `SkPqcError`, never an
  uncaught exception.

### Out of scope (you MUST handle these elsewhere)

- **Authentication / MITM.** KEM-only. An active attacker who substitutes a public
  key is not detected by `sk_pqc`. Authenticate the public key out-of-band or with a
  signature scheme (e.g. sk_pgp / a future hybrid ML-DSA layer).
- **Transport security.** TLS, tailnet, DTLS-SRTP media legs are not this library's
  surface. Residual classical legs in your transport must be documented separately.
- **Key storage / lifecycle.** The 2432-byte private key is the caller's
  responsibility to store and zeroise. `sk_pqc` does not persist keys.
- **Side channels in the bound libraries.** Constant-time guarantees come from
  **liboqs** (native) and **@noble/post-quantum** (web). `sk_pqc` adds no secret-
  dependent branching in the combiner, but does not re-audit the primitives.
- **Symmetric layer.** Use the 32-byte secret with **AES-256-GCM** (or ChaCha20-
  Poly1305). AES-256 is quantum-acceptable (Grover only halves it to ~128-bit).

### Trust roots / dependencies

| Leg | Library | Assurance basis |
|---|---|---|
| ML-KEM-768 (native) | [liboqs](https://github.com/open-quantum-safe/liboqs) (0.14.0) | Open Quantum Safe; you build/bundle the per-platform binary |
| ML-KEM-768 (web) | [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) | audited pure-JS; pin the audited version |
| X25519 (both) | `package:cryptography` | RFC 7748 / RFC 9180 DHKEM |
| HKDF-SHA256 (combiner) | `package:cryptography` | RFC 5869; verified vs §A.1 KAT in `test/combiner_test.dart` |

**We bind vetted libraries; we never hand-roll the lattice or curve primitives.** The
**only** original cryptographic code is the HKDF-SHA256 hybrid combiner
(`lib/src/combiner.dart`), and it is `HKDF-SHA256(X25519_ss ‖ MLKEM768_ss)` —
concatenate-then-KDF, **never XOR, never pure-PQ**.

---

## The one invariant that must never change

```
shared_secret = HKDF-SHA256( IKM = X25519_ss ‖ MLKEM768_ss,   // X25519 FIRST
                             salt, info, L = 32 )
```

Any change to the combiner, the byte order, or the fixed wire-format lengths (1216B
public / 2432B private / 1120B ciphertext / 32B secret) **breaks every peer** and is
a **security-relevant** change. It MUST go through a suite-id bump (`x25519-mlkem768`
→ a new id) and the full cross-impl vector gate — never a silent edit. See
[SOP.md](SOP.md) §(c).

---

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ current |
| < 0.1.0 | ❌ pre-release |

Until 1.0, only the latest published `0.x` line receives security fixes. The wire
format and combiner are frozen across `0.x`; any break ships under a new suite id.

---

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

- Report privately via the repository's **GitHub Security Advisories**
  ("Report a vulnerability" on the Security tab of
  [`smilinTux/sk-pqc-dart`](https://github.com/smilinTux/sk-pqc-dart)), or
- email the maintainers (smilinTux / SKWorld) at the address listed on the GitHub org.

Please include: affected version, platform (web/native + liboqs/noble version), a
minimal reproduction, and — if it concerns the combiner or wire format — a failing
vector against `test_vectors/hybrid_kem_x25519_mlkem768.json`.

**Coordinated disclosure.** We aim to acknowledge within **72 hours** and to ship a
fix or mitigation within **90 days**, coordinating a disclosure date with you. Issues
in a **bound upstream** (liboqs, noble-post-quantum) will be forwarded upstream and
tracked here. Credit is given unless you ask otherwise.

### What we especially want to hear about

- Combiner deviations (XOR, wrong concat order, missing domain separation).
- Wire-format / length confusion that could cause cross-impl secret divergence.
- A path where a malformed input crashes instead of raising `SkPqcError`.
- Any place a claim in the docs overstates assurance (e.g. implies authentication,
  CNSA-2.0, or a "quantum-safe" web client).

---

**License:** Apache-2.0. **Standards:** FIPS 203 (ML-KEM); FIPS 204/205 cited for
out-of-scope signatures; RFC 5869 (HKDF); RFC 7748 / RFC 9180 (X25519 / DHKEM);
NIST CSWP 39 (crypto-agility).

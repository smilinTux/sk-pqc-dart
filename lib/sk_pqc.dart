/// sk_pqc — hybrid post-quantum key encapsulation (X25519 + ML-KEM-768).
///
/// One Dart API, two backends behind a conditional import:
///   * native (dart:ffi)        → liboqs OQS_KEM ML-KEM-768
///   * web    (dart:js_interop) → @noble/post-quantum ml_kem768
/// X25519 is `package:cryptography` on both. The hybrid combiner is
/// HKDF-SHA256 over `X25519_ss ‖ MLKEM768_ss`.
///
/// This is a HYBRID KEM: secure if EITHER X25519 or ML-KEM-768 holds. It is the
/// FIPS 203 ML-KEM-768 tier and is KEM-ONLY (signatures are future work). It is
/// not "quantum-proof".
library;

export 'src/combiner.dart' show HybridCombiner;
export 'src/dm_ratchet.dart'
    show
        DmRatchet,
        deriveDmMessageKey,
        newEpochSecret,
        wrapDmEpochSecret,
        unwrapDmEpochSecret,
        wrappedPayloadLen,
        kEpochSecretLen,
        kMessageKeyLen,
        kDefaultRekeyMsgBound,
        kDefaultRekeyAgeSeconds;
export 'src/hybrid_kem.dart' show HybridKem, WireFormat;
export 'src/hybrid_kem_impl.dart' show HybridKemImpl;
export 'src/mlkem_backend.dart' show MlKem768Backend;
export 'src/mlkem_provider.dart' show createMlKem768Backend;
export 'src/types.dart'
    show
        EncapResult,
        HybridKeyPair,
        SkPqcError,
        SkPqcSizes,
        kSuiteId;
export 'src/x25519_kem.dart' show X25519Kem;

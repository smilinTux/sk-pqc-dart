import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'hybrid_kem.dart';
import 'hybrid_kem_impl.dart';
import 'types.dart';

/// SKChat 1:1 DM epoch-ratchet — Dart bridge layer.
///
/// ## What this is
/// A **thin** Dart re-implementation of the 1:1 DM epoch-ratchet *key schedule*
/// (`skchat/dm_ratchet.py` / `sk-core/src/ratchet.rs`). Per-conversation
/// **epoch secrets** are distributed once per epoch via the vetted [HybridKem]
/// ([HybridKemImpl]); per-message keys derive symmetrically and
/// index-addressably from the epoch secret (loss/reorder tolerant). Periodic
/// rekey (50 messages OR 7 days) starts a fresh independent epoch — forward
/// secrecy across the boundary, post-compromise security within.
///
/// This is the **Level-3** running ratchet (the 1:1 analogue of the group
/// ratchet), lifting the surface above the stateless one-shot hybrid seal.
///
/// ## HONESTY — this is a BRIDGE, not a permanent home
/// The long-term plan (P7) is for the ratchet key schedule to live **once** in
/// the shared Rust core ([`sk-core/src/ratchet.rs`]) and be reached from Dart
/// via **FFI**, exactly as the ML-KEM-768 leg already reaches liboqs. Keeping a
/// hand-written Dart copy of a security-critical key schedule indefinitely
/// means three implementations (Python, Rust, Dart) that can silently drift.
/// So this layer is deliberately **thin and clearly marked**: it exists to
/// unblock the Flutter client today and is validated against the **same
/// cross-language KAT vectors** as Python and Rust. When the Rust core ships an
/// FFI surface, these functions become a shim over it and the original Dart
/// crypto here should be deleted.
///
/// The ONLY original cryptographic code here is label/IKM wiring around vetted
/// primitives (HKDF-SHA256 and AES-256-GCM from `package:cryptography`, and the
/// existing [HybridKem]). We never hand-roll a primitive.
///
/// ## Interop contract (MUST match Python + Rust byte-for-byte)
/// ```text
/// message key:
///   salt = b"skchat/dm-epoch/"          || u64_be(epoch)
///   info = b"skchat/dm-ratchet/msg/v1/" || u64_be(index)
///   key  = HKDF-SHA256(IKM = epoch_secret, salt, info, L = 32)
///
/// epoch-secret wrap (once per epoch):
///   ct, ss   = HybridKem.encapsulate(peer_hybrid_pub)   // x25519-mlkem768
///   wrap_key = HKDF-SHA256(IKM = ss, salt = "",
///                          info = b"skchat/dm-ratchet/epoch-wrap/v1", L = 32)
///   payload  = ct(1120) || nonce(12) || AES-256-GCM(wrap_key, nonce, secret)
/// ```

/// Length of an epoch secret / a derived per-message key (bytes).
const int kEpochSecretLen = 32;

/// Length of a derived per-message key (bytes).
const int kMessageKeyLen = 32;

/// AES-GCM nonce length for the epoch-secret wrap (random per wrap).
const int kWrapNonceLen = 12;

/// Wrapped epoch secret = plaintext(32) + AES-GCM tag(16).
const int kWrappedSecretLen = kEpochSecretLen + 16; // 48

/// Default re-key bounds (RFC-0001 P1 / Apple-PQ3: 50 messages OR 7 days).
const int kDefaultRekeyMsgBound = 50;
const int kDefaultRekeyAgeSeconds = 7 * 24 * 3600;

/// HKDF salt prefix — folds the epoch number into the salt (domain separation).
final Uint8List _epochSaltPrefix = _ascii('skchat/dm-epoch/');

/// HKDF info prefix for per-message keys — folds the index in after a `/`.
/// Equals Python's `_INFO_DM_MESSAGE_KEY + b"/"`.
final Uint8List _msgInfoPrefix = _ascii('skchat/dm-ratchet/msg/v1/');

/// HKDF info for the epoch-secret wrap key.
final Uint8List _wrapInfo = _ascii('skchat/dm-ratchet/epoch-wrap/v1');

/// Total per-conversation, per-epoch distribution payload size:
/// `hybrid_ct(1120) || nonce(12) || wrapped(48)`.
int get wrappedPayloadLen =>
    SkPqcSizes.hybridCiphertext + kWrapNonceLen + kWrappedSecretLen;

Uint8List _ascii(String s) => Uint8List.fromList(s.codeUnits);

/// Big-endian u64 (matches Python `struct.pack(">Q", n)` and Rust
/// `n.to_be_bytes()`).
Uint8List _u64be(int n) {
  final b = Uint8List(8);
  ByteData.view(b.buffer).setUint64(0, n, Endian.big);
  return b;
}

Uint8List _concat(List<Uint8List> parts) {
  var total = 0;
  for (final p in parts) {
    total += p.length;
  }
  final out = Uint8List(total);
  var off = 0;
  for (final p in parts) {
    out.setAll(off, p);
    off += p.length;
  }
  return out;
}

/// Derive the AES-256 key for DM message [index] in [epoch].
///
/// Deterministic and index-addressable: the same `(epochSecret, epoch, index)`
/// always yields the same 32-byte key, and any index can be derived
/// independently of the others (loss/reorder tolerant).
///
/// Matches `skchat.dm_ratchet.derive_dm_message_key` and
/// `sk_core::ratchet::derive_dm_message_key` exactly (see the cross-language
/// KAT vectors in `test/dm_ratchet_test.dart`).
Future<Uint8List> deriveDmMessageKey(
  Uint8List epochSecret,
  int epoch,
  int index,
) async {
  if (epochSecret.length != kEpochSecretLen) {
    throw SkPqcError(
      'epoch_secret must be $kEpochSecretLen bytes, got ${epochSecret.length}',
    );
  }
  final salt = _concat([_epochSaltPrefix, _u64be(epoch)]);
  final info = _concat([_msgInfoPrefix, _u64be(index)]);
  return _hkdfSha256(ikm: epochSecret, salt: salt, info: info, length: kMessageKeyLen);
}

/// Generate a fresh random 32-byte epoch secret (independent of any prior —
/// post-compromise security: a leaked epoch heals at the next rekey).
Uint8List newEpochSecret() {
  final rng = Random.secure();
  final out = Uint8List(kEpochSecretLen);
  for (var i = 0; i < out.length; i++) {
    out[i] = rng.nextInt(256);
  }
  return out;
}

/// Wrap an [epochSecret] to the peer's hybrid-KEM public key.
///
/// Composes the existing [HybridKem.encapsulate] (`x25519-mlkem768`) for a
/// one-time shared secret, HKDF-expands it to an AES-256 wrap key, and
/// AES-256-GCM-encrypts the epoch secret. The KEM ciphertext travels in the
/// blob so the peer can decapsulate — this PQ material is the **per-epoch**
/// cost (NOT per message).
///
/// Returns `hybrid_ct(1120) || nonce(12) || wrapped(48)`.
Future<Uint8List> wrapDmEpochSecret(
  Uint8List epochSecret,
  Uint8List peerHybridPub, {
  HybridKem? kem,
}) async {
  if (epochSecret.length != kEpochSecretLen) {
    throw SkPqcError(
      'epoch_secret must be $kEpochSecretLen bytes, got ${epochSecret.length}',
    );
  }
  if (peerHybridPub.length != SkPqcSizes.hybridPublicKey) {
    throw SkPqcError(
      'peer hybrid public key must be ${SkPqcSizes.hybridPublicKey} bytes, '
      'got ${peerHybridPub.length}',
    );
  }
  final k = kem ?? HybridKemImpl();
  final enc = await k.encapsulate(peerHybridPub);
  final wrapKey = await _hkdfSha256(
    ikm: enc.sharedSecret,
    salt: Uint8List(0),
    info: _wrapInfo,
    length: 32,
  );

  final aes = AesGcm.with256bits();
  final nonce = aes.newNonce(); // 12 random bytes
  final box = await aes.encrypt(
    epochSecret,
    secretKey: SecretKey(wrapKey),
    nonce: nonce,
  );
  // wrapped = ciphertext(32) || tag(16)
  final wrapped = _concat([
    Uint8List.fromList(box.cipherText),
    Uint8List.fromList(box.mac.bytes),
  ]);
  return _concat([enc.ciphertext, Uint8List.fromList(nonce), wrapped]);
}

/// Recover an epoch secret from a wrapped [payload] using the peer's private
/// key. Inverse of [wrapDmEpochSecret].
///
/// Throws [SkPqcError] on a malformed payload or AES-GCM authentication
/// failure.
Future<Uint8List> unwrapDmEpochSecret(
  Uint8List payload,
  Uint8List peerHybridPriv, {
  HybridKem? kem,
}) async {
  if (payload.length != wrappedPayloadLen) {
    throw SkPqcError(
      'wrapped epoch payload must be $wrappedPayloadLen bytes, '
      'got ${payload.length}',
    );
  }
  final ctEnd = SkPqcSizes.hybridCiphertext;
  final nonceEnd = ctEnd + kWrapNonceLen;
  final ciphertext = Uint8List.sublistView(payload, 0, ctEnd);
  final nonce = Uint8List.sublistView(payload, ctEnd, nonceEnd);
  final wrapped = Uint8List.sublistView(payload, nonceEnd);
  final cipherText = Uint8List.sublistView(wrapped, 0, kEpochSecretLen);
  final tag = Uint8List.sublistView(wrapped, kEpochSecretLen);

  final k = kem ?? HybridKemImpl();
  final shared = await k.decapsulate(ciphertext, peerHybridPriv);
  final wrapKey = await _hkdfSha256(
    ikm: shared,
    salt: Uint8List(0),
    info: _wrapInfo,
    length: 32,
  );

  final aes = AesGcm.with256bits();
  try {
    final plain = await aes.decrypt(
      SecretBox(cipherText, nonce: nonce, mac: Mac(tag)),
      secretKey: SecretKey(wrapKey),
    );
    return Uint8List.fromList(plain);
  } catch (e) {
    throw SkPqcError('dm epoch-secret unwrap failed: $e');
  }
}

Future<Uint8List> _hkdfSha256({
  required Uint8List ikm,
  required Uint8List salt,
  required Uint8List info,
  required int length,
}) async {
  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: length);
  final out = await hkdf.deriveKey(
    secretKey: SecretKey(ikm),
    nonce: salt, // `cryptography` names the HKDF salt `nonce`.
    info: info,
  );
  return Uint8List.fromList(await out.extractBytes());
}

/// In-memory ratchet state for one 1:1 conversation epoch (sender or receiver).
///
/// Mirrors `skchat.dm_ratchet.DmRatchet` / the Rust `should_rekey`. The
/// authoritative state is `(epoch, epochSecret)`; per-message keys are derived
/// on demand. The sender's [messageIndex] is its monotone counter for the
/// *next* message it will send; a receiver ignores its own counter and uses
/// each message's carried `(epoch, index)` (index-addressable).
class DmRatchet {
  int epoch;
  Uint8List epochSecret;
  int messageIndex;
  int rekeyMsgBound;
  int rekeyAgeSeconds;
  double epochStartedAt;

  DmRatchet({
    required this.epoch,
    required this.epochSecret,
    this.messageIndex = 0,
    this.rekeyMsgBound = kDefaultRekeyMsgBound,
    this.rekeyAgeSeconds = kDefaultRekeyAgeSeconds,
    double? epochStartedAt,
  }) : epochStartedAt =
            epochStartedAt ?? DateTime.now().millisecondsSinceEpoch / 1000.0;

  /// Derive the message key for [index] (default: the next outbound).
  Future<Uint8List> messageKey({int? index}) {
    final idx = index ?? messageIndex;
    return deriveDmMessageKey(epochSecret, epoch, idx);
  }

  /// Return `(index, key)` for the next message to send and advance the
  /// counter. The returned [index] MUST be placed on the wire so the peer
  /// derives the same key.
  Future<(int, Uint8List)> nextOutboundKey() async {
    final idx = messageIndex;
    final key = await deriveDmMessageKey(epochSecret, epoch, idx);
    messageIndex += 1;
    return (idx, key);
  }

  /// Whether the bound (message count OR age) says this epoch should re-key.
  bool shouldRekey({double? now}) {
    if (messageIndex >= rekeyMsgBound) {
      return true;
    }
    final t = now ?? DateTime.now().millisecondsSinceEpoch / 1000.0;
    return (t - epochStartedAt) >= rekeyAgeSeconds;
  }
}

@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:sk_pqc/sk_pqc.dart';
import 'package:sk_pqc/src/mlkem_provider_ffi.dart';
import 'package:test/test.dart';

Uint8List hex(String h) {
  final out = Uint8List(h.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(h.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String toHex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List rep(int byte, int n) => Uint8List(n)..fillRange(0, n, byte);

void main() {
  group('derive_dm_message_key — cross-impl KAT (matches Python + Rust)', () {
    // These vectors are computed by skchat.dm_ratchet.derive_dm_message_key
    // (Python, cryptography HKDF) and MUST match exactly — they are the
    // Dart↔Python↔Rust interop contract:
    //   salt = b"skchat/dm-epoch/"        || u64_be(epoch)
    //   info = b"skchat/dm-ratchet/msg/v1/" || u64_be(index)
    //   key  = HKDF-SHA256(IKM=epoch_secret, salt, info, L=32)
    final kats = <(Uint8List, int, int, String)>[
      (rep(0x01, 32), 0, 0,
          'a3b2c266a0cc4a92bc4dabd04dd0b5ece0f6e05f4374e9ef04f876b50a5786c4'),
      (rep(0x01, 32), 0, 1,
          'f0b2b91d0078aed7028c281467d65cf5401dc74ef3afd815733c9d4baa2af2f6'),
      (rep(0x02, 32), 3, 7,
          '4b10ee3ab620a8b5b4ae90c5008c466460e8e9b7ee0e7687e3497c142f339798'),
      (rep(0xab, 32), 5, 42,
          '5fd02f06f25ff6707e62c47efe4179e85b7463073326825489df64bb33903de6'),
    ];

    for (final (secret, epoch, index, want) in kats) {
      test('epoch=$epoch index=$index matches Python vector', () async {
        final k = await deriveDmMessageKey(secret, epoch, index);
        expect(k.length, 32);
        expect(toHex(k), want);
      });
    }
  });

  group('derive_dm_message_key — properties', () {
    test('deterministic + index-distinct (loss/reorder tolerant)', () async {
      final secret = rep(0x01, 32);
      final k0a = await deriveDmMessageKey(secret, 0, 0);
      final k0b = await deriveDmMessageKey(secret, 0, 0);
      final k1 = await deriveDmMessageKey(secret, 0, 1);
      expect(toHex(k0a), toHex(k0b));
      expect(toHex(k0a), isNot(toHex(k1)));
    });

    test('epoch separation: same index different epoch differs', () async {
      final secret = rep(0x07, 32);
      final a = await deriveDmMessageKey(secret, 0, 5);
      final b = await deriveDmMessageKey(secret, 1, 5);
      expect(toHex(a), isNot(toHex(b)));
    });

    test('rejects wrong-length epoch secret', () async {
      expect(() => deriveDmMessageKey(rep(0, 16), 0, 0),
          throwsA(isA<SkPqcError>()));
    });
  });

  group('DmRatchet state — outbound counter + rekey policy', () {
    test('nextOutboundKey advances index with distinct keys', () async {
      final r = DmRatchet(epoch: 0, epochSecret: rep(0x03, 32));
      final (i0, k0) = await r.nextOutboundKey();
      final (i1, k1) = await r.nextOutboundKey();
      expect((i0, i1), (0, 1));
      expect(r.messageIndex, 2);
      expect(toHex(k0), isNot(toHex(k1)));
      final direct = await deriveDmMessageKey(rep(0x03, 32), 0, 0);
      expect(toHex(k0), toHex(direct));
    });

    test('shouldRekey on message bound', () {
      final r = DmRatchet(
          epoch: 0, epochSecret: rep(0x04, 32), rekeyMsgBound: 3);
      expect(r.shouldRekey(), isFalse);
      r.messageIndex = 3;
      expect(r.shouldRekey(), isTrue);
    });

    test('shouldRekey on age', () {
      final r = DmRatchet(
        epoch: 0,
        epochSecret: rep(0x05, 32),
        rekeyAgeSeconds: 100,
        epochStartedAt: 1000.0,
      );
      expect(r.shouldRekey(now: 1050.0), isFalse);
      expect(r.shouldRekey(now: 1100.0), isTrue);
    });
  });

  // ---- Epoch-secret distribution over the hybrid KEM (needs liboqs) ----
  bool liboqsAvailable() {
    try {
      LiboqsMlKem768();
      return true;
    } catch (_) {
      return false;
    }
  }

  final haveOqs = liboqsAvailable();

  group('epoch-secret wrap/unwrap over hybrid KEM', () {
    test('round-trips through wrap → unwrap', () async {
      final kem = HybridKemImpl();
      final kp = await kem.generateKeyPair();
      final secret = newEpochSecret();
      expect(secret.length, 32);
      final payload = await wrapDmEpochSecret(secret, kp.publicKey, kem: kem);
      expect(payload.length, SkPqcSizes.hybridCiphertext + 12 + 48);
      final recovered =
          await unwrapDmEpochSecret(payload, kp.privateKey, kem: kem);
      expect(toHex(recovered), toHex(secret));
    }, skip: haveOqs ? false : 'liboqs not available');

    test('newEpochSecret gives independent secrets (PCS)', () {
      expect(toHex(newEpochSecret()), isNot(toHex(newEpochSecret())));
    });

    test('two-party path: both derive same msg key, rekey heals', () async {
      final kem = HybridKemImpl();
      final bob = await kem.generateKeyPair();
      final e0 = newEpochSecret();
      final bobE0 = await unwrapDmEpochSecret(
          await wrapDmEpochSecret(e0, bob.publicKey, kem: kem),
          bob.privateKey,
          kem: kem);
      expect(toHex(bobE0), toHex(e0));

      final aliceR = DmRatchet(epoch: 0, epochSecret: e0);
      final bobR = DmRatchet(epoch: 0, epochSecret: bobE0);
      final (idx, sendKey) = await aliceR.nextOutboundKey();
      final recvKey = await bobR.messageKey(index: idx);
      expect(toHex(sendKey), toHex(recvKey));

      final e1 = newEpochSecret();
      final newKey =
          await DmRatchet(epoch: 1, epochSecret: e1).messageKey(index: 0);
      expect(toHex(newKey), isNot(toHex(recvKey)));
    }, skip: haveOqs ? false : 'liboqs not available');

    test('tampered wrap payload fails authentication', () async {
      final kem = HybridKemImpl();
      final kp = await kem.generateKeyPair();
      final payload =
          await wrapDmEpochSecret(newEpochSecret(), kp.publicKey, kem: kem);
      final bad = Uint8List.fromList(payload);
      bad[bad.length - 1] ^= 0xff; // flip a tag byte
      expect(() => unwrapDmEpochSecret(bad, kp.privateKey, kem: kem),
          throwsA(isA<SkPqcError>()));
    }, skip: haveOqs ? false : 'liboqs not available');
  });
}

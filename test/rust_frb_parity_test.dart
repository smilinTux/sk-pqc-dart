@TestOn('vm')
@Tags(['frb'])
library;

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:sk_pqc/sk_pqc.dart';
import 'package:sk_pqc/rust_core.dart';
import 'package:test/test.dart';

/// PARITY — the `sk-pqc-rs` Rust core reached over **flutter_rust_bridge** must
/// agree, byte-for-byte, with the existing pure-Dart `sk_pqc` implementation.
///
/// This is the Dart twin of `sk-pqc-rs/tests/parity_python.py`:
///   1. `deriveDmMessageKey` is deterministic → assert *byte-for-byte equality*
///      between Rust-via-frb, pure-Dart, and the pinned cross-language KAT hex.
///   2. The hybrid KEM carries fresh randomness → prove interop by
///      *cross-decapsulation*: a ciphertext from one side decapsulates to the
///      identical 32-byte secret on the other, in BOTH directions (shared wire
///      format + identical HKDF combiner).
///
/// Requires the cdylib built with the `dart` feature. By default this test loads
/// `../sk-pqc-rs/target/<profile>/libsk_pqc.so`; override with env
/// `SK_PQC_RS_LIB=/abs/path/to/libsk_pqc.so`. The native liboqs ML-KEM leg used
/// by the pure-Dart side needs `LD_LIBRARY_PATH` / `SK_PQC_LIBOQS` set (same as
/// the other native tests). Skipped gracefully if the cdylib is absent.

String _toHex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List _rep(int byte, int n) => Uint8List(n)..fillRange(0, n, byte);

/// Does [path] dynamically open cleanly? A cdylib built with the WRONG cargo
/// feature (e.g. `python` → undefined `PyDict_Next`) fails to load, so this also
/// rejects a stale `target/release` build from a different binding.
bool _opensCleanly(String path) {
  try {
    DynamicLibrary.open(path);
    return true;
  } catch (_) {
    return false;
  }
}

/// Locate the compiled `sk-pqc-rs` cdylib built `--features dart`, or null if no
/// loadable candidate exists. Honest: a wrong-feature build is treated as absent
/// rather than failing the suite.
String? _findRustLib() {
  final env = Platform.environment['SK_PQC_RS_LIB'];
  if (env != null && env.isNotEmpty) {
    return (File(env).existsSync() && _opensCleanly(env)) ? env : null;
  }
  String libName() {
    if (Platform.isMacOS) return 'libsk_pqc.dylib';
    if (Platform.isWindows) return 'sk_pqc.dll';
    return 'libsk_pqc.so';
  }

  for (final profile in const ['release', 'debug']) {
    final p = '../sk-pqc-rs/target/$profile/${libName()}';
    if (File(p).existsSync() && _opensCleanly(p)) return p;
  }
  return null;
}

void main() {
  final libPath = _findRustLib();
  if (libPath == null) {
    // Honest skip: no overclaiming when the core isn't built.
    test('sk-pqc-rs cdylib not built — frb parity skipped', () {
      // Build it with: cd ../sk-pqc-rs && cargo build --features dart
    }, skip: 'Set SK_PQC_RS_LIB or run `cargo build --features dart` in '
        '../sk-pqc-rs (looked for target/{release,debug}/libsk_pqc.so).');
    return;
  }

  setUpAll(() async {
    await SkPqcRustCore.ensureInitialized(libraryPath: libPath);
  });

  group('frb core self-report', () {
    test('suite id matches the Dart kSuiteId', () {
      expect(SkPqcRustCore.suiteId, kSuiteId);
    });

    test('wire sizes match SkPqcSizes (public/private/ct/secret)', () {
      expect(SkPqcRustCore.wireSizes, [
        SkPqcSizes.hybridPublicKey,
        SkPqcSizes.hybridPrivateKey,
        SkPqcSizes.hybridCiphertext,
        SkPqcSizes.sharedSecret,
      ]);
    });
  });

  group('derive_dm_message_key — Rust-via-frb == pure-Dart == pinned KAT', () {
    // The SAME cross-language vectors asserted in test/dm_ratchet_test.dart and
    // sk-pqc-rs/tests/parity_python.py — the Dart↔Python↔Rust interop contract.
    final kats = <(Uint8List, int, int, String)>[
      (_rep(0x01, 32), 0, 0,
          'a3b2c266a0cc4a92bc4dabd04dd0b5ece0f6e05f4374e9ef04f876b50a5786c4'),
      (_rep(0x01, 32), 0, 1,
          'f0b2b91d0078aed7028c281467d65cf5401dc74ef3afd815733c9d4baa2af2f6'),
      (_rep(0x02, 32), 3, 7,
          '4b10ee3ab620a8b5b4ae90c5008c466460e8e9b7ee0e7687e3497c142f339798'),
      (_rep(0xab, 32), 5, 42,
          '5fd02f06f25ff6707e62c47efe4179e85b7463073326825489df64bb33903de6'),
    ];

    for (final (secret, epoch, index, want) in kats) {
      test('epoch=$epoch index=$index: rust == dart == KAT', () async {
        final rs = SkPqcRustCore.deriveDmMessageKey(secret, epoch, index);
        final dart = await deriveDmMessageKey(secret, epoch, index);
        expect(_toHex(rs), want, reason: 'rust-frb must match pinned KAT');
        expect(_toHex(rs), _toHex(dart), reason: 'rust-frb must match pure-Dart');
        expect(rs.length, 32);
      });
    }

    test('wrong-length epoch secret throws on the Rust binding', () {
      expect(() => SkPqcRustCore.deriveDmMessageKey(_rep(0, 16), 0, 0),
          throwsA(isA<SkPqcError>()));
    });
  });

  group('hybrid KEM cross-decapsulation (FIPS 203 ML-KEM-768 + X25519)', () {
    // Pure-Dart side uses the default backend — native liboqs ML-KEM (FFI).
    final dartKem = HybridKemImpl();

    test('Rust keypair lengths match the wire contract', () {
      final kp = SkPqcRustCore.generateKeyPair();
      expect(kp.publicKey.length, SkPqcSizes.hybridPublicKey);
      expect(kp.privateKey.length, SkPqcSizes.hybridPrivateKey);
    });

    test('Dart-encap -> Rust-decap recovers the same secret', () async {
      final kp = await dartKem.generateKeyPair();
      final enc = await dartKem.encapsulate(kp.publicKey);
      final ssRust = SkPqcRustCore.decapsulate(enc.ciphertext, kp.privateKey);
      expect(_toHex(ssRust), _toHex(enc.sharedSecret));
    });

    test('Rust-encap -> Dart-decap recovers the same secret', () async {
      final kp = SkPqcRustCore.generateKeyPair();
      final enc = SkPqcRustCore.encapsulate(kp.publicKey);
      final ssDart = await dartKem.decapsulate(enc.ciphertext, kp.privateKey);
      expect(_toHex(ssDart), _toHex(enc.sharedSecret));
    });

    test('Dart keypair + Rust encap -> Dart decap (combiner symmetry)',
        () async {
      final kp = await dartKem.generateKeyPair();
      final enc = SkPqcRustCore.encapsulate(kp.publicKey);
      final ssDart = await dartKem.decapsulate(enc.ciphertext, kp.privateKey);
      expect(_toHex(ssDart), _toHex(enc.sharedSecret));
    });

    test('Rust keypair + Dart encap -> Rust decap (combiner symmetry)',
        () async {
      final kp = SkPqcRustCore.generateKeyPair();
      final enc = await dartKem.encapsulate(kp.publicKey);
      final ssRust = SkPqcRustCore.decapsulate(enc.ciphertext, kp.privateKey);
      expect(_toHex(ssRust), _toHex(enc.sharedSecret));
    });

    test('wrong-length public key throws on the Rust binding', () {
      expect(() => SkPqcRustCore.encapsulate(_rep(0, 10)),
          throwsA(isA<SkPqcError>()));
    });
  });
}

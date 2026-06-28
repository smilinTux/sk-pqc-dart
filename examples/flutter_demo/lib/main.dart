// Minimal Flutter demo proving the sk_pqc mobile story.
//
// One button runs a hybrid X25519 + ML-KEM-768 (FIPS 203) KEM round-trip —
// keygen -> encapsulate -> decapsulate — through the sk-pqc-rs pure-Rust core
// over flutter_rust_bridge, then shows that the sender and recipient derived the
// SAME 32-byte shared secret.
//
// Honest claim: this is a HYBRID KEM. The shared secret holds as long as EITHER
// the classical X25519 leg OR the post-quantum ML-KEM-768 leg remains unbroken.
// It is NOT "quantum-proof", and it is KEM-only (no signatures).
//
// Library loading:
//   * Android: the cross-compiled libsk_pqc.so is bundled in jniLibs and found
//     by the generated default loader (stem "sk_pqc").
//   * Desktop / `flutter test`: set SK_PQC_RS_LIB to an absolute path to the
//     host-built libsk_pqc.so (cargo build --release --features dart).
import "dart:io";
import "dart:typed_data";

import "package:flutter/material.dart";
import "package:sk_pqc/rust_core.dart";

void main() {
  runApp(const SkPqcDemoApp());
}

String hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, "0")).join();

/// Result of one hybrid KEM round-trip, surfaced to the UI.
class RoundTrip {
  RoundTrip({
    required this.suite,
    required this.pubLen,
    required this.privLen,
    required this.ctLen,
    required this.senderSecret,
    required this.recipientSecret,
  });

  final String suite;
  final int pubLen;
  final int privLen;
  final int ctLen;
  final Uint8List senderSecret;
  final Uint8List recipientSecret;

  bool get match => hex(senderSecret) == hex(recipientSecret);
}

/// Run keygen -> encap -> decap via the frb Rust core. Optionally load an
/// explicit cdylib (desktop/test); on mobile the bundled lib is auto-found.
Future<RoundTrip> runHybridRoundTrip() async {
  final libPath = Platform.environment["SK_PQC_RS_LIB"];
  await SkPqcRustCore.ensureInitialized(
    libraryPath: (libPath != null && libPath.isNotEmpty) ? libPath : null,
  );

  // Recipient generates a long-term hybrid keypair.
  final kp = SkPqcRustCore.generateKeyPair();
  // Sender encapsulates to the recipient public key.
  final enc = SkPqcRustCore.encapsulate(kp.publicKey);
  // Recipient decapsulates and recovers the shared secret.
  final recovered = SkPqcRustCore.decapsulate(enc.ciphertext, kp.privateKey);

  return RoundTrip(
    suite: SkPqcRustCore.suiteId,
    pubLen: kp.publicKey.length,
    privLen: kp.privateKey.length,
    ctLen: enc.ciphertext.length,
    senderSecret: enc.sharedSecret,
    recipientSecret: recovered,
  );
}

class SkPqcDemoApp extends StatelessWidget {
  const SkPqcDemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: "sk_pqc hybrid KEM demo",
      theme: ThemeData(
        colorSchemeSeed: Colors.indigo,
        useMaterial3: true,
      ),
      home: const DemoPage(),
    );
  }
}

class DemoPage extends StatefulWidget {
  const DemoPage({super.key});

  @override
  State<DemoPage> createState() => _DemoPageState();
}

class _DemoPageState extends State<DemoPage> {
  RoundTrip? _result;
  String? _error;
  bool _running = false;

  Future<void> _run() async {
    setState(() {
      _running = true;
      _error = null;
      _result = null;
    });
    try {
      final r = await runHybridRoundTrip();
      setState(() => _result = r);
    } catch (e) {
      setState(() => _error = "$e");
    } finally {
      setState(() => _running = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final r = _result;
    return Scaffold(
      appBar: AppBar(title: const Text("sk_pqc hybrid KEM")),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: ListView(
          children: [
            const Text(
              "Hybrid X25519 + ML-KEM-768 (FIPS 203), KEM-only.\n"
              "Secure if EITHER leg holds — not \"quantum-proof\".",
              style: TextStyle(fontSize: 13),
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              key: const Key("run-button"),
              onPressed: _running ? null : _run,
              icon: const Icon(Icons.lock),
              label: Text(_running ? "Running..." : "Run PQ round-trip"),
            ),
            const SizedBox(height: 16),
            if (_error != null)
              Text(
                "ERROR: $_error",
                key: const Key("error-text"),
                style: const TextStyle(color: Colors.red),
              ),
            if (r != null) ...[
              Text("suite: ${r.suite}", key: const Key("suite-text")),
              Text("public key: ${r.pubLen} B   "
                  "private key: ${r.privLen} B   "
                  "ciphertext: ${r.ctLen} B"),
              const SizedBox(height: 8),
              const Text("sender shared secret:"),
              SelectableText(hex(r.senderSecret),
                  style: const TextStyle(fontFamily: "monospace")),
              const SizedBox(height: 8),
              const Text("recipient shared secret:"),
              SelectableText(hex(r.recipientSecret),
                  style: const TextStyle(fontFamily: "monospace")),
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.all(12),
                color: r.match ? Colors.green.shade100 : Colors.red.shade100,
                child: Text(
                  r.match
                      ? "SHARED SECRETS MATCH"
                      : "MISMATCH — secrets differ",
                  key: const Key("match-text"),
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    color: r.match
                        ? Colors.green.shade900
                        : Colors.red.shade900,
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

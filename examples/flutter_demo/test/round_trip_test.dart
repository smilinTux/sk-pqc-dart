// Headless proof of the demo: tap the button, assert the hybrid X25519+ML-KEM-768
// round-trip ran through the frb Rust core and the two shared secrets MATCH.
//
// Requires the host cdylib built with --features dart. Point the loader at it:
//   SK_PQC_RS_LIB=/abs/path/to/libsk_pqc.so flutter test
import "package:flutter/material.dart";
import "package:flutter_test/flutter_test.dart";
import "package:sk_pqc_demo/main.dart";

void main() {
  testWidgets("button runs hybrid KEM round-trip and secrets match",
      (tester) async {
    await tester.pumpWidget(const SkPqcDemoApp());

    expect(find.byKey(const Key("run-button")), findsOneWidget);
    expect(find.byKey(const Key("match-text")), findsNothing);

    await tester.tap(find.byKey(const Key("run-button")));
    await tester.pumpAndSettle();

    expect(find.byKey(const Key("error-text")), findsNothing);
    expect(find.text("suite: x25519-mlkem768"), findsOneWidget);

    final match = find.byKey(const Key("match-text"));
    expect(match, findsOneWidget);
    expect(tester.widget<Text>(match).data, "SHARED SECRETS MATCH");
  });
}

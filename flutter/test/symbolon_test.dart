// Runs against the native library: `cargo build --release --manifest-path rust/Cargo.toml` first.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:symbolon_flutter/symbolon_flutter.dart';

String _hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

final _library =
    'rust/target/release/${Platform.isWindows ? '' : 'lib'}symbolon_flutter.'
    '${Platform.isMacOS
        ? 'dylib'
        : Platform.isWindows
        ? 'dll'
        : 'so'}';

void main() {
  setUpAll(() => loadSymbolon(nativeLibrary: _library));

  final context = utf8.encode('test/v1');
  final secret = List.generate(32, (i) => i);

  test('derives the same keys as the Rust crate and the JavaScript binding', () {
    final keys = symbolon.groupKeys(context, secret);
    expect(_hex(keys.fingerprint()), 'f7fa2518636b');
    expect(
      _hex(keys.topic(utf8.encode('signal'))),
      '0aaf3dd06e80e9403c61c9b61d88868c0ce8e73352cad44508bcbda3cb99ddcb',
    );
    expect(() => symbolon.groupKeys(context, List.filled(16, 0)), throwsA(anything));
  });

  test('sealed messages open only with the same key and context', () {
    final keys = symbolon.groupKeys(context, secret);
    final sealed = keys.seal(utf8.encode('hello'), utf8.encode('offer'));
    expect(utf8.decode(keys.open(sealed, utf8.encode('offer'))), 'hello');
    expect(() => keys.open(sealed, utf8.encode('answer')), throwsA(anything));
    expect(
      () => symbolon.groupKeys(utf8.encode('other/v1'), secret).open(sealed, utf8.encode('offer')),
      throwsA(anything),
    );
  });

  (SymbolonChannel, SymbolonChannel) connect(
    SymbolonDeviceKey a,
    SymbolonDeviceKey b,
    SymbolonGroupKeys keysA,
    SymbolonGroupKeys keysB,
  ) {
    final prologue = utf8.encode('test');
    final initiator = symbolon.initiator(a, b.publicKey, keysA, prologue);
    final responder = symbolon.responder(b, keysB, prologue);
    responder.readMessage(initiator.writeMessage([]));
    expect(responder.remoteStatic, a.publicKey);
    initiator.readMessage(responder.writeMessage([]));
    expect(initiator.isFinished && responder.isFinished, isTrue);
    return (initiator.intoChannel(), responder.intoChannel());
  }

  test('two devices of one group get a working channel', () {
    final keys = symbolon.groupKeys(context, secret);
    final a = symbolon.generateDeviceKey();
    final b = symbolon.deviceKeyFromPrivate(symbolon.generateDeviceKey().privateKey());
    expect(
      symbolon.initiates(a.publicKey, b.publicKey),
      isNot(symbolon.initiates(b.publicKey, a.publicKey)),
    );
    final (ca, cb) = connect(a, b, keys, keys);
    expect(cb.decrypt(ca.encrypt(utf8.encode('hi'))), utf8.encode('hi'));
    expect(symbolon.maxPlaintext, greaterThan(60000));
    expect(() => ca.decrypt([1, 2, 3]), throwsA(anything));
    expect(ca.isOpen, isFalse);
  });

  test('a device from another group is rejected', () {
    expect(
      () => connect(
        symbolon.generateDeviceKey(),
        symbolon.generateDeviceKey(),
        symbolon.groupKeys(context, secret),
        symbolon.groupKeys(context, List.filled(32, 7)),
      ),
      throwsA(anything),
    );
  });

  test('device keys load from the RFC 7748 private key', () {
    List<int> h(String s) => [
      for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16),
    ];
    final key = symbolon.deviceKeyFromPrivate(
      h('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'),
    );
    expect(_hex(key.publicKey), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
  });

  test('signalling messages and Nostr events', () {
    final box = symbolon.signalBox(symbolon.groupKeys(context, secret));
    // SignalBox uses the label "signal", so its topic matches the known value above.
    expect(_hex(box.topic), '0aaf3dd06e80e9403c61c9b61d88868c0ce8e73352cad44508bcbda3cb99ddcb');

    const now = 1800000000;
    final me = symbolon.newSession();
    final you = symbolon.newSession();
    final device = symbolon.generateDeviceKey().publicKey;
    final content = box.seal(
      SymbolonSignal(
        kind: SignalKind.offer,
        createdAt: now,
        from: me,
        to: you,
        device: device,
        body: utf8.encode('v=0'),
      ),
    );
    final opened = box.open(content, now + 1);
    expect(opened.kind, SignalKind.offer);
    expect(opened.createdAt, now);
    expect(
      [opened.from, opened.to, opened.device, opened.body],
      [me, you, device, utf8.encode('v=0')],
    );
    expect(() => box.open(content, now + 3600), throwsA(anything));
    expect(
      () => symbolon
          .signalBox(symbolon.groupKeys(utf8.encode('other/v1'), secret))
          .open(content, now),
      throwsA(anything),
    );
    final announce = box.open(
      box.seal(SymbolonSignal(kind: SignalKind.announce, createdAt: now, from: me, device: device)),
      now,
    );
    expect(announce.to, List.filled(16, 0));
    expect(
      () => box.seal(
        SymbolonSignal(kind: SignalKind.offer, createdAt: now, from: me, device: device, body: [1]),
      ),
      throwsA(anything),
    );

    final signer = symbolon.eventSigner();
    final event = jsonDecode(signer.signalEvent(now, box.topic, content)) as Map<String, dynamic>;
    expect(event['pubkey'], signer.publicKey);
    expect(event['content'], content);
    expect(event['tags'][0], ['t', _hex(box.topic)]);
    expect(symbolon.eventSigner().publicKey, isNot(signer.publicKey));
    expect(jsonDecode(symbolon.signalFilter(box.topic, now)), {
      'kinds': [21059],
      '#t': [_hex(box.topic)],
      'since': now,
    });
  });
}

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

import '../symbolon_flutter.dart';
import 'rust/api/symbolon.dart' as rust;
import 'rust/frb_generated.dart';

Future<Symbolon> load({required String webModule, String? nativeLibrary}) async {
  await RustLib.init(
    externalLibrary: nativeLibrary == null ? null : ExternalLibrary.open(nativeLibrary),
  );
  return _Native();
}

class _Native implements Symbolon {
  @override
  SymbolonGroupKeys groupKeys(List<int> context, List<int> secret) =>
      _GroupKeys(rust.GroupKeys(context: context, secret: secret));

  @override
  SymbolonDeviceKey generateDeviceKey() => _DeviceKey(rust.DeviceKey.generate());

  @override
  SymbolonDeviceKey deviceKeyFromPrivate(List<int> privateKey) =>
      _DeviceKey(rust.DeviceKey.fromPrivate(privateKey: privateKey));

  @override
  bool initiates(List<int> localPublic, List<int> remotePublic) =>
      rust.initiates(localPublic: localPublic, remotePublic: remotePublic);

  @override
  SymbolonHandshake initiator(
    SymbolonDeviceKey device,
    List<int> remotePublic,
    SymbolonGroupKeys group,
    List<int> prologue,
  ) => _Handshake(
    rust.NoiseHandshake.initiator(
      device: (device as _DeviceKey).inner,
      remotePublic: remotePublic,
      group: (group as _GroupKeys).inner,
      prologue: prologue,
    ),
  );

  @override
  SymbolonHandshake responder(
    SymbolonDeviceKey device,
    SymbolonGroupKeys group,
    List<int> prologue,
  ) => _Handshake(
    rust.NoiseHandshake.responder(
      device: (device as _DeviceKey).inner,
      group: (group as _GroupKeys).inner,
      prologue: prologue,
    ),
  );

  @override
  int get maxPlaintext => rust.SecureChannel.maxPlaintext().toInt();

  @override
  Uint8List newSession() => rust.newSession();

  @override
  SymbolonSignalBox signalBox(SymbolonGroupKeys group) =>
      _SignalBox(rust.SignalBox(group: (group as _GroupKeys).inner));

  @override
  SymbolonEventSigner eventSigner() => _EventSigner(rust.EventSigner.generate());

  @override
  String signalFilter(List<int> topic, int since) => rust.signalFilter(topic: topic, since: since);
}

class _SignalBox implements SymbolonSignalBox {
  final rust.SignalBox inner;
  @override
  final Uint8List topic;

  _SignalBox(this.inner) : topic = inner.topic();

  @override
  String seal(SymbolonSignal signal) => inner.seal(
    message: rust.SignalMessage(
      kind: signal.kind.name,
      createdAt: signal.createdAt,
      from: signal.from,
      to: signal.to,
      device: signal.device,
      body: signal.body,
    ),
  );

  @override
  SymbolonSignal open(String content, int now) {
    final m = inner.open(content: content, now: now);
    return SymbolonSignal(
      kind: SignalKind.values.byName(m.kind),
      createdAt: m.createdAt,
      from: m.from,
      to: m.to,
      device: m.device,
      body: m.body,
    );
  }
}

class _EventSigner implements SymbolonEventSigner {
  final rust.EventSigner inner;
  @override
  final String publicKey;

  _EventSigner(this.inner) : publicKey = inner.publicKey();

  @override
  String signalEvent(int createdAt, List<int> topic, String content) =>
      inner.signalEvent(createdAt: createdAt, topic: topic, content: content);
}

class _GroupKeys implements SymbolonGroupKeys {
  final rust.GroupKeys inner;

  _GroupKeys(this.inner);

  @override
  Uint8List fingerprint() => inner.fingerprint();

  @override
  Uint8List topic(List<int> label) => inner.topic(label: label);

  @override
  Uint8List seal(List<int> plaintext, List<int> aad) => inner.seal(plaintext: plaintext, aad: aad);

  @override
  Uint8List open(List<int> sealed, List<int> aad) => inner.open(sealed: sealed, aad: aad);
}

class _DeviceKey implements SymbolonDeviceKey {
  final rust.DeviceKey inner;
  @override
  final Uint8List publicKey;

  _DeviceKey(this.inner) : publicKey = inner.publicKey();

  @override
  Uint8List privateKey() => inner.privateKey();
}

class _Handshake implements SymbolonHandshake {
  final rust.NoiseHandshake inner;

  _Handshake(this.inner);

  @override
  Uint8List writeMessage(List<int> payload) => inner.writeMessage(payload: payload);

  @override
  Uint8List readMessage(List<int> message) => inner.readMessage(message: message);

  @override
  bool get isFinished => inner.isFinished();

  @override
  Uint8List? get remoteStatic => inner.remoteStatic();

  @override
  SymbolonChannel intoChannel() => _Channel(inner.intoChannel());
}

class _Channel implements SymbolonChannel {
  final rust.SecureChannel inner;

  _Channel(this.inner);

  @override
  Uint8List encrypt(List<int> plaintext) => inner.encrypt(plaintext: plaintext);

  @override
  Uint8List decrypt(List<int> ciphertext) => inner.decrypt(ciphertext: ciphertext);

  @override
  bool get isOpen => inner.isOpen();
}

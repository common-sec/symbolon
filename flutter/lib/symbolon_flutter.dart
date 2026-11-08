library;

import 'dart:typed_data';

import 'src/native.dart' if (dart.library.js_interop) 'src/web.dart' as backend;

/// Symbolon (github.com/common-sec/symbolon) for Dart and Flutter. Desktop and phone builds call its
/// Rust code through flutter_rust_bridge; web builds call its JavaScript binding. Both run the same
/// Rust code, so devices agree whatever they run on.
abstract class Symbolon {
  /// Every key of a group. `context` names the app and protocol version.
  SymbolonGroupKeys groupKeys(List<int> context, List<int> secret);

  SymbolonDeviceKey generateDeviceKey();

  SymbolonDeviceKey deviceKeyFromPrivate(List<int> privateKey);

  /// Whether the device with `localPublic` starts the handshake.
  bool initiates(List<int> localPublic, List<int> remotePublic);

  SymbolonHandshake initiator(
    SymbolonDeviceKey device,
    List<int> remotePublic,
    SymbolonGroupKeys group,
    List<int> prologue,
  );

  SymbolonHandshake responder(
    SymbolonDeviceKey device,
    SymbolonGroupKeys group,
    List<int> prologue,
  );

  /// The largest plaintext one channel message can carry.
  int get maxPlaintext;

  /// A random session id for this run of the app (16 bytes, not secret).
  Uint8List newSession();

  /// Seals and opens `group`'s signalling messages.
  SymbolonSignalBox signalBox(SymbolonGroupKeys group);

  /// A new throwaway key for signing Nostr events. Make one per app run and don't store it.
  SymbolonEventSigner eventSigner();

  /// The relay filter for `topic`'s signalling events from `since` (Unix seconds) on, to send as
  /// `["REQ", subscriptionId, filter]`.
  String signalFilter(List<int> topic, int since);
}

enum SignalKind {
  /// "I'm online", to everyone.
  announce,

  /// A connection offer, such as a WebRTC SDP offer.
  offer,

  /// The answer to an offer.
  answer,

  /// A further connection candidate, such as a WebRTC ICE candidate.
  candidate,

  /// "I'm going offline", to everyone.
  bye,
}

/// A signalling message. Announce and bye go to everyone: `to` is all zeros and `body` is empty.
class SymbolonSignal {
  final SignalKind kind;

  /// Unix seconds when it was made.
  final int createdAt;

  /// The sender's session id.
  final Uint8List from;

  /// The receiver's session id, or all zeros for everyone.
  final Uint8List to;

  /// The sender's claimed device public key; only the handshake proves it.
  final Uint8List device;
  final Uint8List body;

  /// Leave out `to` for announce and bye, which go to everyone.
  SymbolonSignal({
    required this.kind,
    required this.createdAt,
    required List<int> from,
    List<int>? to,
    required List<int> device,
    List<int> body = const [],
  }) : from = Uint8List.fromList(from),
       to = Uint8List.fromList(to ?? List.filled(16, 0)),
       device = Uint8List.fromList(device),
       body = Uint8List.fromList(body);
}

/// Seals a group's signalling messages into Nostr event content, and opens them.
abstract class SymbolonSignalBox {
  /// The topic every device in the group posts and subscribes under.
  Uint8List get topic;

  String seal(SymbolonSignal signal);

  /// `now` is this device's Unix time in seconds; messages too far from it, from another group, or
  /// malformed throw.
  SymbolonSignal open(String content, int now);
}

/// Signs Nostr events with a throwaway key.
abstract class SymbolonEventSigner {
  /// The public key as hex, as relays show it.
  String get publicKey;

  /// A signed signalling event as JSON, to send as `["EVENT", event]`.
  String signalEvent(int createdAt, List<int> topic, String content);
}

abstract class SymbolonGroupKeys {
  Uint8List fingerprint();
  Uint8List topic(List<int> label);
  Uint8List seal(List<int> plaintext, List<int> aad);
  Uint8List open(List<int> sealed, List<int> aad);
}

abstract class SymbolonDeviceKey {
  Uint8List get publicKey;

  /// Only for storing the key on this device.
  Uint8List privateKey();
}

/// The Noise IKpsk1 handshake. Any error ends it.
abstract class SymbolonHandshake {
  Uint8List writeMessage(List<int> payload);
  Uint8List readMessage(List<int> message);
  bool get isFinished;

  /// The other device's public key, once its first message has been read.
  Uint8List? get remoteStatic;

  /// Ends the handshake; it can't be used afterwards.
  SymbolonChannel intoChannel();
}

/// Encrypted messages after the handshake. Any rejected message closes it.
abstract class SymbolonChannel {
  Uint8List encrypt(List<int> plaintext);
  Uint8List decrypt(List<int> ciphertext);
  bool get isOpen;
}

Future<Symbolon>? _loading;
Symbolon? _loaded;

/// Loads Symbolon once. Safe to call from anywhere that needs it.
///
/// On the web, `webModule` is where the app serves the JavaScript binding (see the README), relative
/// to the page. `nativeLibrary` overrides where the native library is loaded from, for tests that
/// run outside a Flutter app.
Future<Symbolon> loadSymbolon({
  String webModule = './symbolon/symbolon_wasm.js',
  String? nativeLibrary,
}) => _loading ??= backend
    .load(webModule: webModule, nativeLibrary: nativeLibrary)
    .then((s) => _loaded = s);

/// Symbolon after [loadSymbolon] has finished.
Symbolon get symbolon =>
    _loaded ?? (throw StateError('Call loadSymbolon() before using Symbolon.'));

# symbolon_flutter

Symbolon for Dart and Flutter. One Dart API with two backends that run the same Rust code:

- **Android, iOS, macOS, Linux and Windows:** the native library in `rust/`, called through
  [flutter_rust_bridge](https://github.com/fzyzcjy/flutter_rust_bridge) and built by cargokit when the
  app builds.
- **Web:** the JavaScript binding in `../wasm`, loaded with `dart:js_interop`. It runs on one thread,
  so the page needs no COOP/COEP headers.

## Using it

Depend on it by git, pinned to a commit:

```yaml
dependencies:
  symbolon_flutter:
    git:
      url: https://github.com/common-sec/symbolon
      path: flutter
      ref: <commit>
```

Building for a phone or desktop needs Rust (`rustup`); cargokit installs the targets it needs.

```dart
import 'package:symbolon_flutter/symbolon_flutter.dart';

await loadSymbolon();
final keys = symbolon.groupKeys(utf8.encode('my-app/v1'), groupSecret);
final me = symbolon.deviceKeyFromPrivate(storedDeviceKey);
final hs = symbolon.initiates(me.publicKey, peerPublic)
    ? symbolon.initiator(me, peerPublic, keys, prologue)
    : symbolon.responder(me, keys, prologue);
// ...exchange hs.writeMessage() / hs.readMessage(), then:
final channel = hs.intoChannel();
```

Every call is synchronous and throws on any failure. See the main README for what each object does.

### Web apps

Serve the JavaScript binding with the app. Before `flutter build web`, run this package's tool from
wherever pub put it, so the binding comes from the same commit as the Dart code:

```sh
flutter pub get
pkg=$(python3 -c 'import json, os, urllib.parse as u
c = json.load(open(".dart_tool/package_config.json"))
p = next(p for p in c["packages"] if p["name"] == "symbolon_flutter")
print(os.path.normpath(os.path.join(".dart_tool", u.unquote(u.urlparse(p["rootUri"]).path))))')
"$pkg/tool/build_web.sh" web/symbolon
```

`loadSymbolon()` loads `./symbolon/symbolon_wasm.js` by default; pass `webModule` to use another path.

## Develop

```sh
cargo build --release --manifest-path rust/Cargo.toml
flutter test
```

After changing `rust/src/api/`, regenerate the Dart side with `flutter_rust_bridge_codegen generate`
(version 2.13.0, the same as in `pubspec.yaml` and `rust/Cargo.toml`).

# symbolon_flutter

Symbolon for Dart and Flutter. One Dart API with two backends that run the same Rust code:

- **Android, iOS, macOS, Linux and Windows:** the native library in `rust/`, called through
  [flutter_rust_bridge](https://github.com/fzyzcjy/flutter_rust_bridge) and built by cargokit when the
  app builds.
- **Web:** the JavaScript binding in `../wasm`, loaded with `dart:js_interop`. It runs on one thread,
  so the page needs no COOP/COEP headers.

## Using it

Depend on it by git, pinned to a release tag (or a commit):

```yaml
dependencies:
  symbolon_flutter:
    git:
      url: https://github.com/common-sec/symbolon
      path: flutter
      ref: v0.1.0
```

The dependency brings two things, and only one of them is ever compiled by the app:

- **The Dart code** (the API, the generated bridge and cargokit's build scripts). Pub always uses Dart
  packages as source; there is nothing to prebuild.
- **The native library**, which is not compiled. When the app builds, cargokit downloads the prebuilt
  library for each target from Symbolon's releases and checks its signature against the public key in
  `rust/cargokit.yaml`. The download is chosen by a hash of `rust/` at the pinned commit, so it always
  matches the Dart code next to it. Only if a library is missing or fails the check does cargokit
  build it from source, which needs Rust (`rustup`).

```dart
import 'package:symbolon_flutter/symbolon_flutter.dart';

// Names your app and protocol version. Keys from different contexts never match, so keep it fixed.
const appContext = 'my-app/v1';

await loadSymbolon();
final keys = symbolon.groupKeys(utf8.encode(appContext), groupSecret);
final me = symbolon.deviceKeyFromPrivate(storedDeviceKey);
final hs = symbolon.initiates(me.publicKey, peerPublic)
    ? symbolon.initiator(me, peerPublic, keys, prologue)
    : symbolon.responder(me, keys, prologue);
// ...exchange hs.writeMessage() / hs.readMessage(), then:
final channel = hs.intoChannel();
```

Every call is synchronous and throws on any failure. See the main README for what each object does.

### Web apps

Serve the JavaScript binding with the app. Each version tag's release has it as
`symbolon-web-<tag>.tar.gz`, with its SHA-256 in a `.sha256` file. Download the release for the tag
your app depends on, check it against a hash stored in your repository, and unpack it into `web/`:

```sh
curl -fsSLO https://github.com/common-sec/symbolon/releases/download/v0.1.0/symbolon-web-v0.1.0.tar.gz
echo "<sha256>  symbolon-web-v0.1.0.tar.gz" | sha256sum -c
tar -xzf symbolon-web-v0.1.0.tar.gz -C web    # creates web/symbolon/
```

To build it from source instead, run `tool/build_web.sh web/symbolon` from wherever pub put this
package.

`loadSymbolon()` loads `./symbolon/symbolon_wasm.js` by default; pass `webModule` to use another path.

## Develop

```sh
cargo build --release --manifest-path rust/Cargo.toml
flutter test
```

After changing the core crate's `src/`, run `../tool/core_hash.sh --write` (CI checks it). After
changing `rust/src/api/`, regenerate the Dart side with `flutter_rust_bridge_codegen generate`
(version 2.13.0, the same as in `pubspec.yaml` and `rust/Cargo.toml`).

## Releases

- **Prebuilt libraries:** every push to `main` builds the native library for Android, iOS, macOS,
  Linux and Windows, signs each file, and uploads it to a release named `precompiled_<hash>`, where the
  hash covers `rust/` (including `src/core_hash.rs`, which follows the core crate). The signing key is
  the secret `CARGOKIT_PRIVATE_KEY` of the `release` environment, which only `main` can use. It is made
  once with `../tool/new_signing_key.sh` and is only needed to publish, never to build.
- **Web binding:** every `v*` tag attaches `symbolon-web-<tag>.tar.gz` and its SHA-256 to that tag's
  release.

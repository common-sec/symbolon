# Symbolon

In ancient Greece a *symbolon* was a token broken in two: each side kept a half, and whoever later
fitted the halves together proved who they were. This library does the same for devices: one shared
secret, and a handshake that proves each side holds it.

A small, sans-IO secure channel for local-first apps that connect their users' devices directly.
It is shared by [CommonSec Share](https://github.com/common-sec/secure-share) (browser, through
WebAssembly) and [bringmeback](https://github.com/gum0x/bringmeback) (Flutter, through
flutter_rust_bridge), and meant to be reusable by other privacy-focused apps.

**Status: 0.x, not reviewed.** Don't rely on it until the external review planned before
secure-share 1.0.

## What it does

| Module | Purpose |
| --- | --- |
| `keys` | One shared secret (a pairing code, or a link secret mixed with a passphrase) gives every key through HKDF-SHA256, bound to an app context and a purpose: signalling password, seal key, relay topic key, Noise PSK, fingerprint. |
| `seal` | XChaCha20-Poly1305 for the few messages sent before a channel exists, such as WebRTC offers and answers on a public relay. |
| `handshake` | `Noise_IKpsk1_25519_ChaChaPoly_SHA256` on [snow](https://github.com/mcginty/snow). Mutual authentication, forward secrecy, and a responder that rejects anyone without the secret before answering. |
| `channel` | The transport after the handshake, with size limits and rekeying. Needs an ordered, reliable transport; any lost, reordered, replayed or altered message closes it. |

## What it doesn't do

No sockets, no WebRTC and no relay client. Each app moves the bytes over its own transport and feeds
received bytes back in. Keeping I/O out keeps the security-critical code small, testable and the same
on every platform. Everything decrypted from a peer is still untrusted input for the app to validate.

## Design notes

- **Why IKpsk1:** with psk2 (WireGuard's choice) the responder answers before checking the PSK, which
  lets anyone with a link test passphrase guesses offline. See secure-share PR #27.
- **Why ChaChaPoly:** WebAssembly has no AES instructions; ChaCha20 was about 5× faster there.
- **Who initiates:** when both devices know each other's static key, the lower public key initiates
  (`handshake::initiates`).
- **Not post-quantum.** Recorded traffic is not safe from a future quantum computer. Open question.
- **snow is not audited**, though widely used. The tests replay the independent cacophony vectors.

## Develop

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release --target wasm32-unknown-unknown   # needs .cargo/config.toml (getrandom backend)
```

## License

Not chosen yet.

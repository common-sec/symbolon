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

## Choosing the secret

`KeySchedule::new(context, secret)` does not stretch its input, so `secret` must already be hard to guess:
at least 32 bytes that are uniformly random, or the output of a password hash. `context` names the app,
the protocol version and, where there are rooms, the room, so the same secret never gives the same keys
in two places.

| App | `context` | `secret` |
| --- | --- | --- |
| bringmeback | `b"bringmeback/v1"` | the 32-byte group secret from the pairing code |
| secure-share | `b"secure-share/v3/<room id>"` | link secret (32 bytes) followed by PBKDF2-SHA256(passphrase, 600k iterations), 64 bytes |

A passphrase alone must never be passed as `secret`: hash it first, as secure-share does.

## Using it

```rust
use symbolon::{handshake::{initiates, Handshake, StaticKeypair}, keys::{KeySchedule, Purpose}, seal::Sealer};

let keys = KeySchedule::new(b"bringmeback/v1", &group_secret)?;
let topic = keys.topic(b"signal");              // where to meet on the relay
let sealer = Sealer::new(&keys);                // seal / open offers and answers
let me = StaticKeypair::from_private(&stored_device_key)?;
let psk = keys.derive(Purpose::NoisePsk);
let prologue = [b"bringmeback/v1|".as_slice(), &topic].concat();

// Once a data channel is open, the device with the lower public key starts:
let mut hs = if initiates(me.public(), &peer_public) {
    Handshake::initiator(&me, &peer_public, &psk, &prologue)?
} else {
    Handshake::responder(&me, &psk, &prologue)?
};
// initiator: send hs.write_message(b"")?, then hs.read_message(&reply)?
// responder: hs.read_message(&first)?, check hs.remote_static() is a known device, send hs.write_message(b"")?
let mut channel = hs.into_channel()?;
let wire = channel.encrypt(b"changes")?;        // send; the peer calls channel.decrypt(&wire)?
```

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

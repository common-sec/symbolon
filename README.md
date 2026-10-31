# Symbolon

In ancient Greece a *symbolon* was a token broken in two: each side kept a half, and whoever later
fitted the halves together proved who they were. This library does the same for devices: one shared
secret, and a handshake that proves each side holds it.

A small, sans-IO secure channel for local-first apps that connect their users' devices directly.
It is written in Rust and built for native platforms, Flutter (through flutter_rust_bridge) and the
browser (through WebAssembly).

**Status: 0.x, not reviewed.** Don't rely on it until it has had an external security review.

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

| Your app shares | `context` | `secret` |
| --- | --- | --- |
| A random secret, e.g. from a QR pairing code | `b"my-app/v1"` | the 32 random bytes |
| A link secret plus a passphrase | `b"my-app/v1/<room id>"` | the link secret (32 bytes) followed by a password hash of the passphrase (PBKDF2-SHA256 with at least 600k iterations, or Argon2id), salted with the room id |

A passphrase alone must never be passed as `secret`: hash it first.

## Using it

```rust
use symbolon::{handshake::{initiates, Handshake, StaticKeypair}, keys::{KeySchedule, Purpose}, seal::Sealer};

let keys = KeySchedule::new(b"my-app/v1", &group_secret)?;
let topic = keys.topic(b"signal");              // where to meet on the relay
let sealer = Sealer::new(&keys);                // seal / open offers and answers
let me = StaticKeypair::from_private(&stored_device_key)?;
let psk = keys.derive(Purpose::NoisePsk);
let prologue = [b"my-app/v1|".as_slice(), &topic].concat();

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
  lets anyone who knows the responder's key but not the passphrase test guesses offline from its reply.
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

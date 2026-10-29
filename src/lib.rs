//! A sans-IO secure channel for local-first apps that connect devices directly.
//!
//! The crate does no networking. An app moves the bytes it produces over its own transport (a WebRTC
//! data channel, a relay WebSocket) and feeds received bytes back in. That keeps the security-critical
//! part small, testable and the same on every platform: native, Flutter (through flutter_rust_bridge)
//! and the browser (through wasm-bindgen).
//!
//! - [`keys::KeySchedule`] derives every key from one secret the app's peers share (for example a
//!   pairing code, or a link secret mixed with a passphrase).
//! - [`seal`] encrypts the few messages that must travel before a channel exists, such as WebRTC
//!   offers and answers on a public relay.
//! - [`handshake::Handshake`] runs `Noise_IKpsk1_25519_ChaChaPoly_SHA256` and yields a
//!   [`channel::Channel`] with forward secrecy and mutual authentication.
//!
//! Everything that arrives from a peer is untrusted, even after a successful handshake: the app must
//! still validate what it decrypts.

pub mod channel;
pub mod handshake;
pub mod keys;
pub mod seal;

mod error;

pub use error::Error;

pub type Result<T> = core::result::Result<T, Error>;

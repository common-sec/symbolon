//! Cryptographic good practice, checked through the public API only, as an app would use it.
//!
//! The unit tests next to each module check that it works and that known-bad input is refused.
//! These tests pin down the habits that keep the cryptography sound, so a change that weakens one
//! of them fails here instead of passing unnoticed:
//!
//! - **nonces** are random and never repeat (seal, signalling, Nostr signatures, handshakes);
//! - **integrity** covers every byte: any change or truncation is rejected;
//! - **separation**: a key or message made for one purpose, context, group, direction or session
//!   is useless in another;
//! - **parsers** never panic and never accept a message that breaks their own rules;
//! - **wire formats** stay what the documentation says, so other implementations interoperate.
//!
//! At the end are the tests for guarantees the library does not give yet. They are `#[ignore]`d
//! with the id of the finding in the security analysis of 2026-11-14 (SY-1 to SY-7), so
//! `cargo test -- --ignored` lists the open backlog. Remove the attribute in the change that
//! provides the guarantee.

use std::collections::HashSet;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use k256::schnorr::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use symbolon::handshake::{Handshake, StaticKeypair};
use symbolon::keys::{KeySchedule, Purpose};
use symbolon::nostr::{EventSigner, SIGNAL_KIND};
use symbolon::seal::{Sealer, MAX_SEALED};
use symbolon::signal::{new_session, Kind, Signal, SignalBox, EVERYONE, MAX_AGE_SECS};
use symbolon::Error;

const NOW: u64 = 1_800_000_000;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

fn keys(context: &[u8], secret: u8) -> KeySchedule {
    KeySchedule::new(context, &[secret; 32]).unwrap()
}

fn offer() -> Signal {
    Signal {
        kind: Kind::Offer,
        created_at: NOW,
        from: [1; 16],
        to: [2; 16],
        device: [3; 32],
        body: b"v=0 sdp".to_vec(),
    }
}

/// A small deterministic generator, so a failing input can be reproduced from the test alone.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u8 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) as u8
    }
}

// ---------------------------------------------------------------------------------------- seal

/// XChaCha20-Poly1305 is only safe while a nonce never repeats under one key. Nonces are random,
/// so the check is statistical: no repeat in 2,000 messages, and no constant or counting prefix.
#[test]
fn sealed_messages_never_reuse_a_nonce() {
    let sealer = Sealer::new(&keys(b"app/v1", 1));
    let mut nonces = HashSet::new();
    let mut first_bytes = HashSet::new();
    for _ in 0..2000 {
        let sealed = sealer.seal(b"same message", b"aad").unwrap();
        assert_eq!(sealed.len(), NONCE_LEN + b"same message".len() + TAG_LEN);
        first_bytes.insert(sealed[0]);
        assert!(
            nonces.insert(sealed[..NONCE_LEN].to_vec()),
            "nonce repeated"
        );
    }
    assert!(first_bytes.len() > 200, "nonces are not random");
}

/// Every byte is authenticated: the nonce, the ciphertext and the tag. So is the length.
#[test]
fn any_changed_or_missing_byte_is_rejected() {
    let sealer = Sealer::new(&keys(b"app/v1", 1));
    let sealed = sealer.seal(b"sixteen byte msg", b"aad").unwrap();
    for i in 0..sealed.len() {
        for bit in [0x01, 0x80] {
            let mut changed = sealed.clone();
            changed[i] ^= bit;
            assert_eq!(
                sealer.open(&changed, b"aad"),
                Err(Error::Rejected),
                "byte {i}"
            );
        }
    }
    for n in 0..sealed.len() {
        assert_eq!(
            sealer.open(&sealed[..n], b"aad"),
            Err(Error::Rejected),
            "cut to {n}"
        );
    }
    let mut longer = sealed.clone();
    longer.push(0);
    assert_eq!(sealer.open(&longer, b"aad"), Err(Error::Rejected));
    assert_eq!(sealer.open(&sealed, b"aad").unwrap(), b"sixteen byte msg");
}

/// The associated data is what stops a message being used somewhere else. An empty one, a prefix
/// and an extension are all different from the original.
#[test]
fn associated_data_is_compared_whole() {
    let sealer = Sealer::new(&keys(b"app/v1", 1));
    let sealed = sealer.seal(b"offer", b"offer|topic").unwrap();
    for other in [&b""[..], b"offer|topi", b"offer|topic|", b"OFFER|TOPIC"] {
        assert_eq!(sealer.open(&sealed, other), Err(Error::Rejected));
    }
    // An empty plaintext is still authenticated.
    let empty = sealer.seal(b"", b"aad").unwrap();
    assert_eq!(empty.len(), NONCE_LEN + TAG_LEN);
    assert_eq!(sealer.open(&empty, b"aad").unwrap(), b"");
    assert_eq!(sealer.open(&empty, b""), Err(Error::Rejected));
}

/// The size limit is exact, and nothing is ever truncated to fit.
#[test]
fn the_size_limit_is_exact() {
    let sealer = Sealer::new(&keys(b"app/v1", 1));
    let largest = MAX_SEALED - NONCE_LEN - TAG_LEN;
    let sealed = sealer.seal(&vec![7; largest], b"").unwrap();
    assert_eq!(sealed.len(), MAX_SEALED);
    assert_eq!(sealer.open(&sealed, b"").unwrap().len(), largest);
    assert_eq!(
        sealer.seal(&vec![7; largest + 1], b""),
        Err(Error::TooLarge)
    );
}

// ---------------------------------------------------------------------------------------- keys

/// One secret gives many keys. None of them may equal another, the secret, or a topic, and a
/// longer secret or a context that is a prefix of another must give unrelated keys.
#[test]
fn derived_keys_are_separated() {
    let secret = [9u8; 32];
    let a = KeySchedule::new(b"app/v1", &secret).unwrap();
    let purposes = [
        Purpose::Signaling,
        Purpose::Seal,
        Purpose::Topic,
        Purpose::NoisePsk,
        Purpose::Fingerprint,
    ];
    let mut seen = HashSet::new();
    for p in purposes {
        let key = a.derive(p);
        assert_ne!(*key, secret, "a derived key must not be the secret itself");
        assert_ne!(*key, [0u8; 32]);
        assert_eq!(*key, *a.derive(p), "derivation is deterministic");
        assert!(seen.insert(*key), "two purposes share a key");
    }
    assert!(seen.insert(a.topic(b"signal")), "a topic equals a key");
    assert!(
        seen.insert(a.topic(b"")),
        "the empty label is a topic of its own"
    );

    // "app/v1" and "app/v1/room" are different contexts, although one starts with the other.
    let room = KeySchedule::new(b"app/v1/room", &secret).unwrap();
    assert_ne!(*a.derive(Purpose::Seal), *room.derive(Purpose::Seal));
    // A longer secret is accepted, and its extra bytes count.
    let longer = KeySchedule::new(b"app/v1", &[9u8; 33]).unwrap();
    assert_ne!(*a.derive(Purpose::Seal), *longer.derive(Purpose::Seal));
}

/// Short secrets are refused at every length below the minimum, including none at all.
#[test]
fn secrets_below_32_bytes_are_refused() {
    for len in 0..32 {
        assert_eq!(
            KeySchedule::new(b"app/v1", &vec![1; len]).err(),
            Some(Error::InvalidKey),
            "{len} bytes"
        );
    }
}

// -------------------------------------------------------------------------------------- signal

/// The plaintext of a sealed signal, read back with the documented associated data
/// (`"symbolon/signal/v1" || topic`). If this stops working, the wire format has changed.
fn plaintext_of(keys: &KeySchedule, content: &str) -> Vec<u8> {
    let aad = [b"symbolon/signal/v1".as_slice(), &keys.topic(b"signal")].concat();
    Sealer::new(keys)
        .open(&B64.decode(content).unwrap(), &aad)
        .unwrap()
}

fn seal_raw(keys: &KeySchedule, plaintext: &[u8]) -> String {
    let aad = [b"symbolon/signal/v1".as_slice(), &keys.topic(b"signal")].concat();
    B64.encode(Sealer::new(keys).seal(plaintext, &aad).unwrap())
}

/// The documented layout: version, kind, time, from, to, device, body length, body.
#[test]
fn the_signal_wire_format_is_the_documented_one() {
    let keys = keys(b"app/v1", 7);
    let signals = SignalBox::new(&keys);
    assert_eq!(signals.topic(), keys.topic(b"signal"));
    let plain = plaintext_of(&keys, &signals.seal(&offer()).unwrap());
    let mut expected = vec![1u8, 2];
    expected.extend_from_slice(&NOW.to_be_bytes());
    expected.extend_from_slice(&[1; 16]);
    expected.extend_from_slice(&[2; 16]);
    expected.extend_from_slice(&[3; 32]);
    expected.extend_from_slice(&7u16.to_be_bytes());
    expected.extend_from_slice(b"v=0 sdp");
    assert_eq!(plain, expected);
}

/// What `open` returns always obeys the rules `seal` enforces, whoever wrote the message.
fn assert_well_formed(signal: &Signal) {
    let broadcast = matches!(signal.kind, Kind::Announce | Kind::Bye);
    assert_ne!(signal.from, EVERYONE, "a message from nobody");
    assert_eq!(
        signal.to == EVERYONE,
        broadcast,
        "wrong addressing for its kind"
    );
    assert!(
        !broadcast || signal.body.is_empty(),
        "a broadcast with a body"
    );
    assert!(
        signal.created_at.abs_diff(NOW) <= MAX_AGE_SECS,
        "outside the time window"
    );
}

/// A member of the group can seal anything. The parser must then either reject it or return a
/// signal that obeys every rule, and must never panic: it runs on data from the network.
#[test]
fn the_signal_parser_holds_for_any_sealed_bytes() {
    let keys = keys(b"app/v1", 7);
    let signals = SignalBox::new(&keys);
    let good = plaintext_of(&keys, &signals.seal(&offer()).unwrap());

    // Every single-byte change of a valid message: accepted only if still well formed.
    let mut accepted = 0;
    for i in 0..good.len() {
        for value in [0u8, 1, 5, 6, 0x7f, 0xff] {
            let mut changed = good.clone();
            changed[i] = value;
            if let Ok(signal) = signals.open(&seal_raw(&keys, &changed), NOW) {
                assert_well_formed(&signal);
                accepted += 1;
            }
        }
    }
    assert!(
        accepted > 0,
        "some changes (ids, body bytes) are legitimate"
    );

    // Every truncation and extension is rejected: the length must match exactly.
    for n in 0..good.len() {
        assert!(
            signals.open(&seal_raw(&keys, &good[..n]), NOW).is_err(),
            "cut to {n}"
        );
    }
    let mut longer = good.clone();
    longer.push(0);
    assert!(signals.open(&seal_raw(&keys, &longer), NOW).is_err());

    // Random bytes of every small length, and with a plausible header in front.
    let mut rng = Lcg(42);
    for len in 0..300usize {
        let mut bytes: Vec<u8> = (0..len).map(|_| rng.next()).collect();
        if let Ok(signal) = signals.open(&seal_raw(&keys, &bytes), NOW) {
            assert_well_formed(&signal);
        }
        if len >= 2 {
            bytes[0] = 1;
            bytes[1] = 1 + rng.next() % 5;
            if let Ok(signal) = signals.open(&seal_raw(&keys, &bytes), NOW) {
                assert_well_formed(&signal);
            }
        }
    }
}

/// Content that is not base64, or base64 of something that was never sealed, is rejected with the
/// same error as any other bad message.
#[test]
fn relay_content_that_was_never_sealed_is_rejected() {
    let signals = SignalBox::new(&keys(b"app/v1", 7));
    for content in ["", "=", "AAAA", "not base64!", "c2VhbGVk", &"A".repeat(200)] {
        assert_eq!(
            signals.open(content, NOW),
            Err(Error::Rejected),
            "{content:?}"
        );
    }
}

/// Sealing the same signal twice gives different content, so a relay can't tell that two events
/// carry the same message.
#[test]
fn equal_signals_do_not_look_equal_on_the_relay() {
    let signals = SignalBox::new(&keys(b"app/v1", 7));
    let mut seen = HashSet::new();
    for _ in 0..200 {
        assert!(seen.insert(signals.seal(&offer()).unwrap()));
    }
}

#[test]
fn session_ids_do_not_repeat() {
    let mut seen = HashSet::new();
    for _ in 0..2000 {
        let id = new_session().unwrap();
        assert_ne!(id, EVERYONE);
        assert!(seen.insert(id));
    }
}

// --------------------------------------------------------------------------------------- nostr

/// Checks an event as a relay would, with k256 and SHA-256 used directly.
fn relay_verifies(event: &str) -> serde_json::Value {
    let e: serde_json::Value = serde_json::from_str(event).unwrap();
    let canonical = serde_json::json!([
        0,
        e["pubkey"],
        e["created_at"],
        e["kind"],
        e["tags"],
        e["content"]
    ])
    .to_string();
    let id: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
    assert_eq!(e["id"], hex::encode(id));
    let key =
        VerifyingKey::from_bytes(&hex::decode(e["pubkey"].as_str().unwrap()).unwrap()).unwrap();
    let sig = hex::decode(e["sig"].as_str().unwrap()).unwrap();
    key.verify_raw(&id, &Signature::try_from(sig.as_slice()).unwrap())
        .unwrap();
    e
}

/// Signing keys are generated, not fixed, and signatures use fresh randomness each time.
#[test]
fn event_signatures_are_valid_and_freshly_randomised() {
    let signer = EventSigner::generate().unwrap();
    let topic = [0xab; 32];
    let first = relay_verifies(&signer.signal_event(NOW, &topic, "c2VhbGVk").unwrap());
    let second = relay_verifies(&signer.signal_event(NOW, &topic, "c2VhbGVk").unwrap());
    assert_eq!(first["id"], second["id"], "the same event has the same id");
    assert_ne!(
        first["sig"], second["sig"],
        "BIP-340 auxiliary randomness is fresh"
    );
    assert_eq!(first["kind"], SIGNAL_KIND);

    let mut public_keys = HashSet::new();
    for _ in 0..50 {
        assert!(public_keys.insert(EventSigner::generate().unwrap().public_key_hex()));
    }
}

/// An event holds the topic, an expiry and the sealed content, and nothing that identifies the
/// app, the group or the device.
#[test]
fn an_event_holds_only_what_a_relay_needs() {
    let signer = EventSigner::generate().unwrap();
    let keys = keys(b"app/v1", 7);
    let signals = SignalBox::new(&keys);
    let content = signals.seal(&offer()).unwrap();
    let event = signer
        .signal_event(NOW, &signals.topic(), &content)
        .unwrap();
    let e = relay_verifies(&event);
    let mut fields: Vec<&str> = e.as_object().unwrap().keys().map(String::as_str).collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "content",
            "created_at",
            "id",
            "kind",
            "pubkey",
            "sig",
            "tags"
        ]
    );
    assert_eq!(
        e["tags"],
        serde_json::json!([
            ["t", hex::encode(signals.topic())],
            ["expiration", (NOW + MAX_AGE_SECS).to_string()]
        ])
    );
    assert!(!event.contains("app/v1") && !event.contains("v=0"));
}

// ----------------------------------------------------------------------------- handshake, channel

struct Pair {
    initiator: Handshake,
    responder: Handshake,
}

fn handshake(
    guest: &StaticKeypair,
    host: &StaticKeypair,
    prologue: &[u8],
) -> (Pair, Vec<u8>, Vec<u8>) {
    let psk = keys(b"app/v1", 3).derive(Purpose::NoisePsk);
    let mut initiator = Handshake::initiator(guest, host.public(), &psk, prologue).unwrap();
    let mut responder = Handshake::responder(host, &psk, prologue).unwrap();
    let first = initiator.write_message(b"").unwrap();
    responder.read_message(&first).unwrap();
    let second = responder.write_message(b"").unwrap();
    initiator.read_message(&second).unwrap();
    (
        Pair {
            initiator,
            responder,
        },
        first,
        second,
    )
}

/// Two handshakes between the same devices share nothing: fresh ephemeral keys give different
/// messages and a different transcript hash, which is what forward secrecy rests on.
#[test]
fn every_handshake_is_fresh() {
    let host = StaticKeypair::generate().unwrap();
    let guest = StaticKeypair::generate().unwrap();
    let (one, first_1, second_1) = handshake(&guest, &host, b"p");
    let (two, first_2, second_2) = handshake(&guest, &host, b"p");
    assert_ne!(first_1, first_2);
    assert_ne!(second_1, second_2);
    let hash_1 = one.initiator.handshake_hash().unwrap();
    assert_eq!(hash_1.len(), 32);
    assert_eq!(
        Some(&hash_1),
        one.responder.handshake_hash().as_ref(),
        "both sides agree"
    );
    assert_ne!(
        Some(hash_1),
        two.initiator.handshake_hash(),
        "sessions differ"
    );
}

/// A message can be read only by the other side of the same session: not by its own sender
/// (reflection), and not by another session between the same two devices.
#[test]
fn channel_messages_belong_to_one_direction_of_one_session() {
    let host = StaticKeypair::generate().unwrap();
    let guest = StaticKeypair::generate().unwrap();
    let (one, ..) = handshake(&guest, &host, b"p");
    let (two, ..) = handshake(&guest, &host, b"p");
    let (mut a1, mut b1) = (
        one.initiator.into_channel().unwrap(),
        one.responder.into_channel().unwrap(),
    );
    let (mut a2, mut b2) = (
        two.initiator.into_channel().unwrap(),
        two.responder.into_channel().unwrap(),
    );

    let message = a1.encrypt(b"for b1 only").unwrap();
    assert_eq!(message.len(), b"for b1 only".len() + TAG_LEN);
    assert_eq!(
        a1.decrypt(&message),
        Err(Error::Rejected),
        "reflected to its sender"
    );
    assert_eq!(
        b2.decrypt(&message),
        Err(Error::Rejected),
        "another session"
    );
    assert_eq!(
        a2.decrypt(&message),
        Err(Error::Rejected),
        "another session's sender"
    );
    assert_eq!(b1.decrypt(&message).unwrap(), b"for b1 only");
    // A rejected message closed the channels that saw it; the right one is still open.
    assert!(!a1.is_open() && !a2.is_open() && !b2.is_open());
    assert!(b1.is_open());
}

/// The same plaintext never encrypts to the same bytes: the counter moves with every message.
#[test]
fn equal_channel_messages_do_not_look_equal() {
    let host = StaticKeypair::generate().unwrap();
    let guest = StaticKeypair::generate().unwrap();
    let (pair, ..) = handshake(&guest, &host, b"p");
    let mut a = pair.initiator.into_channel().unwrap();
    let mut seen = HashSet::new();
    for _ in 0..500 {
        assert!(seen.insert(a.encrypt(b"same").unwrap()));
    }
}

/// Device keys are generated, and a private key is never all zeros or equal to its public key.
#[test]
fn device_keys_are_fresh() {
    let mut seen = HashSet::new();
    for _ in 0..100 {
        let key = StaticKeypair::generate().unwrap();
        assert_ne!(key.private(), &[0u8; 32]);
        assert_ne!(key.private(), key.public());
        assert!(seen.insert(*key.public()));
    }
}

// ------------------------------------------------------------------- not guaranteed yet (backlog)

/// SY-4: a timestamp near `u64::MAX` must be refused, not overflow when the expiry is added.
/// Fix: `checked_add` in `EventSigner::signal_event`.
#[test]
#[ignore = "SY-4: signal_event overflows on very large timestamps"]
fn a_huge_timestamp_is_refused_not_overflowed() {
    let signer = EventSigner::generate().unwrap();
    assert_eq!(
        signer.signal_event(u64::MAX - 1, &[0; 32], "c2VhbGVk"),
        Err(Error::Rejected)
    );
}

/// SY-7: a handshake that failed to write should be finished for good, as one that failed to read
/// already is. Today the state stays in place after a failed `write_message`.
#[test]
#[ignore = "SY-7: write_message keeps the handshake state after an error"]
fn a_failed_write_ends_the_handshake() {
    let host = StaticKeypair::generate().unwrap();
    let guest = StaticKeypair::generate().unwrap();
    let psk = keys(b"app/v1", 3).derive(Purpose::NoisePsk);
    let mut initiator = Handshake::initiator(&guest, host.public(), &psk, b"p").unwrap();
    assert!(initiator.write_message(&vec![0; 70_000]).is_err());
    assert_eq!(initiator.write_message(b""), Err(Error::HandshakeFinished));
}

/// SY-1: a responder should be able to tell "handshake finished" from "peer confirmed". With the
/// IK pattern the initiator is proven only by its first channel message, so the API needs a way to
/// say so (for example `Channel::is_confirmed`), and the README must tell apps to wait for it.
#[test]
#[ignore = "SY-1: no way yet to tell a finished handshake from a confirmed peer"]
fn a_responder_can_tell_when_the_initiator_is_confirmed() {
    unimplemented!("needs an API such as Channel::is_confirmed; see the analysis, SY-1");
}

/// SY-3: the same sealed signal opens every time within the two-minute window. The library should
/// offer a bounded seen-set, or return the nonce so apps can keep one.
#[test]
#[ignore = "SY-3: no helper yet to drop a signal seen before"]
fn a_signal_seen_before_can_be_recognised() {
    unimplemented!(
        "needs a seen-set helper or the nonce from SignalBox::open; see the analysis, SY-3"
    );
}

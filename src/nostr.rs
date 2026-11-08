//! Just enough Nostr (NIP-01) to post sealed signalling messages to public relays and find them again.
//!
//! Every event is signed with a throwaway key: an [`EventSigner`] is made once per app run and never
//! stored, so relays can't link a group's sessions by key. The signature only satisfies the relay;
//! readers trust an event because its content opens with the group's keys (see [`crate::signal`]),
//! never because of who signed it.
//!
//! Signalling events use [`SIGNAL_KIND`], in Nostr's ephemeral range: relays pass them on to whoever
//! is subscribed at that moment and don't store them. They also carry a NIP-40 expiration tag, for
//! relays that store them anyway.
//!
//! The JSON is written here, not by a JSON library, so it is only ever made from characters that need
//! no escaping: hex, digits, base64, and the fixed tag names. Anything else is refused.

use k256::schnorr::SigningKey;
use sha2::{Digest, Sha256};

use crate::signal::MAX_AGE_SECS;
use crate::{Error, Result};

/// The event kind of signalling messages: ephemeral (20000-29999), so relays don't store them.
pub const SIGNAL_KIND: u16 = 21_059;
/// The single-letter tag that carries the topic, so relays can filter on it (`#t`).
pub const TOPIC_TAG: &str = "t";

pub struct EventSigner {
    key: SigningKey,
}

impl EventSigner {
    /// A new random key. Make one per app run, and don't store it.
    pub fn generate() -> Result<Self> {
        loop {
            let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
            getrandom::fill(bytes.as_mut()).map_err(|_| Error::Random)?;
            // Fails only for zero or a value above the curve order, about 2^-128 of the time.
            if let Ok(key) = SigningKey::from_bytes(bytes.as_ref()) {
                return Ok(Self { key });
            }
        }
    }

    /// The x-only public key as lowercase hex, as Nostr writes it.
    pub fn public_key_hex(&self) -> String {
        hex(&self.key.verifying_key().to_bytes())
    }

    /// A signed event as a JSON object, ready to send as `["EVENT", <event>]`.
    pub fn sign(
        &self,
        created_at: u64,
        kind: u16,
        tags: &[&[&str]],
        content: &str,
    ) -> Result<String> {
        let mut aux = [0u8; 32];
        getrandom::fill(&mut aux).map_err(|_| Error::Random)?;
        self.sign_with_aux(created_at, kind, tags, content, &aux)
    }

    fn sign_with_aux(
        &self,
        created_at: u64,
        kind: u16,
        tags: &[&[&str]],
        content: &str,
        aux: &[u8; 32],
    ) -> Result<String> {
        if !tags
            .iter()
            .flat_map(|t| t.iter())
            .chain([&content])
            .all(|s| plain(s))
        {
            return Err(Error::Rejected);
        }
        let pubkey = self.public_key_hex();
        let tags = tags_json(tags);
        let serialized = format!(r#"[0,"{pubkey}",{created_at},{kind},{tags},"{content}"]"#);
        let id: [u8; 32] = Sha256::digest(serialized.as_bytes()).into();
        let sig = self.key.sign_raw(&id, aux).map_err(|_| Error::Rejected)?;
        Ok(format!(
            r#"{{"id":"{}","pubkey":"{pubkey}","created_at":{created_at},"kind":{kind},"tags":{tags},"content":"{content}","sig":"{}"}}"#,
            hex(&id),
            hex(&sig.to_bytes()),
        ))
    }

    /// A signalling event for `topic` (see [`crate::signal::SignalBox::topic`]) with sealed `content`.
    pub fn signal_event(&self, created_at: u64, topic: &[u8; 32], content: &str) -> Result<String> {
        let topic = hex(topic);
        let expiration = (created_at + MAX_AGE_SECS).to_string();
        self.sign(
            created_at,
            SIGNAL_KIND,
            &[&[TOPIC_TAG, &topic], &["expiration", &expiration]],
            content,
        )
    }
}

/// The filter that subscribes to `topic`'s signalling events from `since` on, ready to send as
/// `["REQ", <subscription id>, <filter>]`.
pub fn signal_filter(topic: &[u8; 32], since: u64) -> String {
    format!(
        r##"{{"kinds":[{SIGNAL_KIND}],"#{TOPIC_TAG}":["{}"],"since":{since}}}"##,
        hex(topic)
    )
}

/// Characters that JSON never escapes and that hex, decimal and base64 (both alphabets) use.
fn plain(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
}

fn tags_json(tags: &[&[&str]]) -> String {
    let tags: Vec<String> = tags
        .iter()
        .map(|tag| {
            let items: Vec<String> = tag.iter().map(|s| format!("\"{s}\"")).collect();
            format!("[{}]", items.join(","))
        })
        .collect();
    format!("[{}]", tags.join(","))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                DIGITS[(b >> 4) as usize] as char,
                DIGITS[(b & 15) as usize] as char,
            ]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::schnorr::{Signature, VerifyingKey};
    use serde_json::{json, Value};

    fn signer(secret: u8) -> EventSigner {
        let mut bytes = [0u8; 32];
        bytes[31] = secret;
        EventSigner {
            key: SigningKey::from_bytes(&bytes).unwrap(),
        }
    }

    /// Checks an event the way a relay does: the id is the hash of the canonical serialization (made
    /// here by serde_json, independently of the code under test) and the signature verifies.
    fn relay_accepts(event: &str) -> Value {
        let e: Value = serde_json::from_str(event).unwrap();
        let canonical = json!([
            0,
            e["pubkey"],
            e["created_at"],
            e["kind"],
            e["tags"],
            e["content"]
        ])
        .to_string();
        let id: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
        assert_eq!(e["id"], hex(&id));
        let key =
            VerifyingKey::from_bytes(&hex::decode(e["pubkey"].as_str().unwrap()).unwrap()).unwrap();
        let sig = Signature::try_from(hex::decode(e["sig"].as_str().unwrap()).unwrap().as_slice())
            .unwrap();
        key.verify_raw(&id, &sig).unwrap();
        e
    }

    #[test]
    fn bip340_vector_0() {
        // From the BIP-340 test vectors: secret key 3, message and aux all zeros.
        let s = signer(3);
        assert_eq!(
            s.public_key_hex(),
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        );
        let sig = s.key.sign_raw(&[0; 32], &[0; 32]).unwrap();
        assert_eq!(
            hex(&sig.to_bytes()).to_uppercase(),
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
        );
    }

    #[test]
    fn signal_event_is_accepted_by_a_relay() {
        let topic = [0xab; 32];
        let event = signer(9)
            .signal_event(1_800_000_000, &topic, "c2VhbGVk+/=")
            .unwrap();
        let e = relay_accepts(&event);
        assert_eq!(e["kind"], SIGNAL_KIND);
        assert_eq!(e["content"], "c2VhbGVk+/=");
        assert_eq!(
            e["tags"],
            json!([
                ["t", hex(&topic)],
                ["expiration", (1_800_000_000 + MAX_AGE_SECS).to_string()]
            ])
        );
    }

    #[test]
    fn random_aux_still_verifies() {
        relay_accepts(
            &EventSigner::generate()
                .unwrap()
                .sign(1, 1, &[], "x")
                .unwrap(),
        );
    }

    #[test]
    fn each_signer_has_its_own_key() {
        let a = EventSigner::generate().unwrap();
        let b = EventSigner::generate().unwrap();
        assert_ne!(a.public_key_hex(), b.public_key_hex());
    }

    #[test]
    fn text_that_would_need_escaping_is_refused() {
        let s = signer(9);
        for bad in ["a\"b", "a\\b", "line\n", "é", "a b", "{"] {
            assert_eq!(s.sign(1, 1, &[], bad), Err(Error::Rejected));
            assert_eq!(s.sign(1, 1, &[&["t", bad]], "ok"), Err(Error::Rejected));
        }
    }

    #[test]
    fn filter_matches_the_event_tag() {
        let topic = [0x01; 32];
        let f: Value = serde_json::from_str(&signal_filter(&topic, 42)).unwrap();
        assert_eq!(
            f,
            json!({"kinds": [SIGNAL_KIND], "#t": [hex(&topic)], "since": 42})
        );
    }
}

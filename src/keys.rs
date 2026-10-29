//! One shared secret gives every key, each bound to the app and to its purpose:
//!
//! ```text
//! secret --HKDF(salt = "symbolon/v1" || context)--> signaling  (password for signalling strategies)
//!                                                   --> seal       (XChaCha20-Poly1305, see `seal`)
//!                                                   --> topic      (HMAC key that names relay topics)
//!                                                   --> noise-psk  (Noise pre-shared key)
//!                                                   --> fingerprint (short code people compare)
//! ```
//!
//! `context` separates apps and rooms, for example `b"bringmeback/v1"` or `b"secure-share/v3/<room>"`,
//! so the same secret never gives the same keys in two places.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Result};

pub const KEY_LEN: usize = 32;
/// Shorter secrets would make the derived keys guessable.
pub const MIN_SECRET_LEN: usize = 32;
const SALT_PREFIX: &[u8] = b"symbolon/v1";

pub type Key = Zeroizing<[u8; KEY_LEN]>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Signaling,
    Seal,
    Topic,
    NoisePsk,
    Fingerprint,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Purpose::Signaling => b"signaling",
            Purpose::Seal => b"seal",
            Purpose::Topic => b"topic",
            Purpose::NoisePsk => b"noise-psk",
            Purpose::Fingerprint => b"fingerprint",
        }
    }
}

pub struct KeySchedule {
    hkdf: Hkdf<Sha256>,
}

impl KeySchedule {
    /// `secret` must be at least [`MIN_SECRET_LEN`] bytes of uniformly random data, or the output of
    /// a password hash; it is not stretched here.
    pub fn new(context: &[u8], secret: &[u8]) -> Result<Self> {
        if secret.len() < MIN_SECRET_LEN {
            return Err(Error::InvalidKey);
        }
        let salt = [SALT_PREFIX, context].concat();
        Ok(Self {
            hkdf: Hkdf::new(Some(&salt), secret),
        })
    }

    pub fn derive(&self, purpose: Purpose) -> Key {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        self.hkdf
            .expand(purpose.label(), key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 length");
        key
    }

    /// A relay topic for `label` that only holders of the secret can compute or recognise.
    pub fn topic(&self, label: &[u8]) -> [u8; 32] {
        let key = self.derive(Purpose::Topic);
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_ref()).expect("any key length works");
        mac.update(label);
        mac.finalize().into_bytes().into()
    }

    /// Six bytes for people to compare on each device, e.g. shown as `1a2b-3c4d-5e6f`.
    pub fn fingerprint(&self) -> [u8; 6] {
        let key = self.derive(Purpose::Fingerprint);
        let mut out = [0u8; 6];
        out.copy_from_slice(&key[..6]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [7; 32];

    #[test]
    fn same_inputs_give_same_keys() {
        let a = KeySchedule::new(b"app/v1", &SECRET).unwrap();
        let b = KeySchedule::new(b"app/v1", &SECRET).unwrap();
        assert_eq!(*a.derive(Purpose::Seal), *b.derive(Purpose::Seal));
        assert_eq!(a.topic(b"signal"), b.topic(b"signal"));
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn keys_differ_by_purpose_context_and_secret() {
        let a = KeySchedule::new(b"app/v1", &SECRET).unwrap();
        let purposes = [
            Purpose::Signaling,
            Purpose::Seal,
            Purpose::Topic,
            Purpose::NoisePsk,
            Purpose::Fingerprint,
        ];
        for (i, p) in purposes.iter().enumerate() {
            for q in &purposes[i + 1..] {
                assert_ne!(*a.derive(*p), *a.derive(*q));
            }
        }
        let other_app = KeySchedule::new(b"other/v1", &SECRET).unwrap();
        assert_ne!(*a.derive(Purpose::Seal), *other_app.derive(Purpose::Seal));
        let other_secret = KeySchedule::new(b"app/v1", &[8; 32]).unwrap();
        assert_ne!(
            *a.derive(Purpose::Seal),
            *other_secret.derive(Purpose::Seal)
        );
        assert_ne!(a.topic(b"x"), a.topic(b"y"));
    }

    #[test]
    fn short_secrets_are_refused() {
        assert_eq!(
            KeySchedule::new(b"app/v1", &[1; 31]).err(),
            Some(Error::InvalidKey)
        );
    }
}

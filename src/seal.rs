//! Encryption for messages sent before a channel exists, such as WebRTC offers and answers on a
//! public relay. XChaCha20-Poly1305 with a random 24-byte nonce, so no counter has to be kept across
//! restarts or devices. These messages have no forward secrecy; keep them to signalling.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::keys::{Key, KeySchedule, Purpose};
use crate::{Error, Result};

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// Signalling messages are small; anything larger is refused before decryption.
pub const MAX_SEALED: usize = 16 * 1024;

pub struct Sealer {
    key: Key,
}

impl Sealer {
    pub fn new(keys: &KeySchedule) -> Self {
        Self {
            key: keys.derive(Purpose::Seal),
        }
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(self.key.as_ref().into())
    }

    /// `aad` is authenticated but not encrypted. Put the message type and anything else the message
    /// must not be replayed outside of (topic, sender) in it.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() + NONCE_LEN + TAG_LEN > MAX_SEALED {
            return Err(Error::TooLarge);
        }
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| Error::Random)?;
        let ct = self
            .cipher()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Rejected)?;
        Ok([nonce.as_slice(), &ct].concat())
    }

    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() > MAX_SEALED {
            return Err(Error::TooLarge);
        }
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::Rejected);
        }
        let (nonce, ct) = sealed.split_at(NONCE_LEN);
        self.cipher()
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
            .map_err(|_| Error::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealer(secret: u8) -> Sealer {
        Sealer::new(&KeySchedule::new(b"app/v1", &[secret; 32]).unwrap())
    }

    #[test]
    fn opens_only_with_same_key_and_aad() {
        let s = sealer(1);
        let sealed = s.seal(b"offer", b"offer|topic").unwrap();
        assert_eq!(s.open(&sealed, b"offer|topic").unwrap(), b"offer");
        assert_ne!(
            s.seal(b"offer", b"").unwrap(),
            s.seal(b"offer", b"").unwrap()
        );
        assert_eq!(s.open(&sealed, b"answer|topic"), Err(Error::Rejected));
        assert_eq!(
            sealer(2).open(&sealed, b"offer|topic"),
            Err(Error::Rejected)
        );
        let mut tampered = sealed.clone();
        tampered[30] ^= 1;
        assert_eq!(s.open(&tampered, b"offer|topic"), Err(Error::Rejected));
        assert_eq!(s.open(&sealed[..20], b"offer|topic"), Err(Error::Rejected));
    }

    #[test]
    fn size_limits() {
        let s = sealer(1);
        assert_eq!(s.seal(&vec![0; MAX_SEALED], b""), Err(Error::TooLarge));
        assert_eq!(s.open(&vec![0; MAX_SEALED + 1], b""), Err(Error::TooLarge));
    }
}

//! The encrypted channel after a handshake. Each direction counts messages, so the transport must be
//! ordered and reliable (a WebRTC data channel in its default mode is). A lost, reordered or rejected
//! message closes the channel; the app then runs a new handshake.

use snow::TransportState;

use crate::{Error, Result};

/// Noise's limit for one message, including the 16-byte tag.
pub const MAX_MESSAGE: usize = 65535;
const TAG_LEN: usize = 16;
pub const MAX_PLAINTEXT: usize = MAX_MESSAGE - TAG_LEN;
/// Each direction changes its key after this many messages, so a long-lived channel doesn't keep
/// one key forever. Both sides apply the same rule, so they stay in step.
pub const REKEY_EVERY: u64 = 1 << 16;

pub struct Channel {
    state: Option<TransportState>,
    sent: u64,
    received: u64,
}

impl Channel {
    pub(crate) fn new(state: TransportState) -> Self {
        Self {
            state: Some(state),
            sent: 0,
            received: 0,
        }
    }

    pub fn is_open(&self) -> bool {
        self.state.is_some()
    }

    /// Splitting larger data into messages is up to the app.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(Error::TooLarge);
        }
        let state = self.state.as_mut().ok_or(Error::Rejected)?;
        let mut buf = vec![0u8; plaintext.len() + TAG_LEN];
        let n = state
            .write_message(plaintext, &mut buf)
            .map_err(|_| Error::Rejected)?;
        buf.truncate(n);
        self.sent += 1;
        if self.sent % REKEY_EVERY == 0 {
            state.rekey_outgoing();
        }
        Ok(buf)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let result = self.try_decrypt(ciphertext);
        if result.is_err() {
            self.state = None;
        }
        result
    }

    fn try_decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() > MAX_MESSAGE {
            return Err(Error::TooLarge);
        }
        let state = self.state.as_mut().ok_or(Error::Rejected)?;
        let mut buf = vec![0u8; ciphertext.len()];
        let n = state
            .read_message(ciphertext, &mut buf)
            .map_err(|_| Error::Rejected)?;
        buf.truncate(n);
        self.received += 1;
        if self.received % REKEY_EVERY == 0 {
            state.rekey_incoming();
        }
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{Handshake, StaticKeypair};
    use crate::keys::{KeySchedule, Purpose};

    fn channels() -> (Channel, Channel) {
        let psk = KeySchedule::new(b"test/v1", &[3; 32])
            .unwrap()
            .derive(Purpose::NoisePsk);
        let host = StaticKeypair::generate().unwrap();
        let guest = StaticKeypair::generate().unwrap();
        let mut ini = Handshake::initiator(&guest, host.public(), &psk, b"p").unwrap();
        let mut res = Handshake::responder(&host, &psk, b"p").unwrap();
        res.read_message(&ini.write_message(b"").unwrap()).unwrap();
        ini.read_message(&res.write_message(b"").unwrap()).unwrap();
        (ini.into_channel().unwrap(), res.into_channel().unwrap())
    }

    #[test]
    fn reordered_message_closes_the_channel() {
        let (mut a, mut b) = channels();
        let first = a.encrypt(b"1").unwrap();
        let second = a.encrypt(b"2").unwrap();
        assert_eq!(b.decrypt(&second), Err(Error::Rejected));
        assert!(!b.is_open());
        assert_eq!(b.decrypt(&first), Err(Error::Rejected));
    }

    #[test]
    fn replayed_message_is_rejected() {
        let (mut a, mut b) = channels();
        let m = a.encrypt(b"once").unwrap();
        assert_eq!(b.decrypt(&m).unwrap(), b"once");
        assert_eq!(b.decrypt(&m), Err(Error::Rejected));
    }

    #[test]
    fn tampered_message_closes_the_channel() {
        let (mut a, mut b) = channels();
        let mut m = a.encrypt(b"data").unwrap();
        m[0] ^= 1;
        assert_eq!(b.decrypt(&m), Err(Error::Rejected));
        assert!(!b.is_open());
    }

    #[test]
    fn size_limits() {
        let (mut a, mut b) = channels();
        assert!(a.encrypt(&vec![0; MAX_PLAINTEXT]).is_ok());
        assert_eq!(a.encrypt(&vec![0; MAX_PLAINTEXT + 1]), Err(Error::TooLarge));
        assert_eq!(b.decrypt(&vec![0; MAX_MESSAGE + 1]), Err(Error::TooLarge));
    }

    #[test]
    fn both_sides_rekey_in_step() {
        let (mut a, mut b) = channels();
        for i in 0..REKEY_EVERY + 3 {
            let m = a.encrypt(&i.to_le_bytes()).unwrap();
            assert_eq!(b.decrypt(&m).unwrap(), i.to_le_bytes());
        }
        assert_eq!(a.decrypt(&b.encrypt(b"back").unwrap()).unwrap(), b"back");
    }
}

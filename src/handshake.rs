//! `Noise_IKpsk1_25519_ChaChaPoly_SHA256`, the suite secure-share chose in its 0.9.0 study.
//!
//! - **IK:** the initiator already knows the responder's static key (from a link, or from the
//!   responder's sealed announcement on the relay), so the handshake is one round trip and the
//!   initiator's identity is encrypted.
//! - **psk1:** the pre-shared key is mixed into the first message, so a responder rejects anyone
//!   without the secret before it answers. With psk2 the responder would answer first, which lets a
//!   caller who knows only the link test passphrase guesses offline (secure-share PR #27).
//! - **ChaChaPoly:** fast without AES instructions, which WebAssembly lacks.
//!
//! The prologue must hold what both sides agree on before the handshake (app context, protocol
//! version, relay topic); a mismatch makes the handshake fail.

use snow::{params::NoiseParams, Builder, HandshakeState};
use zeroize::Zeroizing;

use crate::channel::{Channel, MAX_MESSAGE};
use crate::keys::{Key, KEY_LEN};
use crate::{Error, Result};

pub const PROTOCOL: &str = "Noise_IKpsk1_25519_ChaChaPoly_SHA256";
const PSK_LOCATION: u8 = 1;

fn params() -> NoiseParams {
    PROTOCOL.parse().expect("valid protocol name")
}

/// A device's long-term X25519 key pair. Store the private half like any other secret of the app.
pub struct StaticKeypair {
    private: Zeroizing<[u8; KEY_LEN]>,
    public: [u8; KEY_LEN],
}

impl StaticKeypair {
    pub fn generate() -> Result<Self> {
        let kp = Builder::new(params())
            .generate_keypair()
            .map_err(|_| Error::Random)?;
        let mut private = Zeroizing::new([0u8; KEY_LEN]);
        private.copy_from_slice(&kp.private);
        let mut public = [0u8; KEY_LEN];
        public.copy_from_slice(&kp.public);
        Ok(Self { private, public })
    }

    pub fn from_private(private: &[u8]) -> Result<Self> {
        let private: [u8; KEY_LEN] = private.try_into().map_err(|_| Error::InvalidKey)?;
        Ok(Self {
            public: x25519_public(&private)?,
            private: Zeroizing::new(private),
        })
    }

    pub fn public(&self) -> &[u8; KEY_LEN] {
        &self.public
    }

    pub fn private(&self) -> &[u8; KEY_LEN] {
        &self.private
    }
}

/// The public key for `private`, computed by running a throwaway handshake's key setup.
fn x25519_public(private: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN]> {
    // snow does not expose scalar multiplication; its resolver's DH does.
    use snow::resolvers::{CryptoResolver, DefaultResolver};
    let mut dh = DefaultResolver
        .resolve_dh(&snow::params::DHChoice::Curve25519)
        .ok_or(Error::InvalidKey)?;
    dh.set(private);
    dh.pubkey().try_into().map_err(|_| Error::InvalidKey)
}

/// When two devices both know each other's static keys, the one with the lower public key
/// initiates, so they don't both start a handshake at once.
pub fn initiates(local_public: &[u8; KEY_LEN], remote_public: &[u8; KEY_LEN]) -> bool {
    local_public < remote_public
}

pub struct Handshake {
    state: Option<HandshakeState>,
}

impl Handshake {
    pub fn initiator(
        local: &StaticKeypair,
        remote_public: &[u8; KEY_LEN],
        psk: &Key,
        prologue: &[u8],
    ) -> Result<Self> {
        Self::build(true, local, Some(remote_public), psk, prologue, None)
    }

    pub fn responder(local: &StaticKeypair, psk: &Key, prologue: &[u8]) -> Result<Self> {
        Self::build(false, local, None, psk, prologue, None)
    }

    fn build(
        initiator: bool,
        local: &StaticKeypair,
        remote_public: Option<&[u8; KEY_LEN]>,
        psk: &Key,
        prologue: &[u8],
        ephemeral: Option<&[u8]>,
    ) -> Result<Self> {
        let mut b = Builder::new(params())
            .local_private_key(local.private())
            .and_then(|b| b.psk(PSK_LOCATION, psk))
            .and_then(|b| b.prologue(prologue))
            .map_err(|_| Error::InvalidKey)?;
        if let Some(rs) = remote_public {
            b = b.remote_public_key(rs).map_err(|_| Error::InvalidKey)?;
        }
        if let Some(e) = ephemeral {
            b = b.fixed_ephemeral_key_for_testing_only(e);
        }
        let state = if initiator {
            b.build_initiator()
        } else {
            b.build_responder()
        }
        .map_err(|_| Error::InvalidKey)?;
        Ok(Self { state: Some(state) })
    }

    fn state(&mut self) -> Result<&mut HandshakeState> {
        self.state.as_mut().ok_or(Error::HandshakeFinished)
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_MESSAGE];
        let n = self
            .state()?
            .write_message(payload, &mut buf)
            .map_err(|_| Error::TooLarge)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// A rejected message ends this handshake: start a new one rather than retrying, since snow's
    /// state is not defined after a failed read.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if message.len() > MAX_MESSAGE {
            self.state = None;
            return Err(Error::TooLarge);
        }
        let mut buf = vec![0u8; MAX_MESSAGE];
        match self.state()?.read_message(message, &mut buf) {
            Ok(n) => {
                buf.truncate(n);
                Ok(buf)
            }
            Err(_) => {
                self.state = None;
                Err(Error::Rejected)
            }
        }
    }

    pub fn is_finished(&self) -> bool {
        self.state
            .as_ref()
            .is_some_and(HandshakeState::is_handshake_finished)
    }

    /// The peer's static public key; the responder learns it from the first message.
    pub fn remote_static(&self) -> Option<[u8; KEY_LEN]> {
        self.state.as_ref()?.get_remote_static()?.try_into().ok()
    }

    /// Equal on both sides once finished; usable as a channel binding (e.g. a safety code).
    pub fn handshake_hash(&self) -> Option<Vec<u8>> {
        Some(self.state.as_ref()?.get_handshake_hash().to_vec())
    }

    pub fn into_channel(mut self) -> Result<Channel> {
        let state = self.state.take().ok_or(Error::HandshakeFinished)?;
        if !state.is_handshake_finished() {
            return Err(Error::HandshakeIncomplete);
        }
        Ok(Channel::new(
            state
                .into_transport_mode()
                .map_err(|_| Error::HandshakeIncomplete)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeySchedule, Purpose};

    fn psk(secret: u8) -> Key {
        KeySchedule::new(b"test/v1", &[secret; 32])
            .unwrap()
            .derive(Purpose::NoisePsk)
    }

    fn pair(
        guest_psk: u8,
        host_psk: u8,
        guest_prologue: &[u8],
    ) -> (StaticKeypair, StaticKeypair, Handshake, Handshake) {
        let host = StaticKeypair::generate().unwrap();
        let guest = StaticKeypair::generate().unwrap();
        let ini =
            Handshake::initiator(&guest, host.public(), &psk(guest_psk), guest_prologue).unwrap();
        let res = Handshake::responder(&host, &psk(host_psk), b"prologue").unwrap();
        (host, guest, ini, res)
    }

    #[test]
    fn handshake_then_channel_both_ways() {
        let (_, guest, mut ini, mut res) = pair(1, 1, b"prologue");
        let m1 = ini.write_message(b"hello").unwrap();
        assert_eq!(res.read_message(&m1).unwrap(), b"hello");
        assert_eq!(res.remote_static(), Some(*guest.public()));
        let m2 = res.write_message(b"welcome").unwrap();
        assert_eq!(ini.read_message(&m2).unwrap(), b"welcome");
        assert!(ini.is_finished() && res.is_finished());
        assert_eq!(ini.handshake_hash(), res.handshake_hash());
        let (mut a, mut b) = (ini.into_channel().unwrap(), res.into_channel().unwrap());
        assert_eq!(b.decrypt(&a.encrypt(b"one").unwrap()).unwrap(), b"one");
        assert_eq!(a.decrypt(&b.encrypt(b"two").unwrap()).unwrap(), b"two");
    }

    #[test]
    fn wrong_psk_is_rejected_before_the_responder_answers() {
        let (_, _, mut ini, mut res) = pair(1, 2, b"prologue");
        let m1 = ini.write_message(b"").unwrap();
        assert_eq!(res.read_message(&m1), Err(Error::Rejected));
        assert_eq!(res.write_message(b""), Err(Error::HandshakeFinished));
    }

    #[test]
    fn prologue_mismatch_is_rejected() {
        let (_, _, mut ini, mut res) = pair(1, 1, b"other prologue");
        let m1 = ini.write_message(b"").unwrap();
        assert_eq!(res.read_message(&m1), Err(Error::Rejected));
    }

    #[test]
    fn wrong_responder_key_is_rejected() {
        let host = StaticKeypair::generate().unwrap();
        let stranger = StaticKeypair::generate().unwrap();
        let guest = StaticKeypair::generate().unwrap();
        let mut ini = Handshake::initiator(&guest, stranger.public(), &psk(1), b"p").unwrap();
        let mut res = Handshake::responder(&host, &psk(1), b"p").unwrap();
        assert_eq!(
            res.read_message(&ini.write_message(b"").unwrap()),
            Err(Error::Rejected)
        );
    }

    #[test]
    fn tampered_handshake_message_is_rejected() {
        let (_, _, mut ini, mut res) = pair(1, 1, b"prologue");
        let mut m1 = ini.write_message(b"").unwrap();
        let last = m1.len() - 1;
        m1[last] ^= 1;
        assert_eq!(res.read_message(&m1), Err(Error::Rejected));
    }

    #[test]
    fn channel_needs_a_finished_handshake() {
        let (_, _, mut ini, _) = pair(1, 1, b"prologue");
        ini.write_message(b"").unwrap();
        assert_eq!(ini.into_channel().err(), Some(Error::HandshakeIncomplete));
    }

    #[test]
    fn static_key_round_trips_and_one_side_initiates() {
        let a = StaticKeypair::generate().unwrap();
        let restored = StaticKeypair::from_private(a.private()).unwrap();
        assert_eq!(restored.public(), a.public());
        let b = StaticKeypair::generate().unwrap();
        assert_ne!(
            initiates(a.public(), b.public()),
            initiates(b.public(), a.public())
        );
        assert_eq!(
            StaticKeypair::from_private(&[1; 31]).err(),
            Some(Error::InvalidKey)
        );
    }

    #[derive(serde::Deserialize)]
    struct Vectors {
        vectors: Vec<Vector>,
    }

    #[derive(serde::Deserialize)]
    struct Vector {
        protocol_name: String,
        init_prologue: String,
        init_psks: Vec<String>,
        init_static: String,
        init_ephemeral: String,
        init_remote_static: String,
        resp_prologue: String,
        resp_psks: Vec<String>,
        resp_static: String,
        resp_ephemeral: String,
        handshake_hash: String,
        messages: Vec<Message>,
    }

    #[derive(serde::Deserialize)]
    struct Message {
        payload: String,
        ciphertext: String,
    }

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn key(s: &str) -> Key {
        Zeroizing::new(h(s).try_into().unwrap())
    }

    /// The independent cacophony vectors (Haskell), as shipped with snow.
    #[test]
    fn published_vectors() {
        let all: Vectors =
            serde_json::from_str(include_str!("../tests/data/cacophony.json")).unwrap();
        let v = all
            .vectors
            .iter()
            .find(|v| v.protocol_name == PROTOCOL)
            .expect("vector for our suite");
        let init = StaticKeypair::from_private(&h(&v.init_static)).unwrap();
        let resp = StaticKeypair::from_private(&h(&v.resp_static)).unwrap();
        let remote: [u8; 32] = h(&v.init_remote_static).try_into().unwrap();
        assert_eq!(resp.public(), &remote);
        let mut ini = Handshake::build(
            true,
            &init,
            Some(&remote),
            &key(&v.init_psks[0]),
            &h(&v.init_prologue),
            Some(&h(&v.init_ephemeral)),
        )
        .unwrap();
        let mut res = Handshake::build(
            false,
            &resp,
            None,
            &key(&v.resp_psks[0]),
            &h(&v.resp_prologue),
            Some(&h(&v.resp_ephemeral)),
        )
        .unwrap();
        let (m1, m2) = (&v.messages[0], &v.messages[1]);
        let c1 = ini.write_message(&h(&m1.payload)).unwrap();
        assert_eq!(hex::encode(&c1), m1.ciphertext);
        assert_eq!(res.read_message(&c1).unwrap(), h(&m1.payload));
        let c2 = res.write_message(&h(&m2.payload)).unwrap();
        assert_eq!(hex::encode(&c2), m2.ciphertext);
        assert_eq!(ini.read_message(&c2).unwrap(), h(&m2.payload));
        assert_eq!(hex::encode(ini.handshake_hash().unwrap()), v.handshake_hash);
        let (mut a, mut b) = (ini.into_channel().unwrap(), res.into_channel().unwrap());
        for (i, m) in v.messages[2..].iter().enumerate() {
            let (from, to) = if i % 2 == 0 {
                (&mut a, &mut b)
            } else {
                (&mut b, &mut a)
            };
            let c = from.encrypt(&h(&m.payload)).unwrap();
            assert_eq!(hex::encode(&c), m.ciphertext);
            assert_eq!(to.decrypt(&c).unwrap(), h(&m.payload));
        }
    }
}

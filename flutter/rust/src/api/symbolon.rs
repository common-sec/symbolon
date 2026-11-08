//! Symbolon for Dart on desktop and phones, through flutter_rust_bridge. On the web, the Dart package
//! uses the JavaScript binding in `wasm/` instead, which has the same objects. Group keys stay inside
//! Rust: Dart only sees public values (topics, fingerprints, public keys) and the device's own private
//! key, which it has to store.

use anyhow::{anyhow, Result};
use flutter_rust_bridge::frb;
use symbolon::channel::Channel;
use symbolon::handshake::{self, Handshake, StaticKeypair};
use symbolon::keys::{KeySchedule, Purpose};
use symbolon::nostr::{self, EventSigner as InnerSigner};
use symbolon::seal::Sealer;
use symbolon::signal::{self, Kind, Signal, SignalBox as InnerBox};

fn key32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| anyhow!("expected 32 bytes"))
}

/// Every key of a sync group, derived from its 32-byte group secret. `context` names the app and protocol
/// version, so the same secret gives other apps different keys.
#[frb(opaque)]
pub struct GroupKeys {
    keys: KeySchedule,
}

impl GroupKeys {
    #[frb(sync)]
    pub fn new(context: Vec<u8>, secret: Vec<u8>) -> Result<GroupKeys> {
        Ok(Self {
            keys: KeySchedule::new(&context, &secret)?,
        })
    }

    /// A relay topic only group members can compute.
    #[frb(sync)]
    pub fn topic(&self, label: Vec<u8>) -> Vec<u8> {
        self.keys.topic(&label).to_vec()
    }

    /// Six bytes to show on every device so people can compare them.
    #[frb(sync)]
    pub fn fingerprint(&self) -> Vec<u8> {
        self.keys.fingerprint().to_vec()
    }

    /// Encrypts a signalling message for the relay.
    #[frb(sync)]
    pub fn seal(&self, plaintext: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>> {
        Ok(Sealer::new(&self.keys).seal(&plaintext, &aad)?)
    }

    #[frb(sync)]
    pub fn open(&self, sealed: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>> {
        Ok(Sealer::new(&self.keys).open(&sealed, &aad)?)
    }
}

/// This device's long-term key for the Noise handshake.
#[frb(opaque)]
pub struct DeviceKey {
    keypair: StaticKeypair,
}

impl DeviceKey {
    #[frb(sync)]
    pub fn generate() -> Result<DeviceKey> {
        Ok(Self {
            keypair: StaticKeypair::generate()?,
        })
    }

    #[frb(sync)]
    pub fn from_private(private_key: Vec<u8>) -> Result<DeviceKey> {
        Ok(Self {
            keypair: StaticKeypair::from_private(&private_key)?,
        })
    }

    #[frb(sync)]
    pub fn public_key(&self) -> Vec<u8> {
        self.keypair.public().to_vec()
    }

    /// Only for storing the key on this device.
    #[frb(sync)]
    pub fn private_key(&self) -> Vec<u8> {
        self.keypair.private().to_vec()
    }
}

/// Whether this device starts the handshake with `remote_public`.
#[frb(sync)]
pub fn initiates(local_public: Vec<u8>, remote_public: Vec<u8>) -> Result<bool> {
    Ok(handshake::initiates(
        &key32(&local_public)?,
        &key32(&remote_public)?,
    ))
}

#[frb(opaque)]
pub struct NoiseHandshake {
    handshake: Option<Handshake>,
}

impl NoiseHandshake {
    #[frb(sync)]
    pub fn initiator(
        device: &DeviceKey,
        remote_public: Vec<u8>,
        group: &GroupKeys,
        prologue: Vec<u8>,
    ) -> Result<NoiseHandshake> {
        let psk = group.keys.derive(Purpose::NoisePsk);
        let hs = Handshake::initiator(&device.keypair, &key32(&remote_public)?, &psk, &prologue)?;
        Ok(Self {
            handshake: Some(hs),
        })
    }

    #[frb(sync)]
    pub fn responder(
        device: &DeviceKey,
        group: &GroupKeys,
        prologue: Vec<u8>,
    ) -> Result<NoiseHandshake> {
        let psk = group.keys.derive(Purpose::NoisePsk);
        Ok(Self {
            handshake: Some(Handshake::responder(&device.keypair, &psk, &prologue)?),
        })
    }

    fn handshake(&mut self) -> Result<&mut Handshake> {
        self.handshake
            .as_mut()
            .ok_or_else(|| anyhow!(symbolon::Error::HandshakeFinished))
    }

    #[frb(sync)]
    pub fn write_message(&mut self, payload: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.handshake()?.write_message(&payload)?)
    }

    #[frb(sync)]
    pub fn read_message(&mut self, message: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.handshake()?.read_message(&message)?)
    }

    #[frb(sync)]
    pub fn is_finished(&self) -> bool {
        self.handshake.as_ref().is_some_and(Handshake::is_finished)
    }

    /// The other device's public key, known once its first message has been read.
    #[frb(sync)]
    pub fn remote_static(&self) -> Option<Vec<u8>> {
        self.handshake.as_ref()?.remote_static().map(|k| k.to_vec())
    }

    /// Ends the handshake; this object can't be used afterwards.
    #[frb(sync)]
    pub fn into_channel(&mut self) -> Result<SecureChannel> {
        let hs = self
            .handshake
            .take()
            .ok_or_else(|| anyhow!(symbolon::Error::HandshakeFinished))?;
        Ok(SecureChannel {
            channel: hs.into_channel()?,
        })
    }
}

/// Encrypted messages after the handshake. Any rejected message closes it.
#[frb(opaque)]
pub struct SecureChannel {
    channel: Channel,
}

impl SecureChannel {
    #[frb(sync)]
    pub fn encrypt(&mut self, plaintext: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.channel.encrypt(&plaintext)?)
    }

    #[frb(sync)]
    pub fn decrypt(&mut self, ciphertext: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.channel.decrypt(&ciphertext)?)
    }

    #[frb(sync)]
    pub fn is_open(&self) -> bool {
        self.channel.is_open()
    }

    #[frb(sync)]
    pub fn max_plaintext() -> usize {
        symbolon::channel::MAX_PLAINTEXT
    }
}

fn session(bytes: &[u8]) -> Result<signal::SessionId> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("expected a 16-byte session id"))
}

/// Unix seconds come from Dart as a signed 64-bit int.
fn seconds(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| anyhow!("expected non-negative seconds"))
}

/// A random session id for this run of the app (16 bytes, not secret).
#[frb(sync)]
pub fn new_session() -> Result<Vec<u8>> {
    Ok(signal::new_session()?.to_vec())
}

/// A signalling message. `kind` is one of `announce`, `offer`, `answer`, `candidate` and `bye`;
/// `to` is all zeros for announce and bye, which go to everyone and have an empty body.
pub struct SignalMessage {
    pub kind: String,
    pub created_at: i64,
    pub from: Vec<u8>,
    pub to: Vec<u8>,
    /// The sender's claimed device public key; only the handshake proves it.
    pub device: Vec<u8>,
    pub body: Vec<u8>,
}

/// Seals and opens a group's signalling messages, as Nostr event content.
#[frb(opaque)]
pub struct SignalBox {
    inner: InnerBox,
}

impl SignalBox {
    #[frb(sync)]
    pub fn new(group: &GroupKeys) -> SignalBox {
        Self {
            inner: InnerBox::new(&group.keys),
        }
    }

    /// The topic every device in the group posts and subscribes under.
    #[frb(sync)]
    pub fn topic(&self) -> Vec<u8> {
        self.inner.topic().to_vec()
    }

    #[frb(sync)]
    pub fn seal(&self, message: SignalMessage) -> Result<String> {
        let kind = match message.kind.as_str() {
            "announce" => Kind::Announce,
            "offer" => Kind::Offer,
            "answer" => Kind::Answer,
            "candidate" => Kind::Candidate,
            "bye" => Kind::Bye,
            _ => return Err(anyhow!("unknown signal kind")),
        };
        let signal = Signal {
            kind,
            created_at: seconds(message.created_at)?,
            from: session(&message.from)?,
            to: session(&message.to)?,
            device: key32(&message.device)?,
            body: message.body,
        };
        Ok(self.inner.seal(&signal)?)
    }

    /// `now` is this device's Unix time in seconds; messages too far from it are rejected.
    #[frb(sync)]
    pub fn open(&self, content: String, now: i64) -> Result<SignalMessage> {
        let signal = self.inner.open(&content, seconds(now)?)?;
        let kind = match signal.kind {
            Kind::Announce => "announce",
            Kind::Offer => "offer",
            Kind::Answer => "answer",
            Kind::Candidate => "candidate",
            Kind::Bye => "bye",
        };
        Ok(SignalMessage {
            kind: kind.into(),
            created_at: signal.created_at as i64,
            from: signal.from.to_vec(),
            to: signal.to.to_vec(),
            device: signal.device.to_vec(),
            body: signal.body,
        })
    }
}

/// Signs Nostr events with a throwaway key. Make one per app run and don't store it.
#[frb(opaque)]
pub struct EventSigner {
    inner: InnerSigner,
}

impl EventSigner {
    #[frb(sync)]
    pub fn generate() -> Result<EventSigner> {
        Ok(Self {
            inner: InnerSigner::generate()?,
        })
    }

    /// The public key as hex, as relays show it.
    #[frb(sync)]
    pub fn public_key(&self) -> String {
        self.inner.public_key_hex()
    }

    /// A signed signalling event as JSON, to send as `["EVENT", event]`.
    #[frb(sync)]
    pub fn signal_event(&self, created_at: i64, topic: Vec<u8>, content: String) -> Result<String> {
        Ok(self
            .inner
            .signal_event(seconds(created_at)?, &key32(&topic)?, &content)?)
    }
}

/// The relay filter for a topic's signalling events from `since` on, to send as
/// `["REQ", subscriptionId, filter]`.
#[frb(sync)]
pub fn signal_filter(topic: Vec<u8>, since: i64) -> Result<String> {
    Ok(nostr::signal_filter(&key32(&topic)?, seconds(since)?))
}

#[frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
}

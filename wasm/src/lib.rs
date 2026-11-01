//! Symbolon for JavaScript. Every byte string is a `Uint8Array`, and every error is thrown as a JS
//! `Error`. Arguments are checked to really be `Uint8Array`s: wasm-bindgen's own conversion would
//! silently turn a string or a plain array into other bytes (a 32-character string became 32 zero
//! bytes), which for a secret means a guessable key. Keys stay in wasm memory: JavaScript only sees results, public keys and, for storage, the
//! device's own private key.
//!
//! This build is single-threaded, so it needs no special server headers.

use js_sys::Uint8Array;
use symbolon::channel::{self, Channel as InnerChannel};
use symbolon::handshake::{self, Handshake as InnerHandshake, StaticKeypair};
use symbolon::keys::{KeySchedule, Purpose};
use symbolon::seal::Sealer;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use zeroize::Zeroizing;

fn js<E: std::fmt::Display>(err: E) -> JsError {
    JsError::new(&err.to_string())
}

/// Copies a `Uint8Array` argument into wasm memory, refusing anything else. The copy is wiped when
/// dropped, since some arguments are secrets.
fn bytes(value: &Uint8Array) -> Result<Zeroizing<Vec<u8>>, JsError> {
    if !value.is_instance_of::<Uint8Array>() {
        return Err(JsError::new("expected a Uint8Array"));
    }
    Ok(Zeroizing::new(value.to_vec()))
}

/// A 32-byte key; any other length is an error, never truncated or padded.
fn key32(value: &Uint8Array) -> Result<[u8; 32], JsError> {
    bytes(value)?
        .as_slice()
        .try_into()
        .map_err(|_| JsError::new("expected a 32-byte key"))
}

/// Every key of a group, derived from its secret. `context` names the app and protocol version, such
/// as `my-app/v1`, so two apps with the same secret get different keys.
#[wasm_bindgen]
pub struct GroupKeys {
    keys: KeySchedule,
}

#[wasm_bindgen]
impl GroupKeys {
    #[wasm_bindgen(constructor)]
    pub fn new(context: &Uint8Array, secret: &Uint8Array) -> Result<GroupKeys, JsError> {
        Ok(Self {
            keys: KeySchedule::new(&bytes(context)?, &bytes(secret)?).map_err(js)?,
        })
    }

    /// A relay topic for `label` that only group members can compute.
    pub fn topic(&self, label: &Uint8Array) -> Result<Vec<u8>, JsError> {
        Ok(self.keys.topic(&bytes(label)?).to_vec())
    }

    /// Six bytes for people to compare on their devices.
    pub fn fingerprint(&self) -> Vec<u8> {
        self.keys.fingerprint().to_vec()
    }

    pub fn seal(&self, plaintext: &Uint8Array, aad: &Uint8Array) -> Result<Vec<u8>, JsError> {
        Sealer::new(&self.keys)
            .seal(&bytes(plaintext)?, &bytes(aad)?)
            .map_err(js)
    }

    pub fn open(&self, sealed: &Uint8Array, aad: &Uint8Array) -> Result<Vec<u8>, JsError> {
        Sealer::new(&self.keys)
            .open(&bytes(sealed)?, &bytes(aad)?)
            .map_err(js)
    }
}

/// This device's long-term X25519 key for the handshake.
#[wasm_bindgen]
pub struct DeviceKey {
    keypair: StaticKeypair,
}

#[wasm_bindgen]
impl DeviceKey {
    pub fn generate() -> Result<DeviceKey, JsError> {
        Ok(Self {
            keypair: StaticKeypair::generate().map_err(js)?,
        })
    }

    #[wasm_bindgen(js_name = fromPrivate)]
    pub fn from_private(private_key: &Uint8Array) -> Result<DeviceKey, JsError> {
        Ok(Self {
            keypair: StaticKeypair::from_private(&bytes(private_key)?).map_err(js)?,
        })
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.keypair.public().to_vec()
    }

    /// Only for storing the key on this device.
    #[wasm_bindgen(js_name = privateKey)]
    pub fn private_key(&self) -> Vec<u8> {
        self.keypair.private().to_vec()
    }
}

/// Whether the device with `local_public` starts the handshake with `remote_public`.
#[wasm_bindgen]
pub fn initiates(local_public: &Uint8Array, remote_public: &Uint8Array) -> Result<bool, JsError> {
    Ok(handshake::initiates(
        &key32(local_public)?,
        &key32(remote_public)?,
    ))
}

/// The Noise IKpsk1 handshake. Turn it into a [`Channel`] once [`Handshake::is_finished`] is true.
#[wasm_bindgen]
pub struct Handshake {
    inner: Option<InnerHandshake>,
}

#[wasm_bindgen]
impl Handshake {
    pub fn initiator(
        device: &DeviceKey,
        remote_public: &Uint8Array,
        group: &GroupKeys,
        prologue: &Uint8Array,
    ) -> Result<Handshake, JsError> {
        let psk = group.keys.derive(Purpose::NoisePsk);
        let hs = InnerHandshake::initiator(
            &device.keypair,
            &key32(remote_public)?,
            &psk,
            &bytes(prologue)?,
        )
        .map_err(js)?;
        Ok(Self { inner: Some(hs) })
    }

    pub fn responder(
        device: &DeviceKey,
        group: &GroupKeys,
        prologue: &Uint8Array,
    ) -> Result<Handshake, JsError> {
        let psk = group.keys.derive(Purpose::NoisePsk);
        let hs = InnerHandshake::responder(&device.keypair, &psk, &bytes(prologue)?).map_err(js)?;
        Ok(Self { inner: Some(hs) })
    }

    fn inner(&mut self) -> Result<&mut InnerHandshake, JsError> {
        self.inner
            .as_mut()
            .ok_or_else(|| js(symbolon::Error::HandshakeFinished))
    }

    #[wasm_bindgen(js_name = writeMessage)]
    pub fn write_message(&mut self, payload: &Uint8Array) -> Result<Vec<u8>, JsError> {
        self.inner()?.write_message(&bytes(payload)?).map_err(js)
    }

    #[wasm_bindgen(js_name = readMessage)]
    pub fn read_message(&mut self, message: &Uint8Array) -> Result<Vec<u8>, JsError> {
        self.inner()?.read_message(&bytes(message)?).map_err(js)
    }

    #[wasm_bindgen(getter, js_name = isFinished)]
    pub fn is_finished(&self) -> bool {
        self.inner.as_ref().is_some_and(InnerHandshake::is_finished)
    }

    /// The other device's public key, once its first message has been read.
    #[wasm_bindgen(getter, js_name = remoteStatic)]
    pub fn remote_static(&self) -> Option<Vec<u8>> {
        self.inner.as_ref()?.remote_static().map(|k| k.to_vec())
    }

    /// Ends the handshake; this object can't be used afterwards.
    #[wasm_bindgen(js_name = intoChannel)]
    pub fn into_channel(&mut self) -> Result<Channel, JsError> {
        let hs = self
            .inner
            .take()
            .ok_or_else(|| js(symbolon::Error::HandshakeFinished))?;
        Ok(Channel {
            inner: hs.into_channel().map_err(js)?,
        })
    }
}

/// Encrypted messages after the handshake. Any rejected message closes it.
#[wasm_bindgen]
pub struct Channel {
    inner: InnerChannel,
}

#[wasm_bindgen]
impl Channel {
    pub fn encrypt(&mut self, plaintext: &Uint8Array) -> Result<Vec<u8>, JsError> {
        self.inner.encrypt(&bytes(plaintext)?).map_err(js)
    }

    pub fn decrypt(&mut self, ciphertext: &Uint8Array) -> Result<Vec<u8>, JsError> {
        self.inner.decrypt(&bytes(ciphertext)?).map_err(js)
    }

    #[wasm_bindgen(getter, js_name = isOpen)]
    pub fn is_open(&self) -> bool {
        self.inner.is_open()
    }

    /// The largest plaintext one message can carry.
    #[wasm_bindgen(js_name = maxPlaintext)]
    pub fn max_plaintext() -> usize {
        channel::MAX_PLAINTEXT
    }
}

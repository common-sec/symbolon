//! Signalling: the few messages devices exchange through a public relay before they have a channel,
//! such as "I'm here", WebRTC offers and answers, and ICE candidates.
//!
//! Each message is sealed with the group's seal key (see [`crate::seal`]) and bound to the topic it
//! is posted under, so a relay sees only random-looking bytes, and a message copied to another topic
//! or group is rejected. A message also carries the time it was made, and [`SignalBox::open`] rejects
//! one outside [`MAX_AGE_SECS`] of the reader's clock, so a relay can't replay old offers later.
//!
//! Wire format of the plaintext, all integers big-endian:
//!
//! ```text
//! version (1) = 1 | kind (1) | created_at (8, Unix seconds) | from (16) | to (16) | device (32)
//! | body length (2) | body
//! ```
//!
//! `from` and `to` are session ids: random per app run, so a device can tell its own messages and
//! the messages meant for it apart from the rest. `to` is all zeros for messages to everyone in the
//! group. `device` is the sender's Noise static public key, which the receiver uses to start the
//! handshake. Nothing here is authenticated beyond group membership: any member can claim any `device`,
//! and only the Noise handshake proves it.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::keys::KeySchedule;
use crate::keys::KEY_LEN;
use crate::seal::{Sealer, MAX_SEALED};
use crate::{Error, Result};

pub const SESSION_LEN: usize = 16;
/// Large enough for an SDP offer with its ICE candidates; anything larger is refused.
pub const MAX_BODY: usize = 8 * 1024;
/// How far a message's time may be from the reader's clock, either way.
pub const MAX_AGE_SECS: u64 = 120;

const VERSION: u8 = 1;
const HEADER_LEN: usize = 1 + 1 + 8 + SESSION_LEN + SESSION_LEN + KEY_LEN + 2;
const AAD_PREFIX: &[u8] = b"symbolon/signal/v1";
const TOPIC_LABEL: &[u8] = b"signal";

pub type SessionId = [u8; SESSION_LEN];

/// The session id that addresses everyone in the group.
pub const EVERYONE: SessionId = [0; SESSION_LEN];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// "I'm online". Sent to everyone, with an empty body.
    Announce = 1,
    /// A connection offer, for example a WebRTC SDP offer.
    Offer = 2,
    /// The answer to an offer.
    Answer = 3,
    /// A further connection candidate, for example a WebRTC ICE candidate.
    Candidate = 4,
    /// "I'm going offline". Sent to everyone, with an empty body.
    Bye = 5,
}

impl Kind {
    fn from_byte(byte: u8) -> Result<Self> {
        Ok(match byte {
            1 => Kind::Announce,
            2 => Kind::Offer,
            3 => Kind::Answer,
            4 => Kind::Candidate,
            5 => Kind::Bye,
            _ => return Err(Error::Rejected),
        })
    }

    /// Announce and Bye go to everyone and carry nothing; the others go to one session.
    fn is_broadcast(self) -> bool {
        matches!(self, Kind::Announce | Kind::Bye)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signal {
    pub kind: Kind,
    pub created_at: u64,
    pub from: SessionId,
    pub to: SessionId,
    pub device: [u8; KEY_LEN],
    pub body: Vec<u8>,
}

impl Signal {
    fn check(&self) -> Result<()> {
        let broadcast = self.kind.is_broadcast();
        if self.from == EVERYONE
            || (self.to == EVERYONE) != broadcast
            || (broadcast && !self.body.is_empty())
            || self.body.len() > MAX_BODY
        {
            return Err(Error::Rejected);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>> {
        self.check()?;
        let mut out = Vec::with_capacity(HEADER_LEN + self.body.len());
        out.push(VERSION);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out.extend_from_slice(&self.from);
        out.extend_from_slice(&self.to);
        out.extend_from_slice(&self.device);
        out.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN || bytes[0] != VERSION {
            return Err(Error::Rejected);
        }
        let take = |at: usize, len: usize| &bytes[at..at + len];
        let kind = Kind::from_byte(bytes[1])?;
        let created_at = u64::from_be_bytes(take(2, 8).try_into().unwrap());
        let from: SessionId = take(10, SESSION_LEN).try_into().unwrap();
        let to: SessionId = take(26, SESSION_LEN).try_into().unwrap();
        let device: [u8; KEY_LEN] = take(42, KEY_LEN).try_into().unwrap();
        let body_len = u16::from_be_bytes(take(74, 2).try_into().unwrap()) as usize;
        if bytes.len() != HEADER_LEN + body_len {
            return Err(Error::Rejected);
        }
        let signal = Signal {
            kind,
            created_at,
            from,
            to,
            device,
            body: bytes[HEADER_LEN..].to_vec(),
        };
        signal.check()?;
        Ok(signal)
    }
}

/// A random session id for this run of the app. Not secret.
pub fn new_session() -> Result<SessionId> {
    let mut id = EVERYONE;
    while id == EVERYONE {
        getrandom::fill(&mut id).map_err(|_| Error::Random)?;
    }
    Ok(id)
}

/// Seals and opens signalling messages for one group.
pub struct SignalBox {
    sealer: Sealer,
    topic: [u8; 32],
}

impl SignalBox {
    pub fn new(keys: &KeySchedule) -> Self {
        Self {
            sealer: Sealer::new(keys),
            topic: keys.topic(TOPIC_LABEL),
        }
    }

    /// The topic to post and subscribe under. Only group members can compute it, and it is the same
    /// for every device in the group.
    pub fn topic(&self) -> [u8; 32] {
        self.topic
    }

    fn aad(&self) -> Vec<u8> {
        [AAD_PREFIX, &self.topic].concat()
    }

    /// The sealed message as standard base64, ready to be a relay event's content.
    pub fn seal(&self, signal: &Signal) -> Result<String> {
        let sealed = self.sealer.seal(&signal.encode()?, &self.aad())?;
        Ok(B64.encode(sealed))
    }

    /// Opens a relay event's content. `now` is the reader's Unix time in seconds. Rejects anything
    /// that isn't a well-formed message of this group and topic made within [`MAX_AGE_SECS`] of `now`.
    pub fn open(&self, content: &str, now: u64) -> Result<Signal> {
        // Base64 of the largest sealed message, rounded up; refuse before decoding anything larger.
        if content.len() > MAX_SEALED.div_ceil(3) * 4 {
            return Err(Error::TooLarge);
        }
        let sealed = B64.decode(content).map_err(|_| Error::Rejected)?;
        let signal = Signal::decode(&self.sealer.open(&sealed, &self.aad())?)?;
        if signal.created_at.abs_diff(now) > MAX_AGE_SECS {
            return Err(Error::Rejected);
        }
        Ok(signal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn group(context: &[u8], secret: u8) -> SignalBox {
        SignalBox::new(&KeySchedule::new(context, &[secret; 32]).unwrap())
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

    #[test]
    fn round_trip() {
        let g = group(b"app/v1", 7);
        let content = g.seal(&offer()).unwrap();
        assert_eq!(g.open(&content, NOW + 5).unwrap(), offer());
    }

    #[test]
    fn other_group_or_context_is_rejected() {
        let content = group(b"app/v1", 7).seal(&offer()).unwrap();
        assert_eq!(
            group(b"app/v1", 8).open(&content, NOW),
            Err(Error::Rejected)
        );
        assert_eq!(
            group(b"other/v1", 7).open(&content, NOW),
            Err(Error::Rejected)
        );
    }

    #[test]
    fn old_or_future_messages_are_rejected() {
        let g = group(b"app/v1", 7);
        let content = g.seal(&offer()).unwrap();
        assert!(g.open(&content, NOW + MAX_AGE_SECS).is_ok());
        assert_eq!(
            g.open(&content, NOW + MAX_AGE_SECS + 1),
            Err(Error::Rejected)
        );
        assert_eq!(
            g.open(&content, NOW - MAX_AGE_SECS - 1),
            Err(Error::Rejected)
        );
    }

    #[test]
    fn broadcasts_and_direct_messages_are_addressed_correctly() {
        let g = group(b"app/v1", 7);
        let announce = Signal {
            kind: Kind::Announce,
            to: EVERYONE,
            body: vec![],
            ..offer()
        };
        assert!(g.seal(&announce).is_ok());
        // An announce with a body, an offer to everyone, or a message from nobody is refused.
        assert!(g
            .seal(&Signal {
                body: vec![1],
                ..announce.clone()
            })
            .is_err());
        assert!(g
            .seal(&Signal {
                to: EVERYONE,
                ..offer()
            })
            .is_err());
        assert!(g
            .seal(&Signal {
                from: EVERYONE,
                ..offer()
            })
            .is_err());
    }

    #[test]
    fn size_limits() {
        let g = group(b"app/v1", 7);
        let max = Signal {
            body: vec![0; MAX_BODY],
            ..offer()
        };
        assert_eq!(g.open(&g.seal(&max).unwrap(), NOW).unwrap(), max);
        assert!(g
            .seal(&Signal {
                body: vec![0; MAX_BODY + 1],
                ..offer()
            })
            .is_err());
        assert_eq!(g.open(&"A".repeat(30_000), NOW), Err(Error::TooLarge));
        assert_eq!(g.open("not base64!", NOW), Err(Error::Rejected));
    }

    #[test]
    fn malformed_plaintext_is_rejected() {
        let good = offer().encode().unwrap();
        let mut bad_version = good.clone();
        bad_version[0] = 2;
        let mut bad_kind = good.clone();
        bad_kind[1] = 9;
        let mut extra = good.clone();
        extra.push(0);
        for bytes in [
            bad_version,
            bad_kind,
            extra,
            good[..good.len() - 1].to_vec(),
            vec![],
        ] {
            assert_eq!(Signal::decode(&bytes), Err(Error::Rejected));
        }
        assert_eq!(Signal::decode(&good).unwrap(), offer());
    }

    #[test]
    fn sessions_are_random_and_never_everyone() {
        let a = new_session().unwrap();
        assert_ne!(a, EVERYONE);
        assert_ne!(a, new_session().unwrap());
    }
}

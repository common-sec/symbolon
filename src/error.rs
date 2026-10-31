/// Every failure is reported without detail about which check failed, so an attacker learns nothing
/// from the error beyond "rejected".
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid key material")]
    InvalidKey,
    #[error("message too large")]
    TooLarge,
    #[error("message rejected")]
    Rejected,
    #[error("handshake not finished")]
    HandshakeIncomplete,
    #[error("handshake already finished")]
    HandshakeFinished,
    #[error("no random numbers available")]
    Random,
}

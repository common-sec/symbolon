//! Hash of the core crate's sources, written by `tool/core_hash.sh --write`. It is here so that a
//! change to the core crate changes this crate's cargokit hash, and with it the prebuilt library's name.
#[allow(dead_code)]
pub const CORE_SOURCE_HASH: &str = "d127f848fac2c79f4007c7f82e53a07aa5fffdf8e548e8bd24335bf10ffce9c4";

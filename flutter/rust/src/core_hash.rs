//! Hash of the core crate's sources, written by `tool/core_hash.sh --write`. It is here so that a
//! change to the core crate changes this crate's cargokit hash, and with it the prebuilt library's name.
#[allow(dead_code)]
pub const CORE_SOURCE_HASH: &str = "a0dc28b21ed1862f9819e9cfc8fd9d1cf68999bfd9ee0966b96f40f2c43e1703";

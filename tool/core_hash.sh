#!/usr/bin/env bash
# Prints a hash of the core crate's source code: every .rs file under src/. Its dependencies don't
# need hashing: flutter/rust/Cargo.lock pins them, and cargokit hashes that file.
#
# cargokit names prebuilt Flutter libraries by a hash of flutter/rust only, so a change to the core
# crate alone would keep the old name and apps would download a library built from old code.
# flutter/rust/src/core_hash.rs records this hash; CI fails when it is out of date, and updating it
# changes the library's name.
#   tool/core_hash.sh            print the hash
#   tool/core_hash.sh --write    update flutter/rust/src/core_hash.rs
set -euo pipefail
cd "$(dirname "$0")/.."
hash=$( find src -name '*.rs' | LC_ALL=C sort |
  while read -r f; do printf '%s\n' "$f"; tr -d '\r' < "$f"; done | { command -v sha256sum >/dev/null && sha256sum || shasum -a 256; } | cut -d' ' -f1)
if [ "${1:-}" = --write ]; then
  cat > flutter/rust/src/core_hash.rs <<RS
//! Hash of the core crate's sources, written by \`tool/core_hash.sh --write\`. It is here so that a
//! change to the core crate changes this crate's cargokit hash, and with it the prebuilt library's name.
#[allow(dead_code)]
pub const CORE_SOURCE_HASH: &str = "$hash";
RS
fi
echo "$hash"

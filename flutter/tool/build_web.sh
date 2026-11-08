#!/usr/bin/env bash
# Builds Symbolon's JavaScript binding (../wasm) into OUT_DIR, for a Flutter web app to serve.
# Apps run it from wherever pub put this package, so the binding comes from the same commit as the
# Dart code:
#   tool/build_web.sh web/symbolon
# Needs rustup and the wasm-bindgen CLI version that ../wasm/Cargo.toml pins (installed if missing).
set -euo pipefail
out=$(mkdir -p "$1" && cd "$1" && pwd)
root=$(cd "$(dirname "$0")/../.." && pwd)
# Not inside the package: pub's copy of it may be read-only or shared between apps.
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/symbolon-wasm-target}

bindgen=$(sed -n 's/^wasm-bindgen = "=\(.*\)"/\1/p' "$root/wasm/Cargo.toml")
if [ "$(wasm-bindgen --version 2>/dev/null | cut -d' ' -f2)" != "$bindgen" ]; then
  cargo install wasm-bindgen-cli --version "$bindgen" --locked
fi

rustup target add wasm32-unknown-unknown >/dev/null
(cd "$root" && cargo build --locked --release -p symbolon-wasm --target wasm32-unknown-unknown)
rm -f "$out"/symbolon_wasm*
wasm-bindgen --target web --no-typescript --out-dir "$out" \
  "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/symbolon_wasm.wasm"
echo "Built Symbolon's JavaScript binding into $out"

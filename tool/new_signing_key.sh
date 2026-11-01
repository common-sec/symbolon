#!/usr/bin/env bash
# Creates the key that signs prebuilt Flutter libraries, for a maintainer to run once.
# The private key goes straight into the repository secret CARGOKIT_PRIVATE_KEY and is never printed
# or written to disk. The public key goes into flutter/rust/cargokit.yaml, where apps read it to
# check every library they download; commit that change.
# Needs Dart (or Flutter) and the GitHub CLI, signed in with admin rights on the repository.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=${1:-common-sec/symbolon}

out=$(cd flutter/cargokit/build_tool && dart pub get >/dev/null && dart run build_tool gen-key)
private=$(printf '%s\n' "$out" | sed -n 's/^Private Key: //p')
public=$(printf '%s\n' "$out" | sed -n 's/^Public Key: //p')
unset out
[ ${#private} -eq 128 ] && [ ${#public} -eq 64 ] || { echo "gen-key output not understood" >&2; exit 1; }

printf '%s' "$private" | gh secret set CARGOKIT_PRIVATE_KEY --repo "$repo"
unset private

cat > flutter/rust/cargokit.yaml <<YAML
# Apps download prebuilt libraries from Symbolon's releases and check them with this key. A library
# that is missing or fails the check is built from source instead.
precompiled_binaries:
  url_prefix: https://github.com/$repo/releases/download/precompiled_
  public_key: $public
YAML
echo "Secret CARGOKIT_PRIVATE_KEY set on $repo."
echo "Public key $public written to flutter/rust/cargokit.yaml: commit it."

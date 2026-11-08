#!/usr/bin/env bash
# Creates the key that signs prebuilt Flutter libraries, for a maintainer to run once.
# The private key goes straight into the secret CARGOKIT_PRIVATE_KEY of the `release` environment,
# which only the main branch can use, and is never printed or written to disk. Nobody needs it to
# build: apps only use the public key. The public key goes into flutter/rust/cargokit.yaml, where apps read it to
# check every library they download; commit that change.
# Needs Dart (or Flutter, or Docker: DART=docker runs it in the pinned image from tool/signing-key/Dockerfile) and the GitHub CLI,
# signed in with admin rights on the repository.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=${1:-common-sec/symbolon}

if [ "${DART:-dart}" = docker ]; then
  docker build -q -t symbolon-signing-key -f tool/signing-key/Dockerfile flutter/cargokit/build_tool >/dev/null
  out=$(docker run --rm --network none symbolon-signing-key)
else
  out=$(cd flutter/cargokit/build_tool && dart pub get >/dev/null && dart run build_tool gen-key)
fi
private=$(printf '%s\n' "$out" | sed -n 's/^Private Key: //p')
public=$(printf '%s\n' "$out" | sed -n 's/^Public Key: //p')
unset out
[ ${#private} -eq 128 ] && [ ${#public} -eq 64 ] || { echo "gen-key output not understood" >&2; exit 1; }

# The environment, limited to the main branch, so no other branch's workflow can read the key.
gh api -X PUT "repos/$repo/environments/release" --input - >/dev/null <<'JSON'
{"deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
JSON
gh api "repos/$repo/environments/release/deployment-branch-policies" --jq '.branch_policies[].name' |
  grep -qx main ||
  gh api -X POST "repos/$repo/environments/release/deployment-branch-policies" -f name=main -f type=branch >/dev/null

printf '%s' "$private" | gh secret set CARGOKIT_PRIVATE_KEY --env release --repo "$repo"
unset private

cat > flutter/rust/cargokit.yaml <<YAML
# Apps download prebuilt libraries from Symbolon's releases and check them with this key. A library
# that is missing or fails the check is built from source instead.
precompiled_binaries:
  url_prefix: https://github.com/$repo/releases/download/precompiled_
  public_key: $public
YAML
echo "Secret CARGOKIT_PRIVATE_KEY set in the release environment of $repo (main only)."
echo "Public key $public written to flutter/rust/cargokit.yaml: commit it."

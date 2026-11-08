#!/usr/bin/env bash
# Creates the key that signs prebuilt Flutter libraries, for a maintainer to run once.
# The private key goes straight into the secret CARGOKIT_PRIVATE_KEY of the `release` environment and
# is never printed or written to disk. Nobody needs it to build: apps only use the public key.
#
# The script doesn't create or change the environment, so it can't undo its protection rules. Set it
# up first in Settings > Environments > New environment, named `release`:
#   - Deployment branches and tags: "Selected branches and tags", with only `main`, so no workflow
#     on another branch can read the key.
#   - Optionally, Required reviewers, so each release run waits for a maintainer's approval.
#
# It refuses to run when flutter/rust/cargokit.yaml already exists, since a new key replaces the old
# one: pass --rotate to do that on purpose.
#
# The public key goes into flutter/rust/cargokit.yaml, where apps read it to check every library they
# download; commit that change.
#
# Needs the GitHub CLI, signed in with admin rights on the repository, and Dart or Flutter. With
# DART=docker, Dart runs in the pinned image from tool/signing-key/Dockerfile instead.
set -euo pipefail
cd "$(dirname "$0")/.."
rotate=false
if [ "${1:-}" = --rotate ]; then rotate=true; shift; fi
repo=${1:-common-sec/symbolon}

if [ -f flutter/rust/cargokit.yaml ] && ! $rotate; then
  echo "flutter/rust/cargokit.yaml exists: a key is already set up. Use --rotate to replace it." >&2
  exit 1
fi
if ! gh api "repos/$repo/environments/release" >/dev/null 2>&1; then
  echo "No 'release' environment on $repo. Create it first (see the comment at the top)." >&2
  exit 1
fi

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

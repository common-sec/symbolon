# Runs cargokit's key generator for tool/new_signing_key.sh (DART=docker), so a maintainer needs no
# Dart install. The image is pinned by digest; Dependabot proposes updates.
# Built with flutter/cargokit/build_tool as the context.
FROM dart:3.13.7@sha256:854f3c50b1cbd4a5a54c9fa67d4f5b6702ac49b4a26d21a80e7712a72528b215

WORKDIR /build_tool
COPY . .
RUN dart pub get
# No network at run time: the key is generated offline and printed once to the calling script.
ENTRYPOINT ["dart", "run", "build_tool", "gen-key"]

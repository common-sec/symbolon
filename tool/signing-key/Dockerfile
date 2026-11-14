# Runs cargokit's key generator for tool/new_signing_key.sh (DART=docker), so a maintainer needs no
# Dart install. The image is pinned by digest; Dependabot proposes updates.
# Built with flutter/cargokit/build_tool as the context.
FROM dart:3.14.0-315.3.beta@sha256:d4057f49c8e04e8795486a6f4b449b5d3db9ace5a8fb2a3599fc9263c77daad8

WORKDIR /build_tool
COPY . .
RUN dart pub get
# No network at run time: the key is generated offline and printed once to the calling script.
ENTRYPOINT ["dart", "run", "build_tool", "gen-key"]

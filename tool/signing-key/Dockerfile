# Runs cargokit's key generator for tool/new_signing_key.sh (DART=docker), so a maintainer needs no
# Dart install. The image is pinned by digest; Dependabot proposes updates.
# Built with flutter/cargokit/build_tool as the context.
FROM dart:3.14.0@sha256:c78970229c8944bd6076caf4e5977ef569ba66750d301a2149f63b41a6725cec

WORKDIR /build_tool
COPY . .
RUN dart pub get
# No network at run time: the key is generated offline and printed once to the calling script.
ENTRYPOINT ["dart", "run", "build_tool", "gen-key"]

# Runs cargokit's key generator for tool/new_signing_key.sh (DART=docker), so a maintainer needs no
# Dart install. The image is pinned by digest; Dependabot proposes updates.
# Built with flutter/cargokit/build_tool as the context.
FROM dart:3.13.6@sha256:bf07cd831c34d7cef047bcd50803fa38e3af59664a276440893ca9db77014ca0

WORKDIR /build_tool
COPY . .
RUN dart pub get
# No network at run time: the key is generated offline and printed once to the calling script.
ENTRYPOINT ["dart", "run", "build_tool", "gen-key"]

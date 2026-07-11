FROM debian:trixie-slim@sha256:cedb1ef40439206b673ee8b33a46a03a0c9fa90bf3732f54704f99cb061d2c5a

RUN apt-get update \
    && apt-get install --yes --no-install-recommends gcc libc6-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY peer.c /usr/src/dtls09-peer.c

RUN gcc -O2 -Wall -Wextra -o /usr/local/bin/dtls09-peer /usr/src/dtls09-peer.c -lcrypto

ENTRYPOINT ["/usr/local/bin/dtls09-peer"]

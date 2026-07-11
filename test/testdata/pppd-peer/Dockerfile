FROM debian:trixie-slim@sha256:cedb1ef40439206b673ee8b33a46a03a0c9fa90bf3732f54704f99cb061d2c5a

ARG PPP_VERSION=2.5.2-1+1

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ppp="${PPP_VERSION}" gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY peer.c /usr/src/pppd-peer.c

RUN gcc -O2 -Wall -Wextra -Werror -o /usr/local/bin/pppd-peer /usr/src/pppd-peer.c

EXPOSE 4433/tcp 4433/udp

ENTRYPOINT ["/usr/local/bin/pppd-peer"]

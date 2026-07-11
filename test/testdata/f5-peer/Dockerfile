FROM debian:trixie-slim@sha256:cedb1ef40439206b673ee8b33a46a03a0c9fa90bf3732f54704f99cb061d2c5a

ARG PPP_VERSION=2.5.2-1+1

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        openssl \
        ppp="${PPP_VERSION}" \
        python3 \
    && rm -rf /var/lib/apt/lists/*

COPY f5_peer.py /usr/local/bin/f5-peer

EXPOSE 4433/tcp 4433/udp

ENTRYPOINT ["python3", "/usr/local/bin/f5-peer"]

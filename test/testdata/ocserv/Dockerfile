FROM debian:trixie-slim@sha256:cedb1ef40439206b673ee8b33a46a03a0c9fa90bf3732f54704f99cb061d2c5a

ARG OCSERV_VERSION=1.3.0-2

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ocserv="${OCSERV_VERSION}" iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY ocpasswd /etc/ocserv/ocpasswd
COPY ocserv.conf /etc/ocserv/ocserv.conf
COPY ocserv-legacy.conf /etc/ocserv/ocserv-legacy.conf
COPY server-cert.pem /etc/ocserv/server-cert.pem
COPY server-key.pem /etc/ocserv/server-key.pem

EXPOSE 443/tcp 443/udp

ENTRYPOINT ["ocserv", "-f", "-d", "4", "-c", "/etc/ocserv/ocserv.conf"]

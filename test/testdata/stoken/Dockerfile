FROM debian:trixie-slim@sha256:cedb1ef40439206b673ee8b33a46a03a0c9fa90bf3732f54704f99cb061d2c5a

ARG STOKEN_COMMIT=837e843e8850d14a5d49d799b066d61d04fd649a

RUN apt-get update \
    && apt-get install --yes --no-install-recommends autoconf automake build-essential ca-certificates git libtool libxml2-dev nettle-dev pkg-config \
    && git init /usr/src/stoken \
    && git -C /usr/src/stoken remote add origin https://github.com/cernekee/stoken.git \
    && git -C /usr/src/stoken fetch --depth=1 origin "${STOKEN_COMMIT}" \
    && git -C /usr/src/stoken checkout --detach FETCH_HEAD \
    && cd /usr/src/stoken \
    && ./autogen.sh \
    && ./configure \
    && make -j2 \
    && make install \
    && ldconfig \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/local/bin/stoken"]

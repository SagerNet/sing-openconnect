# Pulse ESP peer

Build the independent UDP peer with the system OpenSSL and liblzo2
implementations:

```sh
cc -std=c11 -Wall -Wextra -Werror \
  -I"$(pkg-config --variable=includedir lzo2)" \
  $(pkg-config --cflags openssl lzo2) esp_peer.c \
  $(pkg-config --libs openssl lzo2) -o pulse-esp-peer
```

Start it with:

```text
pulse-esp-peer PORT ENC AUTH C2S_SPI S2C_SPI C2S_ENC_KEY C2S_AUTH_KEY S2C_ENC_KEY S2C_AUTH_KEY [INITIAL_SEQUENCE] [EXPECTED_PROBE]
```

`PORT` may be zero. The peer binds IPv4 loopback and prints
`READY <selected-port>` once liblzo2 has passed a round-trip self-test and the
UDP socket is ready. SPIs use C integer syntax, including `0x` hexadecimal
values. Keys are hexadecimal without separators. Supported suites are
`aes-128-cbc` and `aes-256-cbc`, combined with `md5`, `sha1`, or `sha256`.
`INITIAL_SEQUENCE` defaults to `zero`, which requires sequence zero for a new
SA (including a type-1 rekey with new SPI/key material). Use `continuation`
when restarting the peer with an existing SA after a client transport failure;
the first accepted sequence must then be nonzero. `zero-established` requires
sequence zero for a rekeyed SA on an already established UDP transport, so its
first packet may be data. `EXPECTED_PROBE` may be `probe4` or `probe41`; a
one-zero-byte probe with the other next-header is rejected.

The C2S material authenticates and decrypts client datagrams. The first valid
C2S sequence must match the selected initial policy, and every uninterrupted
later explicit IV must match the OpenConnect CBC/HMAC next-IV chain. A forward
sequence gap is accepted because a failed UDP write can consume client
sequence and IV state without delivering the datagram. The peer prints
`CONTINUATION <observed-sequence>`, verifies the received packet normally, and
resynchronizes the next-IV chain from it; a replay, backward sequence, or reset
to zero remains invalid. A Pulse probe is an ESP payload containing
the single byte zero; its response preserves the probe's next-header value of
4 or 41. Accepted probes print `PROBE <next-header>`, while data prints
`DATA <next-header> <sequence>`. After that exchange, the peer turns valid ICMPv4 and ICMPv6 echo
requests into real echo replies. IPv4 replies are compressed by liblzo2 and
sent with next-header 5; IPv6 replies are sent with next-header 41. Every
encrypted reply is transmitted twice as the identical UDP datagram so a
client integration test can observe replay suppression.

Three exact ICMPv4 echo payloads inject one authenticated invalid next-header
5 datagram before the normal compressed echo reply:

- `pulse-lzo-malformed` sends the three-byte stream `00 00 00`.
- `pulse-lzo-trailing` appends `42` to an otherwise legal liblzo2 stream.
- `pulse-lzo-oversize` compresses 1401 bytes for a negotiated MTU of 1400.

The peer prints `INJECTED LZO <kind>` after each invalid datagram is sent. The
following valid echo proves that a receiver dropped only the invalid frame and
kept the ESP channel live.

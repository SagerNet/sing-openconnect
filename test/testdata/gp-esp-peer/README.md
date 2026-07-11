# GlobalProtect ESP peer

Build with the system OpenSSL implementation:

```sh
cc -std=c11 -Wall -Wextra -Werror $(pkg-config --cflags openssl) \
  esp_peer.c $(pkg-config --libs openssl) -o esp-peer
```

Start it with:

```text
esp-peer PORT ENC AUTH C2S_SPI S2C_SPI C2S_ENC_KEY C2S_AUTH_KEY S2C_ENC_KEY S2C_AUTH_KEY
```

`PORT` may be zero. The peer binds IPv4 loopback and writes `PORT <selected-port>` to stdout once it is ready. SPIs use C integer syntax, including `0x` hexadecimal values. Keys are hexadecimal without separators. Supported suites are `aes-128-cbc` and `aes-256-cbc`, combined with `md5`, `sha1`, or `sha256`.

The C2S material authenticates and decrypts client datagrams. The peer requires the first C2S sequence to be zero and verifies the OpenConnect OpenSSL next-IV chain on subsequent datagrams. The S2C material encrypts ICMPv4 and ICMPv6 echo replies with independently generated explicit IVs and a sequence beginning at zero. Every encrypted reply is sent twice as the same UDP datagram so the public client integration test can observe replay suppression through normal packet delivery.

# GlobalProtect TLS and GPST peer

`m2_gp_transport_interop_test.go` implements an independent TLS peer on a real
TCP listener. It parses ordinary GlobalProtect POST requests and the headerless
raw GPST GET on the same TLS endpoint, then exchanges `START_TUNNEL` and GPST
frames without importing any production parser or codec.

The tests pair this peer with the independent OpenSSL UDP oracle in
`../gp-esp-peer`. Together they exercise public `openconnect.Client`
authentication, configuration, HIP, GPST, and ESP behavior.

`hip_wrapper.go` is built as a separate executable during the HIP interop test.
It validates the wrapper process contract from environment-provided
expectations and writes the configured report to stdout.

Run the interop matrix with:

```sh
OPENCONNECT_IT=1 go test -race -count=1 -run '^TestM2GlobalProtect' ./...
```

The ESP cases require a C compiler, `pkg-config`, and OpenSSL development
headers and libraries.

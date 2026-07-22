module github.com/sagernet/sing-openconnect/test

go 1.24.0

require (
	github.com/sagernet/sing v0.8.12-0.20260702081104-2ded2af32d3d
	github.com/sagernet/sing-openconnect v0.0.0
)

replace github.com/sagernet/sing-openconnect => ..

require (
	github.com/anchore/go-lzo v0.1.0 // indirect
	github.com/google/certificate-transparency-go v1.3.2 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/pion/dtls/v3 v3.1.5 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v4 v4.0.2 // indirect
	github.com/smallstep/pkcs7 v0.1.1 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

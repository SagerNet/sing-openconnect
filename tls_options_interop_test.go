package openconnect

import (
	"context"
	"crypto"
	"crypto/md5" //nolint:gosec // The peer fixture exercises OpenConnect's retained MD5 certificate compatibility.
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

const tlsOptionsTestServerName = "vpn.tls-options.test"

type tlsOptionsTestPKI struct {
	serverCertificate tls.Certificate
	leaf              *x509.Certificate
	roots             *x509.CertPool
	rootCertificate   *x509.Certificate
	rootKey           *rsa.PrivateKey
}

type tlsOptionsWarningLogger struct {
	logger.ContextLogger
	warnings atomic.Uint32
}

func (l *tlsOptionsWarningLogger) WarnContext(_ context.Context, _ ...any) {
	l.warnings.Add(1)
}

func TestClientTLSPeerFingerprintInterop(t *testing.T) {
	t.Parallel()
	pki := newTLSOptionsTestPKI(t, nil)
	certificateSHA1 := sha1.Sum(pki.leaf.Raw)
	spkiSHA1 := sha1.Sum(pki.leaf.RawSubjectPublicKeyInfo)
	spkiSHA256 := sha256.Sum256(pki.leaf.RawSubjectPublicKeyInfo)
	validFingerprints := []string{
		hex.EncodeToString(certificateSHA1[:]),
		hex.EncodeToString(certificateSHA1[:])[:12],
		"sha1:" + hex.EncodeToString(spkiSHA1[:]),
		"sha1:" + hex.EncodeToString(spkiSHA1[:])[:12],
		"sha256:" + hex.EncodeToString(spkiSHA256[:]),
		"sha256:" + hex.EncodeToString(spkiSHA256[:])[:12],
		"pin-sha256:" + base64.StdEncoding.EncodeToString(spkiSHA256[:]),
		"pin-sha256:" + base64.StdEncoding.EncodeToString(spkiSHA256[:])[:12],
	}
	for _, fingerprint := range validFingerprints {
		t.Run(fingerprint[:min(len(fingerprint), 12)], func(t *testing.T) {
			t.Parallel()
			configuration := buildTLSOptionsTestClientConfiguration(t, nil, []string{fingerprint}, false, false, nil, nil)
			err := runTLSOptionsTestHandshake(t, configuration, pki.serverCertificate, 0, tls.VersionTLS12, tls.NoClientCert)
			if err != nil {
				t.Fatalf("matching peer fingerprint did not accept an otherwise untrusted TLS peer: %v", err)
			}
		})
	}
	wrongDigest := make([]byte, sha256.Size)
	wrongFingerprint := "pin-sha256:" + base64.StdEncoding.EncodeToString(wrongDigest)
	t.Run("trusted-peer-wrong-pin", func(t *testing.T) {
		t.Parallel()
		configuration := buildTLSOptionsTestClientConfiguration(t, pki.roots, []string{wrongFingerprint}, false, false, nil, nil)
		err := runTLSOptionsTestHandshake(t, configuration, pki.serverCertificate, 0, tls.VersionTLS12, tls.NoClientCert)
		if err == nil {
			t.Fatal("trusted TLS peer bypassed a mismatching configured fingerprint")
		}
	})
	t.Run("multiple-pins", func(t *testing.T) {
		t.Parallel()
		callbackCalled := atomic.Bool{}
		configuration := buildTLSOptionsTestClientConfiguration(
			t,
			nil,
			[]string{wrongFingerprint, validFingerprints[len(validFingerprints)-1]},
			false,
			false,
			func(tls.ConnectionState) error {
				callbackCalled.Store(true)
				return nil
			},
			nil,
		)
		err := runTLSOptionsTestHandshake(t, configuration, pki.serverCertificate, 0, tls.VersionTLS12, tls.NoClientCert)
		if err != nil {
			t.Fatalf("one matching fingerprint did not accept TLS peer: %v", err)
		}
		if !callbackCalled.Load() {
			t.Fatal("configured TLS verification callback was not chained after fingerprint verification")
		}
	})
	t.Run("callback-rejection", func(t *testing.T) {
		t.Parallel()
		configuration := buildTLSOptionsTestClientConfiguration(
			t,
			nil,
			[]string{validFingerprints[0]},
			false,
			false,
			func(tls.ConnectionState) error {
				return ErrAuthenticationFailed
			},
			nil,
		)
		err := runTLSOptionsTestHandshake(t, configuration, pki.serverCertificate, 0, tls.VersionTLS12, tls.NoClientCert)
		if err == nil {
			t.Fatal("matching fingerprint bypassed configured TLS verification callback rejection")
		}
	})
}

func TestClientTLSCipherPolicyInterop(t *testing.T) {
	t.Parallel()
	pki := newTLSOptionsTestPKI(t, nil)
	for _, testCase := range []struct {
		name    string
		version uint16
	}{
		{name: "tls10", version: tls.VersionTLS10},
		{name: "tls11", version: tls.VersionTLS11},
	} {
		t.Run("default-rejects-"+testCase.name, func(t *testing.T) {
			t.Parallel()
			configuration, _, err := buildClientTLS(ClientOptions{
				TLSConfig: ClientTLSOptions{
					Config:     &tls.Config{RootCAs: pki.roots},
					ServerName: tlsOptionsTestServerName,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			err = runTLSOptionsTestHandshake(
				t,
				configuration,
				pki.serverCertificate,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				testCase.version,
				tls.NoClientCert,
			)
			if err == nil {
				t.Fatal("default TLS policy accepted ", testCase.name)
			}
		})
		t.Run("insecure-opt-in-accepts-"+testCase.name, func(t *testing.T) {
			t.Parallel()
			configuration, _, err := buildClientTLS(ClientOptions{
				AllowInsecureCrypto: true,
				TLSConfig: ClientTLSOptions{
					Config: &tls.Config{
						MinVersion: testCase.version,
						MaxVersion: testCase.version,
						RootCAs:    pki.roots,
					},
					ServerName: tlsOptionsTestServerName,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			err = runTLSOptionsTestHandshake(
				t,
				configuration,
				pki.serverCertificate,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				testCase.version,
				tls.NoClientCert,
			)
			if err != nil {
				t.Fatalf("insecure crypto opt-in rejected %s: %v", testCase.name, err)
			}
		})
	}
	t.Run("default-rsa-key-exchange", func(t *testing.T) {
		t.Parallel()
		configuration := buildTLSOptionsTestClientConfiguration(t, pki.roots, nil, false, false, nil, nil)
		err := runTLSOptionsTestHandshake(t, configuration, pki.serverCertificate, tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.VersionTLS12, tls.NoClientCert)
		if err != nil {
			t.Fatalf("default OpenConnect TLS policy rejected compatible RSA-AES key exchange: %v", err)
		}
	})
	t.Run("default-rsa-aes-cbc-sha256", func(t *testing.T) {
		t.Parallel()
		configuration := buildTLSOptionsTestClientConfiguration(t, pki.roots, nil, false, false, nil, nil)
		err := runTLSOptionsTestHandshake(t, configuration, pki.serverCertificate, tls.TLS_RSA_WITH_AES_128_CBC_SHA256, tls.VersionTLS12, tls.NoClientCert)
		if err != nil {
			t.Fatalf("default OpenConnect TLS policy rejected Cisco-compatible RSA-AES-SHA256: %v", err)
		}
	})
	t.Run("configured-rsa-aes-cbc-sha256", func(t *testing.T) {
		t.Parallel()
		configuration := buildTLSOptionsTestClientConfiguration(
			t,
			pki.roots,
			nil,
			false,
			false,
			nil,
			[]uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA256},
		)
		err := runTLSOptionsTestHandshake(t, configuration, pki.serverCertificate, tls.TLS_RSA_WITH_AES_128_CBC_SHA256, tls.VersionTLS12, tls.NoClientCert)
		if err != nil {
			t.Fatalf("explicit RSA-AES-SHA256 suite was treated as deprecated crypto: %v", err)
		}
	})
	t.Run("default-ecdhe-aes-cbc-sha256", func(t *testing.T) {
		t.Parallel()
		configuration := buildTLSOptionsTestClientConfiguration(t, pki.roots, nil, false, false, nil, nil)
		err := runTLSOptionsTestHandshake(t, configuration, pki.serverCertificate, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, tls.VersionTLS12, tls.NoClientCert)
		if err != nil {
			t.Fatalf("default OpenConnect TLS policy rejected ECDHE-AES-SHA256: %v", err)
		}
	})
	t.Run("pfs-rejects-rsa-key-exchange", func(t *testing.T) {
		t.Parallel()
		configuration := buildTLSOptionsTestClientConfiguration(t, pki.roots, nil, true, false, nil, nil)
		err := runTLSOptionsTestHandshake(t, configuration, pki.serverCertificate, tls.TLS_RSA_WITH_AES_128_CBC_SHA256, tls.VersionTLS12, tls.NoClientCert)
		if err == nil {
			t.Fatal("PFS TLS policy accepted RSA key exchange")
		}
	})
	t.Run("pfs-accepts-ecdhe-key-exchange", func(t *testing.T) {
		t.Parallel()
		configuration := buildTLSOptionsTestClientConfiguration(t, pki.roots, nil, true, false, nil, nil)
		err := runTLSOptionsTestHandshake(t, configuration, pki.serverCertificate, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.VersionTLS12, tls.NoClientCert)
		if err != nil {
			t.Fatalf("PFS TLS policy rejected ECDHE key exchange: %v", err)
		}
	})
	t.Run("insecure-opt-in-rc4", func(t *testing.T) {
		t.Parallel()
		configuration := buildTLSOptionsTestClientConfiguration(t, pki.roots, nil, false, true, nil, nil)
		err := runTLSOptionsTestHandshake(t, configuration, pki.serverCertificate, tls.TLS_RSA_WITH_RC4_128_SHA, tls.VersionTLS12, tls.NoClientCert)
		if err != nil {
			t.Fatalf("insecure crypto opt-in did not enable RC4 interoperability: %v", err)
		}
	})
	t.Run("default-rejects-rc4", func(t *testing.T) {
		t.Parallel()
		configuration := buildTLSOptionsTestClientConfiguration(t, pki.roots, nil, false, false, nil, nil)
		err := runTLSOptionsTestHandshake(t, configuration, pki.serverCertificate, tls.TLS_RSA_WITH_RC4_128_SHA, tls.VersionTLS12, tls.NoClientCert)
		if err == nil {
			t.Fatal("default TLS policy accepted RC4")
		}
	})
	t.Run("insecure-opt-in-3des", func(t *testing.T) {
		t.Parallel()
		configuration := buildTLSOptionsTestClientConfiguration(t, pki.roots, nil, false, true, nil, nil)
		err := runTLSOptionsTestHandshake(t, configuration, pki.serverCertificate, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.VersionTLS12, tls.NoClientCert)
		if err != nil {
			t.Fatalf("insecure crypto opt-in did not enable 3DES interoperability: %v", err)
		}
	})
	t.Run("default-rejects-3des", func(t *testing.T) {
		t.Parallel()
		configuration := buildTLSOptionsTestClientConfiguration(t, pki.roots, nil, false, false, nil, nil)
		err := runTLSOptionsTestHandshake(t, configuration, pki.serverCertificate, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.VersionTLS12, tls.NoClientCert)
		if err == nil {
			t.Fatal("default TLS policy accepted 3DES")
		}
	})
}

func TestClientTLSLegacyCertificateSignatureInterop(t *testing.T) {
	t.Parallel()
	sha1PKI := newTLSOptionsTestPKI(t, func(template *x509.Certificate) {
		template.SignatureAlgorithm = x509.SHA1WithRSA
	})
	t.Run("disabled", func(t *testing.T) {
		t.Parallel()
		configuration := buildTLSOptionsTestClientConfiguration(t, sha1PKI.roots, nil, false, false, nil, nil)
		err := runTLSOptionsTestHandshake(t, configuration, sha1PKI.serverCertificate, 0, tls.VersionTLS12, tls.NoClientCert)
		if err == nil {
			t.Fatal("default TLS verification accepted a SHA-1 certificate chain")
		}
	})
	md5PKI := newTLSOptionsTestPKI(t, func(template *x509.Certificate) {
		template.SignatureAlgorithm = x509.MD5WithRSA
	})
	t.Run("md5-disabled", func(t *testing.T) {
		t.Parallel()
		configuration := buildTLSOptionsTestClientConfiguration(t, md5PKI.roots, nil, false, false, nil, nil)
		err := runTLSOptionsTestHandshake(t, configuration, md5PKI.serverCertificate, 0, tls.VersionTLS12, tls.NoClientCert)
		if err == nil {
			t.Fatal("default TLS verification accepted an MD5 certificate chain")
		}
	})
	t.Run("md5-opt-in", func(t *testing.T) {
		t.Parallel()
		rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: md5PKI.serverCertificate.Certificate[1]})
		configuration, _, err := buildClientTLS(ClientOptions{
			AllowInsecureCrypto: true,
			TLSConfig: ClientTLSOptions{
				ServerName:           tlsOptionsTestServerName,
				CertificateAuthority: Material{Content: rootPEM},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		err = runTLSOptionsTestHandshake(t, configuration, md5PKI.serverCertificate, 0, tls.VersionTLS12, tls.NoClientCert)
		if err != nil {
			t.Fatalf("insecure crypto opt-in rejected a trusted MD5 certificate chain: %v", err)
		}
	})
	t.Run("custom-root-pool", func(t *testing.T) {
		t.Parallel()
		peerCallbackCalls := atomic.Uint32{}
		connectionCallbackCalls := atomic.Uint32{}
		configuration, _, err := buildClientTLS(ClientOptions{
			AllowInsecureCrypto: true,
			TLSConfig: ClientTLSOptions{
				Config: &tls.Config{
					MinVersion: tls.VersionTLS12,
					MaxVersion: tls.VersionTLS12,
					RootCAs:    sha1PKI.roots,
					VerifyPeerCertificate: func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
						if len(verifiedChains) == 0 {
							return ErrAuthenticationFailed
						}
						peerCallbackCalls.Add(1)
						return nil
					},
					VerifyConnection: func(state tls.ConnectionState) error {
						if len(state.VerifiedChains) == 0 {
							return ErrAuthenticationFailed
						}
						connectionCallbackCalls.Add(1)
						return nil
					},
				},
				ServerName: tlsOptionsTestServerName,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		err = runTLSOptionsTestHandshake(t, configuration, sha1PKI.serverCertificate, 0, tls.VersionTLS12, tls.NoClientCert)
		if err != nil {
			t.Fatalf("insecure crypto opt-in rejected a trusted SHA-1 certificate chain: %v", err)
		}
		if peerCallbackCalls.Load() != 1 || connectionCallbackCalls.Load() != 1 {
			t.Fatalf("configured verification callbacks were not preserved: peer=%d connection=%d", peerCallbackCalls.Load(), connectionCallbackCalls.Load())
		}
	})
	t.Run("certificate-authority-material", func(t *testing.T) {
		t.Parallel()
		rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sha1PKI.serverCertificate.Certificate[1]})
		configuration, _, err := buildClientTLS(ClientOptions{
			AllowInsecureCrypto: true,
			TLSConfig: ClientTLSOptions{
				ServerName: tlsOptionsTestServerName,
				CertificateAuthority: Material{
					Content: rootPEM,
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		err = runTLSOptionsTestHandshake(t, configuration, sha1PKI.serverCertificate, 0, tls.VersionTLS12, tls.NoClientCert)
		if err != nil {
			t.Fatalf("insecure crypto opt-in rejected SHA-1 chain with configured CA material: %v", err)
		}
	})
	t.Run("hostname", func(t *testing.T) {
		t.Parallel()
		configuration, _, err := buildClientTLS(ClientOptions{
			AllowInsecureCrypto: true,
			TLSConfig: ClientTLSOptions{
				Config:     &tls.Config{RootCAs: sha1PKI.roots},
				ServerName: "wrong.tls-options.test",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		err = runTLSOptionsTestHandshake(t, configuration, sha1PKI.serverCertificate, 0, tls.VersionTLS12, tls.NoClientCert)
		if err == nil {
			t.Fatal("SHA-1 compatibility verification accepted a hostname mismatch")
		}
	})
	t.Run("untrusted-root", func(t *testing.T) {
		t.Parallel()
		unrelatedPKI := newTLSOptionsTestPKI(t, nil)
		configuration := buildTLSOptionsTestClientConfiguration(t, unrelatedPKI.roots, nil, false, true, nil, nil)
		err := runTLSOptionsTestHandshake(t, configuration, sha1PKI.serverCertificate, 0, tls.VersionTLS12, tls.NoClientCert)
		if err == nil {
			t.Fatal("SHA-1 compatibility verification accepted an untrusted chain")
		}
	})
	t.Run("expired", func(t *testing.T) {
		t.Parallel()
		expiredPKI := newTLSOptionsTestPKI(t, func(template *x509.Certificate) {
			template.SignatureAlgorithm = x509.SHA1WithRSA
			template.NotAfter = time.Now().Add(-time.Minute)
		})
		configuration := buildTLSOptionsTestClientConfiguration(t, expiredPKI.roots, nil, false, true, nil, nil)
		err := runTLSOptionsTestHandshake(t, configuration, expiredPKI.serverCertificate, 0, tls.VersionTLS12, tls.NoClientCert)
		if err == nil {
			t.Fatal("SHA-1 compatibility verification accepted an expired certificate")
		}
	})
	t.Run("extended-key-usage", func(t *testing.T) {
		t.Parallel()
		clientOnlyPKI := newTLSOptionsTestPKI(t, func(template *x509.Certificate) {
			template.SignatureAlgorithm = x509.SHA1WithRSA
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		})
		configuration := buildTLSOptionsTestClientConfiguration(t, clientOnlyPKI.roots, nil, false, true, nil, nil)
		err := runTLSOptionsTestHandshake(t, configuration, clientOnlyPKI.serverCertificate, 0, tls.VersionTLS12, tls.NoClientCert)
		if err == nil {
			t.Fatal("SHA-1 compatibility verification accepted a client-only certificate")
		}
	})
}

func TestClientTLSCertificateExpiryWarningInterop(t *testing.T) {
	t.Parallel()
	pki := newTLSOptionsTestPKI(t, nil)
	currentTime := time.Now()
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "sing-openconnect TLS warning test client"},
		NotBefore:    currentTime.Add(-time.Hour),
		NotAfter:     currentTime.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, pki.rootCertificate, &clientKey.PublicKey, pki.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate := Material{Content: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})}
	clientPrivateKey := Material{Content: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER})}
	for _, testCase := range []struct {
		name             string
		warning          time.Duration
		warningDisabled  bool
		expectedWarnings uint32
	}{
		{name: "upstream-default", expectedWarnings: 1},
		{name: "custom-threshold", warning: 10 * 24 * time.Hour},
		{name: "disabled", warningDisabled: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			recordingLogger := &tlsOptionsWarningLogger{ContextLogger: logger.NOP()}
			configuration, _, buildErr := buildClientTLS(ClientOptions{
				Context: context.Background(),
				Logger:  recordingLogger,
				TLSConfig: ClientTLSOptions{
					Config: &tls.Config{
						MinVersion: tls.VersionTLS12,
						MaxVersion: tls.VersionTLS12,
						RootCAs:    pki.roots,
						Time: func() time.Time {
							return currentTime
						},
					},
					ServerName:                       tlsOptionsTestServerName,
					Certificate:                      clientCertificate,
					Key:                              clientPrivateKey,
					CertificateExpiryWarning:         testCase.warning,
					CertificateExpiryWarningDisabled: testCase.warningDisabled,
				},
			})
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			if recordingLogger.warnings.Load() != testCase.expectedWarnings {
				t.Fatalf("unexpected certificate expiry warning count: got %d, want %d", recordingLogger.warnings.Load(), testCase.expectedWarnings)
			}
			handshakeErr := runTLSOptionsTestHandshake(
				t,
				configuration,
				pki.serverCertificate,
				0,
				tls.VersionTLS12,
				tls.RequireAnyClientCert,
			)
			if handshakeErr != nil {
				t.Fatalf("TLS peer rejected configured warning-test client certificate: %v", handshakeErr)
			}
		})
	}
}

func TestClientTLSServerNameOverrideInterop(t *testing.T) {
	t.Parallel()
	pki := newTLSOptionsTestPKI(t, nil)
	configuration, _, err := buildClientTLS(ClientOptions{
		TLSConfig: ClientTLSOptions{
			Config: &tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS12,
				RootCAs:    pki.roots,
				ServerName: "wrong.tls-options.test",
			},
			ServerName: tlsOptionsTestServerName,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = runTLSOptionsTestHandshake(t, configuration, pki.serverCertificate, 0, tls.VersionTLS12, tls.NoClientCert)
	if err != nil {
		t.Fatalf("OpenConnect TLS server-name override did not drive certificate verification: %v", err)
	}
}

func TestClientTLSPeerFingerprintResumptionCallbacks(t *testing.T) {
	t.Parallel()
	pki := newTLSOptionsTestPKI(t, nil)
	spkiSHA256 := sha256.Sum256(pki.leaf.RawSubjectPublicKeyInfo)
	verifyPeerCertificateCalls := atomic.Uint32{}
	verifyConnectionCalls := atomic.Uint32{}
	configuration, _, err := buildClientTLS(ClientOptions{
		TLSConfig: ClientTLSOptions{
			Config: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS12,
				RootCAs:            pki.roots,
				ClientSessionCache: tls.NewLRUClientSessionCache(1),
				VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
					verifyPeerCertificateCalls.Add(1)
					return nil
				},
				VerifyConnection: func(tls.ConnectionState) error {
					verifyConnectionCalls.Add(1)
					return nil
				},
			},
			ServerName:       tlsOptionsTestServerName,
			PeerFingerprints: []string{"sha256:" + hex.EncodeToString(spkiSHA256[:])},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverConfiguration := &tls.Config{
		Certificates: []tls.Certificate{pki.serverCertificate},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}
	serverErrors := make(chan error, 2)
	go func() {
		for range 2 {
			rawConnection, acceptErr := listener.Accept()
			if acceptErr != nil {
				serverErrors <- acceptErr
				continue
			}
			_ = rawConnection.SetDeadline(time.Now().Add(5 * time.Second))
			tlsConnection := tls.Server(rawConnection, serverConfiguration)
			handshakeErr := tlsConnection.Handshake()
			_ = tlsConnection.Close()
			serverErrors <- handshakeErr
		}
	}()
	for connectionIndex := range 2 {
		dialer := net.Dialer{Timeout: 5 * time.Second}
		rawConnection, dialErr := dialer.DialContext(context.Background(), "tcp", listener.Addr().String())
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		tlsConnection := tls.Client(rawConnection, configuration.Clone())
		_ = tlsConnection.SetDeadline(time.Now().Add(5 * time.Second))
		handshakeErr := tlsConnection.Handshake()
		if handshakeErr != nil {
			_ = tlsConnection.Close()
			t.Fatal(handshakeErr)
		}
		didResume := tlsConnection.ConnectionState().DidResume
		_ = tlsConnection.Close()
		if didResume != (connectionIndex == 1) {
			t.Fatalf("unexpected TLS resumption state for connection %d: %v", connectionIndex+1, didResume)
		}
	}
	for range 2 {
		serverErr := <-serverErrors
		if serverErr != nil {
			t.Fatal(serverErr)
		}
	}
	if verifyPeerCertificateCalls.Load() != 1 {
		t.Fatalf("VerifyPeerCertificate ran %d times across a full and resumed handshake", verifyPeerCertificateCalls.Load())
	}
	if verifyConnectionCalls.Load() != 2 {
		t.Fatalf("VerifyConnection ran %d times across a full and resumed handshake", verifyConnectionCalls.Load())
	}
}

func buildTLSOptionsTestClientConfiguration(
	t *testing.T,
	roots *x509.CertPool,
	fingerprints []string,
	pfs bool,
	allowInsecure bool,
	verifyConnection func(tls.ConnectionState) error,
	cipherSuites []uint16,
) *tls.Config {
	t.Helper()
	configuration, _, err := buildClientTLS(ClientOptions{
		PFS:                 pfs,
		AllowInsecureCrypto: allowInsecure,
		TLSConfig: ClientTLSOptions{
			Config: &tls.Config{
				MinVersion:       tls.VersionTLS12,
				MaxVersion:       tls.VersionTLS12,
				RootCAs:          roots,
				VerifyConnection: verifyConnection,
				CipherSuites:     cipherSuites,
			},
			ServerName:       tlsOptionsTestServerName,
			PeerFingerprints: fingerprints,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return configuration
}

func runTLSOptionsTestHandshake(
	t *testing.T,
	clientConfiguration *tls.Config,
	serverCertificate tls.Certificate,
	cipherSuite uint16,
	version uint16,
	clientAuth tls.ClientAuthType,
) error {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverConfiguration := &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		MinVersion:   version,
		MaxVersion:   version,
		ClientAuth:   clientAuth,
	}
	if cipherSuite != 0 {
		serverConfiguration.CipherSuites = []uint16{cipherSuite}
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		_ = tls.Server(connection, serverConfiguration).Handshake()
	}()
	dialer := net.Dialer{Timeout: 5 * time.Second}
	rawConnection, err := dialer.DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	connection := tls.Client(rawConnection, clientConfiguration.Clone())
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	handshakeErr := connection.Handshake()
	_ = connection.Close()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("TLS test server did not finish")
	}
	return handshakeErr
}

func newTLSOptionsTestPKI(t *testing.T, configureServerCertificate func(template *x509.Certificate)) tlsOptionsTestPKI {
	t.Helper()
	now := time.Now()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sing-openconnect TLS options test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCertificate, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: tlsOptionsTestServerName},
		DNSNames:     []string{tlsOptionsTestServerName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if configureServerCertificate != nil {
		configureServerCertificate(serverTemplate)
	}
	serverDER, err := createTLSOptionsTestCertificate(serverTemplate, rootCertificate, &serverKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	serverLeaf, err := x509.ParseCertificate(serverDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCertificate)
	return tlsOptionsTestPKI{
		serverCertificate: tls.Certificate{
			Certificate: [][]byte{serverDER, rootDER},
			PrivateKey:  serverKey,
			Leaf:        serverLeaf,
		},
		leaf:            serverLeaf,
		roots:           roots,
		rootCertificate: rootCertificate,
		rootKey:         rootKey,
	}
}

var tlsOptionsTestMD5WithRSAAlgorithmIdentifier = pkix.AlgorithmIdentifier{
	Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4},
	Parameters: asn1.RawValue{Tag: 5},
}

type tlsOptionsTestCertificateASN1 struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

func createTLSOptionsTestCertificate(template *x509.Certificate, parent *x509.Certificate, publicKey any, parentKey crypto.Signer) ([]byte, error) {
	if template.SignatureAlgorithm != x509.MD5WithRSA {
		return x509.CreateCertificate(rand.Reader, template, parent, publicKey, parentKey)
	}
	temporaryTemplate := *template
	temporaryTemplate.SignatureAlgorithm = x509.SHA256WithRSA
	certificateDER, err := x509.CreateCertificate(rand.Reader, &temporaryTemplate, parent, publicKey, parentKey)
	if err != nil {
		return nil, err
	}
	var certificate tlsOptionsTestCertificateASN1
	remaining, err := asn1.Unmarshal(certificateDER, &certificate)
	if err != nil {
		return nil, err
	}
	if len(remaining) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing certificate data"}
	}
	var tbsFields []asn1.RawValue
	remaining, err = asn1.Unmarshal(certificate.TBSCertificate.FullBytes, &tbsFields)
	if err != nil {
		return nil, err
	}
	if len(remaining) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing TBS certificate data"}
	}
	signatureAlgorithmIndex := 1
	if len(tbsFields) > 0 && tbsFields[0].Class == 2 && tbsFields[0].Tag == 0 {
		signatureAlgorithmIndex = 2
	}
	if len(tbsFields) <= signatureAlgorithmIndex {
		return nil, asn1.StructuralError{Msg: "invalid TBS certificate"}
	}
	algorithmDER, err := asn1.Marshal(tlsOptionsTestMD5WithRSAAlgorithmIdentifier)
	if err != nil {
		return nil, err
	}
	tbsFields[signatureAlgorithmIndex] = asn1.RawValue{FullBytes: algorithmDER}
	tbsDER, err := asn1.Marshal(tbsFields)
	if err != nil {
		return nil, err
	}
	parentRSAKey, loaded := parentKey.(*rsa.PrivateKey)
	if !loaded {
		return nil, x509.ErrUnsupportedAlgorithm
	}
	digest := md5.Sum(tbsDER)
	signature, err := rsa.SignPKCS1v15(nil, parentRSAKey, crypto.MD5, digest[:])
	if err != nil {
		return nil, err
	}
	certificate.TBSCertificate = asn1.RawValue{FullBytes: tbsDER}
	certificate.SignatureAlgorithm = tlsOptionsTestMD5WithRSAAlgorithmIdentifier
	certificate.SignatureValue = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	return asn1.Marshal(certificate)
}

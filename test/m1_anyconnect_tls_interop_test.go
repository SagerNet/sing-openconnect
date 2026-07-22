package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
)

const m1OcservSPKISHA256 = "sha256:c69dec71fcf2deb390b2ff4d70ebdeffc61556ffa91ebe2a3425c45eb365e6cf"

func TestM1AnyConnectTLSInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)

	//nolint:paralleltest // Each case completes and cleans up its real ocserv session before the next case.
	t.Run("certificate-authority-and-server-name", func(t *testing.T) {
		certificateAuthority, serverCertificate, serverKey := createM1OcservTLSIdentity(t)
		container := startM1OcservContainer(t, ctx, m1OcservOptions{
			authentication:    `auth = "plain[passwd=/fixture/ocpasswd]"`,
			keepalive:         60,
			dpd:               30,
			rekeyMethod:       "new-tunnel",
			files:             map[string][]byte{"ocpasswd": []byte(m1OcservPasswordFile)},
			serverCertificate: serverCertificate,
			serverKey:         serverKey,
		})
		client := newM1AnyConnectClient(t, ctx, container.tcpAddress, openconnect.ClientOptions{
			Username: ocservUsername,
			Password: ocservPassword,
			NoUDP:    true,
			TLSConfig: openconnect.ClientTLSOptions{
				Config:               &tls.Config{MinVersion: tls.VersionTLS12},
				ServerName:           "localhost",
				SystemTrustDisabled:  true,
				CertificateAuthority: openconnect.Material{Content: certificateAuthority},
			},
		})
		startM1Client(t, client)
		waitForM1Ready(t, ctx, client)
		exchangeM1TunnelEcho(t, ctx, client, 0x4d35, 1, "sing-openconnect-m1-tls-ca")
	})

	pinnedContainer := startM1OcservContainer(t, ctx, m1OcservOptions{
		authentication: `auth = "plain[passwd=/fixture/ocpasswd]"`,
		keepalive:      60,
		dpd:            30,
		rekeyMethod:    "new-tunnel",
		files:          map[string][]byte{"ocpasswd": []byte(m1OcservPasswordFile)},
	})
	//nolint:paralleltest // The pin cases intentionally take turns using the same real ocserv account.
	t.Run("peer-spki-fingerprint", func(t *testing.T) {
		client := newM1AnyConnectClient(t, ctx, pinnedContainer.tcpAddress, openconnect.ClientOptions{
			Username: ocservUsername,
			Password: ocservPassword,
			NoUDP:    true,
			TLSConfig: openconnect.ClientTLSOptions{
				Config:              &tls.Config{MinVersion: tls.VersionTLS12},
				SystemTrustDisabled: true,
				PeerFingerprints:    []string{m1OcservSPKISHA256},
			},
		})
		startM1Client(t, client)
		waitForM1Ready(t, ctx, client)
		exchangeM1TunnelEcho(t, ctx, client, 0x4d35, 2, "sing-openconnect-m1-tls-pin")
	})

	//nolint:paralleltest // The pin cases intentionally take turns using the same real ocserv account.
	t.Run("wrong-peer-spki-fingerprint", func(t *testing.T) {
		client := newM1AnyConnectClient(t, ctx, pinnedContainer.tcpAddress, openconnect.ClientOptions{
			Username: ocservUsername,
			Password: ocservPassword,
			NoUDP:    true,
			TLSConfig: openconnect.ClientTLSOptions{
				Config:              &tls.Config{MinVersion: tls.VersionTLS12},
				SystemTrustDisabled: true,
				PeerFingerprints: []string{
					"sha256:0000000000000000000000000000000000000000000000000000000000000000",
				},
			},
		})
		startM1Client(t, client)
		failureContext, cancelFailure := context.WithTimeout(ctx, 10*time.Second)
		defer cancelFailure()
		_, err := client.ReadDataPacket(failureContext)
		if err == nil || !strings.Contains(err.Error(), "does not match any configured fingerprint") {
			t.Fatalf("real ocserv connection did not reject the wrong certificate pin: %v", err)
		}
	})
}

func createM1OcservTLSIdentity(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	now := time.Now()
	certificateAuthorityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificateAuthorityTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sing-openconnect real ocserv CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certificateAuthorityDER, err := x509.CreateCertificate(
		rand.Reader,
		certificateAuthorityTemplate,
		certificateAuthorityTemplate,
		certificateAuthorityKey.Public(),
		certificateAuthorityKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverCertificateDER, err := x509.CreateCertificate(
		rand.Reader,
		serverTemplate,
		certificateAuthorityTemplate,
		serverKey.Public(),
		certificateAuthorityKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateAuthorityDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER})
}

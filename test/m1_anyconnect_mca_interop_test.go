package test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	fakeCiscoInteropImage         = "sing-openconnect-fake-cisco:2035601b64a5"
	fakeCiscoAuthenticationMarker = "MCA_AUTH_SUCCESS hash=sha512 certificates=2"
)

type multipleCertificateFixture struct {
	directory          string
	machineCertificate []byte
	machineKey         []byte
	userCertificate    []byte
	userKey            []byte
}

func TestM1AnyConnectMultipleCertificateInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	_, err := dockerOutput(ctx, "version", "--format", "{{.Server.Version}}")
	if err != nil {
		t.Fatal(err)
	}
	_, err = dockerOutput(ctx, "build", "--pull=false", "--tag", fakeCiscoInteropImage, filepath.Join("testdata", "fake-cisco"))
	if err != nil {
		t.Fatal(err)
	}

	for _, keyKind := range []string{"rsa", "ecdsa"} {
		t.Run(keyKind, func(subtest *testing.T) {
			subtest.Parallel()
			runAnyConnectMultipleCertificateInterop(subtest, ctx, keyKind)
		})
	}
}

func runAnyConnectMultipleCertificateInterop(t *testing.T, ctx context.Context, keyKind string) {
	t.Helper()
	fixture := createMultipleCertificateFixture(t, keyKind)
	containerName := "sing-openconnect-m1-mca-" + keyKind + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	_, err := dockerOutput(
		ctx,
		"run", "--detach", "--rm", "--name", containerName,
		"--publish", "127.0.0.1::443/tcp",
		"--mount", "type=bind,source="+fixture.directory+",target=/certs,readonly",
		fakeCiscoInteropImage,
		"--enable-multicert",
		"--cafile", "/certs/ca.pem",
		"--client-cafile", "/certs/machine-ca.pem",
		"--expected-hash", "sha512",
		"--expected-certificate-count", "2",
		"--require-client-cert",
		"0.0.0.0", "443", "/certs/server-cert.pem", "/certs/server-key.pem",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logsContext, cancelLogs := context.WithTimeout(context.Background(), 5*time.Second)
			logs, logsErr := dockerOutput(logsContext, "logs", containerName)
			cancelLogs()
			if logsErr == nil {
				t.Log("fake Cisco logs:\n" + logs)
			}
		}
		removeContext, cancelRemove := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = dockerOutput(removeContext, "rm", "--force", containerName)
		cancelRemove()
	})

	address := dockerPublishedAddress(t, ctx, containerName, "443/tcp")
	waitForTCP(t, ctx, address)
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  address,
		Flavor:  openconnect.FlavorAnyConnect,
		TLSConfig: openconnect.ClientTLSOptions{
			Config: &tls.Config{
				InsecureSkipVerify: true,
			},
			Certificate:    openconnect.Material{Content: fixture.machineCertificate},
			Key:            openconnect.Material{Content: fixture.machineKey},
			MCACertificate: openconnect.Material{Content: fixture.userCertificate},
			MCAKey:         openconnect.Material{Content: fixture.userKey},
		},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create AnyConnect MCA client"))
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start AnyConnect MCA client"))
	}

	waitContext, cancelWait := context.WithTimeout(ctx, 30*time.Second)
	defer cancelWait()
	for {
		logs, logsErr := dockerOutput(waitContext, "logs", containerName)
		if logsErr == nil && strings.Contains(logs, fakeCiscoAuthenticationMarker) {
			closeErr := client.Close()
			if closeErr != nil {
				t.Fatal(E.Cause(closeErr, "close AnyConnect MCA client"))
			}
			return
		}
		select {
		case <-waitContext.Done():
			if logsErr != nil {
				t.Fatal(E.Errors(E.Cause(waitContext.Err(), "wait for fake Cisco MCA validation"), logsErr))
			}
			t.Fatal(E.Cause(waitContext.Err(), "wait for fake Cisco MCA validation: ", logs))
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func createMultipleCertificateFixture(t *testing.T, userKeyKind string) multipleCertificateFixture {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate fake Cisco root key"))
	}
	machineRootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sing-openconnect fake Cisco machine root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	machineRootData, machineRootCertificate := createSignedInteropCertificate(t, machineRootTemplate, machineRootTemplate, rootKey.Public(), rootKey)

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate fake Cisco intermediate key"))
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "sing-openconnect fake Cisco machine intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	intermediateData, intermediateCertificate := createSignedInteropCertificate(t, intermediateTemplate, machineRootCertificate, intermediateKey.Public(), rootKey)

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate fake Cisco server key"))
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "fake-cisco-server"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"fake-cisco-server", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverData, _ := createSignedInteropCertificate(t, serverTemplate, intermediateCertificate, serverKey.Public(), intermediateKey)

	machineKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate fake Cisco machine key"))
	}
	machineTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "sing-openconnect machine"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	machineData, _ := createSignedInteropCertificate(t, machineTemplate, intermediateCertificate, machineKey.Public(), intermediateKey)

	userRootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate fake Cisco MCA root key"))
	}
	userRootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "sing-openconnect fake Cisco MCA root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	userRootData, userRootCertificate := createSignedInteropCertificate(t, userRootTemplate, userRootTemplate, userRootKey.Public(), userRootKey)
	userIntermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate fake Cisco MCA intermediate key"))
	}
	userIntermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "sing-openconnect fake Cisco MCA intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	userIntermediateData, userIntermediateCertificate := createSignedInteropCertificate(t, userIntermediateTemplate, userRootCertificate, userIntermediateKey.Public(), userRootKey)

	userKey := generateMultipleCertificateUserKey(t, userKeyKind)
	userTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(12),
		Subject:      pkix.Name{CommonName: "sing-openconnect MCA user " + userKeyKind},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	userData, _ := createSignedInteropCertificate(t, userTemplate, userIntermediateCertificate, userKey.Public(), userIntermediateKey)

	serverKeyData := marshalInteropPrivateKey(t, serverKey)
	machineKeyData := marshalInteropPrivateKey(t, machineKey)
	userKeyData := marshalInteropPrivateKey(t, userKey)
	machineRootPEM := joinCertificatePEM(machineRootData)
	userRootPEM := joinCertificatePEM(userRootData)
	serverPEM := joinCertificatePEM(serverData, intermediateData)
	machinePEM := joinCertificatePEM(machineData, intermediateData)
	userPEM := joinCertificatePEM(userData, userIntermediateData)
	directory := t.TempDir()
	files := map[string][]byte{
		"ca.pem":            userRootPEM,
		"machine-ca.pem":    machineRootPEM,
		"server-cert.pem":   serverPEM,
		"server-key.pem":    serverKeyData,
		"machine-cert.pem":  machinePEM,
		"machine-key.pem":   machineKeyData,
		"mca-user-cert.pem": userPEM,
		"mca-user-key.pem":  userKeyData,
	}
	for name, content := range files {
		writeErr := os.WriteFile(filepath.Join(directory, name), content, 0o600)
		if writeErr != nil {
			t.Fatal(E.Cause(writeErr, "write fake Cisco certificate fixture: ", name))
		}
	}
	return multipleCertificateFixture{
		directory:          directory,
		machineCertificate: machinePEM,
		machineKey:         machineKeyData,
		userCertificate:    userPEM,
		userKey:            userKeyData,
	}
}

func generateMultipleCertificateUserKey(t *testing.T, keyKind string) crypto.Signer {
	t.Helper()
	switch keyKind {
	case "rsa":
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(E.Cause(err, "generate fake Cisco RSA MCA key"))
		}
		return privateKey
	case "ecdsa":
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(E.Cause(err, "generate fake Cisco ECDSA MCA key"))
		}
		return privateKey
	default:
		t.Fatal("unsupported fake Cisco MCA key kind: " + keyKind)
		return nil
	}
}

func createSignedInteropCertificate(
	t *testing.T,
	template *x509.Certificate,
	parent *x509.Certificate,
	publicKey crypto.PublicKey,
	parentKey crypto.Signer,
) ([]byte, *x509.Certificate) {
	t.Helper()
	certificateData, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, parentKey)
	if err != nil {
		t.Fatal(E.Cause(err, "create fake Cisco certificate: ", template.Subject.CommonName))
	}
	certificate, err := x509.ParseCertificate(certificateData)
	if err != nil {
		t.Fatal(E.Cause(err, "parse fake Cisco certificate: ", template.Subject.CommonName))
	}
	return certificateData, certificate
}

func marshalInteropPrivateKey(t *testing.T, privateKey crypto.PrivateKey) []byte {
	t.Helper()
	privateKeyData, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(E.Cause(err, "marshal fake Cisco private key"))
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyData})
}

func joinCertificatePEM(certificates ...[]byte) []byte {
	var content bytes.Buffer
	for _, certificate := range certificates {
		content.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}))
	}
	return content.Bytes()
}

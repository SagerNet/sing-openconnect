package test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/smallstep/pkcs7"
	"github.com/youmark/pkcs8"
)

const (
	m1TLSMaterialHostname       = "vpn.tls-material.example"
	m1TLSMaterialWrongHostname  = "wrong.tls-material.example"
	m1TLSMaterialKeyPassword    = "machine-key-password"
	m1TLSMaterialMCAKeyPassword = "mca-key-password"
	m1TLSMaterialSessionCookie  = "tls-material-session"
)

var m1TLSMaterialMCAChallenge = []byte(`<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<multiple-client-cert-request><hash-algorithm>sha512</hash-algorithm></multiple-client-cert-request>
<cert-authenticated />
</config-auth>`)

type m1TLSMaterialFixture struct {
	certificateAuthorityPEM []byte
	wrongAuthorityPEM       []byte
	serverCertificate       tls.Certificate
	clientCertificatePEM    []byte
	clientEncryptedKeyPEM   []byte
	clientCertificate       *x509.Certificate
	mcaCertificatePEM       []byte
	mcaEncryptedKeyPEM      []byte
	mcaCertificate          *x509.Certificate
}

type m1TLSMaterialPeer struct {
	clientCertificate  *x509.Certificate
	mcaCertificate     *x509.Certificate
	failures           chan error
	mcaVerified        chan struct{}
	clientDataVerified chan struct{}
	tunnelClosed       chan error
	handshakes         atomic.Uint64
}

type m1TLSMaterialDialer struct {
	target M.Socksaddr
}

type m1TLSMaterialMCAReply struct {
	XMLName xml.Name `xml:"config-auth"`
	Type    string   `xml:"type,attr"`
	Auth    struct {
		Chains []struct {
			Store                   string    `xml:"cert-store,attr"`
			CertificateSentProtocol *struct{} `xml:"client-cert-sent-via-protocol"`
			Certificate             struct {
				Format string `xml:"cert-format,attr"`
				Value  string `xml:",chardata"`
			} `xml:"client-cert"`
			Signature struct {
				HashAlgorithm string `xml:"hash-algorithm-chosen,attr"`
				Value         string `xml:",chardata"`
			} `xml:"client-cert-auth-signature"`
		} `xml:"client-cert-chain"`
	} `xml:"auth"`
}

func TestM1TLSMaterialInterop(t *testing.T) {
	t.Parallel()
	fixture := createM1TLSMaterialFixture(t)
	t.Run("trusted-hostname-encrypted-client-and-mca-keys", func(subtest *testing.T) {
		subtest.Parallel()
		runM1TLSMaterialSuccess(subtest, fixture)
	})
	t.Run("wrong-certificate-authority-is-terminal", func(subtest *testing.T) {
		subtest.Parallel()
		runM1TLSMaterialRejection(subtest, fixture, m1TLSMaterialHostname, fixture.wrongAuthorityPEM, true)
	})
	t.Run("wrong-hostname-is-terminal", func(subtest *testing.T) {
		subtest.Parallel()
		runM1TLSMaterialRejection(subtest, fixture, m1TLSMaterialWrongHostname, fixture.certificateAuthorityPEM, false)
	})
}

func runM1TLSMaterialSuccess(t *testing.T, fixture m1TLSMaterialFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	peer := &m1TLSMaterialPeer{
		clientCertificate:  fixture.clientCertificate,
		mcaCertificate:     fixture.mcaCertificate,
		failures:           make(chan error, 8),
		mcaVerified:        make(chan struct{}, 1),
		clientDataVerified: make(chan struct{}, 1),
		tunnelClosed:       make(chan error, 1),
	}
	clientAuthorities := x509.NewCertPool()
	if !clientAuthorities.AppendCertsFromPEM(fixture.certificateAuthorityPEM) {
		t.Fatal("append TLS material client certificate authority")
	}
	server := httptest.NewUnstartedServer(peer)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{fixture.serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientAuthorities,
		MinVersion:   tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			peer.handshakes.Add(1)
			if hello.ServerName != m1TLSMaterialHostname {
				return nil, E.New("TLS material peer received unexpected SNI: ", hello.ServerName)
			}
			return nil, nil
		},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(E.Cause(err, "split TLS material server address"))
	}
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  net.JoinHostPort(m1TLSMaterialHostname, port),
		Flavor:  openconnect.FlavorAnyConnect,
		NoUDP:   true,
		Dialer: &m1TLSMaterialDialer{
			target: M.ParseSocksaddr(server.Listener.Addr().String()),
		},
		TLSConfig: openconnect.ClientTLSOptions{
			CertificateAuthority: openconnect.Material{Content: fixture.certificateAuthorityPEM},
			Certificate:          openconnect.Material{Content: fixture.clientCertificatePEM},
			Key:                  openconnect.Material{Content: fixture.clientEncryptedKeyPEM},
			KeyPassword:          m1TLSMaterialKeyPassword,
			MCACertificate:       openconnect.Material{Content: fixture.mcaCertificatePEM},
			MCAKey:               openconnect.Material{Content: fixture.mcaEncryptedKeyPEM},
			MCAKeyPassword:       m1TLSMaterialMCAKeyPassword,
		},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create TLS material client"))
	}
	t.Cleanup(func() {
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosed(closeErr) {
			t.Error(E.Cause(closeErr, "cleanup TLS material client"))
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start TLS material client"))
	}
	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for encrypted MCA signature verification"))
	case peerErr := <-peer.failures:
		t.Fatal(peerErr)
	case <-peer.mcaVerified:
	}
	readContext, cancelRead := context.WithTimeout(ctx, 5*time.Second)
	payload, err := client.ReadDataPacket(readContext)
	cancelRead()
	if err != nil {
		t.Fatal(E.Cause(err, "read TLS material CSTP data"))
	}
	if string(payload) != "tls-material-cstp-data" {
		t.Fatalf("unexpected TLS material CSTP data: %q", payload)
	}
	err = client.WriteDataPacket([]byte("tls-material-client-data"))
	if err != nil {
		t.Fatal(E.Cause(err, "write TLS material CSTP data"))
	}
	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for TLS material CSTP client data"))
	case peerErr := <-peer.failures:
		t.Fatal(peerErr)
	case <-peer.clientDataVerified:
	}
	closeErr := client.Close()
	if closeErr != nil && !E.IsClosed(closeErr) {
		t.Fatal(E.Cause(closeErr, "close TLS material client"))
	}
	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for TLS material CSTP close"))
	case peerErr := <-peer.failures:
		t.Fatal(peerErr)
	case tunnelErr := <-peer.tunnelClosed:
		if tunnelErr != nil {
			t.Fatal(tunnelErr)
		}
	}
	if handshakes := peer.handshakes.Load(); handshakes != 2 {
		t.Fatalf("TLS material peer observed %d handshakes, expected authentication and CSTP handshakes", handshakes)
	}
}

func runM1TLSMaterialRejection(
	t *testing.T,
	fixture m1TLSMaterialFixture,
	hostname string,
	certificateAuthority []byte,
	expectUnknownAuthority bool,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	sniObserved := make(chan string, 2)
	var handlerRequests atomic.Uint64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		handlerRequests.Add(1)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{fixture.serverCertificate},
		MinVersion:   tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sniObserved <- hello.ServerName
			return nil, nil
		},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(E.Cause(err, "split rejecting TLS material server address"))
	}
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  net.JoinHostPort(hostname, port),
		Flavor:  openconnect.FlavorAnyConnect,
		NoUDP:   true,
		Dialer: &m1TLSMaterialDialer{
			target: M.ParseSocksaddr(server.Listener.Addr().String()),
		},
		TLSConfig: openconnect.ClientTLSOptions{
			CertificateAuthority: openconnect.Material{Content: certificateAuthority},
		},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create rejecting TLS material client"))
	}
	t.Cleanup(func() {
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosed(closeErr) {
			t.Error(E.Cause(closeErr, "close rejecting TLS material client"))
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start rejecting TLS material client"))
	}
	readContext, cancelRead := context.WithTimeout(ctx, 5*time.Second)
	_, terminalErr := client.ReadDataPacket(readContext)
	cancelRead()
	if expectUnknownAuthority {
		_, matched := E.Cast[x509.UnknownAuthorityError](terminalErr)
		if !matched {
			t.Fatalf("wrong CA did not terminate with x509.UnknownAuthorityError: %v", terminalErr)
		}
	} else {
		_, matched := E.Cast[x509.HostnameError](terminalErr)
		if !matched {
			t.Fatalf("wrong hostname did not terminate with x509.HostnameError: %v", terminalErr)
		}
	}
	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for rejecting TLS material SNI"))
	case observedSNI := <-sniObserved:
		if observedSNI != hostname {
			t.Fatalf("rejecting TLS material peer observed SNI %q, expected %q", observedSNI, hostname)
		}
	}
	if requests := handlerRequests.Load(); requests != 0 {
		t.Fatalf("rejected TLS material connection reached HTTP handler %d times", requests)
	}
	secondReadContext, cancelSecondRead := context.WithTimeout(ctx, time.Second)
	_, secondTerminalErr := client.ReadDataPacket(secondReadContext)
	cancelSecondRead()
	if expectUnknownAuthority {
		_, matched := E.Cast[x509.UnknownAuthorityError](secondTerminalErr)
		if !matched {
			t.Fatalf("wrong CA terminal error was not stable: %v", secondTerminalErr)
		}
	} else {
		_, matched := E.Cast[x509.HostnameError](secondTerminalErr)
		if !matched {
			t.Fatalf("wrong hostname terminal error was not stable: %v", secondTerminalErr)
		}
	}
}

func (p *m1TLSMaterialPeer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	err := p.validateTLSRequest(request)
	if err != nil {
		p.fail(writer, err)
		return
	}
	if request.Method == http.MethodConnect {
		if request.RequestURI != "/CSCOSSLC/tunnel" || request.Header.Get("Cookie") != "webvpn="+m1TLSMaterialSessionCookie {
			p.fail(writer, E.New("TLS material peer received invalid CSTP CONNECT: ", request.RequestURI, " cookie=", request.Header.Values("Cookie")))
			return
		}
		p.serveTunnel(writer)
		return
	}
	if request.Method != http.MethodPost || request.URL.Path != "/" {
		p.fail(writer, E.New("TLS material peer received unexpected request: ", request.Method, " ", request.URL.Path))
		return
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		p.fail(writer, E.Cause(err, "read TLS material authentication request"))
		return
	}
	var envelope struct {
		Type string `xml:"type,attr"`
	}
	err = xml.Unmarshal(body, &envelope)
	if err != nil {
		p.fail(writer, E.Cause(err, "parse TLS material authentication request"))
		return
	}
	switch envelope.Type {
	case "init":
		writer.Header().Set("Content-Type", "application/xml")
		_, err = writer.Write(m1TLSMaterialMCAChallenge)
		if err != nil {
			p.recordFailure(E.Cause(err, "write TLS material MCA challenge"))
		}
	case "auth-reply":
		err = verifyM1TLSMaterialMCAReply(body, m1TLSMaterialMCAChallenge, p.mcaCertificate)
		if err != nil {
			p.fail(writer, err)
			return
		}
		writer.Header().Set("Content-Type", "application/xml")
		_, err = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>`+m1TLSMaterialSessionCookie+`</session-token><auth id="success" />
</config-auth>`)
		if err != nil {
			p.recordFailure(E.Cause(err, "write TLS material authentication success"))
			return
		}
		p.mcaVerified <- struct{}{}
	default:
		p.fail(writer, E.New("TLS material peer received unexpected authentication type: ", envelope.Type))
	}
}

func (p *m1TLSMaterialPeer) validateTLSRequest(request *http.Request) error {
	if request.TLS == nil || request.TLS.ServerName != m1TLSMaterialHostname {
		return E.New("TLS material request omitted expected SNI: ", request.TLS)
	}
	if len(request.TLS.VerifiedChains) == 0 || len(request.TLS.PeerCertificates) == 0 {
		return E.New("TLS material request omitted a verified client certificate")
	}
	if !bytes.Equal(request.TLS.PeerCertificates[0].Raw, p.clientCertificate.Raw) {
		return E.New("TLS material request used an unexpected client certificate")
	}
	return nil
}

func (p *m1TLSMaterialPeer) serveTunnel(writer http.ResponseWriter) {
	hijacker, supported := writer.(http.Hijacker)
	if !supported {
		err := E.New("TLS material response writer cannot hijack CSTP CONNECT")
		p.recordFailure(err)
		p.tunnelClosed <- err
		return
	}
	connection, readWriter, err := hijacker.Hijack()
	if err != nil {
		err = E.Cause(err, "hijack TLS material CSTP connection")
		p.recordFailure(err)
		p.tunnelClosed <- err
		return
	}
	defer connection.Close()
	err = connection.SetDeadline(time.Now().Add(10 * time.Second))
	if err == nil {
		_, err = readWriter.WriteString("HTTP/1.1 200 CONNECTED\r\n" +
			"X-CSTP-MTU: 1400\r\n" +
			"X-CSTP-Address: 192.0.2.70\r\n" +
			"X-CSTP-Netmask: 255.255.255.0\r\n" +
			"X-CSTP-DPD: 30\r\n" +
			"X-CSTP-Keepalive: 30\r\n" +
			"X-CSTP-Rekey-Method: none\r\n\r\n")
	}
	if err == nil {
		err = readWriter.Flush()
	}
	if err == nil {
		err = writeM1CSTPWireRecord(readWriter, anyConnectPacketData, []byte("tls-material-cstp-data"))
	}
	if err == nil {
		packetType, payload, readErr := readM1CSTPWireRecord(readWriter)
		err = readErr
		if err == nil && (packetType != anyConnectPacketData || string(payload) != "tls-material-client-data") {
			err = E.New("TLS material peer received unexpected CSTP client data: type=", packetType, " payload=", payload)
		}
		if err == nil {
			p.clientDataVerified <- struct{}{}
		}
	}
	if err == nil {
		packetType, payload, readErr := readM1CSTPWireRecord(readWriter)
		err = readErr
		if err == nil && (packetType != 5 || string(payload) != "\xb0Client disconnect") {
			err = E.New("TLS material peer received unexpected CSTP close: type=", packetType, " payload=", payload)
		}
	}
	if err != nil {
		err = E.Cause(err, "serve TLS material CSTP tunnel")
		p.recordFailure(err)
	}
	p.tunnelClosed <- err
}

func (p *m1TLSMaterialPeer) fail(writer http.ResponseWriter, err error) {
	p.recordFailure(err)
	http.Error(writer, err.Error(), http.StatusBadRequest)
}

func (p *m1TLSMaterialPeer) recordFailure(err error) {
	select {
	case p.failures <- err:
	default:
	}
}

func verifyM1TLSMaterialMCAReply(body []byte, challenge []byte, expectedCertificate *x509.Certificate) error {
	var reply m1TLSMaterialMCAReply
	err := xml.Unmarshal(body, &reply)
	if err != nil {
		return E.Cause(err, "parse TLS material MCA reply")
	}
	if reply.Type != "auth-reply" || len(reply.Auth.Chains) != 2 {
		return E.New("TLS material peer received invalid MCA reply shape")
	}
	machineChain := reply.Auth.Chains[0]
	if machineChain.Store != "1M" || machineChain.CertificateSentProtocol == nil {
		return E.New("TLS material MCA reply omitted the machine certificate protocol marker")
	}
	userChain := reply.Auth.Chains[1]
	if userChain.Store != "1U" || userChain.Certificate.Format != "pkcs7" || userChain.Signature.HashAlgorithm != "sha512" {
		return E.New("TLS material MCA reply contained an invalid user certificate chain")
	}
	certificateData, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(userChain.Certificate.Value), ""))
	if err != nil {
		return E.Cause(err, "decode TLS material MCA certificate chain")
	}
	certificateChain, err := pkcs7.Parse(certificateData)
	if err != nil {
		return E.Cause(err, "parse TLS material MCA certificate chain")
	}
	if len(certificateChain.Certificates) != 1 || !bytes.Equal(certificateChain.Certificates[0].Raw, expectedCertificate.Raw) {
		return E.New("TLS material MCA reply used an unexpected signing certificate")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(userChain.Signature.Value), ""))
	if err != nil {
		return E.Cause(err, "decode TLS material MCA signature")
	}
	digest := sha512.Sum512(challenge)
	publicKey, supported := expectedCertificate.PublicKey.(*ecdsa.PublicKey)
	if !supported || !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		return E.New("TLS material MCA signature verification failed")
	}
	return nil
}

func createM1TLSMaterialFixture(t *testing.T) m1TLSMaterialFixture {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate TLS material root key"))
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sing-openconnect TLS material root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	rootDER, rootCertificate := createM1TLSMaterialCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate TLS material server key"))
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: m1TLSMaterialHostname},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{m1TLSMaterialHostname},
	}
	serverDER, _ := createM1TLSMaterialCertificate(t, serverTemplate, rootCertificate, serverKey.Public(), rootKey)
	serverCertificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	serverKeyPEM := marshalM1TLSMaterialPrivateKey(t, serverKey, "")
	serverCertificate, err := tls.X509KeyPair(serverCertificatePEM, serverKeyPEM)
	if err != nil {
		t.Fatal(E.Cause(err, "parse TLS material server identity"))
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate TLS material client key"))
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "sing-openconnect encrypted TLS client"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, clientCertificate := createM1TLSMaterialCertificate(t, clientTemplate, rootCertificate, clientKey.Public(), rootKey)

	mcaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate TLS material MCA key"))
	}
	mcaTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "sing-openconnect encrypted MCA signer"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	mcaDER, mcaCertificate := createM1TLSMaterialCertificate(t, mcaTemplate, rootCertificate, mcaKey.Public(), rootKey)

	wrongRootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate wrong TLS material root key"))
	}
	wrongRootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(5),
		Subject:               pkix.Name{CommonName: "sing-openconnect wrong TLS material root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	wrongRootDER, _ := createM1TLSMaterialCertificate(t, wrongRootTemplate, wrongRootTemplate, wrongRootKey.Public(), wrongRootKey)
	return m1TLSMaterialFixture{
		certificateAuthorityPEM: rootPEM,
		wrongAuthorityPEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrongRootDER}),
		serverCertificate:       serverCertificate,
		clientCertificatePEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}),
		clientEncryptedKeyPEM:   marshalM1TLSMaterialPrivateKey(t, clientKey, m1TLSMaterialKeyPassword),
		clientCertificate:       clientCertificate,
		mcaCertificatePEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: mcaDER}),
		mcaEncryptedKeyPEM:      marshalM1TLSMaterialPrivateKey(t, mcaKey, m1TLSMaterialMCAKeyPassword),
		mcaCertificate:          mcaCertificate,
	}
}

func createM1TLSMaterialCertificate(
	t *testing.T,
	template *x509.Certificate,
	parent *x509.Certificate,
	publicKey crypto.PublicKey,
	parentKey crypto.Signer,
) ([]byte, *x509.Certificate) {
	t.Helper()
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, parentKey)
	if err != nil {
		t.Fatal(E.Cause(err, "create TLS material certificate"))
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(E.Cause(err, "parse TLS material certificate"))
	}
	return certificateDER, certificate
}

func marshalM1TLSMaterialPrivateKey(t *testing.T, privateKey any, password string) []byte {
	t.Helper()
	keyDER, err := pkcs8.MarshalPrivateKey(privateKey, []byte(password), nil)
	if err != nil {
		t.Fatal(E.Cause(err, "marshal TLS material private key"))
	}
	blockType := "PRIVATE KEY"
	if password != "" {
		blockType = "ENCRYPTED PRIVATE KEY"
	}
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: keyDER})
}

func (d *m1TLSMaterialDialer) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	if network == N.NetworkTCP {
		destination = d.target
	}
	return N.SystemDialer.DialContext(ctx, network, destination)
}

func (d *m1TLSMaterialDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

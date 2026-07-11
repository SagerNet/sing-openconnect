package test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	m4PulseHostname = "pulse-m4.test"
	m4PulseUsername = "pulse-user"
	m4PulsePassword = "pulse-password"
	m4PulseCookie   = "pulse-cookie-0123456789abcdef"

	m4PulseVendorTCG      = 0x5597
	m4PulseVendorJuniper  = 0x0a4c
	m4PulseVendorJuniper2 = 0x0583
	m4PulseAuthJuniper    = m4PulseVendorJuniper<<8 | 1
	m4PulseExpanded       = 0xfe000a4c
)

type m4PulsePeer struct {
	listener net.Listener
	port     uint16
	failures chan error
	done     chan struct{}
	close    sync.Once
}

type m4PulseDialer struct {
	hostname string
	address  M.Socksaddr
}

type m4PulseFrame struct {
	vendor    uint32
	frameType uint32
	sequence  uint32
	payload   []byte
}

type m4PulseAVP struct {
	code   uint32
	vendor uint32
	data   []byte
}

func TestM4PulseIndependentTLSFullPeer(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	certificate, roots := createM2GPPeerCertificate(t, m4PulseHostname)
	peer := newM4PulsePeer(t, certificate)
	defer peer.Close()
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context:    ctx,
		Server:     net.JoinHostPort(m4PulseHostname, strconv.Itoa(int(peer.port))),
		Flavor:     openconnect.FlavorPulse,
		Username:   m4PulseUsername,
		Password:   m4PulsePassword,
		ReportedOS: "linux-64",
		NoUDP:      true,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
		}},
		Dialer: &m4PulseDialer{
			hostname: m4PulseHostname,
			address:  M.ParseSocksaddrHostPort("127.0.0.1", peer.port),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	for !client.Ready() {
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for independent Pulse TLS tunnel"))
		case peerErr := <-peer.failures:
			t.Fatal(peerErr)
		case <-client.AuthFormUpdated():
			if client.PendingAuthForm() != nil {
				t.Fatal("Pulse stable credentials unexpectedly published a form")
			}
		case <-time.After(10 * time.Millisecond):
		}
	}
	configuration := client.TunnelConfiguration()
	if configuration.MTU != 1400 {
		t.Fatalf("unexpected Pulse MTU: %d", configuration.MTU)
	}
	wantedIPv4 := netip.MustParsePrefix("192.0.2.10/24")
	wantedIPv6 := netip.MustParsePrefix("2001:db8:44::10/64")
	if !slices.Contains(configuration.Addresses, wantedIPv4) || !slices.Contains(configuration.Addresses, wantedIPv6) {
		t.Fatalf("unexpected Pulse addresses: %v", configuration.Addresses)
	}
	if !slices.Contains(configuration.DNS, netip.MustParseAddr("198.51.100.53")) ||
		!slices.Contains(configuration.DNS, netip.MustParseAddr("2001:db8:44::53")) {
		t.Fatalf("unexpected Pulse DNS servers: %v", configuration.DNS)
	}
	ipv4Packet := []byte{
		0x45, 0, 0, 20, 0, 1, 0, 0, 64, 59, 0, 0,
		192, 0, 2, 10, 198, 51, 100, 1,
	}
	err = client.WriteDataPacket(ipv4Packet)
	if err != nil {
		t.Fatal(err)
	}
	receivedIPv4, err := client.ReadDataPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(receivedIPv4, ipv4Packet) {
		t.Fatalf("unexpected Pulse IPv4 TLS echo: %x", receivedIPv4)
	}
	ipv6Packet := []byte{
		0x60, 0, 0, 0, 0, 0, 59, 64,
		0x20, 0x01, 0x0d, 0xb8, 0, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
		0x20, 0x01, 0x0d, 0xb8, 0, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
	}
	err = client.WriteDataPacket(ipv6Packet)
	if err != nil {
		t.Fatal(err)
	}
	receivedIPv6, err := client.ReadDataPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(receivedIPv6, ipv6Packet) {
		t.Fatalf("unexpected Pulse IPv6 TLS echo: %x", receivedIPv6)
	}
	err = client.Close()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case peerErr := <-peer.failures:
		t.Fatal(peerErr)
	case <-peer.done:
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for independent Pulse peer close"))
	}
}

func TestM4PulseIndependentEAPTTLSFullPeer(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	certificate, clientCertificate, roots, certificateAuthorityPEM := createM4PulseTTLSCertificates(t, m4PulseHostname)
	temporaryDirectory := t.TempDir()
	certificatePath := filepath.Join(temporaryDirectory, "peer.pem")
	privateKeyPath := filepath.Join(temporaryDirectory, "peer-key.pem")
	certificateAuthorityPath := filepath.Join(temporaryDirectory, "peer-ca.pem")
	var certificatePEM bytes.Buffer
	for _, certificateDER := range certificate.Certificate {
		encodeErr := pem.Encode(&certificatePEM, &pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	err = os.WriteFile(certificatePath, certificatePEM.Bytes(), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(privateKeyPath, privateKeyPEM, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(certificateAuthorityPath, certificateAuthorityPEM, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(
		ctx,
		"python3",
		filepath.Join("testdata", "pulse-peer", "pulse_peer.py"),
		certificatePath,
		privateKeyPath,
		certificateAuthorityPath,
	)
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	var standardError bytes.Buffer
	command.Stderr = &standardError
	standardOutput, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	err = command.Start()
	if err != nil {
		t.Fatal(err)
	}
	commandFinished := false
	defer func() {
		if commandFinished {
			return
		}
		_ = command.Process.Kill()
		_ = command.Wait()
	}()
	portLine, err := bufio.NewReader(standardOutput).ReadString('\n')
	if err != nil {
		t.Fatalf("read independent Python Pulse peer port: %v: %s", err, standardError.String())
	}
	portValue, err := strconv.ParseUint(strings.TrimSpace(portLine), 10, 16)
	if err != nil {
		t.Fatalf("parse independent Python Pulse peer port: %v", err)
	}
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context:    ctx,
		Server:     net.JoinHostPort(m4PulseHostname, strconv.Itoa(int(portValue))),
		Flavor:     openconnect.FlavorPulse,
		Username:   m4PulseUsername,
		Password:   m4PulsePassword,
		ReportedOS: "linux-64",
		NoUDP:      true,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			Certificates: []tls.Certificate{clientCertificate},
			RootCAs:      roots,
			MinVersion:   tls.VersionTLS12,
		}},
		Dialer: &m4PulseDialer{
			hostname: m4PulseHostname,
			address:  M.ParseSocksaddrHostPort("127.0.0.1", uint16(portValue)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatalf("start Pulse EAP-TTLS client: %v: %s", err, standardError.String())
	}
	for !client.Ready() {
		select {
		case <-ctx.Done():
			t.Fatalf("wait for Pulse EAP-TTLS tunnel: %v: %s", ctx.Err(), standardError.String())
		case <-client.AuthFormUpdated():
			if client.PendingAuthForm() != nil {
				t.Fatal("Pulse EAP-TTLS stable credentials unexpectedly published a form")
			}
		case <-time.After(10 * time.Millisecond):
		}
	}
	unassignedIPv6Packet := append([]byte{0x60}, make([]byte, 39)...)
	err = client.WriteDataPacket(unassignedIPv6Packet)
	if err == nil {
		t.Fatal("Pulse IPv4-only tunnel accepted an IPv6 packet")
	}
	packet := []byte{
		0x45, 0, 0, 20, 0, 1, 0, 0, 64, 59, 0, 0,
		192, 0, 2, 20, 198, 51, 100, 2,
	}
	err = client.WriteDataPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	received, err := client.ReadDataPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, packet) {
		t.Fatalf("unexpected Pulse EAP-TTLS echo: %x", received)
	}
	err = client.Close()
	if err != nil {
		t.Fatal(err)
	}
	err = command.Wait()
	commandFinished = true
	if err != nil {
		t.Fatalf("independent Python Pulse peer failed: %v: %s", err, standardError.String())
	}
}

func createM4PulseTTLSCertificates(
	t *testing.T,
	hostname string,
) (tls.Certificate, tls.Certificate, *x509.CertPool, []byte) {
	t.Helper()
	certificateAuthorityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate Pulse TTLS certificate authority key"))
	}
	now := time.Now()
	certificateAuthorityTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Pulse TTLS peer test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certificateAuthorityDER, err := x509.CreateCertificate(
		rand.Reader,
		certificateAuthorityTemplate,
		certificateAuthorityTemplate,
		certificateAuthorityKey.Public(),
		certificateAuthorityKey,
	)
	if err != nil {
		t.Fatal(E.Cause(err, "create Pulse TTLS certificate authority"))
	}
	certificateAuthority, err := x509.ParseCertificate(certificateAuthorityDER)
	if err != nil {
		t.Fatal(E.Cause(err, "parse Pulse TTLS certificate authority"))
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate Pulse TTLS server key"))
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(
		rand.Reader,
		serverTemplate,
		certificateAuthority,
		serverKey.Public(),
		certificateAuthorityKey,
	)
	if err != nil {
		t.Fatal(E.Cause(err, "create Pulse TTLS server certificate"))
	}
	parentCertificate := certificateAuthority
	parentKey := certificateAuthorityKey
	intermediateCertificates := make([][]byte, 0, 30)
	for index := 0; index < 30; index++ {
		intermediateKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			t.Fatal(E.Cause(keyErr, "generate Pulse TTLS intermediate key"))
		}
		intermediateTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(10 + index)),
			Subject:               pkix.Name{CommonName: "Pulse TTLS intermediate " + strconv.Itoa(index)},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		intermediateDER, createErr := x509.CreateCertificate(
			rand.Reader,
			intermediateTemplate,
			parentCertificate,
			intermediateKey.Public(),
			parentKey,
		)
		if createErr != nil {
			t.Fatal(E.Cause(createErr, "create Pulse TTLS intermediate certificate"))
		}
		intermediateCertificate, parseErr := x509.ParseCertificate(intermediateDER)
		if parseErr != nil {
			t.Fatal(E.Cause(parseErr, "parse Pulse TTLS intermediate certificate"))
		}
		intermediateCertificates = append(intermediateCertificates, intermediateDER)
		parentCertificate = intermediateCertificate
		parentKey = intermediateKey
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate Pulse TTLS client key"))
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "Pulse TTLS client"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, parentCertificate, clientKey.Public(), parentKey)
	if err != nil {
		t.Fatal(E.Cause(err, "create Pulse TTLS client certificate"))
	}
	clientChain := make([][]byte, 0, 1+len(intermediateCertificates))
	clientChain = append(clientChain, clientDER)
	for index := len(intermediateCertificates) - 1; index >= 0; index-- {
		clientChain = append(clientChain, intermediateCertificates[index])
	}
	rootCertificates := x509.NewCertPool()
	rootCertificates.AddCert(certificateAuthority)
	certificateAuthorityPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateAuthorityDER})
	return tls.Certificate{
			Certificate: [][]byte{serverDER, certificateAuthorityDER},
			PrivateKey:  serverKey,
		}, tls.Certificate{
			Certificate: clientChain,
			PrivateKey:  clientKey,
		}, rootCertificates, certificateAuthorityPEM
}

func newM4PulsePeer(t *testing.T, certificate tls.Certificate) *m4PulsePeer {
	t.Helper()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(E.Cause(err, "listen for independent Pulse peer"))
	}
	tcpAddress, loaded := listener.Addr().(*net.TCPAddr)
	if !loaded {
		_ = listener.Close()
		t.Fatal("independent Pulse listener has no TCP address")
	}
	peer := &m4PulsePeer{
		listener: listener,
		port:     uint16(tcpAddress.Port),
		failures: make(chan error, 1),
		done:     make(chan struct{}),
	}
	go peer.serve()
	return peer
}

func (p *m4PulsePeer) serve() {
	defer close(p.done)
	conn, err := p.listener.Accept()
	if err != nil {
		if !E.IsClosed(err) {
			p.report(E.Cause(err, "accept independent Pulse connection"))
		}
		return
	}
	defer conn.Close()
	err = p.exchange(conn)
	if err != nil {
		p.report(err)
	}
}

func (p *m4PulsePeer) exchange(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return E.Cause(err, "read independent Pulse upgrade request")
	}
	if request.Method != http.MethodGet || request.URL.Path != "/" || request.Header.Get("Content-Type") != "EAP" ||
		request.Header.Get("Upgrade") != "IF-T/TLS 1.0" || request.ContentLength != 0 {
		return E.New("independent Pulse peer received invalid HTTP upgrade")
	}
	err = writeM4PulseBytes(conn, []byte("HTTP/1.1 101 Switching Protocols\r\n\r\n"))
	if err != nil {
		return err
	}
	frame, err := readM4PulseFrame(reader)
	if err != nil {
		return err
	}
	if frame.vendor != m4PulseVendorTCG || frame.frameType != 1 || !bytes.Equal(frame.payload, []byte{0, 1, 2, 2}) {
		return E.New("independent Pulse peer received invalid version request")
	}
	err = writeM4PulseFrame(conn, m4PulseVendorTCG, 2, 0, []byte{0, 0, 0, 2}, false)
	if err != nil {
		return err
	}
	frame, err = readM4PulseFrame(reader)
	if err != nil {
		return err
	}
	if frame.vendor != m4PulseVendorJuniper || frame.frameType != 0x88 ||
		!bytes.Contains(frame.payload, []byte("clientCapabilities={}")) || frame.payload[len(frame.payload)-1] != 0 {
		return E.New("independent Pulse peer received invalid client information")
	}
	var authType [4]byte
	binary.BigEndian.PutUint32(authType[:], m4PulseAuthJuniper)
	err = writeM4PulseFrame(conn, m4PulseVendorTCG, 5, 1, authType[:], false)
	if err != nil {
		return err
	}
	frame, err = readM4PulseFrame(reader)
	if err != nil {
		return err
	}
	identity, err := parseM4PulseAuthenticationEAP(frame, 2)
	if err != nil {
		return err
	}
	if len(identity) != 14 || identity[4] != 1 || string(identity[5:]) != "anonymous" {
		return E.New("independent Pulse peer received invalid anonymous EAP identity")
	}
	serverInformation := buildM4PulseEAP(1, 3, 0xfe, 1, nil)
	err = writeM4PulseAuthentication(conn, 2, serverInformation, false)
	if err != nil {
		return err
	}
	frame, err = readM4PulseFrame(reader)
	if err != nil {
		return err
	}
	clientInformation, err := parseM4PulseAuthenticationEAP(frame, 2)
	if err != nil {
		return err
	}
	clientAttributes, err := parseM4PulseAVPs(clientInformation[12:])
	if err != nil {
		return err
	}
	if string(m4PulseAVPValue(clientAttributes, 0xd5e, m4PulseVendorJuniper2)) != "Linux" ||
		!strings.HasPrefix(string(m4PulseAVPValue(clientAttributes, 0xd70, m4PulseVendorJuniper2)), "Pulse-Secure/22.2.1.1295 (") {
		return E.New("independent Pulse peer received invalid platform AVPs")
	}
	passwordInner := buildM4PulseEAP(1, 7, 0xfe, 2, []byte{1})
	passwordAttribute := appendM4PulseAVP(nil, 79, 0, passwordInner)
	passwordRequest := buildM4PulseEAP(1, 4, 0xfe, 1, passwordAttribute)
	err = writeM4PulseAuthentication(conn, 3, passwordRequest, false)
	if err != nil {
		return err
	}
	frame, err = readM4PulseFrame(reader)
	if err != nil {
		return err
	}
	credentialResponse, err := parseM4PulseAuthenticationEAP(frame, 2)
	if err != nil {
		return err
	}
	credentialAttributes, err := parseM4PulseAVPs(credentialResponse[12:])
	if err != nil {
		return err
	}
	if string(m4PulseAVPValue(credentialAttributes, 0xd6d, m4PulseVendorJuniper2)) != m4PulseUsername {
		return E.New("independent Pulse peer received incorrect username")
	}
	passwordEAP := m4PulseAVPValue(credentialAttributes, 79, 0)
	if len(passwordEAP) < 15 || passwordEAP[12] != 2 || passwordEAP[13] != 2 ||
		string(passwordEAP[15:15+int(passwordEAP[14])-2]) != m4PulsePassword {
		return E.New("independent Pulse peer received incorrect password")
	}
	cookieAttributes := appendM4PulseAVP(nil, 0xd53, m4PulseVendorJuniper2, []byte(m4PulseCookie))
	var idle [4]byte
	binary.BigEndian.PutUint32(idle[:], 300)
	cookieAttributes = appendM4PulseAVP(cookieAttributes, 0xd75, m4PulseVendorJuniper2, idle[:])
	cookieRequest := buildM4PulseEAP(1, 5, 0xfe, 1, cookieAttributes)
	err = writeM4PulseAuthentication(conn, 4, cookieRequest, false)
	if err != nil {
		return err
	}
	frame, err = readM4PulseFrame(reader)
	if err != nil {
		return err
	}
	finalResponse, err := parseM4PulseAuthenticationEAP(frame, 2)
	if err != nil || len(finalResponse) != 12 {
		return E.New("independent Pulse peer did not acknowledge its cookie")
	}
	success := []byte{3, 5, 0, 4}
	successPayload := append(authType[:0:0], authType[:]...)
	successPayload = append(successPayload, success...)
	err = writeM4PulseFrame(conn, m4PulseVendorTCG, 7, 5, successPayload, false)
	if err != nil {
		return err
	}
	configuration := buildM4PulseMainConfiguration()
	err = writeM4PulseFrame(conn, m4PulseVendorJuniper, 1, 6, configuration, false)
	if err != nil {
		return err
	}
	err = writeM4PulseFrame(conn, m4PulseVendorJuniper, 0x8f, 7, []byte{0, 0, 0, 0}, false)
	if err != nil {
		return err
	}
	frame, err = readM4PulseFrame(reader)
	if err != nil {
		return err
	}
	if frame.vendor != m4PulseVendorJuniper || frame.frameType != 4 || len(frame.payload) == 0 || frame.payload[0]>>4 != 4 {
		return E.New("independent Pulse peer did not receive IPv4 tunnel data")
	}
	err = writeM4PulseFrame(conn, m4PulseVendorJuniper, 4, 8, frame.payload, true)
	if err != nil {
		return err
	}
	frame, err = readM4PulseFrame(reader)
	if err != nil {
		return err
	}
	if frame.vendor != m4PulseVendorJuniper || frame.frameType != 4 || len(frame.payload) == 0 || frame.payload[0]>>4 != 6 {
		return E.New("independent Pulse peer did not receive IPv6 tunnel data")
	}
	err = writeM4PulseFrame(conn, m4PulseVendorJuniper, 4, 9, frame.payload, true)
	if err != nil {
		return err
	}
	frame, err = readM4PulseFrame(reader)
	if err != nil {
		return err
	}
	if frame.vendor != m4PulseVendorJuniper || frame.frameType != 0x89 || len(frame.payload) != 0 {
		return E.New("independent Pulse peer did not receive graceful close")
	}
	return nil
}

func readM4PulseFrame(reader *bufio.Reader) (m4PulseFrame, error) {
	header := make([]byte, 16)
	_, err := io.ReadFull(reader, header)
	if err != nil {
		return m4PulseFrame{}, E.Cause(err, "read independent Pulse frame header")
	}
	totalLength := int(binary.BigEndian.Uint32(header[8:12]))
	if totalLength < 16 || totalLength > 1024*1024 {
		return m4PulseFrame{}, E.New("invalid independent Pulse frame length: ", totalLength)
	}
	payload := make([]byte, totalLength-16)
	_, err = io.ReadFull(reader, payload)
	if err != nil {
		return m4PulseFrame{}, E.Cause(err, "read independent Pulse frame payload")
	}
	return m4PulseFrame{
		vendor:    binary.BigEndian.Uint32(header[0:4]),
		frameType: binary.BigEndian.Uint32(header[4:8]),
		sequence:  binary.BigEndian.Uint32(header[12:16]),
		payload:   payload,
	}, nil
}

func writeM4PulseFrame(conn net.Conn, vendor uint32, frameType uint32, sequence uint32, payload []byte, chunked bool) error {
	frame := make([]byte, 16+len(payload))
	binary.BigEndian.PutUint32(frame[0:4], vendor)
	binary.BigEndian.PutUint32(frame[4:8], frameType)
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(frame)))
	binary.BigEndian.PutUint32(frame[12:16], sequence)
	copy(frame[16:], payload)
	if !chunked {
		return writeM4PulseBytes(conn, frame)
	}
	for len(frame) > 0 {
		chunkLength := min(len(frame), 3)
		err := writeM4PulseBytes(conn, frame[:chunkLength])
		if err != nil {
			return err
		}
		frame = frame[chunkLength:]
	}
	return nil
}

func writeM4PulseAuthentication(conn net.Conn, sequence uint32, eap []byte, chunked bool) error {
	payload := make([]byte, 4+len(eap))
	binary.BigEndian.PutUint32(payload[:4], m4PulseAuthJuniper)
	copy(payload[4:], eap)
	return writeM4PulseFrame(conn, m4PulseVendorTCG, 5, sequence, payload, chunked)
}

func parseM4PulseAuthenticationEAP(frame m4PulseFrame, expectedCode byte) ([]byte, error) {
	if frame.vendor&0x00ffffff != m4PulseVendorTCG || len(frame.payload) < 8 ||
		binary.BigEndian.Uint32(frame.payload[:4]) != m4PulseAuthJuniper {
		return nil, E.New("invalid independent Pulse authentication frame")
	}
	eap := frame.payload[4:]
	if eap[0] != expectedCode || int(binary.BigEndian.Uint16(eap[2:4])) != len(eap) {
		return nil, E.New("invalid independent Pulse EAP packet")
	}
	return eap, nil
}

func buildM4PulseEAP(code byte, identifier byte, eapType byte, subtype uint32, payload []byte) []byte {
	headerLength := 5
	if eapType == 0xfe {
		headerLength = 12
	}
	eap := make([]byte, headerLength+len(payload))
	eap[0] = code
	eap[1] = identifier
	binary.BigEndian.PutUint16(eap[2:4], uint16(len(eap)))
	if eapType == 0xfe {
		binary.BigEndian.PutUint32(eap[4:8], m4PulseExpanded)
		binary.BigEndian.PutUint32(eap[8:12], subtype)
	} else {
		eap[4] = eapType
	}
	copy(eap[headerLength:], payload)
	return eap
}

func appendM4PulseAVP(destination []byte, code uint32, vendor uint32, data []byte) []byte {
	headerLength := 8
	flags := byte(0x40)
	if vendor != 0 {
		headerLength = 12
		flags |= 0x80
	}
	attributeLength := headerLength + len(data)
	alignedLength := (attributeLength + 3) &^ 3
	start := len(destination)
	destination = append(destination, make([]byte, alignedLength)...)
	binary.BigEndian.PutUint32(destination[start:start+4], code)
	binary.BigEndian.PutUint32(destination[start+4:start+8], uint32(flags)<<24|uint32(attributeLength))
	if vendor != 0 {
		binary.BigEndian.PutUint32(destination[start+8:start+12], vendor)
	}
	copy(destination[start+headerLength:start+attributeLength], data)
	return destination
}

func parseM4PulseAVPs(content []byte) ([]m4PulseAVP, error) {
	var attributes []m4PulseAVP
	for len(content) > 0 {
		if len(content) < 8 {
			return nil, E.New("independent Pulse AVP header is truncated")
		}
		flags := content[4]
		attributeLength := int(binary.BigEndian.Uint32(content[4:8]) & 0x00ffffff)
		headerLength := 8
		if flags&0x80 != 0 {
			headerLength = 12
		}
		alignedLength := (attributeLength + 3) &^ 3
		if attributeLength < headerLength || alignedLength > len(content) {
			return nil, E.New("independent Pulse AVP length is invalid")
		}
		attribute := m4PulseAVP{code: binary.BigEndian.Uint32(content[:4])}
		if headerLength == 12 {
			attribute.vendor = binary.BigEndian.Uint32(content[8:12])
		}
		attribute.data = append([]byte(nil), content[headerLength:attributeLength]...)
		attributes = append(attributes, attribute)
		content = content[alignedLength:]
	}
	return attributes, nil
}

func m4PulseAVPValue(attributes []m4PulseAVP, code uint32, vendor uint32) []byte {
	for _, attribute := range attributes {
		if attribute.code == code && attribute.vendor == vendor {
			return attribute.data
		}
	}
	return nil
}

func buildM4PulseMainConfiguration() []byte {
	routing := []byte{0x2e, 0, 0, 8, 0, 0, 0, 0}
	attributes := make([]byte, 8)
	binary.BigEndian.PutUint32(attributes[4:8], 0x03000000)
	attributes = appendM4PulseAttribute(attributes, 0x0001, netip.MustParseAddr("192.0.2.10").AsSlice())
	attributes = appendM4PulseAttribute(attributes, 0x0002, netip.MustParseAddr("255.255.255.0").AsSlice())
	attributes = appendM4PulseAttribute(attributes, 0x0003, netip.MustParseAddr("198.51.100.53").AsSlice())
	assignedIPv6 := netip.MustParseAddr("2001:db8:44::10").As16()
	attributes = appendM4PulseAttribute(attributes, 0x0008, append(assignedIPv6[:], 64))
	dnsIPv6 := netip.MustParseAddr("2001:db8:44::53").As16()
	attributes = appendM4PulseAttribute(attributes, 0x000a, dnsIPv6[:])
	var mtu [4]byte
	binary.BigEndian.PutUint32(mtu[:], 1400)
	attributes = appendM4PulseAttribute(attributes, 0x4005, mtu[:])
	binary.BigEndian.PutUint32(attributes[:4], uint32(len(attributes)))
	section := append(routing, attributes...)
	payload := make([]byte, 28+len(section))
	binary.BigEndian.PutUint32(payload[16:20], 0x2c20f000)
	binary.BigEndian.PutUint32(payload[24:28], uint32(len(payload)))
	copy(payload[28:], section)
	return payload
}

func appendM4PulseAttribute(destination []byte, attributeType uint16, content []byte) []byte {
	start := len(destination)
	destination = append(destination, make([]byte, 4+len(content))...)
	binary.BigEndian.PutUint16(destination[start:start+2], attributeType)
	binary.BigEndian.PutUint16(destination[start+2:start+4], uint16(len(content)))
	copy(destination[start+4:], content)
	return destination
}

func writeM4PulseBytes(w io.Writer, content []byte) error {
	for len(content) > 0 {
		n, err := w.Write(content)
		if err != nil {
			return E.Cause(err, "write independent Pulse peer bytes")
		}
		if n <= 0 || n > len(content) {
			return E.New("invalid independent Pulse peer write length")
		}
		content = content[n:]
	}
	return nil
}

func (p *m4PulsePeer) report(err error) {
	select {
	case p.failures <- err:
	default:
	}
}

func (p *m4PulsePeer) Close() {
	p.close.Do(func() {
		_ = p.listener.Close()
	})
}

func (d *m4PulseDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkTCP || destination.Port != d.address.Port {
		return nil, E.New("unexpected independent Pulse dial destination: ", destination)
	}
	if destination.Fqdn != d.hostname && destination.Addr != d.address.Addr {
		return nil, E.New("independent Pulse client did not use the hostname or accepted address")
	}
	return N.SystemDialer.DialContext(ctx, network, d.address)
}

func (d *m4PulseDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

var _ N.Dialer = (*m4PulseDialer)(nil)

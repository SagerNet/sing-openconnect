package test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const m4NCONCPIPv6Hostname = "gateway.m4-nc-ipv6.test"

type m4NCONCPIPv6Peer struct {
	server       *httptest.Server
	errors       chan error
	control      chan struct{}
	outbound     chan []byte
	tunnelClosed chan struct{}
	logout       chan struct{}
	logoutOnce   sync.Once
}

func TestM4NetworkConnectONCPDisablesESPOverIPv6Peer(t *testing.T) {
	t.Parallel()
	rootCertificate, certificates := createM4NCCertificates(t, []string{m4NCONCPIPv6Hostname})
	peer := &m4NCONCPIPv6Peer{
		errors:       make(chan error, 16),
		control:      make(chan struct{}),
		outbound:     make(chan []byte, 1),
		tunnelClosed: make(chan struct{}),
		logout:       make(chan struct{}),
	}
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback is unavailable: ", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(peer.serve))
	server.Listener = listener
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificates[0]}}
	server.StartTLS()
	peer.server = server
	t.Cleanup(server.Close)
	gatewayAddress := M.SocksaddrFromNet(server.Listener.Addr())
	dialer := &m4NCDialer{
		routes: map[string]M.Socksaddr{
			m4NCONCPIPv6Hostname: gatewayAddress,
		},
		gatewayHostname: m4NCONCPIPv6Hostname,
		gatewayAddress:  gatewayAddress,
	}
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 1)
	serverURL := "https://" + net.JoinHostPort(m4NCONCPIPv6Hostname, strconv.Itoa(int(gatewayAddress.Port)))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  serverURL + "/start",
		Flavor:  openconnect.FlavorNC,
		Dialer:  dialer,
		TLSConfig: openconnect.ClientTLSOptions{
			CertificateAuthority: openconnect.Material{Content: rootCertificate},
		},
		OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
			configurationEvents <- event
			return nil
		},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create IPv6 oNCP peer client"))
	}
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start IPv6 oNCP peer client"))
	}
	select {
	case <-configurationEvents:
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for IPv6 oNCP readiness"))
	}
	select {
	case <-peer.control:
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for IPv6 oNCP KMP 303"))
	}
	outbound := buildM4NCIPv4Packet([]byte("ipv6-outer-tls"))
	err = client.WriteDataPacket(outbound)
	if err != nil {
		t.Fatal(E.Cause(err, "write IPv6-outer oNCP TLS data"))
	}
	select {
	case packet := <-peer.outbound:
		if string(packet) != string(outbound) {
			t.Fatal("IPv6-outer oNCP TLS packet mismatch")
		}
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for IPv6-outer oNCP TLS packet"))
	}
	err = client.Close()
	if err != nil {
		t.Fatal(E.Cause(err, "close IPv6 oNCP peer client"))
	}
	select {
	case <-peer.logout:
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for IPv6 oNCP logout"))
	}
}

func (p *m4NCONCPIPv6Peer) serve(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/start":
		http.SetCookie(writer, &http.Cookie{Name: "DSID", Value: "ipv6-session", Path: "/", Secure: true})
		_, _ = io.WriteString(writer, "accepted")
	case "/dana/js":
		p.serveTunnel(writer)
	case "/dana-na/auth/logout.cgi":
		select {
		case <-p.tunnelClosed:
		default:
			p.fail(writer, E.New("IPv6 oNCP logout arrived before tunnel close"))
			return
		}
		writer.WriteHeader(http.StatusOK)
		p.logoutOnce.Do(func() { close(p.logout) })
	default:
		p.fail(writer, E.New("unexpected IPv6 oNCP peer path: ", request.URL.Path))
	}
}

func (p *m4NCONCPIPv6Peer) serveTunnel(writer http.ResponseWriter) {
	hijacker, loaded := writer.(http.Hijacker)
	if !loaded {
		p.fail(writer, E.New("IPv6 oNCP peer cannot hijack TLS"))
		return
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		p.fail(writer, E.Cause(err, "hijack IPv6 oNCP TLS connection"))
		return
	}
	defer connection.Close()
	_, err = buffered.WriteString("HTTP/1.1 200 OK\r\n\r\n")
	if err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		p.report(err)
		return
	}
	_, err = readM4NCONCPRecord(buffered.Reader)
	if err != nil {
		p.report(err)
		return
	}
	configuration := buildM4NCONCPConfigurationWithESP(4444, 0x55667788, []byte("server-encrypt!!"), []byte("server-auth-key-1234"))
	err = writeM4NCONCPRecord(buffered.Writer, []byte{0})
	if err == nil {
		err = writeM4NCONCPRecord(buffered.Writer, configuration)
	}
	if err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		p.report(err)
		return
	}
	control, err := readM4NCONCPRecord(buffered.Reader)
	if err != nil {
		p.report(err)
		return
	}
	messages, err := splitM4NCONCPMessages(control, true)
	if err != nil || len(messages) != 1 {
		p.report(E.New("IPv6-outer oNCP unexpectedly negotiated ESP KMP 302"))
		return
	}
	err = validateM4NCONCPMTUControl(messages[0], 1300)
	if err != nil {
		p.report(err)
		return
	}
	close(p.control)
	record, err := readM4NCONCPRecord(buffered.Reader)
	if err != nil {
		p.report(err)
		return
	}
	messageType, payload, err := parseM4NCONCPKMP(record, true)
	if err != nil || messageType != 300 {
		p.report(E.New("IPv6-outer oNCP did not remain on KMP 300 TLS data"))
		return
	}
	p.outbound <- append([]byte(nil), payload...)
	one := make([]byte, 1)
	_, err = buffered.Reader.Read(one)
	if err != io.EOF && !E.IsClosed(err) {
		p.report(err)
		return
	}
	close(p.tunnelClosed)
}

func (p *m4NCONCPIPv6Peer) fail(writer http.ResponseWriter, err error) {
	p.report(err)
	http.Error(writer, err.Error(), http.StatusInternalServerError)
}

func (p *m4NCONCPIPv6Peer) report(err error) {
	select {
	case p.errors <- err:
	default:
	}
}

// /tmp/openconnect/oncp.c:179-290 and 333-345 define the fixed KMP 301 ESP attributes emitted by this independent peer.
func buildM4NCONCPConfigurationWithESP(port uint16, spi uint32, encryptionKey []byte, authenticationKey []byte) []byte {
	base := buildM4NCONCPConfiguration()
	messageType, payload, err := parseM4NCONCPKMP(base, false)
	if err != nil || messageType != 301 {
		panic("invalid base oNCP test configuration")
	}
	secret := make([]byte, 64)
	copy(secret, encryptionKey)
	copy(secret[len(encryptionKey):], authenticationKey)
	spiBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(spiBytes, spi)
	keyAttributes := buildM4NCONCPTLV(1, spiBytes)
	keyAttributes = append(keyAttributes, buildM4NCONCPTLV(2, secret)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	fallbackBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(fallbackBytes, 30)
	replayBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(replayBytes, 1)
	algorithmAttributes := buildM4NCONCPTLV(1, []byte{2})
	algorithmAttributes = append(algorithmAttributes, buildM4NCONCPTLV(2, []byte{2})...)
	algorithmAttributes = append(algorithmAttributes, buildM4NCONCPTLV(3, []byte{0})...)
	algorithmAttributes = append(algorithmAttributes, buildM4NCONCPTLV(4, portBytes)...)
	algorithmAttributes = append(algorithmAttributes, buildM4NCONCPTLV(9, fallbackBytes)...)
	algorithmAttributes = append(algorithmAttributes, buildM4NCONCPTLV(10, replayBytes)...)
	payload = append(payload, buildM4NCONCPTLV(7, keyAttributes)...)
	payload = append(payload, buildM4NCONCPTLV(8, algorithmAttributes)...)
	return buildM4NCONCPKMP(301, payload, false)
}

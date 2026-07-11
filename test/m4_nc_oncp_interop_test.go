package test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const m4NCONCPHostname = "gateway.m4-nc-oncp.test"

type m4NCONCPPeer struct {
	access          sync.Mutex
	server          *httptest.Server
	errors          chan error
	controlReceived chan struct{}
	releaseData     chan struct{}
	outboundPacket  chan []byte
	tunnelClosed    chan struct{}
	logout          chan struct{}
	logoutOnce      sync.Once
}

func TestM4NetworkConnectONCPTLSPeerInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rootCertificate, certificates := createM4NCCertificates(t, []string{m4NCONCPHostname})
	peer := &m4NCONCPPeer{
		errors:          make(chan error, 16),
		controlReceived: make(chan struct{}),
		releaseData:     make(chan struct{}),
		outboundPacket:  make(chan []byte, 1),
		tunnelClosed:    make(chan struct{}),
		logout:          make(chan struct{}),
	}
	peer.server = newM2GPTLSServer(t, certificates[0], http.HandlerFunc(peer.serve))
	gatewayAddress := M.SocksaddrFromNet(peer.server.Listener.Addr())
	dialer := &m4NCDialer{
		routes: map[string]M.Socksaddr{
			m4NCONCPHostname: gatewayAddress,
		},
		gatewayHostname: m4NCONCPHostname,
		gatewayAddress:  gatewayAddress,
	}
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 1)
	serverURL := "https://" + net.JoinHostPort(m4NCONCPHostname, strconv.Itoa(int(gatewayAddress.Port)))
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  serverURL + "/start",
		Flavor:  openconnect.FlavorNC,
		NoUDP:   true,
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
		t.Fatal(E.Cause(err, "create oNCP TLS peer client"))
	}
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start oNCP TLS peer client"))
	}
	select {
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case event := <-configurationEvents:
		if event.Reason != openconnect.TunnelConfigurationEventInitial {
			t.Fatalf("unexpected oNCP configuration event reason: %s", event.Reason)
		}
		assertM4NCONCPConfiguration(t, event.Configuration)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for oNCP TLS readiness"))
	}
	if !client.Ready() {
		t.Fatal("oNCP TLS session was not immediately ready after KMP 303 negotiation")
	}
	select {
	case <-peer.controlReceived:
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for oNCP initial control"))
	}
	close(peer.releaseData)
	expectedInbound := [][]byte{
		buildM4NCIPv4Packet([]byte("startup")),
		buildM4NCIPv4Packet([]byte("runtime-one")),
		buildM4NCIPv4Packet([]byte("runtime-two")),
	}
	for packetIndex, expected := range expectedInbound {
		packet, readErr := client.ReadDataPacket(ctx)
		if readErr != nil {
			t.Fatal(E.Cause(readErr, "read oNCP TLS peer packet ", packetIndex))
		}
		if !bytes.Equal(packet, expected) {
			t.Fatalf("oNCP TLS inbound packet %d mismatch", packetIndex)
		}
	}
	outbound := buildM4NCIPv4Packet([]byte("client-outbound"))
	err = client.WriteDataPacket(outbound)
	if err != nil {
		t.Fatal(E.Cause(err, "write oNCP TLS peer packet"))
	}
	select {
	case packet := <-peer.outboundPacket:
		if !bytes.Equal(packet, outbound) {
			t.Fatal("oNCP TLS outbound packet mismatch")
		}
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for oNCP TLS outbound packet"))
	}
	err = client.Close()
	if err != nil {
		t.Fatal(E.Cause(err, "close oNCP TLS peer client"))
	}
	select {
	case <-peer.logout:
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for oNCP logout"))
	}
}

func (p *m4NCONCPPeer) serve(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/start":
		http.SetCookie(writer, &http.Cookie{Name: "DSID", Value: "oncp-session", Path: "/", Secure: true})
		_, _ = io.WriteString(writer, "accepted")
	case "/dana/js":
		p.serveTunnel(writer, request)
	case "/dana-na/auth/logout.cgi":
		select {
		case <-p.tunnelClosed:
		default:
			p.fail(writer, E.New("oNCP logout arrived before the TLS tunnel closed"))
			return
		}
		cookie, err := request.Cookie("DSID")
		if err != nil || cookie.Value != "oncp-session" {
			p.fail(writer, E.New("oNCP logout omitted DSID"))
			return
		}
		writer.WriteHeader(http.StatusOK)
		p.logoutOnce.Do(func() { close(p.logout) })
	default:
		p.fail(writer, E.New("unexpected oNCP peer path: ", request.URL.Path))
	}
}

func (p *m4NCONCPPeer) serveTunnel(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.RawQuery != "prot=1&svc=4" || request.Header.Get("Connection") != "close" || request.Header.Get("NCP-Version") != "3" || request.ContentLength != 256 {
		p.fail(writer, E.New("oNCP HTTP upgrade request mismatch"))
		return
	}
	cookie, err := request.Cookie("DSID")
	if err != nil || cookie.Value != "oncp-session" {
		p.fail(writer, E.New("oNCP HTTP upgrade omitted DSID"))
		return
	}
	hijacker, loaded := writer.(http.Hijacker)
	if !loaded {
		p.fail(writer, E.New("oNCP peer HTTP server cannot hijack TLS"))
		return
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		p.fail(writer, E.Cause(err, "hijack oNCP TLS connection"))
		return
	}
	defer connection.Close()
	_, err = buffered.WriteString("HTTP/1.1 200 OK\r\nNCP-Version: 3\r\n\r\n")
	if err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		p.report(E.Cause(err, "write oNCP HTTP upgrade response"))
		return
	}
	hostnamePacket, err := readM4NCONCPRecord(buffered.Reader)
	if err != nil {
		p.report(err)
		return
	}
	hostname, err := parseM4NCONCPHostname(hostnamePacket)
	if err != nil {
		p.report(err)
		return
	}
	expectedHostname, err := os.Hostname()
	if err != nil {
		p.report(E.Cause(err, "read oNCP peer hostname"))
		return
	}
	if hostname != expectedHostname {
		p.report(E.New("oNCP hostname identity mismatch: ", hostname))
		return
	}
	configuration := buildM4NCONCPConfiguration()
	startupPacket := buildM4NCONCPKMP(300, buildM4NCIPv4Packet([]byte("startup")), true)
	err = writeM4NCONCPRecord(buffered.Writer, []byte{0})
	if err == nil {
		err = writeM4NCONCPRecord(buffered.Writer, configuration[:31])
	}
	if err == nil {
		err = writeM4NCONCPRecord(buffered.Writer, startupPacket)
	}
	if err == nil {
		err = writeM4NCONCPRecord(buffered.Writer, configuration[31:])
	}
	if err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		p.report(E.Cause(err, "write oNCP initial configuration"))
		return
	}
	controlRecord, err := readM4NCONCPRecord(buffered.Reader)
	if err != nil {
		p.report(err)
		return
	}
	err = validateM4NCONCPMTUControl(controlRecord, 1300)
	if err != nil {
		p.report(err)
		return
	}
	close(p.controlReceived)
	select {
	case <-p.releaseData:
	case <-request.Context().Done():
		return
	}
	firstPacket := buildM4NCONCPKMP(300, append(buildM4NCIPv4Packet([]byte("runtime-one")), buildM4NCIPv4Packet([]byte("runtime-two"))...), false)
	secondPacket := buildM4NCONCPKMP(300, buildM4NCIPv4Packet([]byte("unused")), false)
	combinedTail := append(append([]byte(nil), firstPacket[len(firstPacket)/2:]...), secondPacket...)
	err = writeM4NCONCPRecord(buffered.Writer, firstPacket[:len(firstPacket)/2])
	if err == nil {
		err = writeM4NCONCPRecord(buffered.Writer, combinedTail)
	}
	if err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		p.report(E.Cause(err, "write oNCP runtime data"))
		return
	}
	outboundRecord, err := readM4NCONCPRecord(buffered.Reader)
	if err != nil {
		p.report(err)
		return
	}
	messageType, outboundPayload, err := parseM4NCONCPKMP(outboundRecord, true)
	if err != nil || messageType != 300 {
		p.report(E.New("oNCP outbound KMP 300 is invalid"))
		return
	}
	p.outboundPacket <- append([]byte(nil), outboundPayload...)
	one := make([]byte, 1)
	_, err = buffered.Reader.Read(one)
	if err != io.EOF && !E.IsClosed(err) {
		p.report(E.Cause(err, "wait for oNCP TLS close"))
		return
	}
	close(p.tunnelClosed)
}

func (p *m4NCONCPPeer) fail(writer http.ResponseWriter, err error) {
	p.report(err)
	http.Error(writer, err.Error(), http.StatusInternalServerError)
}

func (p *m4NCONCPPeer) report(err error) {
	select {
	case p.errors <- err:
	default:
	}
}

// /tmp/openconnect/oncp.c:58-304 and 390-463 define the independently emitted KMP 301 group/attribute stream consumed by this peer.
func buildM4NCONCPConfiguration() []byte {
	addressGroup := buildM4NCONCPTLV(1, append(
		buildM4NCONCPTLV(1, []byte{10, 47, 0, 10}),
		buildM4NCONCPTLV(2, []byte{255, 255, 255, 0})...,
	))
	dnsGroup := buildM4NCONCPTLV(2, append(
		buildM4NCONCPTLV(1, []byte{1, 1, 1, 1}),
		buildM4NCONCPTLV(2, []byte("corp.test"))...,
	))
	routeGroup := buildM4NCONCPTLV(3, append(
		buildM4NCONCPTLV(3, []byte{10, 0, 0, 0, 255, 0, 0, 0}),
		buildM4NCONCPTLV(4, []byte{192, 168, 0, 0, 255, 255, 0, 0})...,
	))
	nbnsGroup := buildM4NCONCPTLV(4, buildM4NCONCPTLV(1, []byte{10, 47, 0, 2}))
	mtuBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(mtuBytes, 1300)
	mtuGroup := buildM4NCONCPTLV(6, buildM4NCONCPTLV(2, mtuBytes))
	payload := append(addressGroup, dnsGroup...)
	payload = append(payload, routeGroup...)
	payload = append(payload, nbnsGroup...)
	payload = append(payload, mtuGroup...)
	return buildM4NCONCPKMP(301, payload, false)
}

func buildM4NCONCPTLV(identifier uint16, content []byte) []byte {
	encoded := make([]byte, 6, 6+len(content))
	binary.BigEndian.PutUint16(encoded[0:2], identifier)
	binary.BigEndian.PutUint32(encoded[2:6], uint32(len(content)))
	return append(encoded, content...)
}

// /tmp/openconnect/oncp.c:323-331 fixes the opaque KMP header bytes and its big-endian payload length.
func buildM4NCONCPKMP(messageType uint16, payload []byte, legacyData bool) []byte {
	message := make([]byte, 20, 20+len(payload))
	binary.BigEndian.PutUint16(message[6:8], messageType)
	message[8] = 1
	if legacyData {
		message[8] = 0
	}
	binary.BigEndian.PutUint16(message[18:20], uint16(len(payload)))
	return append(message, payload...)
}

func parseM4NCONCPKMP(message []byte, outgoing bool) (uint16, []byte, error) {
	if len(message) < 20 || !bytes.Equal(message[:6], make([]byte, 6)) {
		return 0, nil, E.New("oNCP peer KMP header is truncated")
	}
	expectedTail := []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if outgoing {
		expectedTail[4] = 1
	}
	if !bytes.Equal(message[8:18], expectedTail) {
		return 0, nil, E.New("oNCP peer KMP constants mismatch")
	}
	payloadLength := int(binary.BigEndian.Uint16(message[18:20]))
	if payloadLength != len(message)-20 {
		return 0, nil, E.New("oNCP peer KMP length mismatch")
	}
	return binary.BigEndian.Uint16(message[6:8]), message[20:], nil
}

func splitM4NCONCPMessages(record []byte, outgoing bool) ([][]byte, error) {
	var messages [][]byte
	for len(record) > 0 {
		if len(record) < 20 {
			return nil, E.New("oNCP peer control record has a truncated KMP header")
		}
		messageLength := 20 + int(binary.BigEndian.Uint16(record[18:20]))
		if messageLength > len(record) {
			return nil, E.New("oNCP peer control record has a truncated KMP payload")
		}
		_, _, err := parseM4NCONCPKMP(record[:messageLength], outgoing)
		if err != nil {
			return nil, err
		}
		messages = append(messages, append([]byte(nil), record[:messageLength]...))
		record = record[messageLength:]
	}
	return messages, nil
}

// /tmp/openconnect/oncp.c:837-887 prefixes the independent TLS-stream records with a little-endian uint16 length.
func writeM4NCONCPRecord(writer *bufio.Writer, content []byte) error {
	length := make([]byte, 2)
	binary.LittleEndian.PutUint16(length, uint16(len(content)))
	_, err := writer.Write(length)
	if err == nil {
		_, err = writer.Write(content)
	}
	return err
}

func readM4NCONCPRecord(reader *bufio.Reader) ([]byte, error) {
	length := make([]byte, 2)
	_, err := io.ReadFull(reader, length)
	if err != nil {
		return nil, E.Cause(err, "read oNCP peer record length")
	}
	content := make([]byte, int(binary.LittleEndian.Uint16(length)))
	_, err = io.ReadFull(reader, content)
	if err != nil {
		return nil, E.Cause(err, "read oNCP peer record")
	}
	return content, nil
}

func parseM4NCONCPHostname(packet []byte) (string, error) {
	expectedHead := []byte{0, 4, 0, 0, 0}
	expectedTail := []byte{0xbb, 1, 0, 0, 0, 0}
	if len(packet) < len(expectedHead)+2+len(expectedTail) || !bytes.Equal(packet[:len(expectedHead)], expectedHead) || !bytes.Equal(packet[len(packet)-len(expectedTail):], expectedTail) {
		return "", E.New("oNCP hostname packet constants mismatch")
	}
	hostnameLength := int(binary.LittleEndian.Uint16(packet[len(expectedHead) : len(expectedHead)+2]))
	if hostnameLength+len(expectedHead)+2+len(expectedTail) != len(packet) {
		return "", E.New("oNCP hostname packet length mismatch")
	}
	return string(packet[len(expectedHead)+2 : len(expectedHead)+2+hostnameLength]), nil
}

// /tmp/openconnect/oncp.c:726-765 specifies the KMP 303 MTU acknowledgement expected by this peer.
func validateM4NCONCPMTUControl(record []byte, expectedMTU uint32) error {
	messageType, payload, err := parseM4NCONCPKMP(record, true)
	if err != nil {
		return err
	}
	if messageType != 303 || len(payload) != 16 || binary.BigEndian.Uint16(payload[0:2]) != 6 || binary.BigEndian.Uint32(payload[2:6]) != 10 || binary.BigEndian.Uint16(payload[6:8]) != 2 || binary.BigEndian.Uint32(payload[8:12]) != 4 || binary.BigEndian.Uint32(payload[12:16]) != expectedMTU {
		return E.New("oNCP initial KMP 303 MTU control mismatch")
	}
	return nil
}

func buildM4NCIPv4Packet(content []byte) []byte {
	packet := make([]byte, 20, 20+len(content))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(20+len(content)))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], netip.MustParseAddr("10.47.0.1").AsSlice())
	copy(packet[16:20], netip.MustParseAddr("10.47.0.10").AsSlice())
	return append(packet, content...)
}

func assertM4NCONCPConfiguration(t *testing.T, configuration openconnect.TunnelConfiguration) {
	t.Helper()
	if configuration.MTU != 1300 || len(configuration.Addresses) != 1 || configuration.Addresses[0] != netip.MustParsePrefix("10.47.0.10/24") {
		t.Fatalf("oNCP address configuration mismatch: %#v", configuration)
	}
	if len(configuration.DNS) != 1 || configuration.DNS[0] != netip.MustParseAddr("1.1.1.1") || len(configuration.NBNS) != 1 || configuration.NBNS[0] != netip.MustParseAddr("10.47.0.2") {
		t.Fatalf("oNCP name server configuration mismatch: %#v", configuration)
	}
	if len(configuration.SearchDomains) != 1 || configuration.SearchDomains[0] != "corp.test" || len(configuration.Routes) != 1 || configuration.Routes[0].Prefix != netip.MustParsePrefix("10.0.0.0/8") || len(configuration.ExcludedRoutes) != 1 || configuration.ExcludedRoutes[0].Prefix != netip.MustParsePrefix("192.168.0.0/16") {
		t.Fatalf("oNCP routing configuration mismatch: %#v", configuration)
	}
}

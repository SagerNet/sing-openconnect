package test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
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

const m4NCESPHostname = "gateway.m4-nc-esp.test"

type m4NCESPPeer struct {
	server               *httptest.Server
	udp                  *net.UDPConn
	errors               chan error
	releaseProbe         chan struct{}
	espEnabled           chan struct{}
	espDisabled          chan struct{}
	tunnelClosed         chan struct{}
	logout               chan struct{}
	logoutOnce           sync.Once
	serverSPI            uint32
	serverEncryption     []byte
	serverAuthentication []byte
}

func TestM4NetworkConnectONCPESPPeerInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(E.Cause(err, "listen for oNCP ESP peer"))
	}
	t.Cleanup(func() { _ = udp.Close() })
	peer := &m4NCESPPeer{
		udp:                  udp,
		errors:               make(chan error, 16),
		releaseProbe:         make(chan struct{}),
		espEnabled:           make(chan struct{}),
		espDisabled:          make(chan struct{}),
		tunnelClosed:         make(chan struct{}),
		logout:               make(chan struct{}),
		serverSPI:            0x11223344,
		serverEncryption:     []byte("server-encrypt!!"),
		serverAuthentication: []byte("server-auth-key-1234"),
	}
	rootCertificate, certificates := createM4NCCertificates(t, []string{m4NCESPHostname})
	peer.server = newM2GPTLSServer(t, certificates[0], http.HandlerFunc(peer.serve))
	gatewayAddress := M.SocksaddrFromNet(peer.server.Listener.Addr())
	dialer := &m4NCDialer{
		routes: map[string]M.Socksaddr{
			m4NCESPHostname: gatewayAddress,
		},
		gatewayHostname: m4NCESPHostname,
		gatewayAddress:  gatewayAddress,
	}
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 1)
	serverURL := "https://" + net.JoinHostPort(m4NCESPHostname, strconv.Itoa(int(gatewayAddress.Port)))
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
		t.Fatal(E.Cause(err, "create oNCP ESP peer client"))
	}
	activeTransportUpdated := client.ActiveTransportUpdated()
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start oNCP ESP peer client"))
	}
	select {
	case <-configurationEvents:
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for oNCP TLS readiness before ESP"))
	}
	if !client.Ready() {
		t.Fatal("oNCP TLS was not ready while ESP probe remained withheld")
	}
	waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportONCP)
	activeTransportUpdated = client.ActiveTransportUpdated()
	close(peer.releaseProbe)
	select {
	case <-peer.espEnabled:
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for complete oNCP ESP enable control"))
	}
	waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportESP)
	activeTransportUpdated = client.ActiveTransportUpdated()
	outbound := buildM4NCIPv4Packet([]byte("esp-client-outbound"))
	err = client.WriteDataPacket(outbound)
	if err != nil {
		t.Fatal(E.Cause(err, "write oNCP ESP data packet"))
	}
	inbound, err := client.ReadDataPacket(ctx)
	if err != nil {
		t.Fatal(E.Cause(err, "read oNCP ESP data packet"))
	}
	expectedInbound := buildM4NCIPv4Packet([]byte("esp-server-inbound"))
	if !bytes.Equal(inbound, expectedInbound) {
		t.Fatal("oNCP ESP inbound packet mismatch")
	}
	disableReady := buildM4NCIPv4Packet([]byte("esp-disable-ready"))
	err = client.WriteDataPacket(disableReady)
	if err != nil {
		t.Fatal(E.Cause(err, "write oNCP ESP disable-ready data packet"))
	}
	select {
	case <-peer.espDisabled:
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for complete oNCP ESP disable control"))
	}
	waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportONCP)
	tlsOutbound := buildM4NCIPv4Packet([]byte("tls-client-outbound"))
	err = client.WriteDataPacket(tlsOutbound)
	if err != nil {
		t.Fatal(E.Cause(err, "write oNCP TLS data packet after ESP disable"))
	}
	tlsInbound, err := client.ReadDataPacket(ctx)
	if err != nil {
		t.Fatal(E.Cause(err, "read oNCP TLS data packet after ESP disable"))
	}
	expectedTLSInbound := buildM4NCIPv4Packet([]byte("tls-server-inbound"))
	if !bytes.Equal(tlsInbound, expectedTLSInbound) {
		t.Fatal("oNCP TLS inbound packet mismatch after ESP disable")
	}
	err = client.Close()
	if err != nil {
		t.Fatal(E.Cause(err, "close oNCP ESP peer client"))
	}
	select {
	case <-peer.logout:
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for oNCP ESP logout"))
	}
}

func (p *m4NCESPPeer) serve(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/start":
		http.SetCookie(writer, &http.Cookie{Name: "DSID", Value: "esp-session", Path: "/", Secure: true})
		_, _ = io.WriteString(writer, "accepted")
	case "/dana/js":
		p.serveTunnel(writer, request)
	case "/dana-na/auth/logout.cgi":
		select {
		case <-p.espDisabled:
		default:
			p.fail(writer, E.New("oNCP ESP logout arrived before KMP 303 disable"))
			return
		}
		select {
		case <-p.tunnelClosed:
		default:
			p.fail(writer, E.New("oNCP ESP logout arrived before TLS close"))
			return
		}
		writer.WriteHeader(http.StatusOK)
		p.logoutOnce.Do(func() { close(p.logout) })
	default:
		p.fail(writer, E.New("unexpected oNCP ESP peer path: ", request.URL.Path))
	}
}

func (p *m4NCESPPeer) serveTunnel(writer http.ResponseWriter, request *http.Request) {
	hijacker, loaded := writer.(http.Hijacker)
	if !loaded {
		p.fail(writer, E.New("oNCP ESP peer cannot hijack TLS"))
		return
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		p.fail(writer, E.Cause(err, "hijack oNCP ESP TLS connection"))
		return
	}
	defer connection.Close()
	_, err = buffered.WriteString("HTTP/1.1 200 OK\r\n\r\n")
	if err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		p.report(E.Cause(err, "write oNCP ESP HTTP response"))
		return
	}
	_, err = readM4NCONCPRecord(buffered.Reader)
	if err != nil {
		p.report(err)
		return
	}
	configuration := p.configuration()
	err = writeM4NCONCPRecord(buffered.Writer, []byte{0})
	if err == nil {
		err = writeM4NCONCPRecord(buffered.Writer, configuration)
	}
	if err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		p.report(E.Cause(err, "write oNCP ESP configuration"))
		return
	}
	negotiation, err := readM4NCONCPRecord(buffered.Reader)
	if err != nil {
		p.report(err)
		return
	}
	messages, err := splitM4NCONCPMessages(negotiation, true)
	if err != nil || len(messages) != 2 {
		p.report(E.New("oNCP ESP negotiation did not contain KMP 303 and KMP 302"))
		return
	}
	err = validateM4NCONCPMTUControl(messages[0], 1300)
	if err != nil {
		p.report(err)
		return
	}
	clientSPI, clientEncryption, clientAuthentication, err := parseM4NCONCPESPResponse(messages[1])
	if err != nil {
		p.report(err)
		return
	}
	defer clear(clientEncryption)
	defer clear(clientAuthentication)
	select {
	case <-p.releaseProbe:
	case <-request.Context().Done():
		return
	}
	buffer := make([]byte, 2048)
	_ = p.udp.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, remote, err := p.udp.ReadFromUDP(buffer)
	if err != nil {
		p.report(E.Cause(err, "read oNCP ESP probe"))
		return
	}
	probe, nextHeader, err := openM4NCESPDatagram(buffer[:n], p.serverSPI, p.serverEncryption, p.serverAuthentication)
	if err != nil || len(probe) != 1 || probe[0] != 0 || nextHeader != 4 {
		p.report(E.New("oNCP ESP probe mismatch"))
		return
	}
	response, err := sealM4NCESPDatagram([]byte{0}, 4, 0, clientSPI, clientEncryption, clientAuthentication)
	if err == nil {
		_, err = p.udp.WriteToUDP(response, remote)
	}
	if err != nil {
		p.report(E.Cause(err, "write oNCP ESP probe response"))
		return
	}
	enableRecord, err := readM4NCONCPRecord(buffered.Reader)
	if err != nil {
		p.report(err)
		return
	}
	err = validateM4NCONCPESPControl(enableRecord, true)
	if err != nil {
		p.report(err)
		return
	}
	close(p.espEnabled)
	_ = p.udp.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, remote, err = p.udp.ReadFromUDP(buffer)
	if err != nil {
		p.report(E.Cause(err, "read oNCP ESP data"))
		return
	}
	outbound, nextHeader, err := openM4NCESPDatagram(buffer[:n], p.serverSPI, p.serverEncryption, p.serverAuthentication)
	if err != nil || nextHeader != 4 || !bytes.Equal(outbound, buildM4NCIPv4Packet([]byte("esp-client-outbound"))) {
		p.report(E.New("oNCP ESP outbound data mismatch"))
		return
	}
	inbound := buildM4NCIPv4Packet([]byte("esp-server-inbound"))
	datagram, err := sealM4NCESPDatagram(inbound, 4, 1, clientSPI, clientEncryption, clientAuthentication)
	if err == nil {
		_, err = p.udp.WriteToUDP(datagram, remote)
	}
	if err != nil {
		p.report(E.Cause(err, "write oNCP ESP inbound data"))
		return
	}
	_ = p.udp.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, _, err = p.udp.ReadFromUDP(buffer)
	if err != nil {
		p.report(E.Cause(err, "read oNCP ESP disable-ready data"))
		return
	}
	disableReady, nextHeader, err := openM4NCESPDatagram(buffer[:n], p.serverSPI, p.serverEncryption, p.serverAuthentication)
	if err != nil || nextHeader != 4 || !bytes.Equal(disableReady, buildM4NCIPv4Packet([]byte("esp-disable-ready"))) {
		p.report(E.New("oNCP ESP disable-ready data mismatch"))
		return
	}
	disablePayload := make([]byte, 13)
	binary.BigEndian.PutUint16(disablePayload[0:2], 6)
	binary.BigEndian.PutUint32(disablePayload[2:6], 7)
	binary.BigEndian.PutUint16(disablePayload[6:8], 1)
	binary.BigEndian.PutUint32(disablePayload[8:12], 1)
	err = writeM4NCONCPRecord(buffered.Writer, buildM4NCONCPKMP(303, disablePayload, false))
	if err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		p.report(E.Cause(err, "write oNCP ESP disable control"))
		return
	}
	close(p.espDisabled)
	tlsOutboundRecord, err := readM4NCONCPRecord(buffered.Reader)
	if err != nil {
		p.report(err)
		return
	}
	messageType, tlsOutbound, err := parseM4NCONCPKMP(tlsOutboundRecord, true)
	if err != nil || messageType != 300 || !bytes.Equal(tlsOutbound, buildM4NCIPv4Packet([]byte("tls-client-outbound"))) {
		p.report(E.New("oNCP TLS outbound data mismatch after ESP disable"))
		return
	}
	tlsInbound := buildM4NCONCPKMP(300, buildM4NCIPv4Packet([]byte("tls-server-inbound")), false)
	err = writeM4NCONCPRecord(buffered.Writer, tlsInbound)
	if err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		p.report(E.Cause(err, "write oNCP TLS inbound data after ESP disable"))
		return
	}
	one := make([]byte, 1)
	_, err = buffered.Reader.Read(one)
	if err != io.EOF && !E.IsClosed(err) {
		p.report(E.Cause(err, "wait for oNCP ESP TLS close"))
		return
	}
	close(p.tunnelClosed)
}

func (p *m4NCESPPeer) configuration() []byte {
	return buildM4NCONCPConfigurationWithESP(
		uint16(p.udp.LocalAddr().(*net.UDPAddr).Port),
		p.serverSPI,
		p.serverEncryption,
		p.serverAuthentication,
	)
}

func (p *m4NCESPPeer) fail(writer http.ResponseWriter, err error) {
	p.report(err)
	http.Error(writer, err.Error(), http.StatusInternalServerError)
}

func (p *m4NCESPPeer) report(err error) {
	select {
	case p.errors <- err:
	default:
	}
}

func parseM4NCONCPESPResponse(message []byte) (uint32, []byte, []byte, error) {
	messageType, payload, err := parseM4NCONCPKMP(message, true)
	if err != nil {
		return 0, nil, nil, err
	}
	if messageType != 302 || len(payload) != 86 || binary.BigEndian.Uint16(payload[0:2]) != 7 || binary.BigEndian.Uint32(payload[2:6]) != 80 || binary.BigEndian.Uint16(payload[6:8]) != 1 || binary.BigEndian.Uint32(payload[8:12]) != 4 || binary.BigEndian.Uint16(payload[16:18]) != 2 || binary.BigEndian.Uint32(payload[18:22]) != 64 {
		return 0, nil, nil, E.New("oNCP ESP KMP 302 response structure mismatch")
	}
	clientSPI := binary.BigEndian.Uint32(payload[12:16])
	if clientSPI == 0 {
		return 0, nil, nil, E.New("oNCP ESP KMP 302 returned a zero client SPI")
	}
	secret := payload[22:86]
	return clientSPI, append([]byte(nil), secret[:16]...), append([]byte(nil), secret[16:36]...), nil
}

// /tmp/openconnect/oncp.c:347-375 fixes the complete KMP 303 ESP enable/disable record validated by this peer.
func validateM4NCONCPESPControl(message []byte, enabled bool) error {
	messageType, payload, err := parseM4NCONCPKMP(message, true)
	if err != nil {
		return err
	}
	expected := byte(0)
	if enabled {
		expected = 1
	}
	if messageType != 303 || len(payload) != 13 || binary.BigEndian.Uint16(payload[0:2]) != 6 || binary.BigEndian.Uint32(payload[2:6]) != 7 || binary.BigEndian.Uint16(payload[6:8]) != 1 || binary.BigEndian.Uint32(payload[8:12]) != 1 || payload[12] != expected {
		return E.New("oNCP ESP KMP 303 control mismatch")
	}
	return nil
}

func sealM4NCESPDatagram(payload []byte, nextHeader byte, sequence uint32, spi uint32, encryptionKey []byte, authenticationKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, E.Cause(err, "initialize oNCP ESP peer cipher")
	}
	paddingLength := aes.BlockSize - 1 - (len(payload)+1)%aes.BlockSize
	ciphertextLength := len(payload) + paddingLength + 2
	datagram := make([]byte, 8+aes.BlockSize+ciphertextLength+12)
	binary.BigEndian.PutUint32(datagram[0:4], spi)
	binary.BigEndian.PutUint32(datagram[4:8], sequence)
	for i := 0; i < aes.BlockSize; i++ {
		datagram[8+i] = byte(i + int(sequence) + 1)
	}
	ciphertext := datagram[8+aes.BlockSize : len(datagram)-12]
	copy(ciphertext, payload)
	for i := 0; i < paddingLength; i++ {
		ciphertext[len(payload)+i] = byte(i + 1)
	}
	ciphertext[len(ciphertext)-2] = byte(paddingLength)
	ciphertext[len(ciphertext)-1] = nextHeader
	cipher.NewCBCEncrypter(block, datagram[8:8+aes.BlockSize]).CryptBlocks(ciphertext, ciphertext)
	authenticationHash := hmac.New(sha1.New, authenticationKey)
	_, _ = authenticationHash.Write(datagram[:len(datagram)-12])
	copy(datagram[len(datagram)-12:], authenticationHash.Sum(nil)[:12])
	return datagram, nil
}

func openM4NCESPDatagram(datagram []byte, spi uint32, encryptionKey []byte, authenticationKey []byte) ([]byte, byte, error) {
	if len(datagram) < 8+2*aes.BlockSize+12 || binary.BigEndian.Uint32(datagram[0:4]) != spi || (len(datagram)-8-aes.BlockSize-12)%aes.BlockSize != 0 {
		return nil, 0, E.New("oNCP ESP peer datagram framing mismatch")
	}
	authenticationHash := hmac.New(sha1.New, authenticationKey)
	_, _ = authenticationHash.Write(datagram[:len(datagram)-12])
	if !hmac.Equal(datagram[len(datagram)-12:], authenticationHash.Sum(nil)[:12]) {
		return nil, 0, E.New("oNCP ESP peer datagram authentication mismatch")
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, 0, E.Cause(err, "initialize oNCP ESP peer decipher")
	}
	plaintext := append([]byte(nil), datagram[8+aes.BlockSize:len(datagram)-12]...)
	cipher.NewCBCDecrypter(block, datagram[8:8+aes.BlockSize]).CryptBlocks(plaintext, plaintext)
	paddingLength := int(plaintext[len(plaintext)-2])
	if paddingLength+2 >= len(plaintext) {
		return nil, 0, E.New("oNCP ESP peer padding length mismatch")
	}
	payloadLength := len(plaintext) - paddingLength - 2
	for i := 0; i < paddingLength; i++ {
		if plaintext[payloadLength+i] != byte(i+1) {
			return nil, 0, E.New("oNCP ESP peer padding mismatch")
		}
	}
	return plaintext[:payloadLength], plaintext[len(plaintext)-1], nil
}

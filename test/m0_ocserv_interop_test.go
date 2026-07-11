package test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

const (
	openConnectInteropEnvironment = "OPENCONNECT_IT"
	ocservInteropVersion          = "1.3.0-2"
	ocservInteropImage            = "sing-openconnect-ocserv-m0:" + ocservInteropVersion
	ocservUsername                = "test"
	ocservPassword                = "test"
	ocservTunnelAddress           = "192.168.77.1"
	dtlsPSKExporterLabel          = "EXPORTER-openconnect-psk"
	anyConnectPacketData          = 0
	anyConnectPacketDPDRequest    = 3
	anyConnectPacketDPDResponse   = 4
	anyConnectPacketKeepalive     = 7
)

type ocservContainer struct {
	name       string
	tcpAddress string
	udpAddress string
}

type cstpTunnel struct {
	conn    *tls.Conn
	reader  *bufio.Reader
	headers textproto.MIMEHeader
}

type countingPacketConn struct {
	net.PacketConn
	readPackets  atomic.Uint64
	writePackets atomic.Uint64
}

func (c *countingPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, address, err := c.PacketConn.ReadFrom(buffer)
	if n > 0 {
		c.readPackets.Add(1)
	}
	return n, address, err
}

func (c *countingPacketConn) WriteTo(buffer []byte, address net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(buffer, address)
	if n > 0 {
		c.writePackets.Add(1)
	}
	return n, err
}

func TestM0OcservCSTPAndModernPSKDTLSInterop(t *testing.T) {
	t.Parallel()
	if os.Getenv(openConnectInteropEnvironment) == "" {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	container := startOcservContainer(t, ctx)
	cookie := obtainWebVPNCookie(t, ctx, container.tcpAddress)
	tunnel := connectCSTP(t, container.tcpAddress, cookie)
	defer tunnel.conn.Close()

	err := tunnel.conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		t.Fatal(E.Cause(err, "set CSTP DPD deadline"))
	}
	writeCSTPPacket(t, tunnel.conn, anyConnectPacketDPDRequest, nil)
	var packetType byte
	var packetPayload []byte

readCSTPDPD:
	for {
		packetType, packetPayload = readCSTPPacket(t, tunnel.reader)
		switch packetType {
		case anyConnectPacketDPDRequest:
			writeCSTPPacket(t, tunnel.conn, anyConnectPacketDPDResponse, packetPayload)
		case anyConnectPacketDPDResponse:
			if len(packetPayload) != 0 {
				t.Fatalf("unexpected CSTP DPD payload: %x", packetPayload)
			}
			break readCSTPDPD
		case anyConnectPacketKeepalive:
		default:
			t.Fatalf("unexpected CSTP packet while waiting for DPD echo: type=%d payload=%x", packetType, packetPayload)
		}
	}
	clientTunnelAddress, err := netip.ParseAddr(tunnel.headers.Get("X-CSTP-Address"))
	if err != nil {
		t.Fatal(E.Cause(err, "parse assigned X-CSTP-Address"))
	}
	serverTunnelAddress := netip.MustParseAddr(ocservTunnelAddress)
	cstpEchoRequest := buildIPv4ICMPEchoRequest(t, clientTunnelAddress, serverTunnelAddress, 0x4d30, 1, []byte("sing-openconnect-m0-cstp"))
	err = tunnel.conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		t.Fatal(E.Cause(err, "set CSTP IP data deadline"))
	}
	writeCSTPPacket(t, tunnel.conn, anyConnectPacketData, cstpEchoRequest)

readCSTPEcho:
	for {
		packetType, packetPayload = readCSTPPacket(t, tunnel.reader)
		switch packetType {
		case anyConnectPacketData:
			err = validateIPv4ICMPEchoReply(packetPayload, clientTunnelAddress, serverTunnelAddress, 0x4d30, 1, []byte("sing-openconnect-m0-cstp"))
			if err != nil {
				t.Fatal(err)
			}
			break readCSTPEcho
		case anyConnectPacketDPDRequest:
			writeCSTPPacket(t, tunnel.conn, anyConnectPacketDPDResponse, packetPayload)
		case anyConnectPacketKeepalive:
		default:
			t.Fatalf("unexpected CSTP packet while waiting for ICMP echo: type=%d payload=%x", packetType, packetPayload)
		}
	}

	negotiatedCipher := tunnel.headers.Get("X-DTLS-CipherSuite")
	if negotiatedCipher != "PSK-NEGOTIATE" {
		t.Fatalf("ocserv did not negotiate modern DTLS PSK: %q", negotiatedCipher)
	}
	applicationIDText := tunnel.headers.Get("X-DTLS-App-ID")
	applicationID, err := hex.DecodeString(applicationIDText)
	if err != nil {
		t.Fatal(E.Cause(err, "decode X-DTLS-App-ID"))
	}
	if len(applicationID) != 32 {
		t.Fatalf("unexpected X-DTLS-App-ID length: %d", len(applicationID))
	}

	// Upstream start_dtls_psk_handshake derives the 32-byte PSK from the CSTP TLS exporter without a context.
	connectionState := tunnel.conn.ConnectionState()
	psk, err := connectionState.ExportKeyingMaterial(dtlsPSKExporterLabel, nil, 32)
	if err != nil {
		t.Fatal(E.Cause(err, "export DTLS PSK from CSTP TLS session"))
	}

	udpRemoteAddress, err := net.ResolveUDPAddr("udp4", container.udpAddress)
	if err != nil {
		t.Fatal(E.Cause(err, "resolve ocserv UDP address"))
	}
	udpPacketConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(E.Cause(err, "listen for DTLS"))
	}
	countingConn := &countingPacketConn{PacketConn: udpPacketConn}
	defer countingConn.Close()
	err = countingConn.SetDeadline(time.Now().Add(15 * time.Second))
	if err != nil {
		t.Fatal(E.Cause(err, "set DTLS handshake deadline"))
	}

	dtlsConn, err := dtls.ClientWithOptions(
		countingConn,
		udpRemoteAddress,
		dtls.WithPSK(func([]byte) ([]byte, error) {
			return psk, nil
		}),
		dtls.WithPSKIdentityHint([]byte("psk")),
		dtls.WithCipherSuites(
			dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
		),
		dtls.WithFlightInterval(250*time.Millisecond),
		dtls.WithClientHelloMessageHook(func(message handshake.MessageClientHello) handshake.Message {
			// Upstream start_dtls_psk_handshake places X-DTLS-App-ID in the ClientHello SessionID for ocserv routing.
			message.SessionID = append([]byte(nil), applicationID...)
			return &message
		}),
	)
	if err != nil {
		t.Fatal(E.Cause(err, "establish modern PSK DTLS with ocserv"))
	}
	defer dtlsConn.Close()

	packetsBeforeDPDWrite := countingConn.writePackets.Load()
	packetsBeforeDPDRead := countingConn.readPackets.Load()
	err = dtlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		t.Fatal(E.Cause(err, "set DTLS data deadline"))
	}
	_, err = dtlsConn.Write([]byte{anyConnectPacketDPDRequest})
	if err != nil {
		t.Fatal(E.Cause(err, "write DTLS DPD request"))
	}

	dtlsBuffer := make([]byte, 2048)

readDTLSDPD:
	for {
		n, readErr := dtlsConn.Read(dtlsBuffer)
		if readErr != nil {
			t.Fatal(E.Cause(readErr, "read DTLS DPD response"))
		}
		if n == 0 {
			continue
		}
		switch dtlsBuffer[0] {
		case anyConnectPacketDPDRequest:
			dpdResponse := append([]byte(nil), dtlsBuffer[:n]...)
			dpdResponse[0] = anyConnectPacketDPDResponse
			_, err = dtlsConn.Write(dpdResponse)
			if err != nil {
				t.Fatal(E.Cause(err, "answer server DTLS DPD request"))
			}
		case anyConnectPacketDPDResponse:
			if n != 1 {
				t.Fatalf("unexpected DTLS DPD payload: %x", dtlsBuffer[:n])
			}
			if countingConn.writePackets.Load() <= packetsBeforeDPDWrite || countingConn.readPackets.Load() <= packetsBeforeDPDRead {
				t.Fatal("DTLS DPD echo did not exchange post-handshake UDP datagrams")
			}
			break readDTLSDPD
		case anyConnectPacketKeepalive:
		default:
			t.Fatalf("unexpected DTLS packet: %x", dtlsBuffer[:n])
		}
	}

	dtlsEchoRequest := buildIPv4ICMPEchoRequest(t, clientTunnelAddress, serverTunnelAddress, 0x4d30, 2, []byte("sing-openconnect-m0-dtls"))
	dtlsDataPacket := append([]byte{anyConnectPacketData}, dtlsEchoRequest...)
	packetsBeforeDataWrite := countingConn.writePackets.Load()
	packetsBeforeDataRead := countingConn.readPackets.Load()
	err = dtlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		t.Fatal(E.Cause(err, "set DTLS IP data deadline"))
	}
	_, err = dtlsConn.Write(dtlsDataPacket)
	if err != nil {
		t.Fatal(E.Cause(err, "write IPv4 ICMP echo over DTLS"))
	}
	for {
		n, readErr := dtlsConn.Read(dtlsBuffer)
		if readErr != nil {
			t.Fatal(E.Cause(readErr, "read IPv4 ICMP echo over DTLS"))
		}
		if n == 0 {
			continue
		}
		switch dtlsBuffer[0] {
		case anyConnectPacketData:
			err = validateIPv4ICMPEchoReply(dtlsBuffer[1:n], clientTunnelAddress, serverTunnelAddress, 0x4d30, 2, []byte("sing-openconnect-m0-dtls"))
			if err != nil {
				t.Fatal(err)
			}
			if countingConn.writePackets.Load() <= packetsBeforeDataWrite || countingConn.readPackets.Load() <= packetsBeforeDataRead {
				t.Fatal("DTLS IP packet did not exchange post-handshake UDP datagrams")
			}
			return
		case anyConnectPacketDPDRequest:
			dpdResponse := append([]byte(nil), dtlsBuffer[:n]...)
			dpdResponse[0] = anyConnectPacketDPDResponse
			_, err = dtlsConn.Write(dpdResponse)
			if err != nil {
				t.Fatal(E.Cause(err, "answer server DTLS DPD request"))
			}
		case anyConnectPacketDPDResponse, anyConnectPacketKeepalive:
		default:
			t.Fatalf("unexpected DTLS packet while waiting for ICMP echo: %x", dtlsBuffer[:n])
		}
	}
}

func startOcservContainer(t *testing.T, ctx context.Context) ocservContainer {
	t.Helper()
	_, err := dockerOutput(ctx, "version", "--format", "{{.Server.Version}}")
	if err != nil {
		t.Fatal(err)
	}
	_, err = dockerOutput(ctx, "build", "--pull=false", "--tag", ocservInteropImage, filepath.Join("testdata", "ocserv"))
	if err != nil {
		t.Fatal(err)
	}

	containerName := "sing-openconnect-m0-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	_, err = dockerOutput(ctx,
		"run", "--detach", "--rm", "--name", containerName,
		"--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
		"--publish", "127.0.0.1::443/tcp", "--publish", "127.0.0.1::443/udp",
		"--entrypoint", "ocserv",
		ocservInteropImage,
		"-f", "-d", "5", "-c", "/etc/ocserv/ocserv.conf",
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
				t.Log("ocserv logs:\n" + logs)
			}
		}
		removeContext, cancelRemove := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = dockerOutput(removeContext, "rm", "--force", containerName)
		cancelRemove()
	})
	versionOutput, err := dockerOutput(ctx, "exec", containerName, "dpkg-query", "-W", "-f=${Version}", "ocserv")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(versionOutput) != ocservInteropVersion {
		t.Fatalf("unexpected ocserv package version: expected %s, got %s", ocservInteropVersion, strings.TrimSpace(versionOutput))
	}

	tcpAddress := dockerPublishedAddress(t, ctx, containerName, "443/tcp")
	udpAddress := dockerPublishedAddress(t, ctx, containerName, "443/udp")
	waitForTCP(t, ctx, tcpAddress)
	return ocservContainer{name: containerName, tcpAddress: tcpAddress, udpAddress: udpAddress}
}

func dockerPublishedAddress(t *testing.T, ctx context.Context, containerName string, port string) string {
	t.Helper()
	output, err := dockerOutput(ctx, "port", containerName, port)
	if err != nil {
		t.Fatal(err)
	}
	address := strings.TrimSpace(output)
	_, _, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		t.Fatal(E.Cause(splitErr, "parse Docker published address: ", address))
	}
	return address
}

func dockerOutput(ctx context.Context, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", E.Cause(err, "docker ", strings.Join(args, " "), ": ", strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func waitForTCP(t *testing.T, ctx context.Context, address string) {
	t.Helper()
	for {
		conn, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for ocserv TCP listener"))
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func obtainWebVPNCookie(t *testing.T, ctx context.Context, address string) string {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(E.Cause(err, "create authentication cookie jar"))
	}
	client := &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   15 * time.Second,
	}
	defer client.CloseIdleConnections()

	authURL := &url.URL{Scheme: "https", Host: address, Path: "/"}
	initialBody := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="init" aggregate-auth-version="2">
<version who="vpn">AnyConnect-compatible OpenConnect VPN Agent</version>
<device-id>linux-64</device-id>
<group-access>https://` + address + `/</group-access>
</config-auth>`
	responseBody := postAuthenticationXML(t, ctx, client, authURL.String(), initialBody)
	if !bytes.Contains(responseBody, []byte(`<auth id="main">`)) {
		t.Fatalf("ocserv did not return an authentication form: %s", responseBody)
	}

	authURL.Path = "/auth"
	replyBody := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
<version who="vpn">AnyConnect-compatible OpenConnect VPN Agent</version>
<device-id>linux-64</device-id>
<auth><username>` + ocservUsername + `</username><password>` + ocservPassword + `</password></auth>
</config-auth>`
	responseBody = postAuthenticationXML(t, ctx, client, authURL.String(), replyBody)
	if bytes.Contains(responseBody, []byte(`name="password"`)) {
		passwordReplyBody := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
<version who="vpn">AnyConnect-compatible OpenConnect VPN Agent</version>
<device-id>linux-64</device-id>
<auth><password>` + ocservPassword + `</password></auth>
</config-auth>`
		responseBody = postAuthenticationXML(t, ctx, client, authURL.String(), passwordReplyBody)
	}
	if !bytes.Contains(responseBody, []byte(`<auth id="success">`)) {
		t.Fatalf("ocserv did not authenticate the password: %s", responseBody)
	}

	for _, cookie := range jar.Cookies(authURL) {
		if cookie.Name == "webvpn" && cookie.Value != "" {
			return cookie.Value
		}
	}
	t.Fatal("ocserv authentication succeeded without a webvpn cookie")
	return ""
}

func postAuthenticationXML(t *testing.T, ctx context.Context, client *http.Client, address string, body string) []byte {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, address, strings.NewReader(body))
	if err != nil {
		t.Fatal(E.Cause(err, "create authentication request"))
	}
	request.Header.Set("Content-Type", "application/xml; charset=utf-8")
	request.Header.Set("User-Agent", "AnyConnect-compatible OpenConnect VPN Agent")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(E.Cause(err, "send authentication request"))
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(E.Cause(err, "read authentication response"))
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authentication request returned %s: %s", response.Status, responseBody)
	}
	return responseBody
}

func connectCSTP(t *testing.T, address string, cookie string) cstpTunnel {
	t.Helper()
	tcpConn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		t.Fatal(E.Cause(err, "connect CSTP TCP"))
	}
	tlsConn := tls.Client(tcpConn, &tls.Config{InsecureSkipVerify: true})
	err = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	if err != nil {
		t.Fatal(E.Cause(err, "set CSTP handshake deadline"))
	}
	err = tlsConn.Handshake()
	if err != nil {
		t.Fatal(E.Cause(err, "handshake CSTP TLS"))
	}

	legacyMasterSecret := make([]byte, 48)
	_, err = rand.Read(legacyMasterSecret)
	if err != nil {
		t.Fatal(E.Cause(err, "generate legacy DTLS compatibility secret"))
	}
	request := "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n" +
		"Host: " + address + "\r\n" +
		"User-Agent: AnyConnect-compatible OpenConnect VPN Agent\r\n" +
		"Cookie: webvpn=" + cookie + "\r\n" +
		"X-CSTP-Version: 1\r\n" +
		"X-CSTP-Hostname: sing-openconnect-m0\r\n" +
		"X-CSTP-Protocol: Copyright (c) 2004 Cisco Systems, Inc.\r\n" +
		"X-CSTP-Base-MTU: 1400\r\n" +
		"X-CSTP-MTU: 1350\r\n" +
		"X-CSTP-Address-Type: IPv4\r\n" +
		"X-DTLS-Master-Secret: " + strings.ToUpper(hex.EncodeToString(legacyMasterSecret)) + "\r\n" +
		"X-DTLS-CipherSuite: PSK-NEGOTIATE\r\n\r\n"
	_, err = io.WriteString(tlsConn, request)
	if err != nil {
		t.Fatal(E.Cause(err, "write CSTP CONNECT request"))
	}

	reader := bufio.NewReader(tlsConn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(E.Cause(err, "read CSTP status"))
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 200 ") {
		t.Fatalf("CSTP CONNECT failed: %s", strings.TrimSpace(statusLine))
	}
	headers, err := textproto.NewReader(reader).ReadMIMEHeader()
	if err != nil {
		t.Fatal(E.Cause(err, "read CSTP response headers"))
	}
	err = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		t.Fatal(E.Cause(err, "set CSTP data deadline"))
	}
	return cstpTunnel{conn: tlsConn, reader: reader, headers: headers}
}

func writeCSTPPacket(t *testing.T, w io.Writer, packetType byte, payload []byte) {
	t.Helper()
	if len(payload) > 65535 {
		t.Fatalf("CSTP payload is too large: %d", len(payload))
	}
	header := []byte{'S', 'T', 'F', 1, 0, 0, packetType, 0}
	binary.BigEndian.PutUint16(header[4:6], uint16(len(payload)))
	_, err := w.Write(append(header, payload...))
	if err != nil {
		t.Fatal(E.Cause(err, "write CSTP packet"))
	}
}

func readCSTPPacket(t *testing.T, r io.Reader) (byte, []byte) {
	t.Helper()
	header := make([]byte, 8)
	_, err := io.ReadFull(r, header)
	if err != nil {
		t.Fatal(E.Cause(err, "read CSTP packet header"))
	}
	if !bytes.Equal(header[:4], []byte{'S', 'T', 'F', 1}) || header[7] != 0 {
		t.Fatalf("invalid CSTP packet header: %x", header)
	}
	payload := make([]byte, int(binary.BigEndian.Uint16(header[4:6])))
	_, err = io.ReadFull(r, payload)
	if err != nil {
		t.Fatal(E.Cause(err, "read CSTP packet payload"))
	}
	return header[6], payload
}

func buildIPv4ICMPEchoRequest(
	t *testing.T,
	sourceAddress netip.Addr,
	destinationAddress netip.Addr,
	identifier uint16,
	sequence uint16,
	payload []byte,
) []byte {
	t.Helper()
	if !sourceAddress.Is4() || !destinationAddress.Is4() {
		t.Fatalf("ICMP echo requires IPv4 addresses: source=%s destination=%s", sourceAddress, destinationAddress)
	}
	icmpMessage := make([]byte, 8+len(payload))
	icmpMessage[0] = 8
	binary.BigEndian.PutUint16(icmpMessage[4:6], identifier)
	binary.BigEndian.PutUint16(icmpMessage[6:8], sequence)
	copy(icmpMessage[8:], payload)
	binary.BigEndian.PutUint16(icmpMessage[2:4], internetChecksum(icmpMessage))

	packet := make([]byte, 20+len(icmpMessage))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], identifier)
	packet[8] = 64
	packet[9] = 1
	sourceBytes := sourceAddress.As4()
	destinationBytes := destinationAddress.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:20]))
	copy(packet[20:], icmpMessage)
	return packet
}

func validateIPv4ICMPEchoReply(
	packet []byte,
	clientAddress netip.Addr,
	serverAddress netip.Addr,
	identifier uint16,
	sequence uint16,
	payload []byte,
) error {
	if len(packet) < 28 {
		return E.New("IPv4 ICMP echo reply is too short: ", len(packet))
	}
	if packet[0]>>4 != 4 {
		return E.New("ICMP echo reply has unexpected IP version: ", packet[0]>>4)
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(packet) {
		return E.New("ICMP echo reply has invalid IPv4 header length: ", headerLength)
	}
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLength != len(packet) {
		return E.New("ICMP echo reply length mismatch: header=", totalLength, " packet=", len(packet))
	}
	if packet[9] != 1 {
		return E.New("IPv4 echo reply has unexpected protocol: ", packet[9])
	}
	if internetChecksum(packet[:headerLength]) != 0 {
		return E.New("IPv4 echo reply has invalid header checksum")
	}
	sourceBytes := [4]byte{packet[12], packet[13], packet[14], packet[15]}
	destinationBytes := [4]byte{packet[16], packet[17], packet[18], packet[19]}
	sourceAddress := netip.AddrFrom4(sourceBytes)
	destinationAddress := netip.AddrFrom4(destinationBytes)
	if sourceAddress != serverAddress || destinationAddress != clientAddress {
		return E.New("IPv4 echo reply has unexpected addresses: source=", sourceAddress, " destination=", destinationAddress)
	}
	icmpMessage := packet[headerLength:]
	if len(icmpMessage) != 8+len(payload) {
		return E.New("ICMP echo reply has unexpected length: ", len(icmpMessage))
	}
	if internetChecksum(icmpMessage) != 0 {
		return E.New("ICMP echo reply has invalid checksum")
	}
	if icmpMessage[0] != 0 || icmpMessage[1] != 0 {
		return E.New("unexpected ICMP echo reply type/code: ", icmpMessage[0], "/", icmpMessage[1])
	}
	replyIdentifier := binary.BigEndian.Uint16(icmpMessage[4:6])
	replySequence := binary.BigEndian.Uint16(icmpMessage[6:8])
	if replyIdentifier != identifier || replySequence != sequence {
		return E.New("ICMP echo reply identifier/sequence mismatch: ", replyIdentifier, "/", replySequence)
	}
	if !bytes.Equal(icmpMessage[8:], payload) {
		return E.New("ICMP echo reply payload mismatch: ", hex.EncodeToString(icmpMessage[8:]))
	}
	return nil
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

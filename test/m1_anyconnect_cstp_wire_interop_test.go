package test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
)

type m1CSTPWirePeer struct {
	access          sync.Mutex
	authRequests    int
	connectRequests int
	failures        chan error
	dataSent        chan struct{}
	allowDisconnect chan struct{}
	disconnectSent  chan struct{}
}

type m1CSTPTimerPeer struct {
	ctx          context.Context
	expectedType byte
	failures     chan error
	observed     chan struct{}
}

func TestM1AnyConnectCSTPWireInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	peer := &m1CSTPWirePeer{
		failures:        make(chan error, 8),
		dataSent:        make(chan struct{}),
		allowDisconnect: make(chan struct{}),
		disconnectSent:  make(chan struct{}),
	}
	server := httptest.NewUnstartedServer(peer)
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 4)
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  server.URL,
		Flavor:  openconnect.FlavorAnyConnect,
		NoUDP:   true,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
		}},
		OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
			configurationEvents <- event
			return nil
		},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create CSTP wire interop client"))
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start CSTP wire interop client"))
	}
	select {
	case <-peer.dataSent:
	case failure := <-peer.failures:
		t.Fatal(failure)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for oversized CSTP data"))
	}
	select {
	case event := <-configurationEvents:
		if event.Reason != openconnect.TunnelConfigurationEventInitial ||
			event.Configuration.Banner != "wire banner" ||
			!event.Configuration.TunnelAllDNS ||
			!event.Configuration.ClientBypassProtocol {
			t.Fatalf("unexpected CSTP negotiated configuration: %#v", event)
		}
		assertM1CSTPWireConfiguration(t, event.Configuration)
	case failure := <-peer.failures:
		t.Fatal(failure)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for CSTP negotiated configuration"))
	}
	configuration := client.TunnelConfiguration()
	assertM1CSTPWireConfiguration(t, configuration)
	readContext, cancelRead := context.WithTimeout(ctx, 5*time.Second)
	payload, err := client.ReadDataPacket(readContext)
	cancelRead()
	if err != nil {
		t.Fatal(E.Cause(err, "read oversized CSTP data"))
	}
	expectedPayload := bytes.Repeat([]byte{0x5a}, 1000)
	if !bytes.Equal(payload, expectedPayload) {
		t.Fatalf("unexpected oversized CSTP data: length=%d", len(payload))
	}
	close(peer.allowDisconnect)
	select {
	case <-peer.disconnectSent:
	case failure := <-peer.failures:
		t.Fatal(failure)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for CSTP server disconnect"))
	}
	terminalContext, cancelTerminal := context.WithTimeout(ctx, 5*time.Second)
	_, err = client.ReadDataPacket(terminalContext)
	cancelTerminal()
	if err == nil || !strings.Contains(err.Error(), "policy ended") {
		t.Fatalf("CSTP server disconnect was not terminal with its reason: %v", err)
	}
	timer := time.NewTimer(1200 * time.Millisecond)
	defer timer.Stop()
	select {
	case failure := <-peer.failures:
		t.Fatal(failure)
	case <-timer.C:
	}
	peer.access.Lock()
	authRequests := peer.authRequests
	connectRequests := peer.connectRequests
	peer.access.Unlock()
	if authRequests != 1 || connectRequests != 1 {
		t.Fatalf("terminal CSTP disconnect reconnected: auth=%d connect=%d", authRequests, connectRequests)
	}
}

func TestM1AnyConnectCSTPTimerWireInterop(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name         string
		expectedType byte
	}{
		{name: "active-dpd", expectedType: anyConnectPacketDPDRequest},
		{name: "keepalive", expectedType: anyConnectPacketKeepalive},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			peer := &m1CSTPTimerPeer{
				ctx:          ctx,
				expectedType: testCase.expectedType,
				failures:     make(chan error, 4),
				observed:     make(chan struct{}, 1),
			}
			server := httptest.NewUnstartedServer(peer)
			server.EnableHTTP2 = false
			server.StartTLS()
			defer server.Close()
			client, err := openconnect.NewClient(openconnect.ClientOptions{
				Context: ctx,
				Server:  server.URL,
				Flavor:  openconnect.FlavorAnyConnect,
				NoUDP:   true,
				TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
					InsecureSkipVerify: true,
				}},
			})
			if err != nil {
				t.Fatal(E.Cause(err, "create CSTP timer wire client"))
			}
			defer client.Close()
			err = client.Start()
			if err != nil {
				t.Fatal(E.Cause(err, "start CSTP timer wire client"))
			}
			waitForM1Ready(t, ctx, client)
			select {
			case <-peer.observed:
			case failure := <-peer.failures:
				t.Fatal(failure)
			case <-ctx.Done():
				t.Fatal(E.Cause(ctx.Err(), "wait for active CSTP timer packet"))
			}
			if !client.Ready() {
				t.Fatal("CSTP client stopped after successful timer exchange")
			}
			select {
			case failure := <-peer.failures:
				t.Fatal(failure)
			default:
			}
		})
	}
}

func (p *m1CSTPWirePeer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/":
		body, err := io.ReadAll(request.Body)
		if err != nil {
			p.fail(writer, E.Cause(err, "read CSTP wire authentication request"))
			return
		}
		if !bytes.Contains(body, []byte(`type="init"`)) {
			p.fail(writer, E.New("CSTP wire peer received non-initial authentication request"))
			return
		}
		p.access.Lock()
		p.authRequests++
		p.access.Unlock()
		http.SetCookie(writer, &http.Cookie{Name: "webvpn", Value: "cstp-wire-session", Path: "/", Secure: true})
		writer.Header().Set("Content-Type", "application/xml")
		_, err = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>cstp-wire-session</session-token><auth id="success" />
</config-auth>`)
		if err != nil {
			p.recordFailure(E.Cause(err, "write CSTP wire authentication response"))
		}
	case request.Method == http.MethodConnect && request.URL.Path == "/CSCOSSLC/tunnel":
		cookie, err := request.Cookie("webvpn")
		if err != nil || cookie.Value != "cstp-wire-session" {
			p.fail(writer, E.New("CSTP wire peer received CONNECT without accepted cookie"))
			return
		}
		p.access.Lock()
		p.connectRequests++
		p.access.Unlock()
		p.serveTunnel(writer)
	default:
		p.fail(writer, E.New("CSTP wire peer received unexpected request: ", request.Method, " ", request.URL.Path))
	}
}

func (p *m1CSTPTimerPeer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/":
		body, err := io.ReadAll(request.Body)
		if err != nil || !bytes.Contains(body, []byte(`type="init"`)) {
			if err == nil {
				err = E.New("CSTP timer peer received non-initial authentication")
			}
			p.fail(writer, err)
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: "webvpn", Value: "cstp-timer-session", Path: "/", Secure: true})
		writer.Header().Set("Content-Type", "application/xml")
		_, err = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>cstp-timer-session</session-token><auth id="success" />
</config-auth>`)
		if err != nil {
			p.recordFailure(E.Cause(err, "write CSTP timer authentication response"))
		}
	case request.Method == http.MethodConnect && request.URL.Path == "/CSCOSSLC/tunnel":
		cookie, err := request.Cookie("webvpn")
		if err != nil || cookie.Value != "cstp-timer-session" {
			p.fail(writer, E.New("CSTP timer peer received CONNECT without accepted cookie"))
			return
		}
		p.serveTunnel(writer)
	default:
		p.fail(writer, E.New("CSTP timer peer received unexpected request: ", request.Method, " ", request.URL.Path))
	}
}

func (p *m1CSTPTimerPeer) serveTunnel(writer http.ResponseWriter) {
	hijacker, supported := writer.(http.Hijacker)
	if !supported {
		p.recordFailure(E.New("CSTP timer peer cannot hijack CONNECT"))
		return
	}
	connection, readWriter, err := hijacker.Hijack()
	if err != nil {
		p.recordFailure(E.Cause(err, "hijack CSTP timer connection"))
		return
	}
	defer connection.Close()
	dpd := "0"
	keepalive := "1"
	if p.expectedType == anyConnectPacketDPDRequest {
		dpd = "1"
		keepalive = "0"
	}
	_, err = readWriter.WriteString("HTTP/1.1 200 CONNECTED\r\n" +
		"X-CSTP-MTU: 1200\r\n" +
		"X-CSTP-Address: 192.0.2.45\r\n" +
		"X-CSTP-Netmask: 255.255.255.0\r\n" +
		"X-CSTP-DPD: " + dpd + "\r\n" +
		"X-CSTP-Keepalive: " + keepalive + "\r\n" +
		"X-CSTP-Rekey-Method: none\r\n\r\n")
	if err == nil {
		err = readWriter.Flush()
	}
	if err != nil {
		p.recordFailure(E.Cause(err, "write CSTP timer negotiation"))
		return
	}
	negotiatedAt := time.Now()
	packetType, payload, err := readM1CSTPWireRecord(readWriter)
	if err != nil {
		p.recordFailure(err)
		return
	}
	if packetType != p.expectedType || len(payload) != 0 {
		p.recordFailure(E.New("unexpected active CSTP timer packet: type=", packetType, " payload=", payload))
		return
	}
	elapsed := time.Since(negotiatedAt)
	if elapsed < 750*time.Millisecond || elapsed > 3*time.Second {
		p.recordFailure(E.New("active CSTP timer fired outside negotiated one-second window: ", elapsed))
		return
	}
	if packetType == anyConnectPacketDPDRequest {
		err = writeM1CSTPWireRecord(readWriter, anyConnectPacketDPDResponse, nil)
		if err != nil {
			p.recordFailure(err)
			return
		}
	}
	p.observed <- struct{}{}
	<-p.ctx.Done()
}

func (p *m1CSTPTimerPeer) fail(writer http.ResponseWriter, err error) {
	p.recordFailure(err)
	http.Error(writer, err.Error(), http.StatusBadRequest)
}

func (p *m1CSTPTimerPeer) recordFailure(err error) {
	select {
	case p.failures <- err:
	default:
	}
}

func (p *m1CSTPWirePeer) serveTunnel(writer http.ResponseWriter) {
	hijacker, supported := writer.(http.Hijacker)
	if !supported {
		p.recordFailure(E.New("CSTP wire peer cannot hijack CONNECT"))
		return
	}
	connection, readWriter, err := hijacker.Hijack()
	if err != nil {
		p.recordFailure(E.Cause(err, "hijack CSTP wire connection"))
		return
	}
	defer connection.Close()
	_, err = readWriter.WriteString("HTTP/1.1 200 CONNECTED\r\n" +
		"X-CSTP-MTU: 600\r\n" +
		"X-CSTP-Address: 192.0.2.40\r\n" +
		"X-CSTP-Netmask: 255.255.255.0\r\n" +
		"X-CSTP-Split-Include: 10.20.0.0/255.255.0.0\r\n" +
		"X-CSTP-Split-Include-IP6: 2001:db8:20::/48\r\n" +
		"X-CSTP-Split-Exclude: 198.51.100.0/24\r\n" +
		"X-CSTP-Split-Exclude-IP6: 2001:db8:30::/48\r\n" +
		"X-CSTP-DNS: 192.0.2.53\r\n" +
		"X-CSTP-DNS-IP6: 2001:db8::53\r\n" +
		"X-CSTP-NBNS: 192.0.2.54\r\n" +
		"X-CSTP-Default-Domain: corp.example internal.example\r\n" +
		"X-CSTP-Split-DNS: split-one.example\r\n" +
		"X-CSTP-Split-DNS: split-two.example\r\n" +
		"X-CSTP-MSIE-Proxy-PAC-URL: https://pac.example/proxy.pac\r\n" +
		"X-CSTP-DPD: 30\r\n" +
		"X-CSTP-Keepalive: 30\r\n" +
		"X-CSTP-Idle-Timeout: 17\r\n" +
		"X-CSTP-Lease-Duration: 120\r\n" +
		"X-CSTP-Session-Timeout: 90\r\n" +
		"X-CSTP-Session-Timeout-Remaining: 100\r\n" +
		"X-CSTP-Banner: wire banner\r\n" +
		"X-CSTP-Tunnel-All-DNS: true\r\n" +
		"X-CSTP-Client-Bypass-Protocol: true\r\n" +
		"X-CSTP-Rekey-Method: none\r\n\r\n")
	if err == nil {
		err = readWriter.Flush()
	}
	if err != nil {
		p.recordFailure(E.Cause(err, "write CSTP wire response"))
		return
	}
	err = writeM1CSTPWireRecord(readWriter, anyConnectPacketDPDRequest, []byte("request payload must not be echoed"))
	if err != nil {
		p.recordFailure(err)
		return
	}
	packetType, payload, err := readM1CSTPWireRecord(readWriter)
	if err != nil {
		p.recordFailure(err)
		return
	}
	if packetType != anyConnectPacketDPDResponse || len(payload) != 0 {
		p.recordFailure(E.New("CSTP DPD response was not empty: type=", packetType, " payload=", payload))
		return
	}
	oversizedPayload := bytes.Repeat([]byte{0x5a}, 1000)
	err = writeM1CSTPWireRecord(readWriter, anyConnectPacketData, oversizedPayload)
	if err != nil {
		p.recordFailure(err)
		return
	}
	close(p.dataSent)
	select {
	case <-p.allowDisconnect:
	case <-time.After(5 * time.Second):
		p.recordFailure(E.New("CSTP wire test did not release server disconnect"))
		return
	}
	err = writeM1CSTPWireRecord(readWriter, 5, append([]byte{0xb0}, []byte("policy ended")...))
	if err != nil {
		p.recordFailure(err)
		return
	}
	close(p.disconnectSent)
}

func writeM1CSTPWireRecord(writer *bufio.ReadWriter, packetType byte, payload []byte) error {
	header := []byte{'S', 'T', 'F', 1, 0, 0, packetType, 0}
	binary.BigEndian.PutUint16(header[4:6], uint16(len(payload)))
	_, err := writer.Write(header)
	if err == nil && len(payload) > 0 {
		_, err = writer.Write(payload)
	}
	if err == nil {
		err = writer.Flush()
	}
	if err != nil {
		return E.Cause(err, "write CSTP wire record")
	}
	return nil
}

func readM1CSTPWireRecord(reader *bufio.ReadWriter) (byte, []byte, error) {
	header := make([]byte, 8)
	_, err := io.ReadFull(reader, header)
	if err != nil {
		return 0, nil, E.Cause(err, "read CSTP wire record header")
	}
	if !bytes.Equal(header[:4], []byte{'S', 'T', 'F', 1}) || header[7] != 0 {
		return 0, nil, E.New("invalid CSTP wire record header")
	}
	payload := make([]byte, int(binary.BigEndian.Uint16(header[4:6])))
	_, err = io.ReadFull(reader, payload)
	if err != nil {
		return 0, nil, E.Cause(err, "read CSTP wire record payload")
	}
	return header[6], payload, nil
}

func (p *m1CSTPWirePeer) fail(writer http.ResponseWriter, err error) {
	p.recordFailure(err)
	http.Error(writer, err.Error(), http.StatusBadRequest)
}

func (p *m1CSTPWirePeer) recordFailure(err error) {
	select {
	case p.failures <- err:
	default:
	}
}

func assertM1CSTPWireConfiguration(t *testing.T, configuration openconnect.TunnelConfiguration) {
	t.Helper()
	if configuration.MTU != 600 ||
		!slices.Equal(configuration.Addresses, []netip.Prefix{netip.MustParsePrefix("192.0.2.40/24")}) ||
		!slices.Equal(configuration.Routes, []openconnect.TunnelRoute{
			{Prefix: netip.MustParsePrefix("10.20.0.0/16")},
			{Prefix: netip.MustParsePrefix("2001:db8:20::/48")},
		}) ||
		!slices.Equal(configuration.ExcludedRoutes, []openconnect.TunnelRoute{
			{Prefix: netip.MustParsePrefix("198.51.100.0/24")},
			{Prefix: netip.MustParsePrefix("2001:db8:30::/48")},
		}) ||
		!slices.Equal(configuration.DNS, []netip.Addr{
			netip.MustParseAddr("192.0.2.53"),
			netip.MustParseAddr("2001:db8::53"),
		}) ||
		!slices.Equal(configuration.NBNS, []netip.Addr{netip.MustParseAddr("192.0.2.54")}) ||
		!slices.Equal(configuration.SearchDomains, []string{"corp.example", "internal.example"}) ||
		!slices.Equal(configuration.SplitDNS, []string{"split-one.example", "split-two.example"}) ||
		configuration.ProxyAutoConfigURL != "https://pac.example/proxy.pac" ||
		configuration.Banner != "wire banner" ||
		!configuration.TunnelAllDNS ||
		!configuration.ClientBypassProtocol ||
		configuration.IdleTimeout != 17*time.Second {
		t.Fatalf("unexpected complete CSTP configuration: %#v", configuration)
	}
	remaining := time.Until(configuration.AuthenticationExpiration)
	if remaining < 80*time.Second || remaining > 95*time.Second {
		t.Fatalf("unexpected CSTP authentication expiration: remaining=%s configuration=%#v", remaining, configuration)
	}
}

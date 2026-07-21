package test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
)

type m1AnyConnectOptionsPeer struct {
	ctx                     context.Context
	failures                chan error
	dpdObserved             chan time.Time
	burstSent               chan time.Time
	expectedVersion         string
	expectedHostname        string
	expectedAgent           string
	expectedPlatformVersion string
	expectedDeviceType      string
	expectedDeviceUniqueID  string
}

func TestM1AnyConnectOptionsInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	peer := &m1AnyConnectOptionsPeer{
		ctx:                     ctx,
		failures:                make(chan error, 4),
		dpdObserved:             make(chan time.Time, 1),
		burstSent:               make(chan time.Time, 1),
		expectedVersion:         "v9.21",
		expectedHostname:        "wire-hostname",
		expectedAgent:           "wire-user-agent",
		expectedPlatformVersion: "17.5",
		expectedDeviceType:      "enterprise-tablet",
		expectedDeviceUniqueID:  "device-0123456789",
	}
	server := httptest.NewUnstartedServer(peer)
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 1)
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context:       ctx,
		Server:        server.URL,
		Flavor:        openconnect.FlavorAnyConnect,
		ReportedOS:    "linux-64",
		UserAgent:     peer.expectedAgent,
		LocalHostname: peer.expectedHostname,
		Mobile: &openconnect.MobileOptions{
			PlatformVersion: peer.expectedPlatformVersion,
			DeviceType:      peer.expectedDeviceType,
			DeviceUniqueID:  peer.expectedDeviceUniqueID,
		},
		DTLSCipherSuites:     "AES128-SHA",
		IPv6Disabled:         true,
		MTU:                  1,
		BaseMTU:              1,
		QueueLength:          2,
		DPDInterval:          time.Second,
		ReconnectTimeout:     5 * time.Second,
		ExternalAuthDisabled: true,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
		}},
		OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
			configurationEvents <- event
			return nil
		},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create AnyConnect options interop client"))
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start AnyConnect options interop client"))
	}
	select {
	case event := <-configurationEvents:
		configuration := event.Configuration
		if event.Reason != openconnect.TunnelConfigurationEventInitial ||
			configuration.MTU != 1300 ||
			configuration.RemoteAddress != netip.MustParseAddr("127.0.0.1") ||
			!slices.Equal(configuration.Addresses, []netip.Prefix{netip.MustParsePrefix("192.0.2.80/24")}) ||
			!slices.Equal(configuration.Routes, []openconnect.TunnelRoute{{Prefix: netip.MustParsePrefix("0.0.0.0/0")}}) ||
			!slices.Equal(configuration.ExcludedRoutes, []openconnect.TunnelRoute{{Prefix: netip.MustParsePrefix("198.51.100.0/24")}}) ||
			!slices.Equal(configuration.DNS, []netip.Addr{netip.MustParseAddr("192.0.2.53")}) {
			t.Fatalf("unexpected AnyConnect option-driven tunnel configuration: %#v", event)
		}
	case failure := <-peer.failures:
		t.Fatal(failure)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for AnyConnect option-driven tunnel configuration"))
	}
	var burstTime time.Time
	select {
	case burstTime = <-peer.burstSent:
	case failure := <-peer.failures:
		t.Fatal(failure)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for AnyConnect queue burst"))
	}
	var receivedPayloads []string
	for len(receivedPayloads) < 3 {
		packetBuffers, readErr := client.ReadDataPackets(ctx)
		if readErr != nil {
			t.Fatal(E.Cause(readErr, "consume bounded AnyConnect queue batch"))
		}
		if len(packetBuffers) > 2 {
			for _, packetBuffer := range packetBuffers {
				packetBuffer.Release()
			}
			t.Fatalf("AnyConnect queue batch exceeded configured capacity: %d", len(packetBuffers))
		}
		for _, packetBuffer := range packetBuffers {
			receivedPayloads = append(receivedPayloads, string(packetBuffer.Bytes()))
			packetBuffer.Release()
		}
	}
	if !slices.Equal(receivedPayloads, []string{"discarded", "retained-one", "retained-two"}) {
		t.Fatalf("bounded AnyConnect queue dropped or reordered packets: %v", receivedPayloads)
	}
	select {
	case dpdTime := <-peer.dpdObserved:
		if dpdTime.Sub(burstTime) < 1500*time.Millisecond {
			t.Fatal("one-second DPD interval was not normalized to two seconds")
		}
	case failure := <-peer.failures:
		t.Fatal(failure)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for forced AnyConnect DPD"))
	}
}

func (p *m1AnyConnectOptionsPeer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/":
		body, err := io.ReadAll(request.Body)
		if err != nil {
			p.fail(writer, E.Cause(err, "read AnyConnect options authentication request"))
			return
		}
		versionElement := []byte(`<version who="vpn">` + p.expectedVersion + `</version>`)
		deviceElement := []byte(`<device-id platform-version="` + p.expectedPlatformVersion + `" device-type="` + p.expectedDeviceType + `" unique-id="` + p.expectedDeviceUniqueID + `">`)
		if !bytes.Contains(body, versionElement) ||
			!bytes.Contains(body, deviceElement) ||
			bytes.Contains(body, []byte("single-sign-on-v2")) ||
			request.Header.Get("User-Agent") != p.expectedAgent {
			p.fail(writer, E.New("AnyConnect version and HTTP user agent were not independently reported"))
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: "webvpn", Value: "options-session", Path: "/", Secure: true})
		writer.Header().Set("Content-Type", "application/xml")
		_, err = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>options-session</session-token><auth id="success" />
</config-auth>`)
		if err != nil {
			p.recordFailure(E.Cause(err, "write AnyConnect options authentication response"))
		}
	case request.Method == http.MethodConnect && request.URL.Path == "/CSCOSSLC/tunnel":
		if request.Header.Get("X-CSTP-Hostname") != p.expectedHostname ||
			request.Header.Get("X-AnyConnect-Identifier-ClientVersion") != p.expectedVersion ||
			request.Header.Get("X-AnyConnect-Identifier-Platform") != "linux-64" ||
			request.Header.Get("X-AnyConnect-Identifier-PlatformVersion") != p.expectedPlatformVersion ||
			request.Header.Get("X-AnyConnect-Identifier-DeviceType") != p.expectedDeviceType ||
			request.Header.Get("X-AnyConnect-Identifier-Device-UniqueID") != p.expectedDeviceUniqueID ||
			request.Header.Get("X-CSTP-Address-Type") != "IPv4" ||
			request.Header.Get("X-CSTP-Full-IPv6-Capability") != "" ||
			request.Header.Get("X-CSTP-Base-MTU") != "1280" ||
			request.Header.Get("X-CSTP-MTU") != "576" ||
			request.Header.Get("X-DTLS-CipherSuite") != "AES128-SHA" ||
			request.Header.Get("X-DTLS12-CipherSuite") != "" ||
			request.Header.Get("User-Agent") != p.expectedAgent {
			p.fail(writer, E.New("AnyConnect CSTP options were not emitted on the wire: ", fmt.Sprint(request.Header)))
			return
		}
		p.serveTunnel(writer)
	default:
		p.fail(writer, E.New("AnyConnect options peer received unexpected request: ", request.Method, " ", request.URL.Path))
	}
}

func (p *m1AnyConnectOptionsPeer) serveTunnel(writer http.ResponseWriter) {
	hijacker, supported := writer.(http.Hijacker)
	if !supported {
		p.recordFailure(E.New("AnyConnect options peer cannot hijack CONNECT"))
		return
	}
	connection, readWriter, err := hijacker.Hijack()
	if err != nil {
		p.recordFailure(E.Cause(err, "hijack AnyConnect options connection"))
		return
	}
	defer connection.Close()
	_, err = readWriter.WriteString("HTTP/1.1 200 CONNECTED\r\n" +
		"X-CSTP-MTU: 1300\r\n" +
		"X-CSTP-Address: 192.0.2.80\r\n" +
		"X-CSTP-Netmask: 255.255.255.0\r\n" +
		"X-CSTP-Address: 2001:db8::80\r\n" +
		"X-CSTP-Netmask: ffff:ffff:ffff:ffff::\r\n" +
		"X-CSTP-Split-Exclude: 198.51.100.0/24\r\n" +
		"X-CSTP-Split-Exclude-IP6: 2001:db8:ffff::/48\r\n" +
		"X-CSTP-DNS: 192.0.2.53\r\n" +
		"X-CSTP-DNS-IP6: 2001:db8::53\r\n" +
		"X-CSTP-DPD: 30\r\n" +
		"X-CSTP-Keepalive: 0\r\n" +
		"X-CSTP-Rekey-Method: none\r\n\r\n")
	if err == nil {
		err = readWriter.Flush()
	}
	if err != nil {
		p.recordFailure(E.Cause(err, "write AnyConnect options tunnel response"))
		return
	}
	for _, payload := range []string{"discarded", "retained-one", "retained-two"} {
		err = writeM1CSTPWireRecord(readWriter, anyConnectPacketData, []byte(payload))
		if err != nil {
			p.recordFailure(E.Cause(err, "write AnyConnect options queue burst"))
			return
		}
	}
	p.burstSent <- time.Now()
	packetType, payload, err := readM1AnyConnectOptionsRecord(readWriter)
	if err != nil {
		p.recordFailure(err)
		return
	}
	if packetType != anyConnectPacketDPDRequest || len(payload) != 0 {
		p.recordFailure(E.New("AnyConnect forced DPD emitted an unexpected packet"))
		return
	}
	p.dpdObserved <- time.Now()
	<-p.ctx.Done()
}

func readM1AnyConnectOptionsRecord(reader *bufio.ReadWriter) (byte, []byte, error) {
	header := make([]byte, 8)
	_, err := io.ReadFull(reader, header)
	if err != nil {
		return 0, nil, E.Cause(err, "read AnyConnect options CSTP record header")
	}
	if !bytes.Equal(header[:4], []byte{'S', 'T', 'F', 1}) || header[7] != 0 {
		return 0, nil, E.New("invalid AnyConnect options CSTP record header")
	}
	payload := make([]byte, int(binary.BigEndian.Uint16(header[4:6])))
	_, err = io.ReadFull(reader, payload)
	if err != nil {
		return 0, nil, E.Cause(err, "read AnyConnect options CSTP record payload")
	}
	return header[6], payload, nil
}

func (p *m1AnyConnectOptionsPeer) fail(writer http.ResponseWriter, err error) {
	p.recordFailure(err)
	http.Error(writer, err.Error(), http.StatusBadRequest)
}

func (p *m1AnyConnectOptionsPeer) recordFailure(err error) {
	select {
	case p.failures <- err:
	default:
	}
}

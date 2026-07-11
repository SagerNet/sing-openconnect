package test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	m1DynamicDNSHostname = "dynamic-vpn.example"
	m1DynamicDNSCookie   = "dynamic-dns-session"
)

type m1DynamicDNSPeer struct {
	ctx                     context.Context
	failures                chan error
	primaryTunnelReady      chan struct{}
	replacementTunnelReady  chan struct{}
	fallbackTunnelReady     chan struct{}
	dropPrimary             chan struct{}
	dropReplacement         chan struct{}
	primaryAuthRequests     atomic.Uint64
	replacementAuthRequests atomic.Uint64
	primaryConnects         atomic.Uint64
	replacementConnects     atomic.Uint64
}

type m1DynamicDNSDialMode uint8

const (
	m1DynamicDNSDialPrimary m1DynamicDNSDialMode = iota
	m1DynamicDNSDialReplacement
	m1DynamicDNSDialUnavailable
)

type m1DynamicDNSDialer struct {
	access                 sync.Mutex
	mode                   m1DynamicDNSDialMode
	primary                M.Socksaddr
	replacement            M.Socksaddr
	originalPort           uint16
	domainPrimaryDials     uint64
	primaryAddressDials    uint64
	domainReplacementDials uint64
	domainFailures         uint64
	cachedFallbackDials    uint64
}

func TestM1AnyConnectDynamicDNSReconnectInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	peer := &m1DynamicDNSPeer{
		ctx:                    ctx,
		failures:               make(chan error, 8),
		primaryTunnelReady:     make(chan struct{}, 1),
		replacementTunnelReady: make(chan struct{}, 1),
		fallbackTunnelReady:    make(chan struct{}, 1),
		dropPrimary:            make(chan struct{}),
		dropReplacement:        make(chan struct{}),
	}
	primaryServer := httptest.NewUnstartedServer(http.HandlerFunc(peer.servePrimary))
	primaryServer.EnableHTTP2 = false
	primaryAddress := M.SocksaddrFromNet(primaryServer.Listener.Addr())
	replacementListener, err := net.Listen(
		"tcp6",
		net.JoinHostPort("::1", strconv.Itoa(int(primaryAddress.Port))),
	)
	if err != nil {
		_ = primaryServer.Listener.Close()
		t.Skipf("IPv6 loopback cannot host the dynamic-DNS replacement peer: %v", err)
	}
	replacementServer := httptest.NewUnstartedServer(http.HandlerFunc(peer.serveReplacement))
	replacementServer.EnableHTTP2 = false
	err = replacementServer.Listener.Close()
	if err != nil {
		primaryServer.Close()
		_ = replacementListener.Close()
		t.Fatal(E.Cause(err, "replace dynamic-DNS test listener"))
	}
	replacementServer.Listener = replacementListener
	primaryServer.StartTLS()
	defer primaryServer.Close()
	replacementServer.StartTLS()
	defer replacementServer.Close()

	replacementAddress := m1DynamicDNSServerAddress(t, replacementServer.URL)
	dialer := &m1DynamicDNSDialer{
		primary:      primaryAddress,
		replacement:  replacementAddress,
		originalPort: primaryAddress.Port,
	}
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 8)
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  net.JoinHostPort(m1DynamicDNSHostname, strconv.Itoa(int(primaryAddress.Port))),
		Flavor:  openconnect.FlavorAnyConnect,
		NoUDP:   true,
		Dialer:  dialer,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
		}},
		OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
			configurationEvents <- event
			return nil
		},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create dynamic-DNS AnyConnect client"))
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start dynamic-DNS AnyConnect client"))
	}

	initial := waitForM1DynamicDNSConfiguration(t, ctx, configurationEvents, peer.failures)
	if initial.Reason != openconnect.TunnelConfigurationEventInitial || initial.Configuration.Banner != "dynamic primary" {
		t.Fatalf("unexpected initial dynamic-DNS configuration: %#v", initial)
	}
	waitForM1DynamicDNSTunnel(t, ctx, peer.primaryTunnelReady, peer.failures, "primary dynamic-DNS tunnel")
	dialer.setMode(m1DynamicDNSDialReplacement)
	close(peer.dropPrimary)

	replacement := waitForM1DynamicDNSConfiguration(t, ctx, configurationEvents, peer.failures)
	if replacement.Reason != openconnect.TunnelConfigurationEventReestablishment || replacement.Configuration.Banner != "dynamic replacement" {
		t.Fatalf("unexpected resolver-switched dynamic-DNS configuration: %#v", replacement)
	}
	waitForM1DynamicDNSTunnel(t, ctx, peer.replacementTunnelReady, peer.failures, "replacement dynamic-DNS tunnel")
	readM1DynamicDNSPayload(t, ctx, client, "data from replacement backend")
	if form := client.PendingAuthForm(); form != nil {
		t.Fatalf("dynamic-DNS resolver switch unexpectedly required reauthentication: %#v", form)
	}

	dialer.setMode(m1DynamicDNSDialUnavailable)
	close(peer.dropReplacement)
	fallback := waitForM1DynamicDNSConfiguration(t, ctx, configurationEvents, peer.failures)
	if fallback.Reason != openconnect.TunnelConfigurationEventReestablishment || fallback.Configuration.Banner != "dynamic cached fallback" {
		t.Fatalf("unexpected cached-address fallback configuration: %#v", fallback)
	}
	waitForM1DynamicDNSTunnel(t, ctx, peer.fallbackTunnelReady, peer.failures, "cached-address fallback tunnel")
	readM1DynamicDNSPayload(t, ctx, client, "data from cached-address fallback")
	if form := client.PendingAuthForm(); form != nil {
		t.Fatalf("dynamic-DNS cached fallback unexpectedly required reauthentication: %#v", form)
	}

	peer.assertCounts(t)
	dialer.assertCounts(t)
	select {
	case failure := <-peer.failures:
		t.Fatal(failure)
	default:
	}
}

func (p *m1DynamicDNSPeer) servePrimary(writer http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/":
		body, err := io.ReadAll(request.Body)
		if err != nil {
			p.fail(writer, E.Cause(err, "read dynamic-DNS authentication request"))
			return
		}
		if !bytes.Contains(body, []byte(`type="init"`)) {
			p.fail(writer, E.New("dynamic-DNS primary received a non-initial authentication request"))
			return
		}
		p.primaryAuthRequests.Add(1)
		http.SetCookie(writer, &http.Cookie{Name: "webvpn", Value: m1DynamicDNSCookie, Path: "/", Secure: true})
		writer.Header().Set("Content-Type", "application/xml")
		_, err = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>`+m1DynamicDNSCookie+`</session-token><auth id="success" />
</config-auth>`)
		if err != nil {
			p.recordFailure(E.Cause(err, "write dynamic-DNS authentication response"))
		}
	case request.Method == http.MethodConnect && request.URL.Path == "/CSCOSSLC/tunnel":
		if !p.validCookie(request) {
			p.fail(writer, E.New("dynamic-DNS primary received CONNECT without the accepted cookie"))
			return
		}
		p.primaryConnects.Add(1)
		p.serveTunnel(writer, "dynamic primary", "192.0.2.61", p.primaryTunnelReady, p.dropPrimary, "")
	default:
		p.fail(writer, E.New("dynamic-DNS primary received unexpected request: ", request.Method, " ", request.URL.Path))
	}
}

func (p *m1DynamicDNSPeer) serveReplacement(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodConnect || request.URL.Path != "/CSCOSSLC/tunnel" {
		if request.Method == http.MethodPost {
			p.replacementAuthRequests.Add(1)
		}
		p.fail(writer, E.New("dynamic-DNS replacement received unexpected request: ", request.Method, " ", request.URL.Path))
		return
	}
	if !p.validCookie(request) {
		p.fail(writer, E.New("dynamic-DNS replacement received CONNECT without the accepted cookie"))
		return
	}
	connectNumber := p.replacementConnects.Add(1)
	switch connectNumber {
	case 1:
		p.serveTunnel(
			writer,
			"dynamic replacement",
			"192.0.2.62",
			p.replacementTunnelReady,
			p.dropReplacement,
			"data from replacement backend",
		)
	case 2:
		p.serveTunnel(
			writer,
			"dynamic cached fallback",
			"192.0.2.63",
			p.fallbackTunnelReady,
			p.ctx.Done(),
			"data from cached-address fallback",
		)
	default:
		p.fail(writer, E.New("dynamic-DNS replacement received too many CONNECT requests: ", connectNumber))
	}
}

func (p *m1DynamicDNSPeer) serveTunnel(
	writer http.ResponseWriter,
	banner string,
	address string,
	ready chan<- struct{},
	drop <-chan struct{},
	payload string,
) {
	hijacker, supported := writer.(http.Hijacker)
	if !supported {
		p.recordFailure(E.New("dynamic-DNS peer cannot hijack CSTP CONNECT"))
		return
	}
	connection, readWriter, err := hijacker.Hijack()
	if err != nil {
		p.recordFailure(E.Cause(err, "hijack dynamic-DNS CSTP connection"))
		return
	}
	defer connection.Close()
	_, err = readWriter.WriteString("HTTP/1.1 200 CONNECTED\r\n" +
		"X-CSTP-MTU: 1200\r\n" +
		"X-CSTP-Address: " + address + "\r\n" +
		"X-CSTP-Netmask: 255.255.255.0\r\n" +
		"X-CSTP-DPD: 30\r\n" +
		"X-CSTP-Keepalive: 30\r\n" +
		"X-CSTP-Rekey-Method: none\r\n" +
		"X-CSTP-DynDNS: true\r\n" +
		"X-CSTP-Banner: " + banner + "\r\n\r\n")
	if err == nil {
		err = readWriter.Flush()
	}
	if err != nil {
		p.recordFailure(E.Cause(err, "write dynamic-DNS CSTP response"))
		return
	}
	if payload != "" {
		err = writeM1CSTPWireRecord(readWriter, anyConnectPacketData, []byte(payload))
		if err != nil {
			p.recordFailure(err)
			return
		}
	}
	ready <- struct{}{}
	select {
	case <-drop:
	case <-p.ctx.Done():
	}
}

func (p *m1DynamicDNSPeer) validCookie(request *http.Request) bool {
	cookie, err := request.Cookie("webvpn")
	return err == nil && cookie.Value == m1DynamicDNSCookie
}

func (p *m1DynamicDNSPeer) fail(writer http.ResponseWriter, err error) {
	p.recordFailure(err)
	http.Error(writer, err.Error(), http.StatusBadRequest)
}

func (p *m1DynamicDNSPeer) recordFailure(err error) {
	select {
	case p.failures <- err:
	default:
	}
}

func (p *m1DynamicDNSPeer) assertCounts(t *testing.T) {
	t.Helper()
	if auth := p.primaryAuthRequests.Load(); auth != 1 {
		t.Fatalf("dynamic-DNS primary authentication requests = %d, expected 1", auth)
	}
	if auth := p.replacementAuthRequests.Load(); auth != 0 {
		t.Fatalf("dynamic-DNS replacement authentication requests = %d, expected 0", auth)
	}
	if connects := p.primaryConnects.Load(); connects != 1 {
		t.Fatalf("dynamic-DNS primary CONNECT requests = %d, expected 1", connects)
	}
	if connects := p.replacementConnects.Load(); connects != 2 {
		t.Fatalf("dynamic-DNS replacement CONNECT requests = %d, expected 2", connects)
	}
}

func (d *m1DynamicDNSDialer) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	if network != N.NetworkTCP {
		return N.SystemDialer.DialContext(ctx, network, destination)
	}
	d.access.Lock()
	mode := d.mode
	target := destination
	switch {
	case destination.Fqdn == m1DynamicDNSHostname:
		switch mode {
		case m1DynamicDNSDialPrimary:
			d.domainPrimaryDials++
			target = d.primary
		case m1DynamicDNSDialReplacement:
			d.domainReplacementDials++
			target = d.replacement
		case m1DynamicDNSDialUnavailable:
			d.domainFailures++
			d.access.Unlock()
			return nil, E.New("deliberate dynamic-DNS resolution failure")
		}
	case destination.Addr == netip.MustParseAddr("127.0.0.1") && destination.Port == d.originalPort:
		d.primaryAddressDials++
	case destination.Addr == netip.IPv6Loopback() && destination.Port == d.originalPort:
		d.cachedFallbackDials++
		target = d.replacement
	}
	d.access.Unlock()
	connection, err := N.SystemDialer.DialContext(ctx, network, target)
	if err != nil {
		return nil, err
	}
	return connection, nil
}

func (d *m1DynamicDNSDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

func (d *m1DynamicDNSDialer) setMode(mode m1DynamicDNSDialMode) {
	d.access.Lock()
	d.mode = mode
	d.access.Unlock()
}

func (d *m1DynamicDNSDialer) assertCounts(t *testing.T) {
	t.Helper()
	d.access.Lock()
	defer d.access.Unlock()
	if d.domainPrimaryDials != 1 || d.primaryAddressDials != 1 ||
		d.domainReplacementDials != 1 || d.domainFailures != 1 || d.cachedFallbackDials != 1 {
		t.Fatalf(
			"unexpected dynamic-DNS dial sequence: domain-primary=%d cached-primary=%d domain-replacement=%d domain-failures=%d cached-fallback=%d",
			d.domainPrimaryDials,
			d.primaryAddressDials,
			d.domainReplacementDials,
			d.domainFailures,
			d.cachedFallbackDials,
		)
	}
}

func m1DynamicDNSServerAddress(t *testing.T, serverURL string) M.Socksaddr {
	t.Helper()
	parsed, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(E.Cause(err, "parse dynamic-DNS peer URL"))
	}
	return M.ParseSocksaddr(parsed.Host)
}

func waitForM1DynamicDNSConfiguration(
	t *testing.T,
	ctx context.Context,
	events <-chan openconnect.TunnelConfigurationEvent,
	failures <-chan error,
) openconnect.TunnelConfigurationEvent {
	t.Helper()
	select {
	case event := <-events:
		return event
	case failure := <-failures:
		t.Fatal(failure)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for dynamic-DNS tunnel configuration"))
	}
	return openconnect.TunnelConfigurationEvent{}
}

func waitForM1DynamicDNSTunnel(
	t *testing.T,
	ctx context.Context,
	ready <-chan struct{},
	failures <-chan error,
	description string,
) {
	t.Helper()
	select {
	case <-ready:
	case failure := <-failures:
		t.Fatal(failure)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for ", description))
	}
}

func readM1DynamicDNSPayload(t *testing.T, ctx context.Context, client *openconnect.Client, expected string) {
	t.Helper()
	readContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	payload, err := client.ReadDataPacket(readContext)
	if err != nil {
		t.Fatal(E.Cause(err, "read dynamic-DNS CSTP data"))
	}
	if string(payload) != expected {
		t.Fatalf("unexpected dynamic-DNS CSTP payload: %q", payload)
	}
}

var _ N.Dialer = (*m1DynamicDNSDialer)(nil)

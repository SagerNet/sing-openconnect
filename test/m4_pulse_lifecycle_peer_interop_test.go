package test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	m4PulseLifecycleInitialCookie = "pulse-lifecycle-initial-cookie"
	m4PulseLifecycleFinalCookie   = "pulse-lifecycle-final-cookie"
)

type m4PulseLifecycleScenario uint8

const (
	m4PulseLifecycleReconnectFallback m4PulseLifecycleScenario = iota
	m4PulseLifecycleAbnormalLogout
	m4PulseLifecycleAuthenticationCancellation
)

type m4PulseLifecyclePeer struct {
	listener              net.Listener
	port                  uint16
	scenario              m4PulseLifecycleScenario
	failures              chan error
	done                  chan struct{}
	initialConfigured     chan struct{}
	abortInitial          chan struct{}
	initialAborted        chan struct{}
	authenticationBlocked chan struct{}
	authenticationClosed  chan struct{}
	close                 sync.Once
	access                sync.Mutex
	upgradeCount          int
	fullAuthCount         int
	reconnectCount        int
	gracefulCount         int
	logoutCount           int
}

type m4PulseLifecycleSnapshot struct {
	upgradeCount   int
	fullAuthCount  int
	reconnectCount int
	gracefulCount  int
	logoutCount    int
}

func TestM4PulseCookieRejectionFallsBackToFullAuthentication(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	certificate, roots := createM2GPPeerCertificate(t, m4PulseHostname)
	peer := newM4PulseLifecyclePeer(t, certificate, m4PulseLifecycleReconnectFallback)
	defer peer.Close()
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 4)
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
		OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
			configurationEvents <- event
			return nil
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
	waitM4PulseLifecycleEvent(t, ctx, peer, client, configurationEvents, openconnect.TunnelConfigurationEventInitial)
	select {
	case <-peer.initialConfigured:
	case peerErr := <-peer.failures:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for initial Pulse lifecycle configuration"))
	}
	close(peer.abortInitial)
	select {
	case <-peer.initialAborted:
	case peerErr := <-peer.failures:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for initial Pulse lifecycle EOF"))
	}
	waitM4PulseLifecycleEvent(t, ctx, peer, client, configurationEvents, openconnect.TunnelConfigurationEventReestablishment)
	if !client.Ready() {
		t.Fatal("Pulse client did not become ready after full authentication fallback")
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
		t.Fatal(E.Cause(ctx.Err(), "wait for Pulse lifecycle peer shutdown"))
	}
	snapshot := peer.snapshot()
	if snapshot.upgradeCount != 3 || snapshot.fullAuthCount != 2 || snapshot.reconnectCount != 1 {
		t.Fatalf("unexpected Pulse lifecycle authentication counts: %+v", snapshot)
	}
	if snapshot.gracefulCount != 1 || snapshot.logoutCount != 0 {
		t.Fatalf("Pulse lifecycle close used unexpected wire operations: %+v", snapshot)
	}
}

func TestM4PulseAbnormalEOFUsesHTTPSLogout(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	certificate, roots := createM2GPPeerCertificate(t, m4PulseHostname)
	peer := newM4PulseLifecyclePeer(t, certificate, m4PulseLifecycleAbnormalLogout)
	defer peer.Close()
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 2)
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
		OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
			configurationEvents <- event
			return nil
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
	waitM4PulseLifecycleEvent(t, ctx, peer, client, configurationEvents, openconnect.TunnelConfigurationEventInitial)
	select {
	case <-peer.initialConfigured:
	case peerErr := <-peer.failures:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for Pulse logout scenario configuration"))
	}
	close(peer.abortInitial)
	select {
	case <-peer.initialAborted:
	case peerErr := <-peer.failures:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for Pulse logout scenario EOF"))
	}
	for client.Ready() {
		select {
		case peerErr := <-peer.failures:
			t.Fatal(peerErr)
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for Pulse client to process abnormal EOF"))
		case <-time.After(time.Millisecond):
		}
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
		t.Fatal(E.Cause(ctx.Err(), "wait for Pulse HTTPS logout"))
	}
	snapshot := peer.snapshot()
	if snapshot.upgradeCount != 1 || snapshot.fullAuthCount != 1 || snapshot.reconnectCount != 0 ||
		snapshot.gracefulCount != 0 || snapshot.logoutCount != 1 {
		t.Fatalf("unexpected Pulse abnormal EOF lifecycle: %+v", snapshot)
	}
}

func TestM4PulseStalledTTLSAuthenticationCancellation(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	certificate, roots := createM2GPPeerCertificate(t, m4PulseHostname)
	peer := newM4PulseLifecyclePeer(t, certificate, m4PulseLifecycleAuthenticationCancellation)
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
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-peer.authenticationBlocked:
	case peerErr := <-peer.failures:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for stalled Pulse EAP-TTLS authentication"))
	}
	closeResult := make(chan error, 1)
	go func() {
		closeResult <- client.Close()
	}()
	closeTimer := time.NewTimer(2 * time.Second)
	defer closeTimer.Stop()
	select {
	case err = <-closeResult:
		if err != nil {
			t.Fatal(err)
		}
	case peerErr := <-peer.failures:
		t.Fatal(peerErr)
	case <-closeTimer.C:
		cancel()
		t.Fatal("Client.Close blocked during stalled Pulse EAP-TTLS authentication")
	}
	select {
	case <-peer.authenticationClosed:
	case peerErr := <-peer.failures:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for stalled Pulse authentication connection close"))
	}
	select {
	case peerErr := <-peer.failures:
		t.Fatal(peerErr)
	case <-peer.done:
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for stalled Pulse authentication peer shutdown"))
	}
	snapshot := peer.snapshot()
	if snapshot.upgradeCount != 1 || snapshot.fullAuthCount != 0 || snapshot.reconnectCount != 0 ||
		snapshot.gracefulCount != 0 || snapshot.logoutCount != 0 {
		t.Fatalf("unexpected stalled Pulse authentication lifecycle: %+v", snapshot)
	}
}

func newM4PulseLifecyclePeer(
	t *testing.T,
	certificate tls.Certificate,
	scenario m4PulseLifecycleScenario,
) *m4PulseLifecyclePeer {
	t.Helper()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(E.Cause(err, "listen for independent Pulse lifecycle peer"))
	}
	tcpAddress, loaded := listener.Addr().(*net.TCPAddr)
	if !loaded {
		_ = listener.Close()
		t.Fatal("Pulse lifecycle listener has no TCP address")
	}
	peer := &m4PulseLifecyclePeer{
		listener:              listener,
		port:                  uint16(tcpAddress.Port),
		scenario:              scenario,
		failures:              make(chan error, 1),
		done:                  make(chan struct{}),
		initialConfigured:     make(chan struct{}),
		abortInitial:          make(chan struct{}),
		initialAborted:        make(chan struct{}),
		authenticationBlocked: make(chan struct{}),
		authenticationClosed:  make(chan struct{}),
	}
	go peer.serve()
	return peer
}

func (p *m4PulseLifecyclePeer) serve() {
	defer close(p.done)
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if !E.IsClosed(err) {
				p.report(E.Cause(err, "accept independent Pulse lifecycle connection"))
			}
			return
		}
		keepServing, exchangeErr := p.exchange(conn)
		_ = conn.Close()
		if exchangeErr != nil {
			p.report(exchangeErr)
			return
		}
		if !keepServing {
			return
		}
	}
}

func (p *m4PulseLifecyclePeer) exchange(conn net.Conn) (bool, error) {
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return false, E.Cause(err, "read independent Pulse lifecycle HTTP request")
	}
	if request.URL.Path == "/dana-na/auth/logout.cgi" {
		return p.exchangeLogout(conn, request)
	}
	if request.Method != http.MethodGet || request.URL.Path != "/" || request.Header.Get("Content-Type") != "EAP" ||
		request.Header.Get("Upgrade") != "IF-T/TLS 1.0" || request.ContentLength != 0 {
		return false, E.New("independent Pulse lifecycle peer received invalid HTTP upgrade")
	}
	p.access.Lock()
	p.upgradeCount++
	upgradeCount := p.upgradeCount
	p.access.Unlock()
	switch p.scenario {
	case m4PulseLifecycleReconnectFallback:
		switch upgradeCount {
		case 1:
			if strings.Contains(request.Header.Get("Cookie"), "DSID=") {
				return false, E.New("initial Pulse authentication unexpectedly sent a DSID cookie")
			}
			return p.exchangeFullAuthentication(conn, reader, m4PulseLifecycleInitialCookie, true)
		case 2:
			return p.exchangeRejectedReconnect(conn, reader, request)
		case 3:
			if strings.Contains(request.Header.Get("Cookie"), "DSID=") {
				return false, E.New("fresh Pulse authentication retained the rejected DSID cookie")
			}
			return p.exchangeFullAuthentication(conn, reader, m4PulseLifecycleFinalCookie, false)
		default:
			return false, E.New("independent Pulse lifecycle peer received an extra upgrade")
		}
	case m4PulseLifecycleAbnormalLogout:
		if upgradeCount != 1 {
			return false, E.New("Pulse abnormal EOF scenario unexpectedly reconnected")
		}
		return p.exchangeFullAuthentication(conn, reader, m4PulseLifecycleInitialCookie, true)
	case m4PulseLifecycleAuthenticationCancellation:
		if upgradeCount != 1 {
			return false, E.New("stalled Pulse authentication unexpectedly reconnected")
		}
		return p.exchangeStalledTTLSAuthentication(conn, reader)
	default:
		return false, E.New("unknown Pulse lifecycle peer scenario")
	}
}

func (p *m4PulseLifecyclePeer) exchangeFullAuthentication(
	conn net.Conn,
	reader *bufio.Reader,
	cookie string,
	abortAfterConfiguration bool,
) (bool, error) {
	clientAttributes, err := p.exchangeAuthenticationPreamble(conn, reader)
	if err != nil {
		return false, err
	}
	if len(m4PulseAVPValue(clientAttributes, 0xd53, m4PulseVendorJuniper2)) != 0 {
		return false, E.New("full Pulse authentication unexpectedly included a reconnect cookie AVP")
	}
	passwordInner := buildM4PulseEAP(1, 7, 0xfe, 2, []byte{1})
	passwordAttribute := appendM4PulseAVP(nil, 79, 0, passwordInner)
	passwordRequest := buildM4PulseEAP(1, 4, 0xfe, 1, passwordAttribute)
	err = writeM4PulseAuthentication(conn, 3, passwordRequest, false)
	if err != nil {
		return false, err
	}
	frame, err := readM4PulseFrame(reader)
	if err != nil {
		return false, err
	}
	credentialResponse, err := parseM4PulseAuthenticationEAP(frame, 2)
	if err != nil {
		return false, err
	}
	credentialAttributes, err := parseM4PulseAVPs(credentialResponse[12:])
	if err != nil {
		return false, err
	}
	if string(m4PulseAVPValue(credentialAttributes, 0xd6d, m4PulseVendorJuniper2)) != m4PulseUsername {
		return false, E.New("Pulse lifecycle peer received incorrect username")
	}
	passwordEAP := m4PulseAVPValue(credentialAttributes, 79, 0)
	if len(passwordEAP) < 15 || passwordEAP[12] != 2 || passwordEAP[13] != 2 {
		return false, E.New("Pulse lifecycle peer received malformed password EAP")
	}
	passwordLength := int(passwordEAP[14])
	if passwordLength < 2 || 13+passwordLength > len(passwordEAP) || string(passwordEAP[15:13+passwordLength]) != m4PulsePassword {
		return false, E.New("Pulse lifecycle peer received incorrect password")
	}
	cookieAttributes := appendM4PulseAVP(nil, 0xd53, m4PulseVendorJuniper2, []byte(cookie))
	cookieRequest := buildM4PulseEAP(1, 5, 0xfe, 1, cookieAttributes)
	err = writeM4PulseAuthentication(conn, 4, cookieRequest, false)
	if err != nil {
		return false, err
	}
	frame, err = readM4PulseFrame(reader)
	if err != nil {
		return false, err
	}
	finalResponse, err := parseM4PulseAuthenticationEAP(frame, 2)
	if err != nil || len(finalResponse) != 12 {
		return false, E.New("Pulse lifecycle peer did not receive its cookie acknowledgement")
	}
	var authType [4]byte
	binary.BigEndian.PutUint32(authType[:], m4PulseAuthJuniper)
	successPayload := append(authType[:0:0], authType[:]...)
	successPayload = append(successPayload, 3, 5, 0, 4)
	err = writeM4PulseFrame(conn, m4PulseVendorTCG, 7, 5, successPayload, false)
	if err != nil {
		return false, err
	}
	err = writeM4PulseFrame(conn, m4PulseVendorJuniper, 1, 6, buildM4PulseMainConfiguration(), false)
	if err != nil {
		return false, err
	}
	err = writeM4PulseFrame(conn, m4PulseVendorJuniper, 0x8f, 7, []byte{0, 0, 0, 0}, false)
	if err != nil {
		return false, err
	}
	p.access.Lock()
	p.fullAuthCount++
	p.access.Unlock()
	if abortAfterConfiguration {
		close(p.initialConfigured)
		<-p.abortInitial
		err = abortM4PulseTLSConnection(conn)
		close(p.initialAborted)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	for {
		frame, err = readM4PulseFrame(reader)
		if err != nil {
			if E.IsClosed(err) {
				break
			}
			return false, err
		}
		if frame.vendor != m4PulseVendorJuniper || frame.frameType != 0x89 || len(frame.payload) != 0 {
			return false, E.New("Pulse lifecycle peer received an invalid final close frame")
		}
		p.access.Lock()
		p.gracefulCount++
		p.access.Unlock()
	}
	return false, nil
}

func (p *m4PulseLifecyclePeer) exchangeAuthenticationPreamble(
	conn net.Conn,
	reader *bufio.Reader,
) ([]m4PulseAVP, error) {
	err := p.exchangeOuterIdentity(conn, reader)
	if err != nil {
		return nil, err
	}
	serverInformation := buildM4PulseEAP(1, 3, 0xfe, 1, nil)
	err = writeM4PulseAuthentication(conn, 2, serverInformation, false)
	if err != nil {
		return nil, err
	}
	frame, err := readM4PulseFrame(reader)
	if err != nil {
		return nil, err
	}
	clientInformation, err := parseM4PulseAuthenticationEAP(frame, 2)
	if err != nil {
		return nil, err
	}
	attributes, err := parseM4PulseAVPs(clientInformation[12:])
	if err != nil {
		return nil, err
	}
	if string(m4PulseAVPValue(attributes, 0xd5e, m4PulseVendorJuniper2)) != "Linux" ||
		!strings.HasPrefix(string(m4PulseAVPValue(attributes, 0xd70, m4PulseVendorJuniper2)), "Pulse-Secure/") {
		return nil, E.New("Pulse lifecycle peer received invalid platform AVPs")
	}
	return attributes, nil
}

func (p *m4PulseLifecyclePeer) exchangeOuterIdentity(conn net.Conn, reader *bufio.Reader) error {
	err := writeM4PulseBytes(conn, []byte("HTTP/1.1 101 Switching Protocols\r\n\r\n"))
	if err != nil {
		return err
	}
	frame, err := readM4PulseFrame(reader)
	if err != nil {
		return err
	}
	if frame.vendor != m4PulseVendorTCG || frame.frameType != 1 || !bytes.Equal(frame.payload, []byte{0, 1, 2, 2}) {
		return E.New("Pulse lifecycle peer received invalid version request")
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
		!bytes.Contains(frame.payload, []byte("clientCapabilities={}")) {
		return E.New("Pulse lifecycle peer received invalid client information")
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
		return E.New("Pulse lifecycle peer received invalid anonymous identity")
	}
	return nil
}

func (p *m4PulseLifecyclePeer) exchangeStalledTTLSAuthentication(
	conn net.Conn,
	reader *bufio.Reader,
) (bool, error) {
	err := p.exchangeOuterIdentity(conn, reader)
	if err != nil {
		return false, err
	}
	ttlsRequest := buildM4PulseEAP(1, 9, 0x15, 0, []byte{0x20})
	err = writeM4PulseAuthentication(conn, 2, ttlsRequest, false)
	if err != nil {
		return false, err
	}
	frame, err := readM4PulseFrame(reader)
	if err != nil {
		return false, err
	}
	ttlsResponse, err := parseM4PulseAuthenticationEAP(frame, 2)
	if err != nil {
		return false, err
	}
	if len(ttlsResponse) < 7 || ttlsResponse[4] != 0x15 || ttlsResponse[5] != 0 || ttlsResponse[6] != 0x16 {
		return false, E.New("Pulse client did not begin an inner EAP-TTLS handshake")
	}
	close(p.authenticationBlocked)
	_, err = reader.ReadByte()
	if err == nil {
		return false, E.New("Pulse client sent unexpected data while EAP-TTLS authentication was stalled")
	}
	if !E.IsClosed(err) {
		return false, E.Cause(err, "observe stalled Pulse EAP-TTLS connection close")
	}
	close(p.authenticationClosed)
	return false, nil
}

func (p *m4PulseLifecyclePeer) exchangeRejectedReconnect(
	conn net.Conn,
	reader *bufio.Reader,
	request *http.Request,
) (bool, error) {
	if !strings.Contains(request.Header.Get("Cookie"), "DSID="+m4PulseLifecycleInitialCookie) {
		return false, E.New("Pulse cookie reconnect omitted the DSID HTTP cookie")
	}
	clientAttributes, err := p.exchangeAuthenticationPreamble(conn, reader)
	if err != nil {
		return false, err
	}
	if string(m4PulseAVPValue(clientAttributes, 0xd53, m4PulseVendorJuniper2)) != m4PulseLifecycleInitialCookie {
		return false, E.New("Pulse cookie reconnect omitted the DSID authentication AVP")
	}
	var failureCode [4]byte
	binary.BigEndian.PutUint32(failureCode[:], 1)
	failureAttributes := appendM4PulseAVP(nil, 0xd60, m4PulseVendorJuniper2, failureCode[:])
	failureRequest := buildM4PulseEAP(1, 4, 0xfe, 1, failureAttributes)
	err = writeM4PulseAuthentication(conn, 3, failureRequest, false)
	if err != nil {
		return false, err
	}
	p.access.Lock()
	p.reconnectCount++
	p.access.Unlock()
	return true, nil
}

func (p *m4PulseLifecyclePeer) exchangeLogout(conn net.Conn, request *http.Request) (bool, error) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" ||
		!strings.Contains(request.Header.Get("Cookie"), "DSID="+m4PulseLifecycleInitialCookie) {
		return false, E.New("independent Pulse lifecycle peer received invalid HTTPS logout")
	}
	p.access.Lock()
	p.logoutCount++
	p.access.Unlock()
	err := writeM4PulseBytes(conn, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
	if err != nil {
		return false, err
	}
	return p.scenario == m4PulseLifecycleReconnectFallback, nil
}

func abortM4PulseTLSConnection(conn net.Conn) error {
	tlsConnection, loaded := conn.(*tls.Conn)
	if !loaded {
		return E.New("Pulse lifecycle peer connection is not TLS")
	}
	tcpConnection, loaded := tlsConnection.NetConn().(*net.TCPConn)
	if !loaded {
		return E.New("Pulse lifecycle TLS connection is not TCP")
	}
	err := tcpConnection.SetLinger(0)
	if err != nil {
		return E.Cause(err, "configure Pulse lifecycle abortive close")
	}
	err = tcpConnection.Close()
	if err != nil && !E.IsClosed(err) {
		return E.Cause(err, "abort Pulse lifecycle TLS connection")
	}
	return nil
}

func waitM4PulseLifecycleEvent(
	t *testing.T,
	ctx context.Context,
	peer *m4PulseLifecyclePeer,
	client *openconnect.Client,
	events <-chan openconnect.TunnelConfigurationEvent,
	wanted openconnect.TunnelConfigurationEventReason,
) {
	t.Helper()
	for {
		select {
		case event := <-events:
			if event.Reason == wanted {
				if !client.Ready() {
					t.Fatal("Pulse configuration event was published before the session became ready")
				}
				if client.TunnelConfiguration().MTU != event.Configuration.MTU {
					t.Fatal("Pulse configuration event was published before its public configuration")
				}
				return
			}
		case peerErr := <-peer.failures:
			t.Fatal(peerErr)
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for Pulse lifecycle configuration event: ", wanted))
		}
	}
}

func (p *m4PulseLifecyclePeer) snapshot() m4PulseLifecycleSnapshot {
	p.access.Lock()
	defer p.access.Unlock()
	return m4PulseLifecycleSnapshot{
		upgradeCount:   p.upgradeCount,
		fullAuthCount:  p.fullAuthCount,
		reconnectCount: p.reconnectCount,
		gracefulCount:  p.gracefulCount,
		logoutCount:    p.logoutCount,
	}
}

func (p *m4PulseLifecyclePeer) report(err error) {
	select {
	case p.failures <- err:
	default:
	}
}

func (p *m4PulseLifecyclePeer) Close() {
	p.close.Do(func() {
		_ = p.listener.Close()
		select {
		case <-p.abortInitial:
		default:
			close(p.abortInitial)
		}
	})
}

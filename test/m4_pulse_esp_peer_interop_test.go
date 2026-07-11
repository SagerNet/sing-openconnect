package test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	m4PulseESPAssignedIPv4 = "192.0.2.60"
	m4PulseESPServerIPv4   = "198.51.100.60"
	m4PulseESPAssignedIPv6 = "2001:db8:60::10"
	m4PulseESPServerIPv6   = "2001:db8:60::20"
)

type m4PulseESPScenario struct {
	name             string
	endpointIPv6     bool
	crossFamily      bool
	replayProtection bool
	rekey            bool
	invalidLZO       bool
}

type m4PulseESPControlKind uint8

const (
	m4PulseESPControlLicense m4PulseESPControlKind = iota + 1
	m4PulseESPControlRekey
	m4PulseESPControlInvalidRekeyHeader
	m4PulseESPControlInvalidRekeyKeys
	m4PulseESPControlFatal
)

type m4PulseESPControl struct {
	kind   m4PulseESPControlKind
	result chan error
}

type m4PulseESPFrameResult struct {
	frame m4PulseFrame
	err   error
}

type m4PulseESPKeyMaterial struct {
	serverSPI               uint32
	serverEncryptionKey     []byte
	serverAuthenticationKey []byte
	clientSPI               uint32
	clientEncryptionKey     []byte
	clientAuthenticationKey []byte
}

type m4PulseESPPeer struct {
	ctx            context.Context
	listener       net.Listener
	port           uint16
	scenario       m4PulseESPScenario
	oracleBinary   string
	relay          *m4PulseESPRelay
	failures       chan error
	done           chan struct{}
	controls       chan m4PulseESPControl
	tlsPackets     chan []byte
	configured     chan struct{}
	close          sync.Once
	access         sync.Mutex
	oracle         *m4PulseESPOracle
	connection     net.Conn
	serverSequence uint32
	gracefulCount  int
	logoutCount    int
}

type m4PulseESPOracle struct {
	command       *exec.Cmd
	waitResult    <-chan error
	lines         chan string
	standardError m4PulseUpstreamLog
	stop          sync.Once
}

type m4PulseESPRelay struct {
	ctx             context.Context
	cancel          context.CancelFunc
	conn            *net.UDPConn
	port            uint16
	failures        chan error
	done            chan struct{}
	access          sync.Mutex
	oracleAddress   *net.UDPAddr
	oracleHistory   []*net.UDPAddr
	clientAddress   *net.UDPAddr
	enabled         bool
	clientPaused    bool
	serverDatagrams uint64
	clientDatagrams []time.Time
	heldDatagrams   [][]byte
	holdServerCount int
	heldServer      []byte
}

type m4PulseESPDialer struct {
	hostname         string
	tlsAddress       M.Socksaddr
	udpPort          uint16
	failNextUDPWrite atomic.Bool
	udpDialCount     atomic.Uint64
}

type m4PulseFailingUDPConn struct {
	net.Conn
	dialer *m4PulseESPDialer
}

func TestM4PulseIndependentESPLifecycle(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	buildContext, cancelBuild := context.WithTimeout(context.Background(), 30*time.Second)
	oracleBinary := buildM4PulseESPOracle(t, buildContext)
	cancelBuild()
	testCases := []m4PulseESPScenario{
		{name: "ipv4-retry-lzo-rekey-fatal", replayProtection: true, rekey: true, invalidLZO: true},
		{name: "ipv6-same-family-replay-disabled-close", endpointIPv6: true},
		{name: "cross-family-close", crossFamily: true, replayProtection: true},
	}
	for i := range testCases {
		testCase := testCases[i]
		t.Run(testCase.name, func(caseTest *testing.T) {
			caseTest.Parallel()
			runM4PulseESPScenario(caseTest, oracleBinary, testCase)
		})
	}
}

func runM4PulseESPScenario(
	t *testing.T,
	oracleBinary string,
	scenario m4PulseESPScenario,
) {
	t.Helper()
	caseContext, cancelCase := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancelCase()
	certificate, roots := createM2GPPeerCertificate(t, m4PulseHostname)
	relay := newM4PulseESPRelay(t, caseContext)
	defer relay.Close()
	peer := newM4PulseESPPeer(t, caseContext, certificate, relay, oracleBinary, scenario)
	defer peer.Close()
	peerAddress := "127.0.0.1"
	if scenario.endpointIPv6 {
		peerAddress = "::1"
	}
	dialer := &m4PulseESPDialer{
		hostname:   m4PulseHostname,
		tlsAddress: M.ParseSocksaddrHostPort(peerAddress, peer.port),
		udpPort:    relay.port,
	}
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context:    caseContext,
		Server:     net.JoinHostPort(m4PulseHostname, strconv.Itoa(int(peer.port))),
		Flavor:     openconnect.FlavorPulse,
		Username:   m4PulseUsername,
		Password:   m4PulsePassword,
		ReportedOS: "linux-64",
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
		}},
		Dialer: dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	activeTransportUpdated := client.ActiveTransportUpdated()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	waitM4PulseESPReady(t, caseContext, client, peer, relay, dialer)
	waitForActiveTransportUpdate(t, caseContext, client, activeTransportUpdated, openconnect.TransportIFT)
	configuration := client.TunnelConfiguration()
	if configuration.MTU != 1400 {
		t.Fatalf("unexpected Pulse ESP MTU: %d", configuration.MTU)
	}
	ipv4TLS := buildIPv4ICMPEchoRequest(
		t,
		netip.MustParseAddr(m4PulseESPAssignedIPv4),
		netip.MustParseAddr(m4PulseESPServerIPv4),
		0x4d34,
		1,
		[]byte("pulse-tls-ipv4"),
	)
	exchangeM4PulseExactTLS(t, caseContext, client, peer, ipv4TLS)
	ipv6TLS := buildM2GPIPv6ICMPEchoRequest(
		t,
		netip.MustParseAddr(m4PulseESPAssignedIPv6),
		netip.MustParseAddr(m4PulseESPServerIPv6),
		0x4d34,
		2,
		[]byte("pulse-tls-ipv6"),
	)
	exchangeM4PulseExactTLS(t, caseContext, client, peer, ipv6TLS)
	clientDatagrams, _ := relay.DatagramSnapshot()
	if len(clientDatagrams) == 0 || time.Until(clientDatagrams[len(clientDatagrams)-1].Add(time.Second)) < 800*time.Millisecond {
		t.Fatal("Pulse type-0x96 trigger test did not start far enough ahead of the next periodic probe")
	}
	activeTransportUpdated = client.ActiveTransportUpdated()
	relay.Enable()
	triggerStarted := time.Now()
	err = peer.Control(m4PulseESPControlLicense)
	if err != nil {
		t.Fatal(err)
	}
	waitM4PulseRelayClientDatagrams(t, caseContext, peer, relay, len(clientDatagrams)+1, 700*time.Millisecond)
	if time.Since(triggerStarted) > 700*time.Millisecond {
		t.Fatal("Pulse type-0x96 did not trigger an immediate sleeping ESP probe")
	}
	waitM4PulseOracleLine(t, caseContext, peer, "CONTINUATION ")
	expectedProbeHeader := "PROBE 4"
	if scenario.endpointIPv6 {
		expectedProbeHeader = "PROBE 41"
	}
	waitM4PulseOracleLine(t, caseContext, peer, expectedProbeHeader)
	peer.DrainTLSPackets()
	ipv4Sequence := uint16(10)
	if scenario.endpointIPv6 && !scenario.crossFamily {
		ipv4Fallback := buildIPv4ICMPEchoRequest(
			t,
			netip.MustParseAddr(m4PulseESPAssignedIPv4),
			netip.MustParseAddr(m4PulseESPServerIPv4),
			0x4d34,
			10,
			[]byte("pulse-ipv6-endpoint-ipv4-fallback"),
		)
		exchangeM4PulseExactTLS(t, caseContext, client, peer, ipv4Fallback)
		exchangeM4PulseIPv6ESP(t, caseContext, client, peer, scenario.replayProtection, 11)
	} else {
		waitM4PulseIPv4ESP(t, caseContext, client, peer, scenario.replayProtection, &ipv4Sequence)
		if scenario.crossFamily {
			exchangeM4PulseIPv6ESP(t, caseContext, client, peer, scenario.replayProtection, 11)
		} else {
			ipv6Fallback := buildM2GPIPv6ICMPEchoRequest(
				t,
				netip.MustParseAddr(m4PulseESPAssignedIPv6),
				netip.MustParseAddr(m4PulseESPServerIPv6),
				0x4d34,
				12,
				[]byte("pulse-no-4024"),
			)
			exchangeM4PulseExactTLS(t, caseContext, client, peer, ipv6Fallback)
		}
	}
	waitForActiveTransportUpdate(t, caseContext, client, activeTransportUpdated, openconnect.TransportESP)
	if scenario.invalidLZO {
		for _, invalidKind := range []string{"malformed", "trailing", "oversize"} {
			payload := []byte("pulse-lzo-" + invalidKind)
			exchangeM4PulseIPv4ESP(t, caseContext, client, peer, scenario.replayProtection, &ipv4Sequence, payload, false)
			waitM4PulseOracleLine(t, caseContext, peer, "INJECTED LZO "+invalidKind)
		}
	}
	clientDatagrams, _ = relay.DatagramSnapshot()
	err = peer.Control(m4PulseESPControlLicense)
	if err != nil {
		t.Fatal(err)
	}
	assertM4PulseNoRelayClientDatagram(t, caseContext, peer, relay, len(clientDatagrams), 350*time.Millisecond)
	if !scenario.rekey {
		err = client.Close()
		if err != nil {
			t.Fatal(err)
		}
		peer.Wait(t, caseContext)
		gracefulCount, logoutCount := peer.CloseCounts()
		if gracefulCount != 1 || logoutCount != 0 {
			t.Fatalf("unexpected Pulse ESP graceful close counts: graceful=%d logout=%d", gracefulCount, logoutCount)
		}
		return
	}
	activeTransportUpdated = client.ActiveTransportUpdated()
	dialer.failNextUDPWrite.Store(true)
	failedESPRequest := buildIPv4ICMPEchoRequest(
		t,
		netip.MustParseAddr(m4PulseESPAssignedIPv4),
		netip.MustParseAddr(m4PulseESPServerIPv4),
		0x4d34,
		13,
		[]byte("pulse-esp-write-failure"),
	)
	exchangeM4PulseExactTLS(t, caseContext, client, peer, failedESPRequest)
	if dialer.failNextUDPWrite.Load() {
		t.Fatal("Pulse ESP write-failure injection was not consumed")
	}
	waitForActiveTransportUpdate(t, caseContext, client, activeTransportUpdated, openconnect.TransportIFT)
	activeTransportUpdated = client.ActiveTransportUpdated()
	waitM4PulseOracleLine(t, caseContext, peer, "CONTINUATION ")
	if dialer.udpDialCount.Load() < 2 {
		t.Fatal("Pulse ESP transport failure did not open a replacement UDP socket")
	}
	waitM4PulseIPv4ESP(t, caseContext, client, peer, true, &ipv4Sequence)
	waitForActiveTransportUpdate(t, caseContext, client, activeTransportUpdated, openconnect.TransportESP)
	overlapSequence := ipv4Sequence
	ipv4Sequence++
	overlapPayload := []byte("pulse-old-sa-overlap")
	overlapRequest := buildIPv4ICMPEchoRequest(
		t,
		netip.MustParseAddr(m4PulseESPAssignedIPv4),
		netip.MustParseAddr(m4PulseESPServerIPv4),
		0x4d34,
		overlapSequence,
		overlapPayload,
	)
	relay.HoldNextServerDatagrams(2)
	err = client.WriteDataPacket(overlapRequest)
	if err != nil {
		t.Fatal(err)
	}
	overlapDatagram := waitM4PulseHeldServerDatagram(t, caseContext, peer, relay)
	dialsBeforeRekey := dialer.udpDialCount.Load()
	err = peer.Control(m4PulseESPControlRekey)
	if err != nil {
		t.Fatal(err)
	}
	if dialer.udpDialCount.Load() != dialsBeforeRekey {
		t.Fatal("Pulse ESP type-1 rekey replaced its established UDP socket")
	}
	exchangeM4PulseIPv4ESP(
		t,
		caseContext,
		client,
		peer,
		true,
		&ipv4Sequence,
		[]byte("pulse-new-sa-first-data"),
		false,
	)
	waitM4PulseOracleLine(t, caseContext, peer, "DATA 4 0")
	relay.Inject(t, overlapDatagram)
	overlapContext, cancelOverlap := context.WithTimeout(caseContext, 3*time.Second)
	overlapReply, err := client.ReadDataPacket(overlapContext)
	cancelOverlap()
	if err != nil {
		t.Fatal(E.Cause(err, "read previous Pulse ESP inbound SA overlap"))
	}
	err = validateIPv4ICMPEchoReply(
		overlapReply,
		netip.MustParseAddr(m4PulseESPAssignedIPv4),
		netip.MustParseAddr(m4PulseESPServerIPv4),
		0x4d34,
		overlapSequence,
		overlapPayload,
	)
	if err != nil {
		t.Fatal(E.Cause(err, "validate previous Pulse ESP inbound SA overlap"))
	}
	err = peer.Control(m4PulseESPControlInvalidRekeyHeader)
	if err != nil {
		t.Fatal(err)
	}
	readM4PulseESPBarrier(t, caseContext, client)
	exchangeM4PulseIPv4ESP(t, caseContext, client, peer, true, &ipv4Sequence, []byte("pulse-outer-invalid-kept-sa"), false)
	activeTransportUpdated = client.ActiveTransportUpdated()
	err = peer.Control(m4PulseESPControlInvalidRekeyKeys)
	if err != nil {
		t.Fatal(err)
	}
	readM4PulseESPBarrier(t, caseContext, client)
	innerFailurePacket := buildIPv4ICMPEchoRequest(
		t,
		netip.MustParseAddr(m4PulseESPAssignedIPv4),
		netip.MustParseAddr(m4PulseESPServerIPv4),
		0x4d34,
		ipv4Sequence,
		[]byte("pulse-inner-rekey-failure-tls"),
	)
	exchangeM4PulseExactTLS(t, caseContext, client, peer, innerFailurePacket)
	waitForActiveTransportUpdate(t, caseContext, client, activeTransportUpdated, openconnect.TransportIFT)
	err = peer.Control(m4PulseESPControlFatal)
	if err != nil {
		t.Fatal(err)
	}
	terminalContext, cancelTerminal := context.WithTimeout(caseContext, 5*time.Second)
	_, terminalErr := client.ReadDataPacket(terminalContext)
	cancelTerminal()
	if terminalErr == nil || !strings.Contains(terminalErr.Error(), "Pulse fatal error 7") {
		t.Fatal("Pulse type-0x93 frame did not terminate the session: ", terminalErr)
	}
	peer.Wait(t, caseContext)
	gracefulCount, logoutCount := peer.CloseCounts()
	if gracefulCount != 0 || logoutCount != 1 {
		t.Fatalf("unexpected Pulse ESP fatal close counts: graceful=%d logout=%d", gracefulCount, logoutCount)
	}
}

func buildM4PulseESPOracle(t *testing.T, ctx context.Context) string {
	t.Helper()
	flagsOutput, err := exec.CommandContext(ctx, "pkg-config", "--cflags", "--libs", "openssl", "lzo2").CombinedOutput()
	if err != nil {
		t.Fatal(E.Cause(err, "query OpenSSL/liblzo2 flags for Pulse ESP oracle: ", strings.TrimSpace(string(flagsOutput))))
	}
	includeOutput, err := exec.CommandContext(ctx, "pkg-config", "--variable=includedir", "lzo2").CombinedOutput()
	if err != nil {
		t.Fatal(E.Cause(err, "query liblzo2 include directory for Pulse ESP oracle: ", strings.TrimSpace(string(includeOutput))))
	}
	binaryPath := filepath.Join(t.TempDir(), "pulse-esp-peer")
	arguments := []string{
		"-std=c11",
		"-Wall",
		"-Wextra",
		"-Werror",
		"-I" + strings.TrimSpace(string(includeOutput)),
		filepath.Join("testdata", "pulse-esp-peer", "esp_peer.c"),
		"-o",
		binaryPath,
	}
	arguments = append(arguments, strings.Fields(string(flagsOutput))...)
	output, err := exec.CommandContext(ctx, "cc", arguments...).CombinedOutput()
	if err != nil {
		t.Fatal(E.Cause(err, "build Pulse ESP oracle: ", strings.TrimSpace(string(output))))
	}
	return binaryPath
}

func newM4PulseESPRelay(t *testing.T, ctx context.Context) *m4PulseESPRelay {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(E.Cause(err, "listen for Pulse ESP relay"))
	}
	udpAddress, loaded := conn.LocalAddr().(*net.UDPAddr)
	if !loaded || udpAddress.Port <= 0 || udpAddress.Port > 65535 {
		_ = conn.Close()
		t.Fatal("Pulse ESP relay has no usable UDP port")
	}
	relayContext, cancel := context.WithCancel(ctx)
	relay := &m4PulseESPRelay{
		ctx:      relayContext,
		cancel:   cancel,
		conn:     conn,
		port:     uint16(udpAddress.Port),
		failures: make(chan error, 1),
		done:     make(chan struct{}),
	}
	go relay.run()
	return relay
}

func (r *m4PulseESPRelay) run() {
	defer close(r.done)
	buffer := make([]byte, 65536)
	for {
		n, sourceAddress, err := r.conn.ReadFromUDP(buffer)
		if err != nil {
			if r.ctx.Err() == nil && !E.IsClosed(err) {
				r.report(E.Cause(err, "read Pulse ESP relay datagram"))
			}
			return
		}
		datagram := append([]byte(nil), buffer[:n]...)
		r.access.Lock()
		oracleAddress := cloneM4PulseUDPAddress(r.oracleAddress)
		clientAddress := cloneM4PulseUDPAddress(r.clientAddress)
		enabled := r.enabled
		fromOracle := false
		for _, knownOracleAddress := range r.oracleHistory {
			if sourceAddress.IP.Equal(knownOracleAddress.IP) && sourceAddress.Port == knownOracleAddress.Port {
				fromOracle = true
				break
			}
		}
		clientPaused := r.clientPaused
		holdServer := false
		if fromOracle {
			r.serverDatagrams++
			if r.holdServerCount > 0 {
				holdServer = true
				r.holdServerCount--
				if len(r.heldServer) == 0 {
					r.heldServer = append([]byte(nil), datagram...)
				}
			}
		} else {
			r.clientAddress = cloneM4PulseUDPAddress(sourceAddress)
			clientAddress = cloneM4PulseUDPAddress(sourceAddress)
			r.clientDatagrams = append(r.clientDatagrams, time.Now())
			if clientPaused {
				r.heldDatagrams = append(r.heldDatagrams, datagram)
			}
		}
		r.access.Unlock()
		if !enabled || !fromOracle && clientPaused || fromOracle && holdServer {
			continue
		}
		if fromOracle {
			if clientAddress != nil {
				_, err = r.conn.WriteToUDP(datagram, clientAddress)
			}
		} else if oracleAddress != nil {
			_, err = r.conn.WriteToUDP(datagram, oracleAddress)
		}
		if err != nil && r.ctx.Err() == nil {
			r.report(E.Cause(err, "forward Pulse ESP relay datagram"))
			return
		}
	}
}

func (r *m4PulseESPRelay) SetOracle(address *net.UDPAddr) {
	r.access.Lock()
	r.oracleAddress = cloneM4PulseUDPAddress(address)
	r.oracleHistory = append(r.oracleHistory, cloneM4PulseUDPAddress(address))
	r.access.Unlock()
}

func (r *m4PulseESPRelay) Enable() {
	r.access.Lock()
	r.enabled = true
	r.access.Unlock()
}

func (r *m4PulseESPRelay) PauseClient() {
	r.access.Lock()
	r.clientPaused = true
	r.access.Unlock()
}

func (r *m4PulseESPRelay) ResumeClient() error {
	r.access.Lock()
	r.clientPaused = false
	oracleAddress := cloneM4PulseUDPAddress(r.oracleAddress)
	heldDatagrams := r.heldDatagrams
	r.heldDatagrams = nil
	r.access.Unlock()
	if oracleAddress == nil && len(heldDatagrams) > 0 {
		return E.New("Pulse ESP relay has no oracle for held datagrams")
	}
	for _, datagram := range heldDatagrams {
		_, err := r.conn.WriteToUDP(datagram, oracleAddress)
		if err != nil {
			return E.Cause(err, "release held Pulse ESP datagram")
		}
	}
	return nil
}

func (r *m4PulseESPRelay) DatagramSnapshot() ([]time.Time, uint64) {
	r.access.Lock()
	defer r.access.Unlock()
	return append([]time.Time(nil), r.clientDatagrams...), r.serverDatagrams
}

func (r *m4PulseESPRelay) HoldNextServerDatagrams(count int) {
	r.access.Lock()
	r.holdServerCount = count
	r.heldServer = nil
	r.access.Unlock()
}

func (r *m4PulseESPRelay) HeldServerDatagram() ([]byte, int) {
	r.access.Lock()
	defer r.access.Unlock()
	return append([]byte(nil), r.heldServer...), r.holdServerCount
}

func (r *m4PulseESPRelay) Inject(t *testing.T, datagram []byte) {
	t.Helper()
	r.access.Lock()
	clientAddress := cloneM4PulseUDPAddress(r.clientAddress)
	r.access.Unlock()
	if clientAddress == nil {
		t.Fatal("Pulse ESP relay has no client address for stale injection")
	}
	_, err := r.conn.WriteToUDP(datagram, clientAddress)
	if err != nil {
		t.Fatal(E.Cause(err, "inject stale Pulse ESP datagram"))
	}
}

func (r *m4PulseESPRelay) report(err error) {
	select {
	case r.failures <- err:
	default:
	}
}

func (r *m4PulseESPRelay) Close() {
	r.cancel()
	_ = r.conn.Close()
	<-r.done
}

func cloneM4PulseUDPAddress(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}

func (d *m4PulseESPDialer) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		if destination.Port != d.tlsAddress.Port || (destination.Fqdn != d.hostname && destination.Addr != d.tlsAddress.Addr) {
			return nil, E.New("unexpected Pulse ESP TLS dial destination: ", destination)
		}
		return N.SystemDialer.DialContext(ctx, network, d.tlsAddress)
	case N.NetworkUDP:
		if destination.Port != d.udpPort || destination.Addr != d.tlsAddress.Addr {
			return nil, E.New("unexpected Pulse ESP UDP dial destination: ", destination)
		}
		conn, err := N.SystemDialer.DialContext(ctx, network, M.ParseSocksaddrHostPort("127.0.0.1", d.udpPort))
		if err != nil {
			return nil, err
		}
		d.udpDialCount.Add(1)
		return &m4PulseFailingUDPConn{Conn: conn, dialer: d}, nil
	default:
		return nil, E.New("unexpected Pulse ESP dial network: ", network)
	}
}

func (d *m4PulseESPDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

func (c *m4PulseFailingUDPConn) Write(content []byte) (int, error) {
	if c.dialer.failNextUDPWrite.CompareAndSwap(true, false) {
		return 0, syscall.ENOBUFS
	}
	return c.Conn.Write(content)
}

var _ N.Dialer = (*m4PulseESPDialer)(nil)

func newM4PulseESPPeer(
	t *testing.T,
	ctx context.Context,
	certificate tls.Certificate,
	relay *m4PulseESPRelay,
	oracleBinary string,
	scenario m4PulseESPScenario,
) *m4PulseESPPeer {
	t.Helper()
	listenerNetwork := "tcp4"
	listenerAddress := "127.0.0.1:0"
	if scenario.endpointIPv6 {
		listenerNetwork = "tcp6"
		listenerAddress = "[::1]:0"
	}
	listener, err := tls.Listen(listenerNetwork, listenerAddress, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(E.Cause(err, "listen for independent Pulse ESP peer"))
	}
	tcpAddress, loaded := listener.Addr().(*net.TCPAddr)
	if !loaded {
		_ = listener.Close()
		t.Fatal("Pulse ESP listener has no TCP address")
	}
	peer := &m4PulseESPPeer{
		ctx:          ctx,
		listener:     listener,
		port:         uint16(tcpAddress.Port),
		scenario:     scenario,
		oracleBinary: oracleBinary,
		relay:        relay,
		failures:     make(chan error, 1),
		done:         make(chan struct{}),
		controls:     make(chan m4PulseESPControl),
		tlsPackets:   make(chan []byte, 32),
		configured:   make(chan struct{}),
	}
	go peer.serve()
	return peer
}

func (p *m4PulseESPPeer) serve() {
	defer close(p.done)
	defer p.stopOracle()
	tunnelHandled := false
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if p.ctx.Err() == nil && !E.IsClosed(err) {
				p.report(E.Cause(err, "accept independent Pulse ESP connection"))
			}
			return
		}
		p.access.Lock()
		p.connection = conn
		p.access.Unlock()
		keepServing, exchangeErr := p.exchange(conn, tunnelHandled)
		_ = conn.Close()
		p.access.Lock()
		if p.connection == conn {
			p.connection = nil
		}
		p.access.Unlock()
		if exchangeErr != nil {
			p.report(exchangeErr)
			return
		}
		if !tunnelHandled {
			tunnelHandled = true
		}
		if !keepServing {
			return
		}
	}
}

func (p *m4PulseESPPeer) exchange(conn net.Conn, tunnelHandled bool) (bool, error) {
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return false, E.Cause(err, "read independent Pulse ESP HTTP request")
	}
	if request.URL.Path == "/dana-na/auth/logout.cgi" {
		if !tunnelHandled || request.Method != http.MethodGet || !strings.Contains(request.Header.Get("Cookie"), "DSID=") {
			return false, E.New("independent Pulse ESP peer received invalid HTTPS logout")
		}
		p.access.Lock()
		p.logoutCount++
		p.access.Unlock()
		err = writeM4PulseBytes(conn, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return false, err
	}
	if tunnelHandled || request.Method != http.MethodGet || request.URL.Path != "/" ||
		request.Header.Get("Upgrade") != "IF-T/TLS 1.0" {
		return false, E.New("independent Pulse ESP peer received invalid tunnel upgrade")
	}
	err = writeM4PulseBytes(conn, []byte("HTTP/1.1 101 Switching Protocols\r\n\r\n"))
	if err != nil {
		return false, err
	}
	_, err = exchangeM4PulseFormPreamble(conn, reader)
	if err != nil {
		return false, err
	}
	err = exchangeM4PulseFormPassword(conn, reader, 3, 4)
	if err != nil {
		return false, err
	}
	cookieAttributes := appendM4PulseAVP(nil, 0xd53, m4PulseVendorJuniper2, []byte("pulse-esp-cookie-0123456789"))
	responseAttributes, err := exchangeM4PulseFormChallenge(conn, reader, 4, 5, cookieAttributes)
	if err != nil {
		return false, err
	}
	if len(responseAttributes) != 0 {
		return false, E.New("Pulse ESP peer received non-empty cookie acknowledgement")
	}
	var authType [4]byte
	binary.BigEndian.PutUint32(authType[:], m4PulseAuthJuniper)
	successPayload := append(authType[:0:0], authType[:]...)
	successPayload = append(successPayload, 3, 5, 0, 4)
	p.serverSequence = 4
	err = p.writeFrame(conn, m4PulseVendorTCG, 7, successPayload)
	if err != nil {
		return false, err
	}
	initialKeys := newM4PulseESPServerKeys(1)
	err = p.writeFrame(conn, m4PulseVendorJuniper, 1, buildM4PulseESPMainConfiguration(p.relay.port, p.scenario))
	if err != nil {
		return false, err
	}
	err = p.writeFrame(conn, m4PulseVendorJuniper, 1, buildM4PulseESPKeyConfiguration(initialKeys))
	if err != nil {
		return false, err
	}
	frame, err := readM4PulseFrame(reader)
	if err != nil {
		return false, err
	}
	initialKeys, err = parseM4PulseESPClientResponse(frame, initialKeys)
	if err != nil {
		return false, err
	}
	frame, err = readM4PulseFrame(reader)
	if err != nil {
		return false, err
	}
	if frame.vendor != m4PulseVendorJuniper || frame.frameType != 5 || !bytes.Equal(frame.payload, []byte{'n', 'c', 'm', 'o', '=', '1', '\n', 0}) {
		return false, E.New("Pulse ESP peer received invalid ncmo enable frame")
	}
	err = p.replaceOracle(initialKeys, "continuation")
	if err != nil {
		return false, err
	}
	err = p.writeFrame(conn, m4PulseVendorJuniper, 0x8f, []byte{0, 0, 0, 0})
	if err != nil {
		return false, err
	}
	close(p.configured)
	return p.runTunnel(conn, reader)
}

func (p *m4PulseESPPeer) runTunnel(conn net.Conn, reader *bufio.Reader) (bool, error) {
	frames := make(chan m4PulseESPFrameResult, 1)
	go func() {
		for {
			frame, err := readM4PulseFrame(reader)
			frames <- m4PulseESPFrameResult{frame: frame, err: err}
			if err != nil {
				return
			}
		}
	}()
	for {
		select {
		case <-p.ctx.Done():
			return false, nil
		case control := <-p.controls:
			switch control.kind {
			case m4PulseESPControlLicense:
				control.result <- p.writeFrame(conn, m4PulseVendorJuniper, 0x96, []byte("license"))
			case m4PulseESPControlRekey:
				control.result <- p.exchangeRekey(conn, frames)
			case m4PulseESPControlInvalidRekeyHeader:
				payload := buildM4PulseESPKeyConfiguration(newM4PulseESPServerKeys(1))
				binary.BigEndian.PutUint32(payload[16:20], 0x21202401)
				err := p.writeFrame(conn, m4PulseVendorJuniper, 1, payload)
				if err == nil {
					err = p.writeFrame(conn, m4PulseVendorJuniper, 4, m4PulseESPBarrierPacket())
				}
				control.result <- err
			case m4PulseESPControlInvalidRekeyKeys:
				keys := newM4PulseESPServerKeys(1)
				keys.serverSPI = 0
				err := p.writeFrame(conn, m4PulseVendorJuniper, 1, buildM4PulseESPKeyConfiguration(keys))
				if err == nil {
					err = p.writeFrame(conn, m4PulseVendorJuniper, 4, m4PulseESPBarrierPacket())
				}
				control.result <- err
			case m4PulseESPControlFatal:
				err := p.writeFrame(conn, m4PulseVendorJuniper, 0x93, []byte("errorType=7 errorString=session%20terminated\n"))
				control.result <- err
				return true, err
			default:
				control.result <- E.New("unknown Pulse ESP peer control")
			}
		case frameResult := <-frames:
			if frameResult.err != nil {
				if E.IsClosed(frameResult.err) {
					return false, nil
				}
				return false, frameResult.err
			}
			frame := frameResult.frame
			switch {
			case frame.vendor == m4PulseVendorJuniper && frame.frameType == 4:
				packet := append([]byte(nil), frame.payload...)
				select {
				case p.tlsPackets <- packet:
				default:
					return false, E.New("Pulse ESP peer TLS packet observation queue overflow")
				}
				err := p.writeFrame(conn, m4PulseVendorJuniper, 4, packet)
				if err != nil {
					return false, err
				}
			case frame.vendor == m4PulseVendorJuniper && frame.frameType == 0x89 && len(frame.payload) == 0:
				p.access.Lock()
				p.gracefulCount++
				p.access.Unlock()
				return false, nil
			default:
				return false, E.New("Pulse ESP peer received unexpected tunnel frame")
			}
		}
	}
}

func (p *m4PulseESPPeer) exchangeRekey(
	conn net.Conn,
	frames <-chan m4PulseESPFrameResult,
) error {
	p.relay.PauseClient()
	rekeyKeys := newM4PulseESPServerKeys(2)
	err := p.writeFrame(conn, m4PulseVendorJuniper, 1, buildM4PulseESPKeyConfiguration(rekeyKeys))
	if err != nil {
		return E.Errors(err, p.relay.ResumeClient())
	}
	select {
	case <-p.ctx.Done():
		return E.Errors(p.ctx.Err(), p.relay.ResumeClient())
	case frameResult := <-frames:
		if frameResult.err != nil {
			return E.Errors(frameResult.err, p.relay.ResumeClient())
		}
		rekeyKeys, err = parseM4PulseESPClientResponse(frameResult.frame, rekeyKeys)
		if err != nil {
			return E.Errors(err, p.relay.ResumeClient())
		}
	}
	err = p.replaceOracle(rekeyKeys, "zero-established")
	return E.Errors(err, p.relay.ResumeClient())
}

func (p *m4PulseESPPeer) writeFrame(conn net.Conn, vendor uint32, frameType uint32, payload []byte) error {
	p.serverSequence++
	return writeM4PulseFrame(conn, vendor, frameType, p.serverSequence, payload, false)
}

func newM4PulseESPServerKeys(generation int) m4PulseESPKeyMaterial {
	keys := m4PulseESPKeyMaterial{}
	switch generation {
	case 1:
		keys.serverSPI = 0x12345678
		keys.serverEncryptionKey = bytes.Repeat([]byte{0x11}, 16)
		keys.serverAuthenticationKey = bytes.Repeat([]byte{0x22}, 20)
	case 2:
		keys.serverSPI = 0x23456789
		keys.serverEncryptionKey = bytes.Repeat([]byte{0x55}, 16)
		keys.serverAuthenticationKey = bytes.Repeat([]byte{0x66}, 20)
	default:
		panic("unexpected Pulse ESP key generation")
	}
	return keys
}

func buildM4PulseESPMainConfiguration(port uint16, scenario m4PulseESPScenario) []byte {
	routing := []byte{0x2e, 0, 0, 8, 0, 0, 0, 0}
	attributes := make([]byte, 8)
	binary.BigEndian.PutUint32(attributes[4:8], 0x03000000)
	attributes = appendM4PulseAttribute(attributes, 0x0001, netip.MustParseAddr(m4PulseESPAssignedIPv4).AsSlice())
	attributes = appendM4PulseAttribute(attributes, 0x0002, netip.MustParseAddr("255.255.255.0").AsSlice())
	assignedIPv6 := netip.MustParseAddr(m4PulseESPAssignedIPv6).As16()
	attributes = appendM4PulseAttribute(attributes, 0x0008, append(assignedIPv6[:], 64))
	var algorithm [2]byte
	binary.BigEndian.PutUint16(algorithm[:], 2)
	attributes = appendM4PulseAttribute(attributes, 0x4010, algorithm[:])
	attributes = appendM4PulseAttribute(attributes, 0x4011, algorithm[:])
	var replay [4]byte
	if scenario.replayProtection {
		binary.BigEndian.PutUint32(replay[:], 1)
	}
	attributes = appendM4PulseAttribute(attributes, 0x4014, replay[:])
	var portContent [2]byte
	binary.BigEndian.PutUint16(portContent[:], port)
	attributes = appendM4PulseAttribute(attributes, 0x4016, portContent[:])
	var fallback [4]byte
	binary.BigEndian.PutUint32(fallback[:], 1)
	attributes = appendM4PulseAttribute(attributes, 0x4017, fallback[:])
	if scenario.crossFamily {
		attributes = appendM4PulseAttribute(attributes, 0x4024, []byte{1})
	}
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

func buildM4PulseESPKeyConfiguration(keys m4PulseESPKeyMaterial) []byte {
	payload := make([]byte, 106)
	binary.BigEndian.PutUint32(payload[16:20], 0x21202400)
	binary.BigEndian.PutUint32(payload[24:28], uint32(len(payload)))
	binary.BigEndian.PutUint32(payload[28:32], uint32(len(payload)-28))
	binary.BigEndian.PutUint32(payload[32:36], 0x01000000)
	binary.LittleEndian.PutUint32(payload[36:40], keys.serverSPI)
	binary.BigEndian.PutUint16(payload[40:42], 64)
	copy(payload[42:58], keys.serverEncryptionKey)
	copy(payload[58:78], keys.serverAuthenticationKey)
	return payload
}

func parseM4PulseESPClientResponse(
	frame m4PulseFrame,
	serverKeys m4PulseESPKeyMaterial,
) (m4PulseESPKeyMaterial, error) {
	payload := frame.payload
	if frame.vendor != m4PulseVendorJuniper || frame.frameType != 1 || len(payload) != 176 ||
		!bytes.Equal(payload[:16], make([]byte, 16)) || binary.BigEndian.Uint32(payload[16:20]) != 0x21202400 ||
		binary.BigEndian.Uint32(payload[20:24]) != 0 || binary.BigEndian.Uint32(payload[24:28]) != uint32(len(payload)) ||
		binary.BigEndian.Uint32(payload[28:32]) != uint32(len(payload)-28) ||
		binary.BigEndian.Uint32(payload[32:36]) != 0x01000000 || binary.BigEndian.Uint16(payload[40:42]) != 64 {
		return m4PulseESPKeyMaterial{}, E.New("invalid independent Pulse ESP key response")
	}
	serverConfiguration := buildM4PulseESPKeyConfiguration(serverKeys)
	if !bytes.Equal(payload[106:], serverConfiguration[36:]) {
		return m4PulseESPKeyMaterial{}, E.New("Pulse ESP key response did not copy the server key block")
	}
	serverKeys.clientSPI = binary.LittleEndian.Uint32(payload[36:40])
	serverKeys.clientEncryptionKey = append([]byte(nil), payload[42:58]...)
	serverKeys.clientAuthenticationKey = append([]byte(nil), payload[58:78]...)
	if serverKeys.clientSPI == 0 {
		return m4PulseESPKeyMaterial{}, E.New("Pulse ESP key response used a zero client SPI")
	}
	return serverKeys, nil
}

func (p *m4PulseESPPeer) replaceOracle(keys m4PulseESPKeyMaterial, initialSequence string) error {
	oracle, err := p.startOracle(keys, initialSequence)
	if err != nil {
		return err
	}
	p.access.Lock()
	previousOracle := p.oracle
	p.oracle = oracle
	p.access.Unlock()
	if previousOracle != nil {
		previousOracle.Stop()
	}
	return nil
}

func (p *m4PulseESPPeer) startOracle(
	keys m4PulseESPKeyMaterial,
	initialSequence string,
) (*m4PulseESPOracle, error) {
	oracle := &m4PulseESPOracle{lines: make(chan string, 32)}
	expectedProbe := "probe4"
	if p.scenario.endpointIPv6 {
		expectedProbe = "probe41"
	}
	command := exec.CommandContext(
		p.ctx,
		p.oracleBinary,
		"0",
		"aes-128-cbc",
		"sha1",
		strconv.FormatUint(uint64(keys.serverSPI), 10),
		strconv.FormatUint(uint64(keys.clientSPI), 10),
		hex.EncodeToString(keys.serverEncryptionKey),
		hex.EncodeToString(keys.serverAuthenticationKey),
		hex.EncodeToString(keys.clientEncryptionKey),
		hex.EncodeToString(keys.clientAuthenticationKey),
		initialSequence,
		expectedProbe,
	)
	command.Stderr = &oracle.standardError
	standardOutput, err := command.StdoutPipe()
	if err != nil {
		return nil, E.Cause(err, "open Pulse ESP oracle stdout")
	}
	err = command.Start()
	if err != nil {
		return nil, E.Cause(err, "start Pulse ESP oracle")
	}
	waitResult := make(chan error, 1)
	go func() {
		waitResult <- command.Wait()
	}()
	oracle.command = command
	oracle.waitResult = waitResult
	scanner := bufio.NewScanner(standardOutput)
	if !scanner.Scan() {
		oracle.Stop()
		return nil, E.New("Pulse ESP oracle exited before readiness: ", oracle.standardError.String())
	}
	readyFields := strings.Fields(scanner.Text())
	if len(readyFields) != 2 || readyFields[0] != "READY" {
		oracle.Stop()
		return nil, E.New("invalid Pulse ESP oracle readiness: ", scanner.Text())
	}
	portValue, err := strconv.ParseUint(readyFields[1], 10, 16)
	if err != nil || portValue == 0 {
		oracle.Stop()
		return nil, E.New("invalid Pulse ESP oracle port: ", readyFields[1])
	}
	p.relay.SetOracle(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(portValue)})
	go func() {
		defer close(oracle.lines)
		for scanner.Scan() {
			select {
			case oracle.lines <- scanner.Text():
			case <-p.ctx.Done():
				return
			}
		}
		scannerErr := scanner.Err()
		if scannerErr != nil && p.ctx.Err() == nil {
			p.report(E.Cause(scannerErr, "read Pulse ESP oracle output"))
		}
	}()
	return oracle, nil
}

func (o *m4PulseESPOracle) Stop() {
	o.stop.Do(func() {
		if o.command.Process != nil {
			_ = o.command.Process.Kill()
		}
		<-o.waitResult
	})
}

func (p *m4PulseESPPeer) stopOracle() {
	p.access.Lock()
	oracle := p.oracle
	p.oracle = nil
	p.access.Unlock()
	if oracle != nil {
		oracle.Stop()
	}
}

func (p *m4PulseESPPeer) Control(kind m4PulseESPControlKind) error {
	control := m4PulseESPControl{kind: kind, result: make(chan error, 1)}
	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	case peerErr := <-p.failures:
		return peerErr
	case p.controls <- control:
	}
	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	case peerErr := <-p.failures:
		return peerErr
	case err := <-control.result:
		return err
	}
}

func (p *m4PulseESPPeer) DrainTLSPackets() {
	for {
		select {
		case <-p.tlsPackets:
		default:
			return
		}
	}
}

func (p *m4PulseESPPeer) Wait(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case peerErr := <-p.failures:
		t.Fatal(peerErr)
	case relayErr := <-p.relay.failures:
		t.Fatal(relayErr)
	case <-p.done:
		select {
		case peerErr := <-p.failures:
			t.Fatal(peerErr)
		case relayErr := <-p.relay.failures:
			t.Fatal(relayErr)
		default:
		}
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for independent Pulse ESP peer"))
	}
}

func (p *m4PulseESPPeer) CloseCounts() (int, int) {
	p.access.Lock()
	defer p.access.Unlock()
	return p.gracefulCount, p.logoutCount
}

func (p *m4PulseESPPeer) report(err error) {
	select {
	case p.failures <- err:
	default:
	}
}

func (p *m4PulseESPPeer) Close() {
	p.close.Do(func() {
		_ = p.listener.Close()
		p.access.Lock()
		connection := p.connection
		p.access.Unlock()
		if connection != nil {
			_ = connection.Close()
		}
		p.stopOracle()
	})
}

func waitM4PulseESPReady(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	peer *m4PulseESPPeer,
	relay *m4PulseESPRelay,
	dialer *m4PulseESPDialer,
) {
	t.Helper()
	for !client.Ready() {
		select {
		case peerErr := <-peer.failures:
			t.Fatal(peerErr)
		case relayErr := <-relay.failures:
			t.Fatal(relayErr)
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for immediate Pulse IF-T/TLS readiness"))
		case <-time.After(10 * time.Millisecond):
		}
	}
	select {
	case <-peer.configured:
	case peerErr := <-peer.failures:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for Pulse ESP configuration"))
	}
	var datagramTimes []time.Time
	var serverDatagrams uint64
	for {
		datagramTimes, serverDatagrams = relay.DatagramSnapshot()
		if len(datagramTimes) >= 6 {
			break
		}
		select {
		case peerErr := <-peer.failures:
			t.Fatal(peerErr)
		case relayErr := <-relay.failures:
			t.Fatal(relayErr)
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for Pulse ESP probe retry"))
		case <-time.After(10 * time.Millisecond):
		}
	}
	if len(datagramTimes) != 6 {
		t.Fatalf("Pulse ESP sent more than five initial probes before retry: %d", len(datagramTimes))
	}
	if serverDatagrams != 0 {
		t.Fatalf("Pulse ESP relay observed a server datagram while disabled: %d", serverDatagrams)
	}
	if dialer.udpDialCount.Load() != 1 {
		t.Fatalf("Pulse ESP periodic probe retry unexpectedly replaced its UDP socket: %d dials", dialer.udpDialCount.Load())
	}
	for i := 1; i < 5; i++ {
		interval := datagramTimes[i].Sub(datagramTimes[i-1])
		if interval < 700*time.Millisecond || interval > 1600*time.Millisecond {
			t.Fatalf("Pulse ESP initial probe interval %d was %s", i, interval)
		}
	}
	retryInterval := datagramTimes[5].Sub(datagramTimes[4])
	if retryInterval < 1600*time.Millisecond || retryInterval > 5*time.Second {
		t.Fatalf("Pulse ESP periodic retry followed the fifth probe after %s", retryInterval)
	}
}

func exchangeM4PulseExactTLS(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	peer *m4PulseESPPeer,
	packet []byte,
) {
	t.Helper()
	err := client.WriteDataPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case observedPacket := <-peer.tlsPackets:
		if !bytes.Equal(observedPacket, packet) {
			t.Fatalf("Pulse IF-T/TLS peer observed an unexpected packet: %x", observedPacket)
		}
	case peerErr := <-peer.failures:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for Pulse IF-T/TLS peer packet"))
	}
	readContext, cancelRead := context.WithTimeout(ctx, 3*time.Second)
	receivedPacket, err := client.ReadDataPacket(readContext)
	cancelRead()
	if err != nil {
		t.Fatal(E.Cause(err, "read exact Pulse IF-T/TLS echo"))
	}
	if !bytes.Equal(receivedPacket, packet) {
		t.Fatalf("unexpected Pulse IF-T/TLS echo: %x", receivedPacket)
	}
}

func waitM4PulseIPv4ESP(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	peer *m4PulseESPPeer,
	replayProtection bool,
	sequence *uint16,
) {
	t.Helper()
	exchangeM4PulseIPv4ESP(
		t,
		ctx,
		client,
		peer,
		replayProtection,
		sequence,
		[]byte("pulse-esp-ipv4"),
		true,
	)
}

func exchangeM4PulseIPv4ESP(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	peer *m4PulseESPPeer,
	replayProtection bool,
	sequence *uint16,
	payload []byte,
	allowTLSRetry bool,
) {
	t.Helper()
	clientAddress := netip.MustParseAddr(m4PulseESPAssignedIPv4)
	serverAddress := netip.MustParseAddr(m4PulseESPServerIPv4)
	for attempt := 0; attempt < 20; attempt++ {
		currentSequence := *sequence
		*sequence++
		request := buildIPv4ICMPEchoRequest(t, clientAddress, serverAddress, 0x4d34, currentSequence, payload)
		err := client.WriteDataPacket(request)
		if err != nil {
			t.Fatal(err)
		}
		readContext, cancelRead := context.WithTimeout(ctx, 3*time.Second)
		reply, readErr := client.ReadDataPacket(readContext)
		cancelRead()
		if readErr != nil {
			t.Fatal(E.Cause(readErr, "read Pulse IPv4 ESP echo"))
		}
		if bytes.Equal(reply, request) {
			if !allowTLSRetry {
				t.Fatal("Pulse IPv4 packet unexpectedly fell back to IF-T/TLS")
			}
			select {
			case observedPacket := <-peer.tlsPackets:
				if !bytes.Equal(observedPacket, request) {
					t.Fatalf("Pulse IF-T/TLS fallback observed an unexpected packet: %x", observedPacket)
				}
			case peerErr := <-peer.failures:
				t.Fatal(peerErr)
			case <-ctx.Done():
				t.Fatal(E.Cause(ctx.Err(), "wait for Pulse IPv4 IF-T/TLS fallback observation"))
			}
			select {
			case <-ctx.Done():
				t.Fatal(E.Cause(ctx.Err(), "wait for Pulse ESP readiness"))
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		err = validateIPv4ICMPEchoReply(reply, clientAddress, serverAddress, 0x4d34, currentSequence, payload)
		if err != nil {
			t.Fatal(E.Cause(err, "validate Pulse IPv4 ESP echo"))
		}
		assertM4PulseESPDuplicate(t, ctx, client, reply, replayProtection)
		return
	}
	datagramTimes, serverDatagrams := peer.relay.DatagramSnapshot()
	peer.access.Lock()
	oracle := peer.oracle
	peer.access.Unlock()
	oracleError := ""
	if oracle != nil {
		oracleError = oracle.standardError.String()
	}
	t.Fatalf(
		"Pulse IPv4 ESP did not establish before retry limit: client-datagrams=%d server-datagrams=%d oracle=%s",
		len(datagramTimes),
		serverDatagrams,
		oracleError,
	)
}

func exchangeM4PulseIPv6ESP(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	peer *m4PulseESPPeer,
	replayProtection bool,
	sequence uint16,
) {
	t.Helper()
	payload := []byte("pulse-esp-ipv6")
	clientAddress := netip.MustParseAddr(m4PulseESPAssignedIPv6)
	serverAddress := netip.MustParseAddr(m4PulseESPServerIPv6)
	request := buildM2GPIPv6ICMPEchoRequest(t, clientAddress, serverAddress, 0x4d34, sequence, payload)
	err := client.WriteDataPacket(request)
	if err != nil {
		t.Fatal(err)
	}
	readContext, cancelRead := context.WithTimeout(ctx, 3*time.Second)
	reply, err := client.ReadDataPacket(readContext)
	cancelRead()
	if err != nil {
		t.Fatal(E.Cause(err, "read Pulse IPv6 ESP echo"))
	}
	if bytes.Equal(reply, request) {
		select {
		case observedPacket := <-peer.tlsPackets:
			if !bytes.Equal(observedPacket, request) {
				t.Fatalf("Pulse IPv6 IF-T/TLS fallback observed an unexpected packet: %x", observedPacket)
			}
		default:
		}
		t.Fatal("Pulse cross-family IPv6 packet unexpectedly fell back to IF-T/TLS")
	}
	err = validateM2GPIPv6ICMPEchoReply(reply, clientAddress, serverAddress, 0x4d34, sequence, payload)
	if err != nil {
		t.Fatal(E.Cause(err, "validate Pulse IPv6 ESP echo"))
	}
	assertM4PulseESPDuplicate(t, ctx, client, reply, replayProtection)
}

func assertM4PulseESPDuplicate(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	firstReply []byte,
	replayProtection bool,
) {
	t.Helper()
	duplicateContext, cancelDuplicate := context.WithTimeout(ctx, 250*time.Millisecond)
	duplicate, err := client.ReadDataPacket(duplicateContext)
	cancelDuplicate()
	if replayProtection {
		if err == nil {
			t.Fatalf("Pulse ESP replay protection delivered a duplicate: %x", duplicate)
		}
		if !E.IsCanceled(err) {
			t.Fatal(E.Cause(err, "wait for Pulse ESP duplicate suppression"))
		}
		return
	}
	if err != nil {
		t.Fatal(E.Cause(err, "read Pulse ESP duplicate with replay protection disabled"))
	}
	if !bytes.Equal(duplicate, firstReply) {
		t.Fatalf("Pulse ESP duplicate differed from its first datagram: %x", duplicate)
	}
}

func waitM4PulseRelayClientDatagrams(
	t *testing.T,
	ctx context.Context,
	peer *m4PulseESPPeer,
	relay *m4PulseESPRelay,
	wantedCount int,
	maximumWait time.Duration,
) {
	t.Helper()
	waitContext, cancelWait := context.WithTimeout(ctx, maximumWait)
	defer cancelWait()
	for {
		datagramTimes, _ := relay.DatagramSnapshot()
		if len(datagramTimes) >= wantedCount {
			return
		}
		select {
		case peerErr := <-peer.failures:
			t.Fatal(peerErr)
		case relayErr := <-relay.failures:
			t.Fatal(relayErr)
		case <-waitContext.Done():
			t.Fatal(E.Cause(waitContext.Err(), "wait for immediate Pulse ESP probe"))
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func assertM4PulseNoRelayClientDatagram(
	t *testing.T,
	ctx context.Context,
	peer *m4PulseESPPeer,
	relay *m4PulseESPRelay,
	expectedCount int,
	duration time.Duration,
) {
	t.Helper()
	waitContext, cancelWait := context.WithTimeout(ctx, duration)
	defer cancelWait()
	for {
		datagramTimes, _ := relay.DatagramSnapshot()
		if len(datagramTimes) != expectedCount {
			t.Fatalf("established Pulse ESP type-0x96 triggered a probe: before=%d after=%d", expectedCount, len(datagramTimes))
		}
		select {
		case peerErr := <-peer.failures:
			t.Fatal(peerErr)
		case relayErr := <-relay.failures:
			t.Fatal(relayErr)
		case <-waitContext.Done():
			return
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func waitM4PulseHeldServerDatagram(
	t *testing.T,
	ctx context.Context,
	peer *m4PulseESPPeer,
	relay *m4PulseESPRelay,
) []byte {
	t.Helper()
	for {
		datagram, remaining := relay.HeldServerDatagram()
		if len(datagram) > 0 && remaining == 0 {
			return datagram
		}
		select {
		case peerErr := <-peer.failures:
			t.Fatal(peerErr)
		case relayErr := <-relay.failures:
			t.Fatal(relayErr)
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for held previous Pulse ESP inbound SA datagram"))
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func m4PulseESPBarrierPacket() []byte {
	return []byte{
		0x45, 0, 0, 20, 0, 1, 0, 0, 64, 59, 0, 0,
		198, 51, 100, 60, 192, 0, 2, 60,
	}
}

func readM4PulseESPBarrier(t *testing.T, ctx context.Context, client *openconnect.Client) {
	t.Helper()
	readContext, cancelRead := context.WithTimeout(ctx, 3*time.Second)
	packet, err := client.ReadDataPacket(readContext)
	cancelRead()
	if err != nil {
		t.Fatal(E.Cause(err, "read Pulse ESP rekey processing barrier"))
	}
	if !bytes.Equal(packet, m4PulseESPBarrierPacket()) {
		t.Fatalf("unexpected Pulse ESP rekey processing barrier: %x", packet)
	}
}

func waitM4PulseOracleLine(t *testing.T, ctx context.Context, peer *m4PulseESPPeer, expectedPrefix string) {
	t.Helper()
	peer.access.Lock()
	oracle := peer.oracle
	peer.access.Unlock()
	if oracle == nil {
		t.Fatal("Pulse ESP peer has no oracle output")
	}
	for {
		select {
		case line, open := <-oracle.lines:
			if !open {
				t.Fatal("Pulse ESP oracle exited before expected output: " + oracle.standardError.String())
			}
			if strings.HasPrefix(line, expectedPrefix) {
				return
			}
		case peerErr := <-peer.failures:
			t.Fatal(peerErr)
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for Pulse ESP oracle output: ", expectedPrefix))
		}
	}
}

package test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5" //nolint:gosec // The GlobalProtect peer contract uses MD5 only as a correlation identifier.
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	m2GPHostname        = "m2-gateway.test"
	m2GPUsername        = "m2 user"
	m2GPPassword        = "m2-password"
	m2GPPortal          = "m2-portal"
	m2GPDomain          = "m2-domain"
	m2GPAssignedIPv4    = "192.0.2.10"
	m2GPAssignedIPv6    = "2001:db8:1::10"
	m2GPServerIPv4      = "198.51.100.77"
	m2GPSessionCookie   = "M2GPSession"
	m2GPMaximumBodySize = 16 * 1024 * 1024
	m2GPUDPCloseFailure = "injected GlobalProtect ESP UDP close failure"
)

type m2GPPeerScenario struct {
	portal                bool
	serverByIP            bool
	hipNeeded             []bool
	loginStatus           int
	configurationStatus   int
	tunnelRejections      int
	closeFirstGPSTOnData  bool
	esp                   *m2GPESPParameters
	omitIPSecMode         bool
	rekeySeconds          int
	decoy                 bool
	validateBuiltInHIP    bool
	expectedWrapperReport string
	hipRedirect           string
	periodicHIPGate       <-chan struct{}
	periodicHIPStarted    chan<- struct{}
}

type m2GPESPParameters struct {
	port                    uint16
	encryption              string
	authentication          string
	clientSPI               string
	serverSPI               string
	clientEncryptionKey     string
	clientAuthenticationKey string
	serverEncryptionKey     string
	serverAuthenticationKey string
	magicIPv6               bool
	responseMode            string
}

type m2GPESPOracle struct {
	command *exec.Cmd
	stderr  bytes.Buffer
}

type m2GPPeer struct {
	ctx               context.Context
	cancel            context.CancelFunc
	hostname          string
	authority         string
	rootCAs           *x509.CertPool
	listener          net.Listener
	address           M.Socksaddr
	scenario          m2GPPeerScenario
	failures          chan error
	tunnelStarted     chan time.Time
	access            sync.Mutex
	connections       map[net.Conn]struct{}
	waitGroup         sync.WaitGroup
	loginCount        int
	getConfigCount    int
	hipCheckCount     int
	hipReportCount    int
	tunnelCount       int
	logoutCount       int
	gpstDataCount     int
	gpstDPDCount      int
	getConfigAt       time.Time
	tunnelAt          time.Time
	computer          string
	opaqueQuery       string
	sessionCookie     string
	assignedIPv4      string
	assignedIPv6      string
	getConfigBodies   []string
	hipCheckTimes     []time.Time
	tunnelStartTimes  []time.Time
	tunnelCloseTimes  []time.Time
	decoyRequestCount int
	afterLogin        func()
}

type m2GPWireRequest struct {
	method     string
	target     string
	path       string
	rawQuery   string
	header     textproto.MIMEHeader
	body       []byte
	serverName string
	receivedAt time.Time
}

type m2GPWireResponse struct {
	statusCode int
	header     textproto.MIMEHeader
	body       []byte
}

type m2GPPeerSnapshot struct {
	loginCount        int
	getConfigCount    int
	hipCheckCount     int
	hipReportCount    int
	tunnelCount       int
	logoutCount       int
	gpstDataCount     int
	gpstDPDCount      int
	opaqueQuery       string
	getConfigAt       time.Time
	tunnelAt          time.Time
	getConfigBodies   []string
	hipCheckTimes     []time.Time
	tunnelStartTimes  []time.Time
	tunnelCloseTimes  []time.Time
	decoyRequestCount int
}

type m2GPHIPReportXML struct {
	XMLName     xml.Name             `xml:"hip-report"`
	MD5         string               `xml:"md5-sum"`
	UserName    string               `xml:"user-name"`
	Domain      string               `xml:"domain"`
	HostName    string               `xml:"host-name"`
	HostID      string               `xml:"host-id"`
	IPAddress   string               `xml:"ip-address"`
	IPv6Address string               `xml:"ipv6-address"`
	Version     int                  `xml:"hip-report-version"`
	Categories  []m2GPHIPCategoryXML `xml:"categories>entry"`
}

type m2GPHIPCategoryXML struct {
	Name                  string                   `xml:"name,attr"`
	ClientVersion         string                   `xml:"client-version"`
	OperatingSystem       string                   `xml:"os"`
	OperatingSystemVendor string                   `xml:"os-vendor"`
	Domain                string                   `xml:"domain"`
	HostName              string                   `xml:"host-name"`
	Interfaces            []m2GPHIPInterfaceXML    `xml:"network-interface>entry"`
	Products              []m2GPHIPProductEntryXML `xml:"list>entry"`
}

type m2GPHIPInterfaceXML struct {
	Name       string `xml:"name,attr"`
	MACAddress string `xml:"mac-address"`
}

type m2GPHIPProductEntryXML struct{}

type m2GPDialer struct {
	hostname             string
	primary              M.Socksaddr
	decoy                M.Socksaddr
	access               sync.Mutex
	switched             bool
	domainDials          int
	pinnedDials          int
	decoyDials           int
	udpDialAt            time.Time
	udpClosedAt          time.Time
	udpDials             int
	udpConn              net.Conn
	udpFailuresRemaining int
	udpFirstAttemptAt    time.Time
	udpCloseFailure      bool
}

type m2GPObservedUDPConn struct {
	net.Conn
	closeOnce    sync.Once
	onClose      func()
	closeFailure bool
}

type m2GPUDPRelay struct {
	ctx                   context.Context
	cancel                context.CancelFunc
	conn                  *net.UDPConn
	oracleAddress         *net.UDPAddr
	port                  uint16
	failures              chan error
	access                sync.Mutex
	clientAddress         *net.UDPAddr
	heldDatagram          []byte
	released              bool
	firstClientDatagramAt time.Time
	clientDatagramCount   int
	waitGroup             sync.WaitGroup
}

func TestM2GlobalProtectGPSTInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	peer := startM2GPPeer(t, ctx, m2GPPeerScenario{})
	dialer := &m2GPDialer{hostname: m2GPHostname, primary: peer.address}
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 4)
	client := newM2GPClient(t, ctx, peer, dialer, openconnect.ClientOptions{
		NoUDP: true,
		OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
			configurationEvents <- event
			return nil
		},
	})
	activeTransportUpdated := client.ActiveTransportUpdated()
	startM2GPClient(t, client)
	waitForM2GPReady(t, ctx, client, peer)
	waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportGPST)
	configurationEvent := waitForM1ConfigurationEvent(t, ctx, configurationEvents)
	if configurationEvent.Reason != openconnect.TunnelConfigurationEventInitial {
		t.Fatalf("unexpected GlobalProtect configuration reason: %s", configurationEvent.Reason)
	}
	configuration := client.TunnelConfiguration()
	assertM2GPTunnelConfiguration(t, configuration, m2GPAssignedIPv4)
	assertM2GPTunnelConfiguration(t, configurationEvent.Configuration, m2GPAssignedIPv4)
	exchangeM2GPGPSTEcho(t, ctx, client, 1, "sing-openconnect-m2-gpst")
	waitForM2GPGPSTDPD(t, ctx, peer)
	exchangeM2GPGPSTEcho(t, ctx, client, 2, "sing-openconnect-m2-gpst-after-dpd")
	snapshot := peer.snapshot()
	if snapshot.loginCount != 1 || snapshot.getConfigCount != 1 || snapshot.hipCheckCount != 1 || snapshot.tunnelCount != 1 || snapshot.gpstDataCount != 2 || snapshot.gpstDPDCount == 0 {
		t.Fatalf("unexpected GPST peer state: %#v", snapshot)
	}
	peer.assertNoFailure(t)

	ipPeer := startM2GPPeer(t, ctx, m2GPPeerScenario{
		serverByIP:         true,
		hipNeeded:          []bool{true},
		validateBuiltInHIP: true,
	})
	ipDialer := &m2GPDialer{hostname: m2GPHostname, primary: ipPeer.address}
	ipClient := newM2GPClient(t, ctx, ipPeer, ipDialer, openconnect.ClientOptions{
		NoUDP: true,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			RootCAs:    ipPeer.rootCAs,
			ServerName: m2GPHostname,
		}},
	})
	startM2GPClient(t, ipClient)
	waitForM2GPReady(t, ctx, ipClient, ipPeer)
	assertM2GPTunnelConfiguration(t, ipClient.TunnelConfiguration(), m2GPAssignedIPv4)
	exchangeM2GPGPSTEcho(t, ctx, ipClient, 3, "sing-openconnect-m2-gpst-explicit-server-name")
	ipSnapshot := ipPeer.snapshot()
	if ipSnapshot.loginCount != 1 || ipSnapshot.getConfigCount != 1 || ipSnapshot.hipCheckCount != 1 || ipSnapshot.hipReportCount != 1 ||
		ipSnapshot.tunnelCount != 1 || ipSnapshot.gpstDataCount != 1 {
		t.Fatalf("unexpected IP-addressed GPST peer state: %#v", ipSnapshot)
	}
	ipPeer.assertNoFailure(t)
}

func TestM2GlobalProtectESPInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	oracleBinary := buildM2GPESPOracle(t, ctx)
	testCases := []struct {
		name            string
		encryption      string
		authentication  string
		magicIPv6       bool
		omitIPSecMode   bool
		udpDialFailures int
		udpCloseFailure bool
	}{
		{name: "aes128-md5-v4-magic-missing-ipsec-mode-transient-udp", encryption: "aes-128-cbc", authentication: "md5", omitIPSecMode: true, udpDialFailures: 1},
		{name: "aes128-sha1-v6-magic", encryption: "aes-128-cbc", authentication: "sha1", magicIPv6: true},
		{name: "aes128-sha256-v4-magic", encryption: "aes-128-cbc", authentication: "sha256"},
		{name: "aes256-md5-v6-magic", encryption: "aes-256-cbc", authentication: "md5", magicIPv6: true},
		{name: "aes256-sha1-v4-magic", encryption: "aes-256-cbc", authentication: "sha1"},
		{name: "aes256-sha256-v6-magic-close-error", encryption: "aes-256-cbc", authentication: "sha256", magicIPv6: true, udpCloseFailure: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			parameters := newM2GPESPParameters(testCase.encryption, testCase.authentication, testCase.magicIPv6)
			startM2GPESPOracle(t, ctx, oracleBinary, &parameters)
			peer := startM2GPPeer(t, ctx, m2GPPeerScenario{esp: &parameters, omitIPSecMode: testCase.omitIPSecMode})
			dialer := &m2GPDialer{
				hostname:             m2GPHostname,
				primary:              peer.address,
				udpFailuresRemaining: testCase.udpDialFailures,
				udpCloseFailure:      testCase.udpCloseFailure,
			}
			client := newM2GPClient(t, ctx, peer, dialer, openconnect.ClientOptions{})
			activeTransportUpdated := client.ActiveTransportUpdated()
			startM2GPClient(t, client)
			waitForM2GPReady(t, ctx, client, peer)
			waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportESP)
			configuration := client.TunnelConfiguration()
			clientIPv4 := firstIPv4Address(t, configuration.Addresses)
			clientIPv6 := firstM2GPIPv6Address(t, configuration.Addresses)
			exchangeM2GPESPEcho(t, ctx, client, buildIPv4ICMPEchoRequest(
				t,
				clientIPv4,
				netip.MustParseAddr(m2GPServerIPv4),
				0x4d32,
				1,
				[]byte("m2-esp-ipv4-"+testCase.name),
			), func(response []byte) error {
				return validateIPv4ICMPEchoReply(
					response,
					clientIPv4,
					netip.MustParseAddr(m2GPServerIPv4),
					0x4d32,
					1,
					[]byte("m2-esp-ipv4-"+testCase.name),
				)
			})
			serverIPv6 := netip.MustParseAddr("2001:db8:2::77")
			ipv6Payload := []byte("m2-esp-ipv6-" + testCase.name)
			exchangeM2GPESPEcho(t, ctx, client, buildM2GPIPv6ICMPEchoRequest(
				t,
				clientIPv6,
				serverIPv6,
				0x4d32,
				2,
				ipv6Payload,
			), func(response []byte) error {
				return validateM2GPIPv6ICMPEchoReply(response, clientIPv6, serverIPv6, 0x4d32, 2, ipv6Payload)
			})
			snapshot := peer.snapshot()
			if snapshot.tunnelCount != 0 || snapshot.gpstDataCount != 0 || snapshot.hipCheckCount != 1 {
				t.Fatalf("ESP session unexpectedly used GPST or skipped HIP: %#v", snapshot)
			}
			if testCase.udpDialFailures > 0 {
				firstAttemptAt, connectedAt := dialer.udpAttemptTimes()
				recoveryDelay := connectedAt.Sub(firstAttemptAt)
				if firstAttemptAt.IsZero() || connectedAt.IsZero() || recoveryDelay < 750*time.Millisecond || recoveryDelay > 2*time.Second {
					t.Fatalf("ESP did not recover from the transient UDP dial failure at the next absolute probe deadline: first=%s connected=%s delay=%s", firstAttemptAt, connectedAt, recoveryDelay)
				}
			}
			peer.assertNoFailure(t)
			if testCase.udpCloseFailure {
				closeErr := client.Close()
				if closeErr == nil || !strings.Contains(closeErr.Error(), m2GPUDPCloseFailure) {
					t.Fatalf("ESP UDP cleanup error did not propagate through Client.Close: %v", closeErr)
				}
			}
		})
	}
}

func TestM2GlobalProtectESPDefaultPolicyInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	oracleBinary := buildM2GPESPOracle(t, ctx)
	parameters := newM2GPESPParameters("aes-128-cbc", "sha1", false)
	parameters.responseMode = "lzo-after-echo"
	startM2GPESPOracle(t, ctx, oracleBinary, &parameters)
	peer := startM2GPPeer(t, ctx, m2GPPeerScenario{esp: &parameters})
	dialer := &m2GPDialer{hostname: m2GPHostname, primary: peer.address}
	client := newM2GPClient(t, ctx, peer, dialer, openconnect.ClientOptions{})
	activeTransportUpdated := client.ActiveTransportUpdated()
	startM2GPClient(t, client)
	waitForM2GPReady(t, ctx, client, peer)
	waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportESP)
	exchangeM2GPESPEcho(t, ctx, client, buildIPv4ICMPEchoRequest(
		t,
		netip.MustParseAddr(m2GPAssignedIPv4),
		netip.MustParseAddr(m2GPServerIPv4),
		0x4d32,
		60,
		[]byte("m2-esp-default-policy-replay"),
	), func(response []byte) error {
		return validateIPv4ICMPEchoReply(
			response,
			netip.MustParseAddr(m2GPAssignedIPv4),
			netip.MustParseAddr(m2GPServerIPv4),
			0x4d32,
			60,
			[]byte("m2-esp-default-policy-replay"),
		)
	})
	err := client.WriteDataPacket(buildIPv4ICMPEchoRequest(
		t,
		netip.MustParseAddr(m2GPAssignedIPv4),
		netip.MustParseAddr(m2GPServerIPv4),
		0x4d32,
		61,
		[]byte("m2-esp-default-policy-lzo"),
	))
	if err != nil {
		t.Fatal(E.Cause(err, "write GlobalProtect ESP request for unsupported LZO response"))
	}
	readContext, cancelRead := context.WithTimeout(ctx, 5*time.Second)
	_, err = client.ReadDataPacket(readContext)
	cancelRead()
	if err == nil || !E.IsMulti(err, openconnect.ErrProtocolNotSupported) || !strings.Contains(err.Error(), "received LZO-compressed ESP payload") {
		t.Fatalf("GlobalProtect accepted LZO or returned a non-specific error: %v", err)
	}
	snapshot := peer.snapshot()
	if snapshot.loginCount != 1 || snapshot.getConfigCount != 1 || snapshot.tunnelCount != 0 {
		t.Fatalf("unsupported GlobalProtect LZO response changed default ESP ownership or fell back to GPST: %#v", snapshot)
	}
	peer.assertNoFailure(t)
}

func TestM2GlobalProtectESPDPDAndSocketFallbackInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	oracleBinary := buildM2GPESPOracle(t, ctx)
	parameters := newM2GPESPParameters("aes-128-cbc", "sha1", false)
	startM2GPESPOracle(t, ctx, oracleBinary, &parameters)
	relay := startM2GPUDPRelay(t, ctx, parameters.port)
	relay.enable()
	parameters.port = relay.port
	peer := startM2GPPeer(t, ctx, m2GPPeerScenario{esp: &parameters})
	dialer := &m2GPDialer{hostname: m2GPHostname, primary: peer.address}
	client := newM2GPClient(t, ctx, peer, dialer, openconnect.ClientOptions{})
	activeTransportUpdated := client.ActiveTransportUpdated()
	startM2GPClient(t, client)
	waitForM2GPReady(t, ctx, client, peer)
	waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportESP)
	initialDatagrams := relay.datagramCount()
	if initialDatagrams == 0 {
		t.Fatal("transparent GlobalProtect ESP relay did not observe the initial magic probe")
	}
	for relay.datagramCount() <= initialDatagrams {
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for periodic GlobalProtect ESP DPD probe"))
		case relayErr := <-relay.failures:
			t.Fatal(relayErr)
		case peerErr := <-peer.failures:
			t.Fatal(peerErr)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !client.Ready() || peer.snapshot().tunnelCount != 0 {
		t.Fatal("periodic ESP DPD did not keep the UDP session active")
	}
	exchangeM2GPESPEcho(t, ctx, client, buildIPv4ICMPEchoRequest(
		t, netip.MustParseAddr(m2GPAssignedIPv4), netip.MustParseAddr(m2GPServerIPv4), 0x4d32, 40, []byte("esp-after-real-dpd"),
	), func(response []byte) error {
		return validateIPv4ICMPEchoReply(response, netip.MustParseAddr(m2GPAssignedIPv4), netip.MustParseAddr(m2GPServerIPv4), 0x4d32, 40, []byte("esp-after-real-dpd"))
	})
	activeTransportUpdated = client.ActiveTransportUpdated()
	dialer.closeUDP(t)
	waitForM2GPPeerState(t, ctx, peer, func(snapshot m2GPPeerSnapshot) bool {
		return snapshot.tunnelCount == 1
	})
	waitForM2GPReady(t, ctx, client, peer)
	waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportGPST)
	exchangeM2GPGPSTEcho(t, ctx, client, 41, "gpst-after-esp-socket-failure")
	snapshot := peer.snapshot()
	if snapshot.loginCount != 1 || snapshot.getConfigCount != 1 || snapshot.tunnelCount != 1 || snapshot.gpstDataCount != 1 {
		t.Fatalf("ESP socket failure did not fall back within the same authenticated session: %#v", snapshot)
	}
	relay.assertNoFailure(t)
	peer.assertNoFailure(t)
}

func TestM2GlobalProtectFallbackInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	t.Run("no-esp-keys-starts-gpst-directly", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		t.Cleanup(cancel)
		peer := startM2GPPeer(t, ctx, m2GPPeerScenario{})
		dialer := &m2GPDialer{hostname: m2GPHostname, primary: peer.address}
		client := newM2GPClient(t, ctx, peer, dialer, openconnect.ClientOptions{})
		startM2GPClient(t, client)
		waitForM2GPReady(t, ctx, client, peer)
		snapshot := peer.snapshot()
		if snapshot.tunnelCount != 1 || snapshot.tunnelAt.Sub(snapshot.getConfigAt) >= time.Second {
			t.Fatalf("no-key GlobalProtect session did not start GPST directly: %#v delay=%s", snapshot, snapshot.tunnelAt.Sub(snapshot.getConfigAt))
		}
		exchangeM2GPGPSTEcho(t, ctx, client, 10, "no-esp-keys")
		peer.assertNoFailure(t)
	})

	t.Run("silent-esp-five-second-fallback-and-late-reply", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		t.Cleanup(cancel)
		oracleBinary := buildM2GPESPOracle(t, ctx)
		parameters := newM2GPESPParameters("aes-128-cbc", "sha256", false)
		startM2GPESPOracle(t, ctx, oracleBinary, &parameters)
		relay := startM2GPUDPRelay(t, ctx, parameters.port)
		parameters.port = relay.port
		peer := startM2GPPeer(t, ctx, m2GPPeerScenario{esp: &parameters})
		dialer := &m2GPDialer{hostname: m2GPHostname, primary: peer.address}
		client := newM2GPClient(t, ctx, peer, dialer, openconnect.ClientOptions{})
		startM2GPClient(t, client)
		waitForM2GPReady(t, ctx, client, peer)
		snapshot := peer.snapshot()
		fallbackDelay := snapshot.tunnelAt.Sub(snapshot.getConfigAt)
		if snapshot.tunnelCount != 1 || fallbackDelay < 5*time.Second {
			t.Fatalf("silent ESP started GPST before the five-second deadline: count=%d delay=%s", snapshot.tunnelCount, fallbackDelay)
		}
		udpDialAt, udpClosedAt := dialer.udpTimes()
		if udpDialAt.IsZero() || udpClosedAt.IsZero() || udpClosedAt.After(snapshot.tunnelAt) {
			t.Fatalf("GPST fallback did not close ESP before dialing the tunnel: dial=%s close=%s tunnel=%s", udpDialAt, udpClosedAt, snapshot.tunnelAt)
		}
		firstDatagramAt := relay.firstDatagramTime()
		if firstDatagramAt.IsZero() || firstDatagramAt.Before(snapshot.getConfigAt) {
			t.Fatalf("silent ESP relay did not observe a post-config magic probe: config=%s probe=%s", snapshot.getConfigAt, firstDatagramAt)
		}
		relay.release(t)
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait after late GlobalProtect ESP reply"))
		case <-time.After(300 * time.Millisecond):
		}
		exchangeM2GPGPSTEcho(t, ctx, client, 11, "late-esp-must-not-take-over")
		if peer.snapshot().gpstDataCount != 1 {
			t.Fatal("late ESP response took over the established GPST data path")
		}
		relay.assertNoFailure(t)
		peer.assertNoFailure(t)
	})
}

func TestM2GlobalProtectRecoveryInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	t.Run("gpst-502-reauthenticates", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		t.Cleanup(cancel)
		peer := startM2GPPeer(t, ctx, m2GPPeerScenario{tunnelRejections: 1})
		dialer := &m2GPDialer{hostname: m2GPHostname, primary: peer.address}
		client := newM2GPClient(t, ctx, peer, dialer, openconnect.ClientOptions{NoUDP: true})
		startM2GPClient(t, client)
		waitForM2GPReady(t, ctx, client, peer)
		snapshot := peer.snapshot()
		if snapshot.loginCount != 2 || snapshot.getConfigCount != 2 || snapshot.tunnelCount != 2 || snapshot.logoutCount != 0 || !strings.Contains(snapshot.opaqueQuery, "m2-auth%2bcookie-2") {
			t.Fatalf("GPST 502 did not perform cookie reauthentication: %#v", snapshot)
		}
		exchangeM2GPGPSTEcho(t, ctx, client, 20, "gpst-502-reauthenticated")
		peer.assertNoFailure(t)
	})

	for _, testCase := range []struct {
		name                   string
		scenario               m2GPPeerScenario
		expectedConfigurations int
	}{
		{
			name:     "gateway-login-513-is-terminal",
			scenario: m2GPPeerScenario{loginStatus: 513},
		},
		{
			name:                   "gateway-config-513-is-terminal",
			scenario:               m2GPPeerScenario{configurationStatus: 513},
			expectedConfigurations: 1,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			t.Cleanup(cancel)
			peer := startM2GPPeer(t, ctx, testCase.scenario)
			dialer := &m2GPDialer{hostname: m2GPHostname, primary: peer.address}
			client := newM2GPClient(t, ctx, peer, dialer, openconnect.ClientOptions{NoUDP: true})
			startM2GPClient(t, client)
			_, terminalErr := client.ReadDataPacket(ctx)
			if !E.IsMulti(terminalErr, openconnect.ErrAuthenticationFailed) {
				t.Fatalf("GlobalProtect HTTP 513 was not a terminal authentication failure: %v", terminalErr)
			}
			snapshot := peer.snapshot()
			if snapshot.loginCount != 1 || snapshot.getConfigCount != testCase.expectedConfigurations {
				t.Fatalf("GlobalProtect retried after terminal HTTP 513: %#v", snapshot)
			}
			peer.assertNoFailure(t)
		})
	}

	t.Run("gpst-eof-reestablishes-without-login", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		t.Cleanup(cancel)
		peer := startM2GPPeer(t, ctx, m2GPPeerScenario{closeFirstGPSTOnData: true})
		dialer := &m2GPDialer{hostname: m2GPHostname, primary: peer.address}
		configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 8)
		client := newM2GPClient(t, ctx, peer, dialer, openconnect.ClientOptions{
			NoUDP: true,
			OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
				configurationEvents <- event
				return nil
			},
		})
		startM2GPClient(t, client)
		waitForM2GPReady(t, ctx, client, peer)
		initialEvent := waitForM1ConfigurationEvent(t, ctx, configurationEvents)
		if initialEvent.Reason != openconnect.TunnelConfigurationEventInitial {
			t.Fatalf("unexpected initial GlobalProtect configuration reason: %s", initialEvent.Reason)
		}
		exchangeM2GPGPSTEcho(t, ctx, client, 22, "gpst-before-peer-eof")
		var reestablishmentEvent openconnect.TunnelConfigurationEvent
		for reestablishmentEvent.Reason != openconnect.TunnelConfigurationEventReestablishment {
			reestablishmentEvent = waitForM1ConfigurationEvent(t, ctx, configurationEvents)
		}
		waitForM2GPReady(t, ctx, client, peer)
		snapshot := peer.snapshot()
		if snapshot.loginCount != 1 || snapshot.getConfigCount < 2 || snapshot.hipCheckCount < 2 || snapshot.tunnelCount < 2 {
			t.Fatalf("GPST EOF did not reestablish with the existing authenticated session: %#v", snapshot)
		}
		exchangeM2GPGPSTEcho(t, ctx, client, 23, "gpst-after-peer-eof")
		peer.assertNoFailure(t)
	})

	t.Run("short-timeout-rekeys-without-login", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		t.Cleanup(cancel)
		peer := startM2GPPeer(t, ctx, m2GPPeerScenario{rekeySeconds: 61})
		dialer := &m2GPDialer{hostname: m2GPHostname, primary: peer.address}
		configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 8)
		client := newM2GPClient(t, ctx, peer, dialer, openconnect.ClientOptions{
			NoUDP: true,
			OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
				configurationEvents <- event
				return nil
			},
		})
		startM2GPClient(t, client)
		waitForM2GPReady(t, ctx, client, peer)
		initialEvent := waitForM1ConfigurationEvent(t, ctx, configurationEvents)
		if initialEvent.Reason != openconnect.TunnelConfigurationEventInitial {
			t.Fatalf("unexpected initial GlobalProtect configuration reason: %s", initialEvent.Reason)
		}
		var rekeyEvent openconnect.TunnelConfigurationEvent
		for rekeyEvent.Reason != openconnect.TunnelConfigurationEventRekey {
			rekeyEvent = waitForM1ConfigurationEvent(t, ctx, configurationEvents)
		}
		snapshot := peer.snapshot()
		if snapshot.loginCount != 1 || snapshot.getConfigCount < 2 || snapshot.logoutCount != 0 || len(snapshot.getConfigBodies) < 2 {
			t.Fatalf("short GlobalProtect timeout reauthenticated instead of rekeying: %#v", snapshot)
		}
		if !strings.Contains(snapshot.getConfigBodies[1], "&preferred-ip=192.0.2.10&preferred-ipv6=2001%3adb8%3a1%3a%3a10&") ||
			strings.Count(snapshot.getConfigBodies[1], "preferred-ip=") != 1 || strings.Count(snapshot.getConfigBodies[1], "preferred-ipv6=") != 1 {
			t.Fatalf("GlobalProtect rekey did not preserve preferred addresses and filter old opaque preferences: %s", snapshot.getConfigBodies[1])
		}
		assertM2GPTunnelConfiguration(t, rekeyEvent.Configuration, "192.0.2.11")
		exchangeM2GPGPSTEcho(t, ctx, client, 21, "gpst-rekey-same-cookie")
		peer.assertNoFailure(t)
	})
}

func TestM2GlobalProtectHIPInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	t.Run("truthful-built-in-periodic-gpst-and-address-pin", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		t.Cleanup(cancel)
		decoy := startM2GPPeer(t, ctx, m2GPPeerScenario{decoy: true})
		periodicGate := make(chan struct{})
		periodicStarted := make(chan struct{}, 1)
		peer := startM2GPPeer(t, ctx, m2GPPeerScenario{
			portal:             true,
			hipNeeded:          []bool{true, false},
			validateBuiltInHIP: true,
			periodicHIPGate:    periodicGate,
			periodicHIPStarted: periodicStarted,
		})
		dialer := &m2GPDialer{hostname: m2GPHostname, primary: peer.address, decoy: decoy.address}
		peer.afterLogin = dialer.switchResolver
		client := newM2GPClient(t, ctx, peer, dialer, openconnect.ClientOptions{NoUDP: true})
		t.Cleanup(dialer.restoreResolver)
		startM2GPClient(t, client)
		waitForM2GPReady(t, ctx, client, peer)
		waitForM2GPPeerState(t, ctx, peer, func(snapshot m2GPPeerSnapshot) bool {
			return snapshot.hipReportCount == 1 && snapshot.tunnelCount == 1
		})
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for periodic GlobalProtect HIP check"))
		case <-periodicStarted:
		}
		if client.Ready() {
			t.Fatal("GPST client remained Ready while its raw tunnel was closed for periodic HIP")
		}
		blockedSnapshot := peer.snapshot()
		if len(blockedSnapshot.tunnelCloseTimes) == 0 || len(blockedSnapshot.hipCheckTimes) < 2 || blockedSnapshot.tunnelCloseTimes[0].After(blockedSnapshot.hipCheckTimes[1]) {
			t.Fatalf("periodic GPST HIP did not close the old raw tunnel before checking: %#v", blockedSnapshot)
		}
		close(periodicGate)
		waitForM2GPReady(t, ctx, client, peer)
		waitForM2GPPeerState(t, ctx, peer, func(snapshot m2GPPeerSnapshot) bool {
			return snapshot.hipCheckCount >= 2 && snapshot.tunnelCount >= 2
		})
		exchangeM2GPGPSTEcho(t, ctx, client, 30, "periodic-hip-reconnected-gpst")
		domainDials, pinnedDials, decoyDials, _, _ := dialer.snapshot()
		if domainDials == 0 || pinnedDials == 0 || decoyDials != 0 || decoy.snapshot().decoyRequestCount != 0 {
			t.Fatalf("GlobalProtect HIP/config/tunnel did not stay pinned: domain=%d pinned=%d decoy-dials=%d decoy-requests=%d", domainDials, pinnedDials, decoyDials, decoy.snapshot().decoyRequestCount)
		}
		dialer.restoreResolver()
		beforeClose := peer.snapshot().hipCheckCount
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosed(closeErr) {
			t.Fatal(E.Cause(closeErr, "close periodic GlobalProtect HIP client"))
		}
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for stopped GlobalProtect HIP timer"))
		case <-time.After(1300 * time.Millisecond):
		}
		if peer.snapshot().hipCheckCount != beforeClose {
			t.Fatal("GlobalProtect periodic HIP continued after Client.Close")
		}
		peer.assertNoFailure(t)
		decoy.assertNoFailure(t)
	})

	t.Run("periodic-hip-keeps-esp-active", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		t.Cleanup(cancel)
		oracleBinary := buildM2GPESPOracle(t, ctx)
		parameters := newM2GPESPParameters("aes-256-cbc", "sha1", true)
		startM2GPESPOracle(t, ctx, oracleBinary, &parameters)
		peer := startM2GPPeer(t, ctx, m2GPPeerScenario{portal: true, hipNeeded: []bool{false, false}, esp: &parameters})
		dialer := &m2GPDialer{hostname: m2GPHostname, primary: peer.address}
		client := newM2GPClient(t, ctx, peer, dialer, openconnect.ClientOptions{})
		startM2GPClient(t, client)
		waitForM2GPReady(t, ctx, client, peer)
		exchangeM2GPESPEcho(t, ctx, client, buildIPv4ICMPEchoRequest(
			t, netip.MustParseAddr(m2GPAssignedIPv4), netip.MustParseAddr(m2GPServerIPv4), 0x4d32, 31, []byte("esp-before-periodic-hip"),
		), func(response []byte) error {
			return validateIPv4ICMPEchoReply(response, netip.MustParseAddr(m2GPAssignedIPv4), netip.MustParseAddr(m2GPServerIPv4), 0x4d32, 31, []byte("esp-before-periodic-hip"))
		})
		waitForM2GPPeerState(t, ctx, peer, func(snapshot m2GPPeerSnapshot) bool {
			return snapshot.hipCheckCount >= 2
		})
		exchangeM2GPESPEcho(t, ctx, client, buildIPv4ICMPEchoRequest(
			t, netip.MustParseAddr(m2GPAssignedIPv4), netip.MustParseAddr(m2GPServerIPv4), 0x4d32, 32, []byte("esp-after-periodic-hip"),
		), func(response []byte) error {
			return validateIPv4ICMPEchoReply(response, netip.MustParseAddr(m2GPAssignedIPv4), netip.MustParseAddr(m2GPServerIPv4), 0x4d32, 32, []byte("esp-after-periodic-hip"))
		})
		_, _, _, udpDials, udpClosedAt := dialer.snapshot()
		if peer.snapshot().tunnelCount != 0 || udpDials != 1 || !udpClosedAt.IsZero() {
			t.Fatalf("periodic HIP disrupted ESP: peer=%#v udp-dials=%d udp-close=%s", peer.snapshot(), udpDials, udpClosedAt)
		}
		peer.assertNoFailure(t)
	})

	t.Run("hip-redirect-does-not-leak", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		t.Cleanup(cancel)
		decoy := startM2GPPeer(t, ctx, m2GPPeerScenario{decoy: true})
		peer := startM2GPPeer(t, ctx, m2GPPeerScenario{})
		peer.scenario.hipRedirect = "https://" + decoy.authority + "/stolen"
		dialer := &m2GPDialer{hostname: m2GPHostname, primary: peer.address, decoy: decoy.address}
		peer.afterLogin = dialer.switchResolver
		client := newM2GPClient(t, ctx, peer, dialer, openconnect.ClientOptions{NoUDP: true})
		t.Cleanup(dialer.restoreResolver)
		startM2GPClient(t, client)
		terminalContext, cancelTerminal := context.WithTimeout(ctx, 8*time.Second)
		_, terminalErr := client.ReadDataPacket(terminalContext)
		cancelTerminal()
		if terminalErr == nil {
			t.Fatal("GlobalProtect HIP redirect did not terminate the session")
		}
		dialer.restoreResolver()
		if peer.snapshot().hipCheckCount != 1 || decoy.snapshot().decoyRequestCount != 0 {
			t.Fatalf("GlobalProtect HIP redirect leaked to decoy: primary=%#v decoy=%#v", peer.snapshot(), decoy.snapshot())
		}
		peer.assertNoFailure(t)
		decoy.assertNoFailure(t)
	})
}

func TestM2GlobalProtectHIPWrapperInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(E.Cause(err, "read hostname for GlobalProtect HIP wrapper test"))
	}
	opaqueQuery := m2GPOpaqueQuery("m2-auth+cookie-1", hostname)
	report := `<?xml version="1.0"?><hip-report name="independent-wrapper"/>`
	expectedArguments := []string{
		"--cookie", opaqueQuery,
		"--client-ip", m2GPAssignedIPv4,
		"--client-ipv6", m2GPAssignedIPv6,
		"--md5", m2GPHIPMD5(opaqueQuery),
		"--client-os", "Linux",
	}
	buildContext, cancelBuild := context.WithTimeout(context.Background(), time.Minute)
	defer cancelBuild()
	wrapperPaths := make(map[string]string, 3)
	for _, behavior := range []string{"", "nonzero", "abnormal"} {
		wrapperPaths[behavior] = buildM2GPHIPWrapper(t, buildContext, expectedArguments, "6.3.0-33", report, behavior)
	}
	testCases := []struct {
		name       string
		behavior   string
		startError bool
		succeeds   bool
	}{
		{name: "stdout-and-exact-process-contract", succeeds: true},
		{name: "nonzero-is-terminal", behavior: "nonzero"},
		{name: "abnormal-is-terminal", behavior: "abnormal"},
		{name: "start-error-is-terminal", startError: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			t.Cleanup(cancel)
			wrapperPath := filepath.Join(t.TempDir(), "missing-hip-wrapper")
			if !testCase.startError {
				wrapperPath = wrapperPaths[testCase.behavior]
			}
			scenario := m2GPPeerScenario{hipNeeded: []bool{true}}
			if testCase.succeeds {
				scenario.expectedWrapperReport = report
			}
			peer := startM2GPPeer(t, ctx, scenario)
			dialer := &m2GPDialer{hostname: m2GPHostname, primary: peer.address}
			client := newM2GPClient(t, ctx, peer, dialer, openconnect.ClientOptions{
				NoUDP: true,
				HIP:   &openconnect.HIPOptions{WrapperPath: wrapperPath},
			})
			startM2GPClient(t, client)
			if testCase.succeeds {
				waitForM2GPReady(t, ctx, client, peer)
				if peer.snapshot().hipReportCount != 1 {
					t.Fatal("successful GlobalProtect HIP wrapper stdout was not submitted")
				}
			} else {
				terminalContext, cancelTerminal := context.WithTimeout(ctx, 8*time.Second)
				_, terminalErr := client.ReadDataPacket(terminalContext)
				cancelTerminal()
				if terminalErr == nil {
					t.Fatal("failing GlobalProtect HIP wrapper did not become terminal")
				}
			}
			peer.assertNoFailure(t)
		})
	}
}

func startM2GPPeer(t *testing.T, parentContext context.Context, scenario m2GPPeerScenario) *m2GPPeer {
	t.Helper()
	certificate, rootCAs := createM2GPPeerCertificate(t, m2GPHostname)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(E.Cause(err, "listen for GlobalProtect M2 TLS peer"))
	}
	ctx, cancel := context.WithCancel(parentContext)
	peer := &m2GPPeer{
		ctx:           ctx,
		cancel:        cancel,
		hostname:      m2GPHostname,
		rootCAs:       rootCAs,
		listener:      listener,
		address:       M.SocksaddrFromNet(listener.Addr()),
		scenario:      scenario,
		failures:      make(chan error, 32),
		tunnelStarted: make(chan time.Time, 8),
		connections:   make(map[net.Conn]struct{}),
	}
	authorityHostname := peer.hostname
	if scenario.serverByIP {
		authorityHostname = peer.address.Addr.String()
	}
	peer.authority = net.JoinHostPort(authorityHostname, strconv.Itoa(int(peer.address.Port)))
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"http/1.1"},
	})
	peer.waitGroup.Add(1)
	go peer.acceptLoop(tlsListener)
	t.Cleanup(func() {
		closeErr := peer.close()
		if closeErr != nil && !E.IsClosed(closeErr) {
			t.Error(E.Cause(closeErr, "close GlobalProtect M2 TLS peer"))
		}
	})
	return peer
}

func createM2GPPeerCertificate(t *testing.T, hostname string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	certificateAuthorityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate GlobalProtect M2 TLS certificate authority key"))
	}
	now := time.Now()
	certificateAuthorityTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "GlobalProtect M2 peer test CA"},
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
		t.Fatal(E.Cause(err, "create GlobalProtect M2 TLS certificate authority"))
	}
	certificateAuthority, err := x509.ParseCertificate(certificateAuthorityDER)
	if err != nil {
		t.Fatal(E.Cause(err, "parse GlobalProtect M2 TLS certificate authority"))
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate GlobalProtect M2 TLS server key"))
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, certificateAuthority, privateKey.Public(), certificateAuthorityKey)
	if err != nil {
		t.Fatal(E.Cause(err, "create GlobalProtect M2 TLS certificate"))
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(certificateAuthority)
	return tls.Certificate{Certificate: [][]byte{certificateDER, certificateAuthorityDER}, PrivateKey: privateKey}, rootCAs
}

func (p *m2GPPeer) acceptLoop(listener net.Listener) {
	defer p.waitGroup.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if p.ctx.Err() == nil && !E.IsClosed(err) {
				p.recordFailure(E.Cause(err, "accept GlobalProtect M2 TLS connection"))
			}
			return
		}
		p.access.Lock()
		p.connections[conn] = struct{}{}
		p.access.Unlock()
		p.waitGroup.Add(1)
		go p.handleConnection(conn)
	}
}

func (p *m2GPPeer) handleConnection(conn net.Conn) {
	defer p.waitGroup.Done()
	defer func() {
		p.access.Lock()
		delete(p.connections, conn)
		p.access.Unlock()
		_ = conn.Close()
	}()
	tlsConn, loaded := conn.(*tls.Conn)
	if !loaded {
		p.recordFailure(E.New("GlobalProtect M2 peer accepted a non-TLS connection"))
		return
	}
	err := tlsConn.HandshakeContext(p.ctx)
	if err != nil {
		if p.ctx.Err() == nil && !E.IsClosedOrCanceled(err) {
			p.recordFailure(E.Cause(err, "handshake GlobalProtect M2 TLS connection"))
		}
		return
	}
	serverName := tlsConn.ConnectionState().ServerName
	reader := bufio.NewReader(tlsConn)
	request, err := readM2GPWireRequest(reader, serverName)
	if err != nil {
		if p.ctx.Err() == nil && !E.IsClosedOrCanceled(err) {
			p.recordFailure(err)
		}
		return
	}
	if request.method == http.MethodGet && request.path == "/ssl-tunnel-connect.sslvpn" {
		err = p.serveGPST(tlsConn, reader, request)
		if err != nil && p.ctx.Err() == nil && !E.IsClosedOrCanceled(err) {
			p.recordFailure(err)
		}
		return
	}
	response, err := p.handleRequest(request)
	if err != nil {
		p.recordFailure(err)
		response = m2GPWireResponse{statusCode: http.StatusInternalServerError, body: []byte("peer validation failed")}
	}
	err = writeM2GPWireResponse(tlsConn, response)
	if err != nil && p.ctx.Err() == nil && !E.IsClosedOrCanceled(err) {
		p.recordFailure(E.Cause(err, "write GlobalProtect M2 response"))
	}
}

func readM2GPWireRequest(reader *bufio.Reader, serverName string) (m2GPWireRequest, error) {
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return m2GPWireRequest{}, E.Cause(err, "read GlobalProtect M2 request line")
	}
	requestLine = strings.TrimSuffix(strings.TrimSuffix(requestLine, "\n"), "\r")
	parts := strings.Split(requestLine, " ")
	if len(parts) != 3 || parts[2] != "HTTP/1.1" {
		return m2GPWireRequest{}, E.New("invalid GlobalProtect M2 request line: ", requestLine)
	}
	headerReader := textproto.NewReader(reader)
	header, err := headerReader.ReadMIMEHeader()
	if err != nil {
		return m2GPWireRequest{}, E.Cause(err, "read GlobalProtect M2 request headers")
	}
	contentLength := 0
	contentLengthText := header.Get("Content-Length")
	if contentLengthText != "" {
		contentLength, err = strconv.Atoi(contentLengthText)
		if err != nil || contentLength < 0 || contentLength > m2GPMaximumBodySize {
			return m2GPWireRequest{}, E.New("invalid GlobalProtect M2 Content-Length")
		}
	}
	body := make([]byte, contentLength)
	_, err = io.ReadFull(reader, body)
	if err != nil {
		return m2GPWireRequest{}, E.Cause(err, "read GlobalProtect M2 request body")
	}
	targetURL, err := url.ParseRequestURI(parts[1])
	if err != nil {
		return m2GPWireRequest{}, E.Cause(err, "parse GlobalProtect M2 request target")
	}
	return m2GPWireRequest{
		method:     parts[0],
		target:     parts[1],
		path:       targetURL.Path,
		rawQuery:   targetURL.RawQuery,
		header:     header,
		body:       body,
		serverName: serverName,
		receivedAt: time.Now(),
	}, nil
}

func writeM2GPWireResponse(w io.Writer, response m2GPWireResponse) error {
	statusText := http.StatusText(response.statusCode)
	if statusText == "" {
		statusText = "GlobalProtect"
	}
	var header strings.Builder
	header.WriteString("HTTP/1.1 ")
	header.WriteString(strconv.Itoa(response.statusCode))
	header.WriteByte(' ')
	header.WriteString(statusText)
	header.WriteString("\r\nContent-Length: ")
	header.WriteString(strconv.Itoa(len(response.body)))
	header.WriteString("\r\nConnection: close\r\n")
	for name, values := range response.header {
		for _, value := range values {
			header.WriteString(name)
			header.WriteString(": ")
			header.WriteString(value)
			header.WriteString("\r\n")
		}
	}
	header.WriteString("\r\n")
	_, err := io.WriteString(w, header.String())
	if err != nil {
		return err
	}
	_, err = w.Write(response.body)
	return err
}

func (p *m2GPPeer) handleRequest(request m2GPWireRequest) (m2GPWireResponse, error) {
	if p.scenario.decoy {
		p.access.Lock()
		p.decoyRequestCount++
		p.access.Unlock()
		return m2GPWireResponse{statusCode: http.StatusInternalServerError}, nil
	}
	if request.serverName != p.hostname {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 request used unexpected SNI: ", request.serverName)
	}
	if request.header.Get("Host") != p.authority {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 request used unexpected Host: ", request.header.Get("Host"))
	}
	if request.header.Get("User-Agent") != "PAN GlobalProtect" {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 request used unexpected User-Agent: ", request.header.Get("User-Agent"))
	}
	switch request.path {
	case "/ssl-vpn/prelogin.esp", "/global-protect/prelogin.esp":
		return p.handlePrelogin(request)
	case "/global-protect/getconfig.esp":
		return p.handlePortalConfiguration(request)
	case "/ssl-vpn/login.esp":
		return p.handleGatewayLogin(request)
	case "/ssl-vpn/getconfig.esp":
		return p.handleGatewayConfiguration(request)
	case "/ssl-vpn/hipreportcheck.esp":
		return p.handleHIPCheck(request)
	case "/ssl-vpn/hipreport.esp":
		return p.handleHIPReport(request)
	case "/ssl-vpn/logout.esp":
		return p.handleLogout(request)
	default:
		return m2GPWireResponse{statusCode: http.StatusNotFound}, nil
	}
}

func (p *m2GPPeer) handlePrelogin(request m2GPWireRequest) (m2GPWireResponse, error) {
	if request.method != http.MethodPost || string(request.body) != "cas-support=yes" {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 peer received invalid prelogin request")
	}
	expectedPath := "/ssl-vpn/prelogin.esp"
	if p.scenario.portal {
		expectedPath = "/global-protect/prelogin.esp"
	}
	if request.path != expectedPath {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 peer received prelogin on unexpected interface")
	}
	body := `<prelogin-response><status>Success</status><msg/><authentication-message>M2 GlobalProtect login</authentication-message><username-label>Username</username-label><password-label>Password</password-label><region>M2</region></prelogin-response>`
	return m2GPXMLResponse(body), nil
}

func (p *m2GPPeer) handlePortalConfiguration(request m2GPWireRequest) (m2GPWireResponse, error) {
	if !p.scenario.portal || request.method != http.MethodPost {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 peer received unexpected portal configuration request")
	}
	form, err := url.ParseQuery(string(request.body))
	if err != nil {
		return m2GPWireResponse{}, E.Cause(err, "parse GlobalProtect M2 portal form")
	}
	if form.Get("user") != m2GPUsername || form.Get("passwd") != m2GPPassword {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 portal received invalid credentials")
	}
	body := `<policy><version>6.7.8-9</version><gateways><external><list><entry name="` + p.authority + `"><description>M2 Gateway</description><priority-rule><entry name="M2"><priority>1</priority></entry></priority-rule></entry></list></external></gateways><hip-collection><hip-report-interval>61</hip-report-interval></hip-collection></policy>`
	return m2GPXMLResponse(body), nil
}

func (p *m2GPPeer) handleGatewayLogin(request m2GPWireRequest) (m2GPWireResponse, error) {
	if request.method != http.MethodPost {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 peer received non-POST gateway login")
	}
	form, err := url.ParseQuery(string(request.body))
	if err != nil {
		return m2GPWireResponse{}, E.Cause(err, "parse GlobalProtect M2 gateway login form")
	}
	if form.Get("user") != m2GPUsername || form.Get("passwd") != m2GPPassword || form.Get("jnlpReady") != "jnlpReady" ||
		form.Get("clientVer") != "4100" || form.Get("clientos") != "Linux" || form.Get("os-version") != "linux-64" {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 gateway received invalid login form")
	}
	computer := form.Get("computer")
	if computer == "" {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 gateway login omitted computer")
	}
	p.access.Lock()
	p.loginCount++
	generation := p.loginCount
	p.computer = computer
	authCookie := "m2-auth+cookie-" + strconv.Itoa(generation)
	p.opaqueQuery = m2GPOpaqueQuery(authCookie, computer)
	p.sessionCookie = "m2-session-" + strconv.Itoa(generation)
	p.assignedIPv4 = m2GPAssignedIPv4
	p.assignedIPv6 = m2GPAssignedIPv6
	afterLogin := p.afterLogin
	sessionCookie := p.sessionCookie
	p.access.Unlock()
	if p.scenario.loginStatus != 0 {
		return m2GPWireResponse{statusCode: p.scenario.loginStatus, body: []byte("Valid client certificate is required")}, nil
	}
	if generation == 1 && (form.Get("preferred-ip") != "" || form.Get("preferred-ipv6") != "") {
		return m2GPWireResponse{}, E.New("initial GlobalProtect M2 login unexpectedly sent preferred addresses")
	}
	if generation > 1 && (form.Get("preferred-ip") != m2GPAssignedIPv4 || form.Get("preferred-ipv6") != m2GPAssignedIPv6) {
		return m2GPWireResponse{}, E.New("reauthenticated GlobalProtect M2 login omitted previous preferred addresses")
	}
	if afterLogin != nil {
		afterLogin()
	}
	arguments := []string{
		"(null)", m2GPEncodeComponent(authCookie), "PersistentCookie", m2GPPortal,
		m2GPEncodeComponent(m2GPUsername), "TestAuth", "vsys1", m2GPDomain,
		"(null)", "", "", "", "tunnel", "-1", "4100", m2GPAssignedIPv4, "", "", m2GPAssignedIPv6,
	}
	var body strings.Builder
	body.WriteString(`<?xml version="1.0" encoding="UTF-8"?><jnlp><application-desc>`)
	for _, argument := range arguments {
		body.WriteString("<argument>")
		body.WriteString(html.EscapeString(argument))
		body.WriteString("</argument>")
	}
	body.WriteString("</application-desc></jnlp>")
	response := m2GPXMLResponse(body.String())
	response.header.Add("Set-Cookie", m2GPSessionCookie+"="+sessionCookie+"; Path=/; Secure; HttpOnly")
	return response, nil
}

func (p *m2GPPeer) handleGatewayConfiguration(request m2GPWireRequest) (m2GPWireResponse, error) {
	if request.method != http.MethodPost {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 peer received non-POST getconfig")
	}
	p.access.Lock()
	opaqueQuery := p.opaqueQuery
	p.getConfigCount++
	getConfigCount := p.getConfigCount
	loginCount := p.loginCount
	p.getConfigAt = request.receivedAt
	p.getConfigBodies = append(p.getConfigBodies, string(request.body))
	p.access.Unlock()
	if p.scenario.configurationStatus != 0 {
		return m2GPWireResponse{statusCode: p.scenario.configurationStatus, body: []byte("Valid client certificate is required")}, nil
	}
	appVersion := "6.3.0-33"
	if p.scenario.portal {
		appVersion = "6.7.8-9"
	}
	expectedPrefix := "client-type=1&protocol-version=p1&internal=no&app-version=" + m2GPEncodeComponent(appVersion) +
		"&ipv6-support=yes&clientos=Linux&os-version=linux-64&hmac-algo=sha1%2cmd5%2csha256&enc-algo=aes-128-cbc%2caes-256-cbc&"
	expectedBody := expectedPrefix + opaqueQuery
	usesPreviousAddresses := getConfigCount > 1
	isRekey := p.scenario.rekeySeconds > 0 && loginCount == 1 && usesPreviousAddresses
	if usesPreviousAddresses {
		expectedBody = strings.TrimSuffix(expectedPrefix, "&") +
			"&preferred-ip=" + m2GPEncodeComponent(m2GPAssignedIPv4) +
			"&preferred-ipv6=" + m2GPEncodeComponent(m2GPAssignedIPv6) +
			"&" + m2GPFilterOpaqueQuery(opaqueQuery, []string{"preferred-ip", "preferred-ipv6"}, false)
	}
	if string(request.body) != expectedBody {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 getconfig body differed from the source-observed field order")
	}
	assignedIPv4 := m2GPAssignedIPv4
	assignedIPv6 := m2GPAssignedIPv6
	if isRekey {
		assignedIPv4 = "192.0.2.11"
		assignedIPv6 = "2001:db8:1::11"
	}
	p.access.Lock()
	p.assignedIPv4 = assignedIPv4
	p.assignedIPv6 = assignedIPv6
	p.access.Unlock()
	var body strings.Builder
	body.WriteString(`<response><ip-address>` + assignedIPv4 + `</ip-address><ip-address-v6>` + assignedIPv6 + `/64</ip-address-v6><netmask>255.255.255.0</netmask><mtu>1380</mtu><lifetime>120</lifetime><disconnect-on-idle>90</disconnect-on-idle>`)
	if p.scenario.rekeySeconds > 0 {
		body.WriteString(`<timeout>` + strconv.Itoa(p.scenario.rekeySeconds) + `</timeout>`)
	}
	body.WriteString(`<gw-address>198.51.100.1</gw-address>`)
	if p.scenario.esp == nil || p.scenario.esp.magicIPv6 {
		body.WriteString(`<gw-address-v6>2001:db8:ffff::1</gw-address-v6>`)
	}
	body.WriteString(`<dns><member>203.0.113.53</member></dns><dns-v6><member>2001:db8::53</member></dns-v6><wins><member>203.0.113.54</member></wins><dns-suffix><member>m2.example</member><member>corp.m2.example</member></dns-suffix><access-routes><member>10.20.0.0/16</member></access-routes><access-routes-v6><member>2001:db8:20::/48</member></access-routes-v6><exclude-access-routes><member>10.30.0.0/16</member></exclude-access-routes><exclude-access-routes-v6><member>2001:db8:30::/48</member></exclude-access-routes-v6><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url>`)
	if p.scenario.esp != nil {
		esp := p.scenario.esp
		body.WriteString(`<ipsec><udp-port>` + strconv.Itoa(int(esp.port)) + `</udp-port>`)
		if !p.scenario.omitIPSecMode {
			body.WriteString(`<ipsec-mode>esp-tunnel</ipsec-mode>`)
		}
		body.WriteString(`<enc-algo>` + esp.encryption + `</enc-algo><hmac-algo>` + esp.authentication + `</hmac-algo><c2s-spi>` + esp.clientSPI + `</c2s-spi><s2c-spi>` + esp.serverSPI + `</s2c-spi>`)
		body.WriteString(m2GPESPXMLKey("ekey-c2s", esp.clientEncryptionKey))
		body.WriteString(m2GPESPXMLKey("akey-c2s", esp.clientAuthenticationKey))
		body.WriteString(m2GPESPXMLKey("ekey-s2c", esp.serverEncryptionKey))
		body.WriteString(m2GPESPXMLKey("akey-s2c", esp.serverAuthenticationKey))
		body.WriteString(`</ipsec>`)
	}
	body.WriteString(`</response>`)
	return m2GPXMLResponse(body.String()), nil
}

func (p *m2GPPeer) handleHIPCheck(request m2GPWireRequest) (m2GPWireResponse, error) {
	if request.method != http.MethodPost {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 peer received non-POST HIP check")
	}
	p.access.Lock()
	opaqueQuery := p.opaqueQuery
	sessionCookie := p.sessionCookie
	assignedIPv4 := p.assignedIPv4
	assignedIPv6 := p.assignedIPv6
	p.hipCheckCount++
	checkIndex := p.hipCheckCount - 1
	p.hipCheckTimes = append(p.hipCheckTimes, request.receivedAt)
	needed := checkIndex < len(p.scenario.hipNeeded) && p.scenario.hipNeeded[checkIndex]
	p.access.Unlock()
	if checkIndex > 0 && p.scenario.periodicHIPStarted != nil {
		select {
		case p.scenario.periodicHIPStarted <- struct{}{}:
		default:
		}
	}
	if checkIndex > 0 && p.scenario.periodicHIPGate != nil {
		select {
		case <-p.ctx.Done():
			return m2GPWireResponse{}, p.ctx.Err()
		case <-p.scenario.periodicHIPGate:
		}
	}
	if !strings.Contains(request.header.Get("Cookie"), m2GPSessionCookie+"="+sessionCookie) {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 HIP check omitted the gateway session cookie")
	}
	form, err := url.ParseQuery(string(request.body))
	if err != nil {
		return m2GPWireResponse{}, E.Cause(err, "parse GlobalProtect M2 HIP check")
	}
	if form.Get("client-role") != "global-protect-full" || form.Get("client-ip") != assignedIPv4 ||
		form.Get("client-ipv6") != assignedIPv6 || !strings.Contains(string(request.body), "&"+opaqueQuery+"&") {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 HIP check omitted session identity fields")
	}
	if form.Get("md5") != m2GPHIPMD5(opaqueQuery) {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 HIP check sent an invalid MD5 correlation identifier")
	}
	if p.scenario.hipRedirect != "" {
		return m2GPWireResponse{
			statusCode: http.StatusTemporaryRedirect,
			header:     textproto.MIMEHeader{"Location": []string{p.scenario.hipRedirect}},
		}, nil
	}
	neededText := "no"
	if needed {
		neededText = "yes"
	}
	return m2GPXMLResponse("<response><hip-report-needed>" + neededText + "</hip-report-needed></response>"), nil
}

func (p *m2GPPeer) handleHIPReport(request m2GPWireRequest) (m2GPWireResponse, error) {
	if request.method != http.MethodPost {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 peer received non-POST HIP report")
	}
	p.access.Lock()
	opaqueQuery := p.opaqueQuery
	sessionCookie := p.sessionCookie
	assignedIPv4 := p.assignedIPv4
	assignedIPv6 := p.assignedIPv6
	computer := p.computer
	p.hipReportCount++
	p.access.Unlock()
	if !strings.Contains(request.header.Get("Cookie"), m2GPSessionCookie+"="+sessionCookie) {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 HIP report omitted the gateway session cookie")
	}
	form, err := url.ParseQuery(string(request.body))
	if err != nil {
		return m2GPWireResponse{}, E.Cause(err, "parse GlobalProtect M2 HIP report form")
	}
	if form.Get("client-role") != "global-protect-full" || form.Get("client-ip") != assignedIPv4 ||
		form.Get("client-ipv6") != assignedIPv6 || !strings.Contains(string(request.body), "&"+opaqueQuery+"&") {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 HIP report omitted session identity fields")
	}
	report := form.Get("report")
	if p.scenario.expectedWrapperReport != "" {
		if report != p.scenario.expectedWrapperReport {
			return m2GPWireResponse{}, E.New("GlobalProtect M2 HIP wrapper stdout was not submitted verbatim")
		}
	} else if p.scenario.validateBuiltInHIP {
		err = validateM2GPBuiltInHIPReport(report, opaqueQuery, assignedIPv4, assignedIPv6, computer)
		if err != nil {
			return m2GPWireResponse{}, err
		}
	}
	return m2GPXMLResponse(`<response status="success"/>`), nil
}

func (p *m2GPPeer) handleLogout(request m2GPWireRequest) (m2GPWireResponse, error) {
	if request.method != http.MethodPost {
		return m2GPWireResponse{}, E.New("GlobalProtect M2 peer received non-POST logout")
	}
	p.access.Lock()
	p.logoutCount++
	p.access.Unlock()
	return m2GPXMLResponse(`<response status="success"/>`), nil
}

// OpenConnect gpst_connect sends a headerless HTTP/1.1 GET and expects the peer to replace the HTTP response with the 12-byte START_TUNNEL marker.
func (p *m2GPPeer) serveGPST(conn net.Conn, reader *bufio.Reader, request m2GPWireRequest) error {
	if request.serverName != p.hostname || request.header.Get("Host") != "" {
		return E.New("GlobalProtect M2 GPST request did not preserve SNI or unexpectedly sent Host")
	}
	p.access.Lock()
	p.tunnelCount++
	tunnelCount := p.tunnelCount
	opaqueQuery := p.opaqueQuery
	reject := tunnelCount <= p.scenario.tunnelRejections
	p.tunnelAt = request.receivedAt
	p.access.Unlock()
	if request.rawQuery != m2GPFilterOpaqueQuery(opaqueQuery, []string{"user", "authcookie"}, true) {
		return E.New("GlobalProtect M2 GPST request used an invalid raw query: ", request.rawQuery)
	}
	if reject {
		_, err := io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
		return err
	}
	_, err := io.WriteString(conn, "START_TUNNEL")
	if err != nil {
		return E.Cause(err, "write GlobalProtect M2 START_TUNNEL")
	}
	select {
	case p.tunnelStarted <- time.Now():
	default:
	}
	p.access.Lock()
	p.tunnelStartTimes = append(p.tunnelStartTimes, time.Now())
	p.access.Unlock()
	defer func() {
		p.access.Lock()
		p.tunnelCloseTimes = append(p.tunnelCloseTimes, time.Now())
		p.access.Unlock()
	}()
	for {
		header := make([]byte, 16)
		_, err = io.ReadFull(reader, header)
		if err != nil {
			return E.Cause(err, "read GlobalProtect M2 GPST header")
		}
		if binary.BigEndian.Uint32(header[:4]) != 0x1a2b3c4d {
			return E.New("GlobalProtect M2 received invalid GPST magic")
		}
		payloadLength := int(binary.BigEndian.Uint16(header[6:8]))
		payload := make([]byte, payloadLength)
		_, err = io.ReadFull(reader, payload)
		if err != nil {
			return E.Cause(err, "read GlobalProtect M2 GPST payload")
		}
		etherType := binary.BigEndian.Uint16(header[4:6])
		if etherType == 0 {
			if payloadLength != 0 || !bytes.Equal(header[8:], make([]byte, 8)) {
				return E.New("GlobalProtect M2 received invalid GPST DPD")
			}
			p.access.Lock()
			p.gpstDPDCount++
			p.access.Unlock()
			err = writeM2GPSTFrame(conn, 0, nil)
			if err != nil {
				return err
			}
			continue
		}
		if binary.LittleEndian.Uint32(header[8:12]) != 1 || binary.LittleEndian.Uint32(header[12:16]) != 0 {
			return E.New("GlobalProtect M2 received invalid GPST data flags")
		}
		if etherType != 0x0800 && etherType != 0x86dd {
			return E.New("GlobalProtect M2 received invalid GPST EtherType")
		}
		echo, echoErr := echoM2GPIPPacket(payload)
		if echoErr != nil {
			return echoErr
		}
		p.access.Lock()
		p.gpstDataCount++
		p.access.Unlock()
		err = writeM2GPSTFrame(conn, etherType, echo)
		if err != nil {
			return err
		}
		if p.scenario.closeFirstGPSTOnData && tunnelCount == 1 {
			return nil
		}
	}
}

func writeM2GPSTFrame(w io.Writer, etherType uint16, payload []byte) error {
	header := make([]byte, 16)
	binary.BigEndian.PutUint32(header[:4], 0x1a2b3c4d)
	binary.BigEndian.PutUint16(header[4:6], etherType)
	binary.BigEndian.PutUint16(header[6:8], uint16(len(payload)))
	if len(payload) > 0 {
		binary.LittleEndian.PutUint32(header[8:12], 1)
	}
	_, err := w.Write(header)
	if err != nil {
		return E.Cause(err, "write GlobalProtect M2 GPST header")
	}
	_, err = w.Write(payload)
	if err != nil {
		return E.Cause(err, "write GlobalProtect M2 GPST payload")
	}
	return nil
}

func echoM2GPIPPacket(packet []byte) ([]byte, error) {
	if len(packet) < 1 {
		return nil, E.New("GlobalProtect M2 GPST peer received an empty packet")
	}
	if packet[0]>>4 == 6 {
		return echoM2GPIPv6Packet(packet)
	}
	if packet[0]>>4 != 4 {
		return nil, E.New("GlobalProtect M2 GPST peer received an unknown IP version")
	}
	if len(packet) < 28 || packet[9] != 1 {
		return nil, E.New("GlobalProtect M2 GPST peer received invalid IPv4 ICMP")
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength+8 > len(packet) || packet[headerLength] != 8 || internetChecksum(packet[:headerLength]) != 0 || internetChecksum(packet[headerLength:]) != 0 {
		return nil, E.New("GlobalProtect M2 GPST peer received invalid ICMP echo request")
	}
	echo := append([]byte(nil), packet...)
	copy(echo[12:16], packet[16:20])
	copy(echo[16:20], packet[12:16])
	echo[headerLength] = 0
	echo[headerLength+2] = 0
	echo[headerLength+3] = 0
	binary.BigEndian.PutUint16(echo[headerLength+2:headerLength+4], internetChecksum(echo[headerLength:]))
	echo[10] = 0
	echo[11] = 0
	binary.BigEndian.PutUint16(echo[10:12], internetChecksum(echo[:headerLength]))
	return echo, nil
}

func echoM2GPIPv6Packet(packet []byte) ([]byte, error) {
	if len(packet) < 48 || packet[6] != 58 || int(binary.BigEndian.Uint16(packet[4:6]))+40 != len(packet) || packet[40] != 128 {
		return nil, E.New("GlobalProtect M2 GPST peer received invalid IPv6 ICMP")
	}
	if m2GPIPv6ICMPChecksum(packet) != 0 {
		return nil, E.New("GlobalProtect M2 GPST peer received an invalid ICMPv6 checksum")
	}
	echo := append([]byte(nil), packet...)
	copy(echo[8:24], packet[24:40])
	copy(echo[24:40], packet[8:24])
	echo[40] = 129
	echo[42] = 0
	echo[43] = 0
	binary.BigEndian.PutUint16(echo[42:44], m2GPIPv6ICMPChecksum(echo))
	return echo, nil
}

func m2GPXMLResponse(body string) m2GPWireResponse {
	return m2GPWireResponse{
		statusCode: http.StatusOK,
		header:     textproto.MIMEHeader{"Content-Type": []string{"application/xml"}},
		body:       []byte(body),
	}
}

func m2GPESPXMLKey(name string, value string) string {
	return "<" + name + "><bits>" + strconv.Itoa(len(value)*4) + "</bits><val>" + value + "</val></" + name + ">"
}

func newM2GPESPParameters(encryption string, authentication string, magicIPv6 bool) m2GPESPParameters {
	encryptionKeySize := 16
	if encryption == "aes-256-cbc" {
		encryptionKeySize = 32
	}
	authenticationKeySize := 16
	switch authentication {
	case "sha1":
		authenticationKeySize = 20
	case "sha256":
		authenticationKeySize = 32
	}
	return m2GPESPParameters{
		encryption:              encryption,
		authentication:          authentication,
		clientSPI:               "0xa5a5a5a5",
		serverSPI:               "0x5a5a5a5a",
		clientEncryptionKey:     strings.Repeat("11", encryptionKeySize),
		clientAuthenticationKey: strings.Repeat("22", authenticationKeySize),
		serverEncryptionKey:     strings.Repeat("33", encryptionKeySize),
		serverAuthenticationKey: strings.Repeat("44", authenticationKeySize),
		magicIPv6:               magicIPv6,
		responseMode:            "normal",
	}
}

func buildM2GPESPOracle(t *testing.T, ctx context.Context) string {
	t.Helper()
	flagsOutput, err := exec.CommandContext(ctx, "pkg-config", "--cflags", "--libs", "openssl").CombinedOutput()
	if err != nil {
		t.Fatal(E.Cause(err, "query OpenSSL flags for GlobalProtect ESP oracle: ", strings.TrimSpace(string(flagsOutput))))
	}
	binaryPath := filepath.Join(t.TempDir(), "gp-esp-peer")
	arguments := []string{
		"-std=c11",
		"-Wall",
		"-Wextra",
		"-Werror",
		filepath.Join("testdata", "gp-esp-peer", "esp_peer.c"),
		"-o",
		binaryPath,
	}
	arguments = append(arguments, strings.Fields(string(flagsOutput))...)
	output, err := exec.CommandContext(ctx, "cc", arguments...).CombinedOutput()
	if err != nil {
		t.Fatal(E.Cause(err, "build GlobalProtect ESP oracle: ", strings.TrimSpace(string(output))))
	}
	return binaryPath
}

func buildM2GPHIPWrapper(
	t *testing.T,
	ctx context.Context,
	expectedArguments []string,
	appVersion string,
	report string,
	behavior string,
) string {
	t.Helper()
	expectedArgumentsJSON, err := json.Marshal(expectedArguments)
	if err != nil {
		t.Fatal(E.Cause(err, "encode GlobalProtect M2 HIP wrapper expectations"))
	}
	linkerFlags := strings.Join([]string{
		"-X=main.expectedArgumentsBase64=" + base64.StdEncoding.EncodeToString(expectedArgumentsJSON),
		"-X=main.expectedAppVersion=" + appVersion,
		"-X=main.wrapperReportBase64=" + base64.StdEncoding.EncodeToString([]byte(report)),
		"-X=main.wrapperBehavior=" + behavior,
	}, " ")
	wrapperPath := filepath.Join(t.TempDir(), "gp-hip-wrapper")
	output, err := exec.CommandContext(
		ctx,
		"go", "build",
		"-o", wrapperPath,
		"-ldflags", linkerFlags,
		filepath.Join("testdata", "gp-peer", "hip_wrapper.go"),
	).CombinedOutput()
	if err != nil {
		t.Fatal(E.Cause(err, "build GlobalProtect M2 HIP wrapper: ", strings.TrimSpace(string(output))))
	}
	return wrapperPath
}

func startM2GPESPOracle(
	t *testing.T,
	ctx context.Context,
	binaryPath string,
	parameters *m2GPESPParameters,
) {
	t.Helper()
	oracle := &m2GPESPOracle{}
	command := exec.CommandContext(
		ctx,
		binaryPath,
		"0",
		parameters.encryption,
		parameters.authentication,
		parameters.clientSPI,
		parameters.serverSPI,
		parameters.clientEncryptionKey,
		parameters.clientAuthenticationKey,
		parameters.serverEncryptionKey,
		parameters.serverAuthenticationKey,
		parameters.responseMode,
	)
	standardOutput, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(E.Cause(err, "open GlobalProtect ESP oracle stdout"))
	}
	command.Stderr = &oracle.stderr
	oracle.command = command
	err = command.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start GlobalProtect ESP oracle"))
	}
	readyLine, err := bufio.NewReader(standardOutput).ReadString('\n')
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(E.Cause(err, "read GlobalProtect ESP oracle readiness"))
	}
	readyFields := strings.Fields(readyLine)
	if len(readyFields) != 2 || readyFields[0] != "PORT" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("invalid GlobalProtect ESP oracle readiness: %q", readyLine)
	}
	port, err := strconv.ParseUint(readyFields[1], 10, 16)
	if err != nil || port == 0 {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("invalid GlobalProtect ESP oracle port: %q", readyFields[1])
	}
	parameters.port = uint16(port)
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
		if oracle.stderr.Len() > 0 {
			t.Logf("GlobalProtect ESP oracle stderr:\n%s", oracle.stderr.String())
		}
	})
}

func exchangeM2GPESPEcho(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	request []byte,
	validate func([]byte) error,
) {
	t.Helper()
	err := client.WriteDataPacket(request)
	if err != nil {
		t.Fatal(E.Cause(err, "write GlobalProtect ESP ICMP request"))
	}
	readContext, cancelRead := context.WithTimeout(ctx, 5*time.Second)
	response, err := client.ReadDataPacket(readContext)
	cancelRead()
	if err != nil {
		t.Fatal(E.Cause(err, "read GlobalProtect ESP ICMP response"))
	}
	err = validate(response)
	if err != nil {
		t.Fatal(err)
	}
	duplicateContext, cancelDuplicate := context.WithTimeout(ctx, 200*time.Millisecond)
	duplicate, duplicateErr := client.ReadDataPacket(duplicateContext)
	cancelDuplicate()
	if duplicateErr == nil {
		t.Fatalf("duplicate ESP datagram escaped replay protection: %x", duplicate)
	}
	if !E.IsCanceled(duplicateErr) {
		t.Fatal(E.Cause(duplicateErr, "wait for suppressed duplicate ESP datagram"))
	}
}

func exchangeM2GPGPSTEcho(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	sequence uint16,
	payloadText string,
) {
	t.Helper()
	configuration := client.TunnelConfiguration()
	clientAddress := firstIPv4Address(t, configuration.Addresses)
	serverAddress := netip.MustParseAddr(m2GPServerIPv4)
	payload := []byte(payloadText)
	request := buildIPv4ICMPEchoRequest(t, clientAddress, serverAddress, 0x4d32, sequence, payload)
	err := client.WriteDataPacket(request)
	if err != nil {
		t.Fatal(E.Cause(err, "write GlobalProtect GPST ICMP request"))
	}
	readContext, cancelRead := context.WithTimeout(ctx, 5*time.Second)
	response, err := client.ReadDataPacket(readContext)
	cancelRead()
	if err != nil {
		t.Fatal(E.Cause(err, "read GlobalProtect GPST ICMP response"))
	}
	err = validateIPv4ICMPEchoReply(response, clientAddress, serverAddress, 0x4d32, sequence, payload)
	if err != nil {
		t.Fatal(err)
	}
}

func waitForM2GPGPSTDPD(t *testing.T, ctx context.Context, peer *m2GPPeer) {
	t.Helper()
	for peer.snapshot().gpstDPDCount == 0 {
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for GlobalProtect GPST dead-peer-detection frame"))
		case peerErr := <-peer.failures:
			t.Fatal(peerErr)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func assertM2GPTunnelConfiguration(t *testing.T, configuration openconnect.TunnelConfiguration, assignedIPv4 string) {
	t.Helper()
	assignedIPv6 := "2001:db8:1::10/64"
	if assignedIPv4 == "192.0.2.11" {
		assignedIPv6 = "2001:db8:1::11/64"
	}
	expectedAddresses := []netip.Prefix{
		netip.MustParsePrefix(assignedIPv4 + "/24"),
		netip.MustParsePrefix(assignedIPv6),
	}
	expectedRoutes := []openconnect.TunnelRoute{
		{Prefix: netip.MustParsePrefix("10.20.0.0/16")},
		{Prefix: netip.MustParsePrefix("2001:db8:20::/48")},
	}
	expectedExcludedRoutes := []openconnect.TunnelRoute{
		{Prefix: netip.MustParsePrefix("10.30.0.0/16")},
		{Prefix: netip.MustParsePrefix("2001:db8:30::/48")},
	}
	if configuration.MTU != 1380 ||
		!slices.Equal(configuration.Addresses, expectedAddresses) ||
		!slices.Equal(configuration.Routes, expectedRoutes) ||
		!slices.Equal(configuration.ExcludedRoutes, expectedExcludedRoutes) ||
		!slices.Equal(configuration.DNS, []netip.Addr{netip.MustParseAddr("203.0.113.53"), netip.MustParseAddr("2001:db8::53")}) ||
		!slices.Equal(configuration.NBNS, []netip.Addr{netip.MustParseAddr("203.0.113.54")}) ||
		!slices.Equal(configuration.SearchDomains, []string{"m2.example", "corp.m2.example"}) ||
		configuration.IdleTimeout != 90*time.Second {
		t.Fatalf("GlobalProtect configuration mapping mismatch: %#v", configuration)
	}
	remainingLifetime := time.Until(configuration.AuthenticationExpiration)
	if remainingLifetime < 100*time.Second || remainingLifetime > 125*time.Second {
		t.Fatalf("GlobalProtect authentication lifetime mismatch: %s", remainingLifetime)
	}
}

func startM2GPUDPRelay(t *testing.T, parentContext context.Context, oraclePort uint16) *m2GPUDPRelay {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(E.Cause(err, "listen for GlobalProtect M2 silent UDP relay"))
	}
	localAddress, loaded := conn.LocalAddr().(*net.UDPAddr)
	if !loaded {
		_ = conn.Close()
		t.Fatal("GlobalProtect M2 UDP relay has a non-UDP address")
	}
	ctx, cancel := context.WithCancel(parentContext)
	relay := &m2GPUDPRelay{
		ctx:           ctx,
		cancel:        cancel,
		conn:          conn,
		oracleAddress: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(oraclePort)},
		port:          uint16(localAddress.Port),
		failures:      make(chan error, 8),
	}
	relay.waitGroup.Add(1)
	go relay.run()
	t.Cleanup(func() {
		relay.cancel()
		closeErr := relay.conn.Close()
		if closeErr != nil && !E.IsClosed(closeErr) {
			t.Error(E.Cause(closeErr, "close GlobalProtect M2 UDP relay"))
		}
		relay.waitGroup.Wait()
	})
	return relay
}

func (r *m2GPUDPRelay) run() {
	defer r.waitGroup.Done()
	buffer := make([]byte, 65536)
	for {
		n, remoteAddress, err := r.conn.ReadFromUDP(buffer)
		if err != nil {
			if r.ctx.Err() == nil && !E.IsClosed(err) {
				r.recordFailure(E.Cause(err, "read GlobalProtect M2 UDP relay datagram"))
			}
			return
		}
		datagram := append([]byte(nil), buffer[:n]...)
		r.access.Lock()
		if remoteAddress.Port == r.oracleAddress.Port && remoteAddress.IP.Equal(r.oracleAddress.IP) {
			clientAddress := r.clientAddress
			r.access.Unlock()
			if clientAddress != nil {
				_, err = r.conn.WriteToUDP(datagram, clientAddress)
				if err != nil && r.ctx.Err() == nil {
					r.recordFailure(E.Cause(err, "forward late GlobalProtect ESP response"))
				}
			}
			continue
		}
		clientAddress := *remoteAddress
		r.clientAddress = &clientAddress
		r.clientDatagramCount++
		if r.firstClientDatagramAt.IsZero() {
			r.firstClientDatagramAt = time.Now()
			r.heldDatagram = datagram
		}
		released := r.released
		r.access.Unlock()
		if released {
			_, err = r.conn.WriteToUDP(datagram, r.oracleAddress)
			if err != nil && r.ctx.Err() == nil {
				r.recordFailure(E.Cause(err, "forward GlobalProtect ESP datagram"))
			}
		}
	}
}

func (r *m2GPUDPRelay) release(t *testing.T) {
	t.Helper()
	r.access.Lock()
	r.released = true
	datagram := append([]byte(nil), r.heldDatagram...)
	r.access.Unlock()
	if len(datagram) == 0 {
		t.Fatal("GlobalProtect M2 UDP relay has no held ESP probe")
	}
	_, err := r.conn.WriteToUDP(datagram, r.oracleAddress)
	if err != nil {
		t.Fatal(E.Cause(err, "release late GlobalProtect ESP probe"))
	}
}

func (r *m2GPUDPRelay) enable() {
	r.access.Lock()
	r.released = true
	r.access.Unlock()
}

func (r *m2GPUDPRelay) datagramCount() int {
	r.access.Lock()
	defer r.access.Unlock()
	return r.clientDatagramCount
}

func (r *m2GPUDPRelay) firstDatagramTime() time.Time {
	r.access.Lock()
	defer r.access.Unlock()
	return r.firstClientDatagramAt
}

func (r *m2GPUDPRelay) recordFailure(err error) {
	select {
	case r.failures <- err:
	default:
	}
}

func (r *m2GPUDPRelay) assertNoFailure(t *testing.T) {
	t.Helper()
	select {
	case err := <-r.failures:
		t.Fatal(err)
	default:
	}
}

func firstM2GPIPv6Address(t *testing.T, addresses []netip.Prefix) netip.Addr {
	t.Helper()
	for _, prefix := range addresses {
		if prefix.Addr().Is6() {
			return prefix.Addr()
		}
	}
	t.Fatal("production GlobalProtect tunnel has no IPv6 address")
	return netip.Addr{}
}

func buildM2GPIPv6ICMPEchoRequest(
	t *testing.T,
	sourceAddress netip.Addr,
	destinationAddress netip.Addr,
	identifier uint16,
	sequence uint16,
	payload []byte,
) []byte {
	t.Helper()
	if !sourceAddress.Is6() || !destinationAddress.Is6() {
		t.Fatalf("ICMPv6 echo requires IPv6 addresses: source=%s destination=%s", sourceAddress, destinationAddress)
	}
	packet := make([]byte, 48+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(payload)))
	packet[6] = 58
	packet[7] = 64
	sourceBytes := sourceAddress.As16()
	destinationBytes := destinationAddress.As16()
	copy(packet[8:24], sourceBytes[:])
	copy(packet[24:40], destinationBytes[:])
	packet[40] = 128
	binary.BigEndian.PutUint16(packet[44:46], identifier)
	binary.BigEndian.PutUint16(packet[46:48], sequence)
	copy(packet[48:], payload)
	binary.BigEndian.PutUint16(packet[42:44], m2GPIPv6ICMPChecksum(packet))
	return packet
}

func validateM2GPIPv6ICMPEchoReply(
	packet []byte,
	clientAddress netip.Addr,
	serverAddress netip.Addr,
	identifier uint16,
	sequence uint16,
	payload []byte,
) error {
	if len(packet) != 48+len(payload) || packet[0]>>4 != 6 || packet[6] != 58 || packet[40] != 129 || packet[41] != 0 {
		return E.New("invalid GlobalProtect ICMPv6 echo reply")
	}
	var sourceBytes [16]byte
	var destinationBytes [16]byte
	copy(sourceBytes[:], packet[8:24])
	copy(destinationBytes[:], packet[24:40])
	if netip.AddrFrom16(sourceBytes) != serverAddress || netip.AddrFrom16(destinationBytes) != clientAddress {
		return E.New("GlobalProtect ICMPv6 echo reply used unexpected addresses")
	}
	if binary.BigEndian.Uint16(packet[44:46]) != identifier || binary.BigEndian.Uint16(packet[46:48]) != sequence || !bytes.Equal(packet[48:], payload) {
		return E.New("GlobalProtect ICMPv6 echo reply payload or identity mismatch")
	}
	if m2GPIPv6ICMPChecksum(packet) != 0 {
		return E.New("GlobalProtect ICMPv6 echo reply has invalid checksum")
	}
	return nil
}

func m2GPIPv6ICMPChecksum(packet []byte) uint16 {
	if len(packet) < 40 {
		return 1
	}
	payloadLength := len(packet) - 40
	pseudoHeader := make([]byte, 40+payloadLength)
	copy(pseudoHeader[:32], packet[8:40])
	binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(payloadLength))
	pseudoHeader[39] = 58
	copy(pseudoHeader[40:], packet[40:])
	return internetChecksum(pseudoHeader)
}

func m2GPOpaqueQuery(authCookie string, computer string) string {
	return "authcookie=" + m2GPEncodeComponent(authCookie) +
		"&portal=" + m2GPEncodeComponent(m2GPPortal) +
		"&user=" + m2GPEncodeComponent(m2GPUsername) +
		"&domain=" + m2GPEncodeComponent(m2GPDomain) +
		"&preferred-ip=" + m2GPEncodeComponent(m2GPAssignedIPv4) +
		"&preferred-ipv6=" + m2GPEncodeComponent(m2GPAssignedIPv6) +
		"&computer=" + m2GPEncodeComponent(computer)
}

func m2GPFilterOpaqueQuery(opaqueQuery string, names []string, include bool) string {
	filtered := make([]string, 0, len(strings.Split(opaqueQuery, "&")))
	for _, segment := range strings.Split(opaqueQuery, "&") {
		name, _, _ := strings.Cut(segment, "=")
		listed := slices.Contains(names, name)
		if listed == include {
			filtered = append(filtered, segment)
		}
	}
	return strings.Join(filtered, "&")
}

// OpenConnect textbuf.c buf_append_urlencoded preserves these bytes and uses lowercase hexadecimal escapes for every other byte.
func m2GPEncodeComponent(value string) string {
	const hexadecimal = "0123456789abcdef"
	var encoded strings.Builder
	for i := 0; i < len(value); i++ {
		character := value[i]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' || character == '~' {
			encoded.WriteByte(character)
			continue
		}
		encoded.WriteByte('%')
		encoded.WriteByte(hexadecimal[character>>4])
		encoded.WriteByte(hexadecimal[character&0x0f])
	}
	return encoded.String()
}

// OpenConnect gpst.c build_csd_token removes only volatile authentication and preferred-address segments before hashing the remaining raw query.
func m2GPHIPMD5(opaqueQuery string) string {
	var filtered []string
	for _, segment := range strings.Split(opaqueQuery, "&") {
		name, _, _ := strings.Cut(segment, "=")
		if name == "authcookie" || name == "preferred-ip" || name == "preferred-ipv6" {
			continue
		}
		filtered = append(filtered, segment)
	}
	digest := md5.Sum([]byte(strings.Join(filtered, "&")))
	return hex.EncodeToString(digest[:])
}

func validateM2GPBuiltInHIPReport(
	report string,
	opaqueQuery string,
	assignedIPv4 string,
	assignedIPv6 string,
	computer string,
) error {
	var document m2GPHIPReportXML
	err := xml.Unmarshal([]byte(report), &document)
	if err != nil {
		return E.Cause(err, "consume GlobalProtect M2 built-in HIP report")
	}
	hostname, err := os.Hostname()
	if err != nil {
		return E.Cause(err, "read hostname for GlobalProtect M2 HIP peer")
	}
	if document.XMLName.Local != "hip-report" || document.MD5 != m2GPHIPMD5(opaqueQuery) ||
		document.UserName != m2GPUsername || document.Domain != m2GPDomain || document.HostName != hostname ||
		computer != hostname || document.HostID != "" || document.IPAddress != assignedIPv4 ||
		document.IPv6Address != assignedIPv6 || document.Version != 4 {
		return E.New("GlobalProtect M2 built-in HIP identity report is invalid")
	}
	if strings.Contains(report, "<ProductInfo") || strings.Contains(report, "<Prod") || strings.Contains(report, "<enc-state>") ||
		strings.Contains(report, "<is-enabled>") || strings.Contains(report, "<real-time-protection>") {
		return E.New("GlobalProtect M2 built-in HIP report fabricated a security product or state")
	}
	actualInterfaces, err := net.Interfaces()
	if err != nil {
		return E.Cause(err, "list interfaces for GlobalProtect M2 HIP peer")
	}
	actualMACs := make(map[string]struct{})
	for _, networkInterface := range actualInterfaces {
		if len(networkInterface.HardwareAddr) > 0 {
			actualMACs[strings.ToUpper(strings.ReplaceAll(networkInterface.HardwareAddr.String(), ":", "-"))] = struct{}{}
		}
	}
	securityCategories := map[string]struct{}{
		"antivirus": {}, "anti-malware": {}, "anti-spyware": {}, "disk-backup": {},
		"disk-encryption": {}, "firewall": {}, "patch-management": {}, "data-loss-prevention": {},
	}
	hostInfoFound := false
	for _, category := range document.Categories {
		if category.Name == "host-info" {
			hostInfoFound = true
			if category.ClientVersion == "" || category.HostName != hostname || category.Domain != m2GPDomain || category.OperatingSystem == "" || category.OperatingSystemVendor == "" {
				return E.New("GlobalProtect M2 HIP host-info omitted truthful host fields")
			}
			for _, networkInterface := range category.Interfaces {
				if _, exists := actualMACs[networkInterface.MACAddress]; !exists {
					return E.New("GlobalProtect M2 HIP report contained a non-local MAC address: ", networkInterface.MACAddress)
				}
			}
			continue
		}
		if _, exists := securityCategories[category.Name]; !exists {
			return E.New("GlobalProtect M2 HIP report contained an unknown category: ", category.Name)
		}
		if len(category.Products) != 0 || category.ClientVersion != "" || category.Domain != "" {
			return E.New("GlobalProtect M2 HIP security category was not empty: ", category.Name)
		}
		delete(securityCategories, category.Name)
	}
	if !hostInfoFound || len(securityCategories) != 0 {
		return E.New("GlobalProtect M2 HIP report omitted host-info or empty security categories")
	}
	switch runtime.GOOS {
	case "darwin":
		if !strings.Contains(report, "Apple macOS") {
			return E.New("GlobalProtect M2 HIP report did not identify the actual macOS runtime")
		}
	case "windows":
		if !strings.Contains(report, "Microsoft Windows") {
			return E.New("GlobalProtect M2 HIP report did not identify the actual Windows runtime")
		}
	case "linux":
		if !strings.Contains(report, "Linux "+runtime.GOARCH) {
			return E.New("GlobalProtect M2 HIP report did not identify the actual Linux runtime")
		}
	}
	return nil
}

func (p *m2GPPeer) snapshot() m2GPPeerSnapshot {
	p.access.Lock()
	defer p.access.Unlock()
	return m2GPPeerSnapshot{
		loginCount:        p.loginCount,
		getConfigCount:    p.getConfigCount,
		hipCheckCount:     p.hipCheckCount,
		hipReportCount:    p.hipReportCount,
		tunnelCount:       p.tunnelCount,
		logoutCount:       p.logoutCount,
		gpstDataCount:     p.gpstDataCount,
		gpstDPDCount:      p.gpstDPDCount,
		opaqueQuery:       p.opaqueQuery,
		getConfigAt:       p.getConfigAt,
		tunnelAt:          p.tunnelAt,
		getConfigBodies:   append([]string(nil), p.getConfigBodies...),
		hipCheckTimes:     append([]time.Time(nil), p.hipCheckTimes...),
		tunnelStartTimes:  append([]time.Time(nil), p.tunnelStartTimes...),
		tunnelCloseTimes:  append([]time.Time(nil), p.tunnelCloseTimes...),
		decoyRequestCount: p.decoyRequestCount,
	}
}

func (p *m2GPPeer) recordFailure(err error) {
	select {
	case p.failures <- err:
	default:
	}
}

func (p *m2GPPeer) assertNoFailure(t *testing.T) {
	t.Helper()
	select {
	case err := <-p.failures:
		t.Fatal(err)
	default:
	}
}

func (p *m2GPPeer) close() error {
	p.cancel()
	listenerErr := p.listener.Close()
	p.access.Lock()
	connections := make([]net.Conn, 0, len(p.connections))
	for conn := range p.connections {
		connections = append(connections, conn)
	}
	p.access.Unlock()
	var closeErrors []error
	if listenerErr != nil && !E.IsClosed(listenerErr) {
		closeErrors = append(closeErrors, listenerErr)
	}
	for _, conn := range connections {
		closeErr := conn.Close()
		if closeErr != nil && !E.IsClosed(closeErr) {
			closeErrors = append(closeErrors, closeErr)
		}
	}
	p.waitGroup.Wait()
	return E.Errors(closeErrors...)
}

func (d *m2GPDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	target := destination
	if network == N.NetworkUDP {
		d.access.Lock()
		if d.udpFirstAttemptAt.IsZero() {
			d.udpFirstAttemptAt = time.Now()
		}
		if d.udpFailuresRemaining > 0 {
			d.udpFailuresRemaining--
			d.access.Unlock()
			return nil, E.New("injected transient GlobalProtect ESP UDP dial failure")
		}
		d.access.Unlock()
		conn, err := N.SystemDialer.DialContext(ctx, network, target)
		if err != nil {
			return nil, err
		}
		d.access.Lock()
		d.udpDialAt = time.Now()
		d.udpDials++
		d.access.Unlock()
		observedConn := &m2GPObservedUDPConn{
			Conn:         conn,
			closeFailure: d.udpCloseFailure,
			onClose: func() {
				d.access.Lock()
				d.udpClosedAt = time.Now()
				d.access.Unlock()
			},
		}
		d.access.Lock()
		d.udpConn = observedConn
		d.access.Unlock()
		return observedConn, nil
	}
	if network == N.NetworkTCP {
		d.access.Lock()
		switch {
		case destination.Fqdn == d.hostname:
			d.domainDials++
			target = d.primary
			if d.switched && d.decoy.IsValid() {
				d.decoyDials++
				target = d.decoy
			}
		case destination.Addr.IsValid() && destination.Addr == d.primary.Addr && destination.Port == d.primary.Port:
			d.pinnedDials++
			target = d.primary
		}
		d.access.Unlock()
	}
	return N.SystemDialer.DialContext(ctx, network, target)
}

func (c *m2GPObservedUDPConn) Close() error {
	c.closeOnce.Do(c.onClose)
	closeErr := c.Conn.Close()
	if c.closeFailure {
		return E.Errors(closeErr, E.New(m2GPUDPCloseFailure))
	}
	return closeErr
}

func (d *m2GPDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

func (d *m2GPDialer) udpTimes() (time.Time, time.Time) {
	d.access.Lock()
	defer d.access.Unlock()
	return d.udpDialAt, d.udpClosedAt
}

func (d *m2GPDialer) udpAttemptTimes() (time.Time, time.Time) {
	d.access.Lock()
	defer d.access.Unlock()
	return d.udpFirstAttemptAt, d.udpDialAt
}

func (d *m2GPDialer) switchResolver() {
	d.access.Lock()
	d.switched = true
	d.access.Unlock()
}

func (d *m2GPDialer) restoreResolver() {
	d.access.Lock()
	d.switched = false
	d.access.Unlock()
}

func (d *m2GPDialer) snapshot() (int, int, int, int, time.Time) {
	d.access.Lock()
	defer d.access.Unlock()
	return d.domainDials, d.pinnedDials, d.decoyDials, d.udpDials, d.udpClosedAt
}

func (d *m2GPDialer) closeUDP(t *testing.T) {
	t.Helper()
	d.access.Lock()
	conn := d.udpConn
	d.access.Unlock()
	if conn == nil {
		t.Fatal("GlobalProtect M2 dialer has no ESP connection to close")
	}
	err := conn.Close()
	if err != nil && !E.IsClosed(err) {
		t.Fatal(E.Cause(err, "inject GlobalProtect ESP socket failure"))
	}
}

func newM2GPClient(
	t *testing.T,
	ctx context.Context,
	peer *m2GPPeer,
	dialer *m2GPDialer,
	extra openconnect.ClientOptions,
) *openconnect.Client {
	t.Helper()
	serverPath := "/gateway"
	if peer.scenario.portal {
		serverPath = "/portal"
	}
	extra.Context = ctx
	extra.Server = "https://" + peer.authority + serverPath
	extra.Flavor = openconnect.FlavorGP
	extra.Username = m2GPUsername
	extra.Password = m2GPPassword
	extra.ReportedOS = "linux-64"
	extra.Dialer = dialer
	if extra.TLSConfig.Config == nil {
		extra.TLSConfig.Config = &tls.Config{InsecureSkipVerify: true}
	}
	client, err := openconnect.NewClient(extra)
	if err != nil {
		t.Fatal(E.Cause(err, "create GlobalProtect M2 client"))
	}
	t.Cleanup(func() {
		closeErr := client.Close()
		if dialer.udpCloseFailure && closeErr != nil && strings.Contains(closeErr.Error(), m2GPUDPCloseFailure) {
			return
		}
		if closeErr != nil && !E.IsClosed(closeErr) {
			t.Error(E.Cause(closeErr, "close GlobalProtect M2 client"))
		}
	})
	return client
}

func startM2GPClient(t *testing.T, client *openconnect.Client) {
	t.Helper()
	err := client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start GlobalProtect M2 client"))
	}
}

func waitForM2GPReady(t *testing.T, ctx context.Context, client *openconnect.Client, peer *m2GPPeer) {
	t.Helper()
	for !client.Ready() {
		select {
		case <-ctx.Done():
			t.Fatalf("wait for GlobalProtect M2 client readiness: %v peer=%#v form=%#v", ctx.Err(), peer.snapshot(), client.PendingAuthForm())
		case peerErr := <-peer.failures:
			t.Fatal(peerErr)
		case <-client.AuthFormUpdated():
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func waitForM2GPPeerState(
	t *testing.T,
	ctx context.Context,
	peer *m2GPPeer,
	ready func(snapshot m2GPPeerSnapshot) bool,
) {
	t.Helper()
	for !ready(peer.snapshot()) {
		select {
		case <-ctx.Done():
			t.Fatalf("wait for GlobalProtect M2 peer state: %v snapshot=%#v", ctx.Err(), peer.snapshot())
		case peerErr := <-peer.failures:
			t.Fatal(peerErr)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

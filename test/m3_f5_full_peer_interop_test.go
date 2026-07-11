package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
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
	m3F5FullPeerImage    = "sing-openconnect-f5-peer:m3"
	m3F5FullPeerHostname = "f5.test"
)

type m3F5FullPeerCase struct {
	name                string
	environment         map[string]string
	allowInsecureCrypto bool
	expectedCarrier     string
	expectedVersion     string
	expectedTunnels     []string
	expectedHostDials   int32
	lateTakeover        bool
	tlsRecovery         bool
	recoveryTransport   string
	forbiddenMarkers    []string
}

type m3F5FullPeerCertificateFixture struct {
	directory       string
	rootCertificate []byte
}

type m3F5FullPeer struct {
	name       string
	port       uint16
	local      *m3F5LocalPeer
	serverIPv4 netip.Addr
	clientIPv4 netip.Addr
	serverIPv6 netip.Addr
	clientIPv6 netip.Addr
}

type m3F5LocalPeer struct {
	logs *m3F5SynchronizedLogs
}

type m3F5SynchronizedLogs struct {
	access sync.Mutex
	buffer bytes.Buffer
}

var (
	m3F5PeerAddressSequence atomic.Uint32
	m3F5LocalOptionsAccess  sync.Mutex
	m3F5LocalOptionsReady   bool
	m3F5LocalOptionsOwned   bool
	m3F5LocalOptionsInode   uint64
)

type m3F5PinnedDialer struct {
	port          uint16
	maximumDials  int32
	hostnameDials atomic.Int32
}

//nolint:paralleltest // The full peers require privileged real-pppd containers and intentionally stress host networking.
func TestM3F5IndependentFullPeerMatrix(t *testing.T) {
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	_, dockerErr := dockerOutput(ctx, "version", "--format", "{{.Server.Version}}")
	if dockerErr != nil {
		t.Fatal(dockerErr)
	}
	_, buildErr := dockerOutput(ctx, "build", "--pull=false", "--tag", m3F5FullPeerImage, filepath.Join("testdata", "f5-peer"))
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	fixture := createM3F5FullPeerCertificateFixture(t)
	testCases := []m3F5FullPeerCase{
		{
			name:            "tls-plain-dual-stack",
			expectedCarrier: "TLS",
			expectedTunnels: []string{"F5_PEER_TLS_TUNNEL_1"},
		},
		{
			name:            "tls-hdlc-dual-stack",
			environment:     map[string]string{"HDLC": "1"},
			expectedCarrier: "TLS",
			expectedTunnels: []string{"F5_PEER_TLS_TUNNEL_1"},
		},
		{
			name:             "dtls12-first-dual-stack",
			environment:      map[string]string{"DTLS": "1", "DTLS12": "1"},
			expectedCarrier:  "DTLS",
			expectedVersion:  "F5_PEER_DTLS_LISTENING_12",
			expectedTunnels:  []string{"F5_PEER_DTLS_TUNNEL_1"},
			forbiddenMarkers: []string{"F5_PEER_TLS_TUNNEL_"},
		},
		{
			name:                "dtls10-first-dual-stack",
			environment:         map[string]string{"DTLS": "1", "DTLS12": "0"},
			allowInsecureCrypto: true,
			expectedCarrier:     "DTLS",
			expectedVersion:     "F5_PEER_DTLS_LISTENING_10",
			expectedTunnels:     []string{"F5_PEER_DTLS_TUNNEL_1"},
			forbiddenMarkers:    []string{"F5_PEER_TLS_TUNNEL_"},
		},
		{
			name:             "legacy-disabled-falls-back-without-clienthello",
			environment:      map[string]string{"DTLS": "1", "DTLS12": "0"},
			expectedCarrier:  "TLS",
			expectedVersion:  "F5_PEER_DTLS_LISTENING_10",
			expectedTunnels:  []string{"F5_PEER_TLS_TUNNEL_1"},
			forbiddenMarkers: []string{"F5_PEER_DTLS_TUNNEL_", "F5_PEER_OPENSSL CONNECTION ESTABLISHED"},
		},
		{
			name:            "malformed-dtls-probe-falls-back",
			environment:     map[string]string{"DTLS": "1", "DTLS12": "1", "MALFORMED_DTLS": "1"},
			expectedCarrier: "TLS",
			expectedVersion: "F5_PEER_DTLS_LISTENING_12",
			expectedTunnels: []string{"F5_PEER_DTLS_MALFORMED_RESPONSE", "F5_PEER_TLS_TUNNEL_2"},
		},
		{
			name: "dtls-certificate-rejection-falls-back",
			environment: map[string]string{
				"DTLS":             "1",
				"DTLS12":           "1",
				"DTLS_CERTIFICATE": "/certs/untrusted-cert.pem",
				"DTLS_PRIVATE_KEY": "/certs/untrusted-key.pem",
			},
			expectedCarrier:  "TLS",
			expectedVersion:  "F5_PEER_DTLS_LISTENING_12",
			expectedTunnels:  []string{"F5_PEER_TLS_TUNNEL_1"},
			forbiddenMarkers: []string{"F5_PEER_DTLS_TUNNEL_"},
		},
		{
			name:            "late-dtls12-takeover",
			environment:     map[string]string{"DTLS": "1", "DTLS12": "1", "DTLS_DELAY": "6"},
			expectedCarrier: "TLS",
			expectedVersion: "F5_PEER_DTLS_LISTENING_12",
			expectedTunnels: []string{"F5_PEER_TLS_TUNNEL_1", "F5_PEER_DTLS_TUNNEL_2"},
			lateTakeover:    true,
		},
		{
			name:              "dtls-carrier-loss-falls-back-to-tls",
			environment:       map[string]string{"DTLS": "1", "DTLS12": "1", "FAIL_FIRST_DTLS": "1"},
			expectedCarrier:   "DTLS",
			expectedVersion:   "F5_PEER_DTLS_LISTENING_12",
			expectedTunnels:   []string{"F5_PEER_DTLS_TUNNEL_1", "F5_PEER_FORCED_DTLS_FAILURE", "F5_PEER_TLS_TUNNEL_2"},
			tlsRecovery:       true,
			recoveryTransport: openconnect.TransportTLS,
		},
		{
			name:            "tls-carrier-recovery-reuses-config",
			environment:     map[string]string{"FAIL_FIRST_TLS": "1"},
			expectedCarrier: "TLS",
			expectedTunnels: []string{"F5_PEER_TLS_TUNNEL_1", "F5_PEER_FORCED_TLS_FAILURE", "F5_PEER_TLS_TUNNEL_2"},
			tlsRecovery:     true,
		},
		{
			name:              "deferred-primary-password-survives-reauthentication",
			environment:       map[string]string{"DEFER_PASSWORD": "1", "REJECT_FIRST_TLS": "1"},
			expectedCarrier:   "TLS",
			expectedTunnels:   []string{"F5_PEER_PRE_PASSWORD_FORM_2", "F5_PEER_PRIMARY_PASSWORD_2", "F5_PEER_TLS_SESSION_REJECTED", "F5_PEER_TLS_TUNNEL_2", "F5_PEER_PROFILE_2"},
			expectedHostDials: 8,
		},
		{
			name:              "tls-504-reauthenticates",
			environment:       map[string]string{"REJECT_FIRST_TLS": "1"},
			expectedCarrier:   "TLS",
			expectedTunnels:   []string{"F5_PEER_TLS_SESSION_REJECTED", "F5_PEER_TLS_TUNNEL_2", "F5_PEER_PROFILE_2"},
			expectedHostDials: 6,
		},
		{
			name:              "dtls-403-reauthenticates",
			environment:       map[string]string{"DTLS": "1", "DTLS12": "1", "REJECT_FIRST_DTLS": "1"},
			expectedCarrier:   "TLS",
			expectedVersion:   "F5_PEER_DTLS_LISTENING_12",
			expectedTunnels:   []string{"F5_PEER_DTLS_SESSION_REJECTED", "F5_PEER_TLS_TUNNEL_2", "F5_PEER_PROFILE_2"},
			expectedHostDials: 6,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			addressIndex := m3F5PeerAddressSequence.Add(1)
			if addressIndex > 127 {
				t.Fatal("independent F5 peer address sequence exhausted")
			}
			environment := make(map[string]string, len(testCase.environment)+1)
			for name, value := range testCase.environment {
				environment[name] = value
			}
			environment["ADDRESS_INDEX"] = strconv.FormatUint(uint64(addressIndex), 10)
			peer := startM3F5FullPeer(t, ctx, fixture, environment, addressIndex)
			runM3F5FullPeerCase(t, ctx, peer, fixture.rootCertificate, testCase)
		})
	}
}

//nolint:paralleltest // The independent peer probes privileged real-pppd availability before exercising authentication.
func TestM3F5AuthenticationNon2xxIsTerminal(t *testing.T) {
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, dockerErr := dockerOutput(ctx, "version", "--format", "{{.Server.Version}}")
	if dockerErr != nil {
		t.Fatal(dockerErr)
	}
	_, buildErr := dockerOutput(ctx, "build", "--pull=false", "--tag", m3F5FullPeerImage, filepath.Join("testdata", "f5-peer"))
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	fixture := createM3F5FullPeerCertificateFixture(t)
	addressIndex := m3F5PeerAddressSequence.Add(1)
	if addressIndex > 127 {
		t.Fatal("independent F5 peer address sequence exhausted")
	}
	peer := startM3F5FullPeer(t, ctx, fixture, map[string]string{
		"ADDRESS_INDEX":       strconv.FormatUint(uint64(addressIndex), 10),
		"AUTH_FAILURE_STATUS": "401",
	}, addressIndex)
	dialer := &m3F5PinnedDialer{port: peer.port, maximumDials: 3}
	client, clientErr := openconnect.NewClient(openconnect.ClientOptions{
		Context:  ctx,
		Server:   "https://" + net.JoinHostPort(m3F5FullPeerHostname, strconv.Itoa(int(peer.port))),
		Flavor:   openconnect.FlavorF5,
		Username: "test",
		Password: "test",
		Dialer:   dialer,
		TLSConfig: openconnect.ClientTLSOptions{
			CertificateAuthority: openconnect.Material{Content: fixture.rootCertificate},
		},
	})
	if clientErr != nil {
		t.Fatal(E.Cause(clientErr, "create non-2xx F5 authentication client"))
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	startErr := client.Start()
	if startErr != nil {
		t.Fatal(E.Cause(startErr, "start non-2xx F5 authentication client"))
	}
	terminalContext, cancelTerminal := context.WithTimeout(ctx, 10*time.Second)
	_, terminalErr := client.ReadDataPacket(terminalContext)
	cancelTerminal()
	if terminalErr == nil || !strings.Contains(terminalErr.Error(), "unexpected HTTP status 401 Unauthorized") {
		t.Fatalf(
			"F5 authentication 401 was not a status-specific terminal protocol error: %v; dials=%d pending=%#v logs:\n%s",
			terminalErr,
			dialer.hostnameDials.Load(),
			client.PendingAuthForm(),
			m3F5PeerLogs(t, ctx, peer),
		)
	}
	if client.Ready() || client.PendingAuthForm() != nil {
		t.Fatal("F5 authentication 401 left a ready session or repeated credential form")
	}
	waitM3F5PeerMarker(t, ctx, peer, "F5_PEER_AUTH_REJECTED_401_1", 5*time.Second)
	logs := m3F5PeerLogs(t, ctx, peer)
	if strings.Count(logs, "F5_PEER_AUTH_REJECTED_401_") != 1 || dialer.hostnameDials.Load() != 3 {
		t.Fatalf("F5 authentication 401 retried credentials: dials=%d logs:\n%s", dialer.hostnameDials.Load(), logs)
	}
	for _, marker := range []string{"F5_PEER_PROFILE_", "F5_PEER_TLS_TUNNEL_", "F5_PEER_DTLS_TUNNEL_", "F5_PEER_CLIENT_IPV4"} {
		if strings.Contains(logs, marker) {
			t.Fatalf("F5 authentication 401 advanced past authentication (%s):\n%s", marker, logs)
		}
	}
}

func startM3F5FullPeer(
	t *testing.T,
	ctx context.Context,
	fixture m3F5FullPeerCertificateFixture,
	environment map[string]string,
	addressIndex uint32,
) m3F5FullPeer {
	t.Helper()
	port := reserveM3F5FullPeerPort(t)
	serverHost := addressIndex*2 - 1
	clientHost := addressIndex * 2
	peer := m3F5FullPeer{
		port:       port,
		serverIPv4: netip.AddrFrom4([4]byte{192, 0, 2, byte(serverHost)}),
		clientIPv4: netip.AddrFrom4([4]byte{192, 0, 2, byte(clientHost)}),
		serverIPv6: netip.MustParseAddr("fe80::" + strconv.FormatUint(uint64(serverHost), 16)),
		clientIPv6: netip.MustParseAddr("fe80::" + strconv.FormatUint(uint64(clientHost), 16)),
	}
	if runtime.GOOS == "darwin" {
		peer.local = startM3F5LocalPeer(t, port, fixture, environment)
		waitM3F5PeerMarker(t, ctx, peer, "F5_PEER_TLS_LISTENING", 20*time.Second)
		return peer
	}
	portText := strconv.Itoa(int(port))
	containerName := "sing-openconnect-m3-f5-full-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	arguments := []string{
		"run", "--detach", "--name", containerName, "--privileged",
		"--publish", "127.0.0.1:" + portText + ":" + portText + "/tcp",
		"--publish", "127.0.0.1:" + portText + ":" + portText + "/udp",
		"--mount", "type=bind,source=" + fixture.directory + ",target=/certs,readonly",
		"--env", "PORT=" + portText,
	}
	for name, value := range environment {
		arguments = append(arguments, "--env", name+"="+value)
	}
	arguments = append(arguments, m3F5FullPeerImage)
	_, runErr := dockerOutput(ctx, arguments...)
	if runErr != nil {
		t.Fatal(runErr)
	}
	peer.name = containerName
	t.Cleanup(func() {
		if t.Failed() {
			logsContext, cancelLogs := context.WithTimeout(context.Background(), 5*time.Second)
			logs, logsErr := dockerOutput(logsContext, "logs", containerName)
			cancelLogs()
			if logsErr == nil {
				t.Log("independent F5 peer logs:\n" + logs)
			}
		}
		removeContext, cancelRemove := context.WithTimeout(context.Background(), 10*time.Second)
		_, _ = dockerOutput(removeContext, "rm", "--force", containerName)
		cancelRemove()
	})
	waitM3F5PeerMarker(t, ctx, peer, "F5_PEER_TLS_LISTENING", 20*time.Second)
	pppDeviceProbe := "import os,stat\ntry:\n os.mknod('/dev/ppp',stat.S_IFCHR|0o600,os.makedev(108,0))\nexcept FileExistsError:\n pass\ndescriptor=os.open('/dev/ppp',os.O_RDWR)\nos.close(descriptor)"
	_, pppDeviceErr := dockerOutput(ctx, "exec", containerName, "python3", "-c", pppDeviceProbe)
	if pppDeviceErr != nil {
		if runtime.GOOS != "darwin" {
			t.Fatal(E.Cause(pppDeviceErr, "independent F5 peer has no usable real pppd device"))
		}
		_, _ = dockerOutput(ctx, "rm", "--force", containerName)
		localPeer := startM3F5LocalPeer(t, port, fixture, environment)
		peer.name = ""
		peer.local = localPeer
		waitM3F5PeerMarker(t, ctx, peer, "F5_PEER_TLS_LISTENING", 20*time.Second)
	} else {
		version, versionErr := dockerOutput(ctx, "exec", containerName, "dpkg-query", "-W", "-f=${Version}", "ppp")
		if versionErr != nil || strings.TrimSpace(version) != "2.5.2-1+1" {
			t.Fatal(E.Errors(E.New("unexpected independent F5 Docker pppd version: ", strings.TrimSpace(version)), versionErr))
		}
	}
	return peer
}

func runM3F5FullPeerCase(
	t *testing.T,
	ctx context.Context,
	peer m3F5FullPeer,
	rootCertificate []byte,
	testCase m3F5FullPeerCase,
) {
	t.Helper()
	expectedHostDials := testCase.expectedHostDials
	if expectedHostDials == 0 {
		expectedHostDials = 3
	}
	maximumHostDials := expectedHostDials
	if expectedHostDials > 3 {
		maximumHostDials += 6
	}
	if testCase.expectedVersion != "" && !testCase.lateTakeover {
		waitM3F5PeerMarker(t, ctx, peer, testCase.expectedVersion, 10*time.Second)
	}
	dialer := &m3F5PinnedDialer{port: peer.port, maximumDials: maximumHostDials}
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 16)
	client, clientErr := openconnect.NewClient(openconnect.ClientOptions{
		Context:             ctx,
		Server:              "https://" + net.JoinHostPort(m3F5FullPeerHostname, strconv.Itoa(int(peer.port))),
		Flavor:              openconnect.FlavorF5,
		Username:            "test",
		Password:            "test",
		AllowInsecureCrypto: testCase.allowInsecureCrypto,
		Dialer:              dialer,
		TLSConfig: openconnect.ClientTLSOptions{
			CertificateAuthority: openconnect.Material{Content: rootCertificate},
		},
		OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
			configurationEvents <- event
			return nil
		},
	})
	if clientErr != nil {
		t.Fatal(E.Cause(clientErr, "create independent F5 client"))
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	activeTransportUpdated := client.ActiveTransportUpdated()
	startErr := client.Start()
	if startErr != nil {
		t.Fatal(E.Cause(startErr, "start independent F5 client"))
	}
	initialEvent := waitM3F5ConfigurationEvent(t, client, configurationEvents, openconnect.TunnelConfigurationEventInitial, 40*time.Second)
	assertM3F5Configuration(t, initialEvent.Configuration, peer)
	expectedInitialTransport := openconnect.TransportTLS
	if testCase.expectedCarrier == "DTLS" {
		expectedInitialTransport = openconnect.TransportDTLS
	}
	waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, expectedInitialTransport)
	actualHostDials := dialer.hostnameDials.Load()
	if expectedHostDials == 3 && actualHostDials != expectedHostDials ||
		expectedHostDials > 3 && (actualHostDials < expectedHostDials || actualHostDials > maximumHostDials) {
		t.Fatalf("F5 accepted-endpoint pinning used %d logical-host dials; expected %d authentication dials", dialer.hostnameDials.Load(), expectedHostDials)
	}
	if testCase.tlsRecovery {
		if testCase.recoveryTransport != "" {
			activeTransportUpdated = client.ActiveTransportUpdated()
		}
		request := buildIPv4ICMPEchoRequest(
			t,
			peer.clientIPv4,
			peer.serverIPv4,
			0x4d35,
			1,
			[]byte("sing-openconnect-m3-f5-trigger-recovery"),
		)
		writeErr := client.WriteDataPacket(request)
		if writeErr != nil {
			t.Fatal(E.Cause(writeErr, "trigger independent F5 carrier recovery"))
		}
		if testCase.recoveryTransport != "" {
			waitForActiveTransportLossAndRecovery(t, ctx, client, activeTransportUpdated, testCase.recoveryTransport)
		}
		reestablished := waitM3F5ConfigurationEvent(t, client, configurationEvents, openconnect.TunnelConfigurationEventReestablishment, 40*time.Second)
		assertM3F5Configuration(t, reestablished.Configuration, peer)
		exchangeM3F5IPv4(t, ctx, client, peer, 2)
		exchangeM3F5IPv6(t, ctx, client, peer, 2)
	} else if testCase.lateTakeover {
		activeTransportUpdated = client.ActiveTransportUpdated()
		exchangeM3F5IPv4(t, ctx, client, peer, 1)
		reestablished := waitM3F5ConfigurationEvent(t, client, configurationEvents, openconnect.TunnelConfigurationEventReestablishment, 40*time.Second)
		assertM3F5Configuration(t, reestablished.Configuration, peer)
		waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportDTLS)
		exchangeM3F5IPv4(t, ctx, client, peer, 2)
		exchangeM3F5IPv6(t, ctx, client, peer, 2)
	} else {
		exchangeM3F5IPv4(t, ctx, client, peer, 1)
		exchangeM3F5IPv6(t, ctx, client, peer, 1)
	}
	requiredMarkers := []string{
		"F5_PEER_AUTHENTICATED",
		"F5_PEER_PROFILE_1",
		"F5_PEER_OPTIONS",
		"F5_PEER_TUNNEL_REQUEST_EXACT",
		"F5_PEER_TUNNEL_COOKIE_FREE",
		"F5_PEER_SNI_" + m3F5FullPeerHostname,
		"F5_PEER_PPPD_ECHO_REQUEST",
		"F5_PEER_CLIENT_IPV4 ",
		"F5_PEER_CLIENT_IPV6 ",
		"F5_PEER_PPPD_IPV4 ",
		"F5_PEER_PPPD_IPV6 ",
	}
	for _, marker := range requiredMarkers {
		waitM3F5PeerMarker(t, ctx, peer, marker, 10*time.Second)
	}
	logs := m3F5PeerLogs(t, ctx, peer)
	for _, marker := range requiredMarkers {
		if !strings.Contains(logs, marker) {
			t.Fatalf("independent F5 peer did not report %s:\n%s", marker, logs)
		}
	}
	if testCase.expectedVersion != "" && !strings.Contains(logs, testCase.expectedVersion) {
		t.Fatalf("independent F5 peer did not report %s:\n%s", testCase.expectedVersion, logs)
	}
	for _, marker := range testCase.expectedTunnels {
		if !strings.Contains(logs, marker) {
			t.Fatalf("independent F5 peer did not report %s:\n%s", marker, logs)
		}
	}
	for _, marker := range testCase.forbiddenMarkers {
		if strings.Contains(logs, marker) {
			t.Fatalf("independent F5 peer unexpectedly reported %s:\n%s", marker, logs)
		}
	}
	if testCase.expectedCarrier == "TLS" {
		for _, marker := range []string{"F5_PEER_STREAM_SPLIT", "F5_PEER_STREAM_COALESCED"} {
			if !strings.Contains(logs, marker) {
				t.Fatalf("independent F5 stream peer did not report %s:\n%s", marker, logs)
			}
		}
	}
	if testCase.tlsRecovery && strings.Contains(logs, "F5_PEER_PROFILE_2") {
		t.Fatalf("F5 carrier recovery refetched immutable configuration:\n%s", logs)
	}
	closeErr := client.Close()
	if closeErr != nil {
		t.Fatal(E.Cause(closeErr, "close independent F5 client"))
	}
	waitM3F5PeerMarker(t, ctx, peer, "F5_PEER_LOGOUT", 10*time.Second)
	waitM3F5PeerMarker(t, ctx, peer, "F5_PEER_PPP_BRIDGE_CLOSED", 10*time.Second)
	closedLogs := m3F5PeerLogs(t, ctx, peer)
	for _, marker := range []string{"F5_PEER_CLIENT_TERMINATE_REQUEST", "F5_PEER_PPP_BRIDGE_CLOSED", "F5_PEER_LOGOUT"} {
		if !strings.Contains(closedLogs, marker) {
			t.Fatalf("independent F5 clean close did not report %s:\n%s", marker, closedLogs)
		}
	}
}

func waitM3F5ConfigurationEvent(
	t *testing.T,
	client *openconnect.Client,
	events <-chan openconnect.TunnelConfigurationEvent,
	reason openconnect.TunnelConfigurationEventReason,
	timeout time.Duration,
) openconnect.TunnelConfigurationEvent {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if form := client.PendingAuthForm(); form != nil {
			t.Fatalf("independent F5 peer unexpectedly required interactive authentication: %#v", form)
		}
		select {
		case event := <-events:
			if event.Reason == reason {
				return event
			}
		case <-timer.C:
			t.Fatal("timed out waiting for F5 tunnel configuration event " + string(reason))
		case <-ticker.C:
		}
	}
}

func assertM3F5Configuration(t *testing.T, configuration openconnect.TunnelConfiguration, peer m3F5FullPeer) {
	t.Helper()
	expectedAddresses := []netip.Prefix{
		netip.PrefixFrom(peer.clientIPv4, 32),
		netip.PrefixFrom(peer.clientIPv6, 64),
	}
	expectedDNS := []netip.Addr{netip.MustParseAddr("203.0.113.53"), netip.MustParseAddr("203.0.113.54")}
	expectedNBNS := []netip.Addr{netip.MustParseAddr("203.0.113.137"), netip.MustParseAddr("203.0.113.138")}
	if configuration.MTU != 1320 || !slices.Equal(configuration.Addresses, expectedAddresses) ||
		!slices.Equal(configuration.DNS, expectedDNS) || !slices.Equal(configuration.NBNS, expectedNBNS) ||
		!slices.Equal(configuration.SearchDomains, []string{"f5.test"}) ||
		!slices.Equal(configuration.SplitDNS, []string{"internal.f5.test"}) ||
		configuration.IdleTimeout != 15*time.Minute || configuration.AuthenticationExpiration.IsZero() {
		t.Fatalf("unexpected independent F5 configuration: %+v", configuration)
	}
	for _, expectedPrefix := range []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	} {
		if !slices.ContainsFunc(configuration.Routes, func(route openconnect.TunnelRoute) bool {
			return route.Prefix == expectedPrefix
		}) {
			t.Fatalf("independent F5 configuration omitted route %s: %+v", expectedPrefix, configuration.Routes)
		}
	}
	if !slices.ContainsFunc(configuration.ExcludedRoutes, func(route openconnect.TunnelRoute) bool {
		return route.Prefix == netip.MustParsePrefix("198.51.100.128/25")
	}) {
		t.Fatalf("independent F5 configuration omitted excluded route: %+v", configuration.ExcludedRoutes)
	}
}

func exchangeM3F5IPv4(t *testing.T, ctx context.Context, client *openconnect.Client, peer m3F5FullPeer, sequence uint16) {
	t.Helper()
	clientAddress := peer.clientIPv4
	serverAddress := peer.serverIPv4
	payload := []byte("sing-openconnect-m3-f5-ipv4")
	request := buildIPv4ICMPEchoRequest(t, clientAddress, serverAddress, 0x4d35, sequence, payload)
	exchangeM3F5Packet(t, ctx, client, request, 4, func(packet []byte) error {
		return validateIPv4ICMPEchoReply(packet, clientAddress, serverAddress, 0x4d35, sequence, payload)
	})
}

func exchangeM3F5IPv6(t *testing.T, ctx context.Context, client *openconnect.Client, peer m3F5FullPeer, sequence uint16) {
	t.Helper()
	clientAddress := peer.clientIPv6
	serverAddress := peer.serverIPv6
	payload := []byte("sing-openconnect-m3-f5-ipv6")
	request := buildM2GPIPv6ICMPEchoRequest(t, clientAddress, serverAddress, 0x4d36, sequence, payload)
	exchangeM3F5Packet(t, ctx, client, request, 6, func(packet []byte) error {
		return validateM2GPIPv6ICMPEchoReply(packet, clientAddress, serverAddress, 0x4d36, sequence, payload)
	})
}

func exchangeM3F5Packet(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	request []byte,
	version byte,
	validate func([]byte) error,
) {
	t.Helper()
	exchangeContext, cancelExchange := context.WithTimeout(ctx, 25*time.Second)
	defer cancelExchange()
	var lastValidationErr error
	for exchangeContext.Err() == nil {
		writeErr := client.WriteDataPacket(request)
		if writeErr != nil {
			t.Fatal(E.Cause(writeErr, "write IPv", version, " packet through independent F5 peer"))
		}
		readContext, cancelRead := context.WithTimeout(exchangeContext, 1500*time.Millisecond)
		for {
			packet, readErr := client.ReadDataPacket(readContext)
			if readErr != nil {
				if readContext.Err() != nil {
					break
				}
				cancelRead()
				t.Fatal(E.Cause(readErr, "read IPv", version, " packet from independent F5 peer"))
			}
			if !isM3F5ICMPEchoReply(packet, version) {
				continue
			}
			lastValidationErr = validate(packet)
			if lastValidationErr == nil {
				cancelRead()
				return
			}
		}
		cancelRead()
	}
	if lastValidationErr != nil {
		t.Fatal(E.Cause(lastValidationErr, "validate IPv", version, " reply from independent F5 peer"))
	}
	t.Fatal(E.Cause(exchangeContext.Err(), "exchange IPv", version, " packet with independent F5 peer"))
}

func isM3F5ICMPEchoReply(packet []byte, version byte) bool {
	if len(packet) == 0 || packet[0]>>4 != version {
		return false
	}
	if version == 4 && len(packet) >= 20 && packet[9] == 1 {
		headerLength := int(packet[0]&0xf) * 4
		return headerLength >= 20 && len(packet) > headerLength && packet[headerLength] == 0
	}
	return version == 6 && len(packet) >= 41 && packet[6] == 58 && packet[40] == 129
}

func createM3F5FullPeerCertificateFixture(t *testing.T) m3F5FullPeerCertificateFixture {
	t.Helper()
	now := time.Now()
	rootKey, rootKeyErr := rsa.GenerateKey(rand.Reader, 2048)
	if rootKeyErr != nil {
		t.Fatal(E.Cause(rootKeyErr, "generate independent F5 root key"))
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sing-openconnect independent F5 root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootData, rootCertificate := createSignedInteropCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	serverKey, serverKeyErr := rsa.GenerateKey(rand.Reader, 2048)
	if serverKeyErr != nil {
		t.Fatal(E.Cause(serverKeyErr, "generate independent F5 server key"))
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: m3F5FullPeerHostname},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{m3F5FullPeerHostname},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverData, _ := createSignedInteropCertificate(t, serverTemplate, rootCertificate, serverKey.Public(), rootKey)
	directory := t.TempDir()
	certificateErr := os.WriteFile(filepath.Join(directory, "server-cert.pem"), joinCertificatePEM(serverData), 0o600)
	if certificateErr != nil {
		t.Fatal(E.Cause(certificateErr, "write independent F5 server certificate"))
	}
	keyErr := os.WriteFile(filepath.Join(directory, "server-key.pem"), marshalInteropPrivateKey(t, serverKey), 0o600)
	if keyErr != nil {
		t.Fatal(E.Cause(keyErr, "write independent F5 server key"))
	}
	untrustedRootKey, untrustedRootKeyErr := rsa.GenerateKey(rand.Reader, 2048)
	if untrustedRootKeyErr != nil {
		t.Fatal(E.Cause(untrustedRootKeyErr, "generate untrusted F5 DTLS root key"))
	}
	untrustedRootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "sing-openconnect untrusted F5 DTLS root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	_, untrustedRootCertificate := createSignedInteropCertificate(
		t,
		untrustedRootTemplate,
		untrustedRootTemplate,
		untrustedRootKey.Public(),
		untrustedRootKey,
	)
	untrustedServerKey, untrustedServerKeyErr := rsa.GenerateKey(rand.Reader, 2048)
	if untrustedServerKeyErr != nil {
		t.Fatal(E.Cause(untrustedServerKeyErr, "generate untrusted F5 DTLS server key"))
	}
	untrustedServerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: m3F5FullPeerHostname},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{m3F5FullPeerHostname},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	untrustedServerData, _ := createSignedInteropCertificate(
		t,
		untrustedServerTemplate,
		untrustedRootCertificate,
		untrustedServerKey.Public(),
		untrustedRootKey,
	)
	untrustedCertificateErr := os.WriteFile(
		filepath.Join(directory, "untrusted-cert.pem"),
		joinCertificatePEM(untrustedServerData),
		0o600,
	)
	if untrustedCertificateErr != nil {
		t.Fatal(E.Cause(untrustedCertificateErr, "write untrusted F5 DTLS server certificate"))
	}
	untrustedKeyErr := os.WriteFile(
		filepath.Join(directory, "untrusted-key.pem"),
		marshalInteropPrivateKey(t, untrustedServerKey),
		0o600,
	)
	if untrustedKeyErr != nil {
		t.Fatal(E.Cause(untrustedKeyErr, "write untrusted F5 DTLS server key"))
	}
	return m3F5FullPeerCertificateFixture{
		directory:       directory,
		rootCertificate: joinCertificatePEM(rootData),
	}
}

func startM3F5LocalPeer(
	t *testing.T,
	port uint16,
	fixture m3F5FullPeerCertificateFixture,
	environment map[string]string,
) *m3F5LocalPeer {
	t.Helper()
	prepareM3F5LocalPPPOptions(t)
	scriptPath, pathErr := filepath.Abs(filepath.Join("testdata", "f5-peer", "f5_peer.py"))
	if pathErr != nil {
		t.Fatal(E.Cause(pathErr, "resolve independent local F5 peer path"))
	}
	opensslPath := filepath.Join("/opt/homebrew/opt/openssl@3", "bin", "openssl")
	_, statErr := os.Stat(opensslPath)
	if statErr != nil {
		t.Fatal(E.Cause(statErr, "locate Homebrew OpenSSL for independent F5 DTLS peer"))
	}
	versionCommand := exec.Command("sudo", "-n", "/usr/sbin/pppd", "--version")
	versionOutput, versionErr := versionCommand.CombinedOutput()
	if versionErr != nil || !strings.Contains(string(versionOutput), "2.4.2") {
		t.Fatal(E.Errors(E.New("unexpected independent F5 system pppd version: ", strings.TrimSpace(string(versionOutput))), versionErr))
	}
	environmentValues := []string{
		"PORT=" + strconv.Itoa(int(port)),
		"CERTIFICATE=" + filepath.Join(fixture.directory, "server-cert.pem"),
		"PRIVATE_KEY=" + filepath.Join(fixture.directory, "server-key.pem"),
		"OPENSSL=" + opensslPath,
		"PPPD=/usr/sbin/pppd",
		"PPPD_USE_SUDO=1",
	}
	for name, value := range environment {
		if strings.HasPrefix(value, "/certs/") {
			value = filepath.Join(fixture.directory, strings.TrimPrefix(value, "/certs/"))
		}
		environmentValues = append(environmentValues, name+"="+value)
	}
	logs := &m3F5SynchronizedLogs{}
	_, _ = logs.Write([]byte("F5_PEER_PPPD_VERSION " + strings.TrimSpace(string(versionOutput)) + "\n"))
	command := exec.Command("/usr/bin/python3", scriptPath)
	command.Env = append(os.Environ(), environmentValues...)
	command.Stdout = logs
	command.Stderr = logs
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	startErr := command.Start()
	if startErr != nil {
		t.Fatal(E.Cause(startErr, "start independent local F5 peer"))
	}
	done := make(chan error, 1)
	go func() {
		done <- command.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		if t.Failed() {
			t.Log("independent local F5 peer logs:\n" + logs.String())
		}
		finished := false
		select {
		case <-done:
			finished = true
		default:
		}
		if !finished {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		}
		if !finished {
			timer := time.NewTimer(15 * time.Second)
			select {
			case <-done:
				if !timer.Stop() {
					<-timer.C
				}
			case <-timer.C:
				_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
				<-done
			}
		}
		closedLogs := logs.String()
		if !strings.Contains(closedLogs, "F5_PEER_CHILDREN_REAPED") {
			t.Errorf("independent local F5 peer exited without confirming child-process reaping; logs:\n%s", closedLogs)
		}
		assertNoM3LocalPeerProcess(t, "F5", command.Process.Pid, scriptPath)
		assertNoM3LocalOpenSSLProcesses(t, "F5", fixture.directory)
	})
	return &m3F5LocalPeer{logs: logs}
}

func assertNoM3LocalPeerProcess(t *testing.T, flavor string, processID int, scriptPath string) {
	t.Helper()
	process, listErr := m3LocalPeerProcess(processID, scriptPath)
	if listErr != nil {
		t.Errorf("inspect independent local %s peer process: %v", flavor, listErr)
		return
	}
	if process == "" {
		return
	}
	_ = syscall.Kill(-processID, syscall.SIGTERM)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		remaining, remainingErr := m3LocalPeerProcess(processID, scriptPath)
		if remainingErr == nil && remaining == "" {
			t.Errorf("independent local %s peer process escaped parent cleanup; cleanup terminated it: %s", flavor, process)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = syscall.Kill(-processID, syscall.SIGKILL)
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		remaining, remainingErr := m3LocalPeerProcess(processID, scriptPath)
		if remainingErr == nil && remaining == "" {
			t.Errorf("independent local %s peer process escaped parent cleanup; cleanup killed it: %s", flavor, process)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("independent local %s peer process survived SIGKILL: %s", flavor, process)
}

func m3LocalPeerProcess(processID int, scriptPath string) (string, error) {
	output, commandErr := exec.Command("/bin/ps", "-axo", "pid=,pgid=,command=").Output()
	if commandErr != nil {
		return "", commandErr
	}
	processIDText := strconv.Itoa(processID)
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != processIDText || fields[1] != processIDText {
			continue
		}
		if strings.Contains(strings.Join(fields[2:], " "), scriptPath) {
			return strings.TrimSpace(line), nil
		}
	}
	return "", nil
}

func assertNoM3LocalOpenSSLProcesses(t *testing.T, flavor string, fixtureDirectory string) {
	t.Helper()
	processGroups, listErr := m3LocalOpenSSLProcessGroups(fixtureDirectory)
	if listErr != nil {
		t.Errorf("inspect independent local %s OpenSSL processes: %v", flavor, listErr)
		return
	}
	if len(processGroups) == 0 {
		return
	}
	for processGroup := range processGroups {
		_ = syscall.Kill(-processGroup, syscall.SIGTERM)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		remaining, remainingErr := m3LocalOpenSSLProcessGroups(fixtureDirectory)
		if remainingErr == nil && len(remaining) == 0 {
			t.Errorf("independent local %s peer leaked OpenSSL process groups %v; cleanup terminated them", flavor, processGroups)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	remaining, remainingErr := m3LocalOpenSSLProcessGroups(fixtureDirectory)
	if remainingErr != nil {
		t.Errorf("reinspect independent local %s OpenSSL processes: %v", flavor, remainingErr)
		return
	}
	for processGroup := range remaining {
		_ = syscall.Kill(-processGroup, syscall.SIGKILL)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		remaining, remainingErr = m3LocalOpenSSLProcessGroups(fixtureDirectory)
		if remainingErr == nil && len(remaining) == 0 {
			t.Errorf("independent local %s peer leaked OpenSSL process groups %v; cleanup killed them", flavor, processGroups)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("independent local %s peer left fixture-owned OpenSSL process groups after SIGKILL: %v", flavor, remaining)
}

func m3LocalOpenSSLProcessGroups(fixtureDirectory string) (map[int]string, error) {
	output, commandErr := exec.Command("/bin/ps", "-axo", "pid=,pgid=,command=").Output()
	if commandErr != nil {
		return nil, commandErr
	}
	processGroups := make(map[int]string)
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		command := strings.Join(fields[2:], " ")
		if !strings.Contains(command, "openssl") || !strings.Contains(command, "s_server") ||
			!strings.Contains(command, fixtureDirectory+string(os.PathSeparator)) {
			continue
		}
		processGroup, parseErr := strconv.Atoi(fields[1])
		if parseErr != nil {
			return nil, E.Cause(parseErr, "parse independent local OpenSSL process group")
		}
		if processGroup > 1 {
			processGroups[processGroup] = strings.TrimSpace(line)
		}
	}
	return processGroups, nil
}

func prepareM3F5LocalPPPOptions(t *testing.T) {
	t.Helper()
	m3F5LocalOptionsAccess.Lock()
	defer m3F5LocalOptionsAccess.Unlock()
	if m3F5LocalOptionsReady {
		return
	}
	optionsInfo, statErr := os.Stat("/etc/ppp/options")
	if statErr == nil {
		if optionsInfo.Size() != 0 {
			t.Fatal("refusing to use nonempty /etc/ppp/options for independent F5 real-pppd peer")
		}
		m3F5LocalOptionsReady = true
		m3F5LocalOptionsOwned = false
		return
	}
	if !os.IsNotExist(statErr) {
		t.Fatal(E.Cause(statErr, "inspect local PPP options for independent F5 peer"))
	}
	temporary, temporaryErr := os.CreateTemp("/tmp", "sing-openconnect-f5-ppp-options-")
	if temporaryErr != nil {
		t.Fatal(E.Cause(temporaryErr, "create temporary local PPP options for independent F5 peer"))
	}
	temporaryPath := temporary.Name()
	closeErr := temporary.Close()
	if closeErr != nil {
		_ = os.Remove(temporaryPath)
		t.Fatal(E.Cause(closeErr, "close temporary local PPP options for independent F5 peer"))
	}
	defer os.Remove(temporaryPath)
	moveCommand := exec.Command("sudo", "-n", "/bin/mv", "-n", temporaryPath, "/etc/ppp/options")
	moveOutput, moveErr := moveCommand.CombinedOutput()
	if moveErr != nil {
		t.Fatal(E.Cause(moveErr, "install temporary local PPP options for independent F5 peer: ", strings.TrimSpace(string(moveOutput))))
	}
	installedInfo, installedErr := os.Stat("/etc/ppp/options")
	if installedErr != nil {
		t.Fatal(E.Cause(installedErr, "verify temporary local PPP options for independent F5 peer"))
	}
	installedStat, loaded := installedInfo.Sys().(*syscall.Stat_t)
	if !loaded || installedInfo.Size() != 0 {
		t.Fatal("temporary local PPP options for independent F5 peer is not an empty regular file")
	}
	m3F5LocalOptionsReady = true
	m3F5LocalOptionsOwned = true
	m3F5LocalOptionsInode = installedStat.Ino
	t.Cleanup(func() {
		m3F5LocalOptionsAccess.Lock()
		defer m3F5LocalOptionsAccess.Unlock()
		if !m3F5LocalOptionsOwned {
			m3F5LocalOptionsReady = false
			return
		}
		currentInfo, currentErr := os.Stat("/etc/ppp/options")
		if currentErr != nil {
			t.Errorf("temporary local PPP options disappeared before independent F5 cleanup: %v", currentErr)
			m3F5LocalOptionsReady = false
			m3F5LocalOptionsOwned = false
			return
		}
		currentStat, currentLoaded := currentInfo.Sys().(*syscall.Stat_t)
		if !currentLoaded || currentStat.Ino != m3F5LocalOptionsInode || currentInfo.Size() != 0 {
			t.Error("temporary local PPP options changed; refusing independent F5 cleanup")
			m3F5LocalOptionsReady = false
			m3F5LocalOptionsOwned = false
			return
		}
		removeCommand := exec.Command("sudo", "-n", "/bin/rm", "/etc/ppp/options")
		removeOutput, removeErr := removeCommand.CombinedOutput()
		if removeErr != nil {
			t.Errorf("remove temporary local PPP options after independent F5 peer: %v: %s", removeErr, strings.TrimSpace(string(removeOutput)))
		}
		m3F5LocalOptionsReady = false
		m3F5LocalOptionsOwned = false
		m3F5LocalOptionsInode = 0
	})
}

func (l *m3F5SynchronizedLogs) Write(content []byte) (int, error) {
	l.access.Lock()
	defer l.access.Unlock()
	return l.buffer.Write(content)
}

func (l *m3F5SynchronizedLogs) String() string {
	l.access.Lock()
	defer l.access.Unlock()
	return l.buffer.String()
}

func reserveM3F5FullPeerPort(t *testing.T) uint16 {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		listener, listenErr := net.Listen("tcp4", "127.0.0.1:0")
		if listenErr != nil {
			t.Fatal(E.Cause(listenErr, "reserve independent F5 TCP port"))
		}
		port := listener.Addr().(*net.TCPAddr).Port
		packetConn, packetErr := net.ListenPacket("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if packetErr == nil {
			closePacketErr := packetConn.Close()
			closeListenerErr := listener.Close()
			if closePacketErr != nil || closeListenerErr != nil {
				t.Fatal(E.Errors(closePacketErr, closeListenerErr))
			}
			return uint16(port)
		}
		_ = listener.Close()
	}
	t.Fatal("could not reserve shared independent F5 TCP/UDP port")
	return 0
}

func waitM3F5PeerMarker(
	t *testing.T,
	ctx context.Context,
	peer m3F5FullPeer,
	marker string,
	timeout time.Duration,
) {
	t.Helper()
	waitContext, cancelWait := context.WithTimeout(ctx, timeout)
	defer cancelWait()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		logs := ""
		var logsErr error
		if peer.local != nil {
			logs = peer.local.logs.String()
		} else {
			logs, logsErr = dockerOutput(waitContext, "logs", peer.name)
		}
		if logsErr == nil && strings.Contains(logs, marker) {
			return
		}
		select {
		case <-waitContext.Done():
			t.Fatal(E.Cause(waitContext.Err(), "wait for independent F5 peer marker ", marker, ": ", logs))
		case <-ticker.C:
		}
	}
}

func m3F5PeerLogs(t *testing.T, ctx context.Context, peer m3F5FullPeer) string {
	t.Helper()
	if peer.local != nil {
		return peer.local.logs.String()
	}
	logs, logsErr := dockerOutput(ctx, "logs", peer.name)
	if logsErr != nil {
		t.Fatal(logsErr)
	}
	return logs
}

func (d *m3F5PinnedDialer) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	target := destination
	if destination.Fqdn == m3F5FullPeerHostname && destination.Port == d.port {
		if d.hostnameDials.Add(1) > d.maximumDials {
			return nil, E.New("poisoned F5 logical DNS after authentication")
		}
		target = M.ParseSocksaddrHostPort("127.0.0.1", d.port)
	}
	return N.SystemDialer.DialContext(ctx, network, target)
}

func (d *m3F5PinnedDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

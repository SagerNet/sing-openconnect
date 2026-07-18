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
	m3FortinetFullPeerImage    = "sing-openconnect-fortinet-peer:m3"
	m3FortinetFullPeerHostname = "fortinet.test"
)

type m3FortinetFullPeerCase struct {
	name              string
	environment       map[string]string
	expectedCarrier   string
	expectedVersion   string
	expectedTunnels   []string
	expectedHostDials int32
	lateTakeover      bool
	tlsRecovery       bool
	recoveryTransport string
	configurationTwo  bool
	changeSourceIP    bool
	configurationErr  string
	configurationMark string
	tunnelAttempts    int
	closedBridges     int
	initialMTU        uint32
	reestablishedMTU  uint32
	maximumPacket     bool
	token             bool
	answer405         bool
	forbiddenMarkers  []string
}

type m3FortinetFullPeerCertificateFixture struct {
	directory       string
	rootCertificate []byte
}

type m3FortinetFullPeer struct {
	name  string
	port  uint16
	local *m3FortinetLocalPeer
}

type m3FortinetLocalPeer struct {
	logs *m3FortinetSynchronizedLogs
}

type m3FortinetSynchronizedLogs struct {
	access sync.Mutex
	buffer bytes.Buffer
}

var (
	m3FortinetLocalOptionsAccess sync.Mutex
	m3FortinetLocalOptionsReady  bool
	m3FortinetLocalOptionsOwned  bool
	m3FortinetLocalOptionsInode  uint64
)

type m3FortinetPinnedDialer struct {
	port          uint16
	maximumDials  int32
	hostnameDials atomic.Int32
	acceptedDials atomic.Int32
	changeSource  bool
}

//nolint:paralleltest // The full peers require privileged real-pppd containers and intentionally stress host networking.
func TestM3FortinetIndependentFullPeerMatrix(t *testing.T) {
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	_, dockerErr := dockerOutput(ctx, "version", "--format", "{{.Server.Version}}")
	if dockerErr != nil {
		t.Fatal(dockerErr)
	}
	_, buildErr := dockerOutput(ctx, "build", "--pull=false", "--tag", m3FortinetFullPeerImage, filepath.Join("testdata", "fortinet-peer"))
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	fixture := createM3FortinetFullPeerCertificateFixture(t)
	testCases := []m3FortinetFullPeerCase{
		{
			name:            "tls-plain-dual-stack",
			expectedCarrier: "TLS",
			expectedTunnels: []string{"FORTINET_PEER_TLS_TUNNEL_1"},
		},
		{
			name:             "dtls12-first-dual-stack",
			environment:      map[string]string{"DTLS": "1"},
			expectedCarrier:  "DTLS",
			expectedVersion:  "FORTINET_PEER_DTLS_LISTENING_12",
			expectedTunnels:  []string{"FORTINET_PEER_DTLS_TUNNEL_1"},
			forbiddenMarkers: []string{"FORTINET_PEER_TLS_TUNNEL_"},
		},
		{
			name:              "html-style-hidden-2fa-full-tunnel",
			environment:       map[string]string{"HTML_2FA": "1"},
			expectedCarrier:   "TLS",
			expectedTunnels:   []string{"FORTINET_PEER_HTML_STYLE_CHALLENGE", "FORTINET_PEER_HTML_STYLE_RESPONSE", "FORTINET_PEER_TLS_TUNNEL_1"},
			expectedHostDials: 4,
			token:             true,
		},
		{
			name:              "http-405-clears-and-reprompts",
			environment:       map[string]string{"REJECT_FIRST_LOGIN": "1"},
			expectedCarrier:   "TLS",
			expectedTunnels:   []string{"FORTINET_PEER_LOGIN_405", "FORTINET_PEER_TLS_TUNNEL_1"},
			expectedHostDials: 4,
			answer405:         true,
		},
		{
			name:             "dtls12-lost-ok-ppp-first",
			environment:      map[string]string{"DTLS": "1", "LOST_DTLS_OK": "1"},
			expectedCarrier:  "DTLS",
			expectedVersion:  "FORTINET_PEER_DTLS_LISTENING_12",
			expectedTunnels:  []string{"FORTINET_PEER_DTLS_PPP_FIRST", "FORTINET_PEER_CLIENT_ACKED_PPP_FIRST", "FORTINET_PEER_DTLS_TUNNEL_1"},
			forbiddenMarkers: []string{"FORTINET_PEER_TLS_TUNNEL_"},
		},
		{
			name:            "malformed-dtls-probe-falls-back",
			environment:     map[string]string{"DTLS": "1", "MALFORMED_DTLS": "1"},
			expectedCarrier: "TLS",
			expectedVersion: "FORTINET_PEER_DTLS_LISTENING_12",
			expectedTunnels: []string{"FORTINET_PEER_DTLS_MALFORMED_RESPONSE", "FORTINET_PEER_TLS_TUNNEL_2"},
			tunnelAttempts:  2,
		},
		{
			name: "dtls-certificate-rejection-falls-back",
			environment: map[string]string{
				"DTLS":             "1",
				"DTLS_CERTIFICATE": "/certs/untrusted-cert.pem",
				"DTLS_PRIVATE_KEY": "/certs/untrusted-key.pem",
			},
			expectedCarrier:  "TLS",
			expectedVersion:  "FORTINET_PEER_DTLS_LISTENING_12",
			expectedTunnels:  []string{"FORTINET_PEER_TLS_TUNNEL_1"},
			forbiddenMarkers: []string{"FORTINET_PEER_DTLS_TUNNEL_"},
		},
		{
			name:             "late-dtls12-takeover",
			environment:      map[string]string{"DTLS": "1", "DTLS_DELAY": "6", "PPPD_MTU": "1400"},
			expectedCarrier:  "TLS",
			expectedVersion:  "FORTINET_PEER_DTLS_LISTENING_12",
			expectedTunnels:  []string{"FORTINET_PEER_TLS_TUNNEL_1", "FORTINET_PEER_DTLS_TUNNEL_2"},
			lateTakeover:     true,
			tunnelAttempts:   2,
			closedBridges:    2,
			initialMTU:       1400,
			reestablishedMTU: 1353,
			maximumPacket:    true,
		},
		{
			name:              "dtls-carrier-loss-falls-back-to-tls",
			environment:       map[string]string{"DTLS": "1", "FAIL_FIRST_DTLS": "1"},
			expectedCarrier:   "DTLS",
			expectedVersion:   "FORTINET_PEER_DTLS_LISTENING_12",
			expectedTunnels:   []string{"FORTINET_PEER_DTLS_TUNNEL_1", "FORTINET_PEER_FORCED_DTLS_FAILURE", "FORTINET_PEER_TLS_TUNNEL_2"},
			tlsRecovery:       true,
			recoveryTransport: openconnect.TransportTLS,
			tunnelAttempts:    2,
			closedBridges:     2,
		},
		{
			name:            "late-dtls-ppp-failure-recovers-over-tls",
			environment:     map[string]string{"DTLS": "1", "DTLS_DELAY": "6", "FAIL_DTLS_PPP": "1"},
			expectedCarrier: "TLS",
			expectedVersion: "FORTINET_PEER_DTLS_LISTENING_12",
			expectedTunnels: []string{
				"FORTINET_PEER_TLS_TUNNEL_1",
				"FORTINET_PEER_DTLS_TUNNEL_2",
				"FORTINET_PEER_DTLS_PPP_NEGOTIATION_FAILED",
				"FORTINET_PEER_TLS_TUNNEL_3",
			},
			tlsRecovery:    true,
			tunnelAttempts: 3,
			closedBridges:  2,
		},
		{
			name:            "tls-carrier-recovery-reuses-config",
			environment:     map[string]string{"FAIL_FIRST_TLS": "1"},
			expectedCarrier: "TLS",
			expectedTunnels: []string{"FORTINET_PEER_TLS_TUNNEL_1", "FORTINET_PEER_FORCED_TLS_FAILURE", "FORTINET_PEER_TLS_TUNNEL_2"},
			tlsRecovery:     true,
			tunnelAttempts:  2,
			closedBridges:   2,
		},
		{
			name:              "partial-tls-403-reauthenticates",
			environment:       map[string]string{"REJECT_FIRST_TLS": "1"},
			expectedCarrier:   "TLS",
			expectedTunnels:   []string{"FORTINET_PEER_TLS_SESSION_REJECTED", "FORTINET_PEER_TLS_TUNNEL_2", "FORTINET_PEER_CONFIGURATION_2"},
			expectedHostDials: 6,
			configurationTwo:  true,
			tunnelAttempts:    2,
		},
		{
			name:              "reconnect-disabled-reauthenticates",
			environment:       map[string]string{"FAIL_FIRST_TLS": "1", "RECONNECT_ALLOWED": "0"},
			expectedCarrier:   "TLS",
			expectedTunnels:   []string{"FORTINET_PEER_FORCED_TLS_FAILURE", "FORTINET_PEER_TLS_TUNNEL_2", "FORTINET_PEER_CONFIGURATION_2"},
			expectedHostDials: 6,
			tlsRecovery:       true,
			configurationTwo:  true,
			tunnelAttempts:    2,
			closedBridges:     2,
		},
		{
			name:              "reconnect-source-ip-change-reauthenticates",
			environment:       map[string]string{"FAIL_FIRST_TLS": "1"},
			expectedCarrier:   "TLS",
			expectedTunnels:   []string{"FORTINET_PEER_FORCED_TLS_FAILURE", "FORTINET_PEER_TLS_TUNNEL_3", "FORTINET_PEER_CONFIGURATION_2"},
			expectedHostDials: 6,
			tlsRecovery:       true,
			configurationTwo:  true,
			changeSourceIP:    true,
			tunnelAttempts:    3,
			closedBridges:     3,
		},
		{
			name:              "zero-cleanup-timeout-reauthenticates",
			environment:       map[string]string{"FAIL_FIRST_TLS": "1", "RECONNECT_TIMEOUT": "0"},
			expectedCarrier:   "TLS",
			expectedTunnels:   []string{"FORTINET_PEER_FORCED_TLS_FAILURE", "FORTINET_PEER_TLS_TUNNEL_2", "FORTINET_PEER_CONFIGURATION_2"},
			expectedHostDials: 6,
			tlsRecovery:       true,
			configurationTwo:  true,
			tunnelAttempts:    2,
			closedBridges:     2,
		},
		{
			name:              "expired-cleanup-timeout-reauthenticates",
			environment:       map[string]string{"FAIL_FIRST_TLS": "1", "RECONNECT_TIMEOUT": "1"},
			expectedCarrier:   "TLS",
			expectedTunnels:   []string{"FORTINET_PEER_FORCED_TLS_FAILURE", "FORTINET_PEER_TLS_TUNNEL_2", "FORTINET_PEER_CONFIGURATION_2"},
			expectedHostDials: 6,
			tlsRecovery:       true,
			configurationTwo:  true,
			tunnelAttempts:    2,
			closedBridges:     2,
		},
		{
			name:             "malformed-split-dns-is-terminal",
			environment:      map[string]string{"MALFORMED_SPLIT_DNS": "1"},
			configurationErr: "split-DNS",
		},
		{
			name:              "trailing-xml-is-terminal",
			environment:       map[string]string{"MALFORMED_TRAILING_XML": "1"},
			configurationErr:  "trailing XML data",
			configurationMark: "FORTINET_PEER_TRAILING_XML_CONFIGURATION",
		},
		{
			name:              "mapped-ipv6-is-terminal",
			environment:       map[string]string{"MAPPED_IPV6": "1"},
			configurationErr:  "assigned address is invalid",
			configurationMark: "FORTINET_PEER_MAPPED_IPV6_CONFIGURATION",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			peer := startM3FortinetFullPeer(t, ctx, fixture, testCase.environment)
			runM3FortinetFullPeerCase(t, ctx, peer, fixture.rootCertificate, testCase)
		})
	}
}

func startM3FortinetFullPeer(
	t *testing.T,
	ctx context.Context,
	fixture m3FortinetFullPeerCertificateFixture,
	environment map[string]string,
) m3FortinetFullPeer {
	t.Helper()
	port := reserveM3FortinetFullPeerPort(t)
	portText := strconv.Itoa(int(port))
	containerName := "sing-openconnect-m3-fortinet-full-" + strconv.FormatInt(time.Now().UnixNano(), 36)
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
	arguments = append(arguments, m3FortinetFullPeerImage)
	_, runErr := dockerOutput(ctx, arguments...)
	if runErr != nil {
		t.Fatal(runErr)
	}
	peer := m3FortinetFullPeer{name: containerName, port: port}
	t.Cleanup(func() {
		if t.Failed() {
			logsContext, cancelLogs := context.WithTimeout(context.Background(), 5*time.Second)
			logs, logsErr := dockerOutput(logsContext, "logs", containerName)
			cancelLogs()
			if logsErr == nil {
				t.Log("independent Fortinet peer logs:\n" + logs)
			}
		}
		removeContext, cancelRemove := context.WithTimeout(context.Background(), 10*time.Second)
		_, _ = dockerOutput(removeContext, "rm", "--force", containerName)
		cancelRemove()
	})
	waitM3FortinetPeerMarker(t, ctx, peer, "FORTINET_PEER_TLS_LISTENING", 20*time.Second)
	pppDeviceProbe := "import os,stat\ntry:\n os.mknod('/dev/ppp',stat.S_IFCHR|0o600,os.makedev(108,0))\nexcept FileExistsError:\n pass\ndescriptor=os.open('/dev/ppp',os.O_RDWR)\nos.close(descriptor)"
	_, pppDeviceErr := dockerOutput(ctx, "exec", containerName, "python3", "-c", pppDeviceProbe)
	if pppDeviceErr != nil {
		if runtime.GOOS != "darwin" {
			t.Fatal(E.Cause(pppDeviceErr, "independent Fortinet peer has no usable real pppd device"))
		}
		_, _ = dockerOutput(ctx, "rm", "--force", containerName)
		localPeer := startM3FortinetLocalPeer(t, port, fixture, environment)
		peer.name = ""
		peer.local = localPeer
		waitM3FortinetPeerMarker(t, ctx, peer, "FORTINET_PEER_TLS_LISTENING", 20*time.Second)
	} else {
		version, versionErr := dockerOutput(ctx, "exec", containerName, "dpkg-query", "-W", "-f=${Version}", "ppp")
		if versionErr != nil || strings.TrimSpace(version) != "2.5.2-1+1" {
			t.Fatal(E.Errors(E.New("unexpected independent Fortinet Docker pppd version: ", strings.TrimSpace(version)), versionErr))
		}
	}
	if environment["DTLS"] == "1" {
		dtlsDelay := 0.0
		if environment["DTLS_DELAY"] != "" {
			parsedDelay, parseErr := strconv.ParseFloat(environment["DTLS_DELAY"], 64)
			if parseErr != nil {
				t.Fatal(E.Cause(parseErr, "parse independent Fortinet DTLS peer delay"))
			}
			dtlsDelay = parsedDelay
		}
		if dtlsDelay == 0 {
			waitM3FortinetPeerMarker(t, ctx, peer, "FORTINET_PEER_DTLS_LISTENING_12", 20*time.Second)
		}
	}
	return peer
}

func runM3FortinetFullPeerCase(
	t *testing.T,
	ctx context.Context,
	peer m3FortinetFullPeer,
	rootCertificate []byte,
	testCase m3FortinetFullPeerCase,
) {
	t.Helper()
	if testCase.changeSourceIP {
		prepareM3FortinetChangedLoopback(t)
	}
	expectedHostDials := testCase.expectedHostDials
	if expectedHostDials == 0 {
		expectedHostDials = 3
	}
	dialer := &m3FortinetPinnedDialer{port: peer.port, maximumDials: expectedHostDials, changeSource: testCase.changeSourceIP}
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 16)
	clientOptions := openconnect.ClientOptions{
		Context:  ctx,
		Server:   "https://" + net.JoinHostPort(m3FortinetFullPeerHostname, strconv.Itoa(int(peer.port))) + "/fake+Realm",
		Flavor:   openconnect.FlavorFortinet,
		Username: "test",
		Password: "test",
		Dialer:   dialer,
		TLSConfig: openconnect.ClientTLSOptions{
			CertificateAuthority: openconnect.Material{Content: rootCertificate},
		},
		OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
			configurationEvents <- event
			return nil
		},
	}
	if testCase.token {
		clientOptions.Token = &openconnect.TokenOptions{Mode: openconnect.TokenModeTOTP, Secret: "JBSWY3DPEHPK3PXP"}
	}
	client, clientErr := openconnect.NewClient(clientOptions)
	if clientErr != nil {
		t.Fatal(E.Cause(clientErr, "create independent Fortinet client"))
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	activeTransportUpdated := client.ActiveTransportUpdated()
	startErr := client.Start()
	if startErr != nil {
		t.Fatal(E.Cause(startErr, "start independent Fortinet client"))
	}
	if testCase.answer405 {
		answerM3Fortinet405(t, ctx, client)
	}
	if testCase.configurationErr != "" {
		readContext, cancelRead := context.WithTimeout(ctx, 20*time.Second)
		_, readErr := client.ReadDataPacket(readContext)
		cancelRead()
		if readErr == nil || !strings.Contains(readErr.Error(), testCase.configurationErr) {
			t.Fatalf("malformed Fortinet configuration did not fail specifically: %v", readErr)
		}
		waitM3FortinetPeerMarker(t, ctx, peer, "FORTINET_PEER_CONFIGURATION_1", 10*time.Second)
		logs := m3FortinetPeerLogs(t, ctx, peer)
		if !strings.Contains(logs, "FORTINET_PEER_CONFIGURATION_1") || strings.Contains(logs, "FORTINET_PEER_TLS_TUNNEL_") || strings.Contains(logs, "FORTINET_PEER_DTLS_TUNNEL_") {
			t.Fatalf("malformed Fortinet configuration reached a data tunnel:\n%s", logs)
		}
		if testCase.configurationMark != "" && !strings.Contains(logs, testCase.configurationMark) {
			t.Fatalf("malformed Fortinet configuration peer did not report %s:\n%s", testCase.configurationMark, logs)
		}
		if strings.Count(logs, "FORTINET_PEER_AUTHENTICATED") != 1 ||
			strings.Count(logs, "FORTINET_PEER_CONFIGURATION_") != 1 ||
			strings.Count(logs, "FORTINET_PEER_TUNNEL_ATTEMPT_") != 0 {
			t.Fatalf("malformed Fortinet configuration reported unexpected auth/config/tunnel counts; expected 1/1/0:\n%s", logs)
		}
		closeErr := client.Close()
		if closeErr != nil {
			t.Fatal(E.Cause(closeErr, "close malformed-configuration Fortinet client"))
		}
		waitM3FortinetPeerMarker(t, ctx, peer, "FORTINET_PEER_LOGOUT", 10*time.Second)
		closedLogs := m3FortinetPeerLogs(t, ctx, peer)
		if strings.Count(closedLogs, "FORTINET_PEER_LOGOUT") != 1 ||
			strings.Count(closedLogs, "FORTINET_PEER_CLIENT_TERMINATE_REQUEST") != 0 ||
			strings.Count(closedLogs, "FORTINET_PEER_PPP_BRIDGE_CLOSED") != 0 {
			t.Fatalf("malformed Fortinet configuration reported unexpected logout/terminate/bridge counts; expected 1/0/0:\n%s", closedLogs)
		}
		return
	}
	expectedInitialMTU := testCase.initialMTU
	if expectedInitialMTU == 0 {
		expectedInitialMTU = 1320
	}
	expectedReestablishedMTU := testCase.reestablishedMTU
	if expectedReestablishedMTU == 0 {
		expectedReestablishedMTU = expectedInitialMTU
	}
	initialEvent := waitM3FortinetConfigurationEvent(t, client, configurationEvents, openconnect.TunnelConfigurationEventInitial, 40*time.Second)
	assertM3FortinetConfiguration(t, initialEvent.Configuration, expectedInitialMTU)
	expectedInitialTransport := openconnect.TransportTLS
	if testCase.expectedCarrier == "DTLS" {
		expectedInitialTransport = openconnect.TransportDTLS
	}
	waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, expectedInitialTransport)
	initialEvent.Configuration.SplitDNSRules[0].Domains[0] = "mutated.invalid"
	initialEvent.Configuration.SplitDNSRules[0].Servers[0] = netip.IPv4Unspecified()
	assertM3FortinetConfiguration(t, client.TunnelConfiguration(), expectedInitialMTU)
	if testCase.tlsRecovery {
		if testCase.recoveryTransport != "" {
			activeTransportUpdated = client.ActiveTransportUpdated()
		}
		request := buildIPv4ICMPEchoRequest(
			t,
			netip.MustParseAddr("192.0.2.2"),
			netip.MustParseAddr("192.0.2.1"),
			0x4d35,
			1,
			[]byte("sing-openconnect-m3-fortinet-trigger-recovery"),
		)
		writeErr := client.WriteDataPacket(request)
		if writeErr != nil {
			t.Fatal(E.Cause(writeErr, "trigger independent Fortinet carrier recovery"))
		}
		if testCase.recoveryTransport != "" {
			waitForActiveTransportLossAndRecovery(t, ctx, client, activeTransportUpdated, testCase.recoveryTransport)
		}
		reestablished := waitM3FortinetConfigurationEvent(t, client, configurationEvents, openconnect.TunnelConfigurationEventReestablishment, 40*time.Second)
		assertM3FortinetConfiguration(t, reestablished.Configuration, expectedReestablishedMTU)
		exchangeM3FortinetIPv4(t, ctx, client, 2)
		exchangeM3FortinetIPv6(t, ctx, client, 2)
	} else if testCase.lateTakeover {
		activeTransportUpdated = client.ActiveTransportUpdated()
		exchangeM3FortinetIPv4(t, ctx, client, 1)
		reestablished := waitM3FortinetConfigurationEvent(t, client, configurationEvents, openconnect.TunnelConfigurationEventReestablishment, 40*time.Second)
		assertM3FortinetConfiguration(t, reestablished.Configuration, expectedReestablishedMTU)
		waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportDTLS)
		exchangeM3FortinetIPv4(t, ctx, client, 2)
		exchangeM3FortinetIPv6(t, ctx, client, 2)
		if testCase.maximumPacket {
			exchangeM3FortinetMaximumIPv4(t, ctx, client, int(expectedReestablishedMTU), 9)
		}
	} else {
		exchangeM3FortinetIPv4(t, ctx, client, 1)
		exchangeM3FortinetIPv6(t, ctx, client, 1)
	}
	if testCase.expectedCarrier == "DTLS" {
		exchangeM3FortinetMaximumIPv4(t, ctx, client, int(expectedInitialMTU), 9)
	}
	requiredMarkers := []string{
		"FORTINET_PEER_AUTHENTICATED",
		"FORTINET_PEER_JAVASCRIPT_REDIRECT",
		"FORTINET_PEER_LOGIN_QUERY_EXACT",
		"FORTINET_PEER_CONFIGURATION_1",
		"FORTINET_PEER_COOKIE_REPLACED",
		"FORTINET_PEER_SNI_" + m3FortinetFullPeerHostname,
		"FORTINET_PEER_PPPD_ECHO_REQUEST",
		"FORTINET_PEER_CLIENT_IPV4 ",
		"FORTINET_PEER_CLIENT_IPV6 ",
		"FORTINET_PEER_PPPD_IPV4 ",
		"FORTINET_PEER_PPPD_IPV6 ",
	}
	for _, marker := range requiredMarkers {
		waitM3FortinetPeerMarker(t, ctx, peer, marker, 10*time.Second)
	}
	actualHostDials := dialer.hostnameDials.Load()
	if actualHostDials != expectedHostDials {
		t.Fatalf("Fortinet accepted-endpoint pinning used %d logical-host dials; expected %d authentication dials", actualHostDials, expectedHostDials)
	}
	logs := m3FortinetPeerLogs(t, ctx, peer)
	expectedAuthenticationCount := 1
	expectedConfigurationCount := 1
	if testCase.configurationTwo {
		expectedAuthenticationCount = 2
		expectedConfigurationCount = 2
	}
	expectedTunnelAttempts := testCase.tunnelAttempts
	if expectedTunnelAttempts == 0 {
		expectedTunnelAttempts = 1
	}
	if strings.Count(logs, "FORTINET_PEER_AUTHENTICATED") != expectedAuthenticationCount ||
		strings.Count(logs, "FORTINET_PEER_CONFIGURATION_") != expectedConfigurationCount ||
		strings.Count(logs, "FORTINET_PEER_TUNNEL_ATTEMPT_") != expectedTunnelAttempts {
		t.Fatalf(
			"independent Fortinet peer reported unexpected auth/config/tunnel counts; expected %d/%d/%d:\n%s",
			expectedAuthenticationCount,
			expectedConfigurationCount,
			expectedTunnelAttempts,
			logs,
		)
	}
	for _, marker := range requiredMarkers {
		if !strings.Contains(logs, marker) {
			t.Fatalf("independent Fortinet peer did not report %s:\n%s", marker, logs)
		}
	}
	if testCase.expectedVersion != "" && !strings.Contains(logs, testCase.expectedVersion) {
		t.Fatalf("independent Fortinet peer did not report %s:\n%s", testCase.expectedVersion, logs)
	}
	for _, marker := range testCase.expectedTunnels {
		if !strings.Contains(logs, marker) {
			t.Fatalf("independent Fortinet peer did not report %s:\n%s", marker, logs)
		}
	}
	for _, marker := range testCase.forbiddenMarkers {
		if strings.Contains(logs, marker) {
			t.Fatalf("independent Fortinet peer unexpectedly reported %s:\n%s", marker, logs)
		}
	}
	if testCase.expectedCarrier == "DTLS" && !strings.Contains(logs, "FORTINET_PEER_DTLS_HELLO_EXACT") {
		t.Fatalf("independent Fortinet DTLS peer did not report the exact application hello:\n%s", logs)
	}
	if strings.Contains(logs, "FORTINET_PEER_TLS_TUNNEL_") && !strings.Contains(logs, "FORTINET_PEER_TLS_REQUEST_EXACT") {
		t.Fatalf("independent Fortinet TLS peer did not report the exact response-less request:\n%s", logs)
	}
	if testCase.expectedCarrier == "TLS" {
		for _, marker := range []string{"FORTINET_PEER_STREAM_SPLIT", "FORTINET_PEER_STREAM_COALESCED"} {
			if !strings.Contains(logs, marker) {
				t.Fatalf("independent Fortinet stream peer did not report %s:\n%s", marker, logs)
			}
		}
	}
	if testCase.tlsRecovery && !testCase.configurationTwo && strings.Contains(logs, "FORTINET_PEER_CONFIGURATION_2") {
		t.Fatalf("Fortinet carrier recovery refetched immutable configuration:\n%s", logs)
	}
	if testCase.configurationTwo && !strings.Contains(logs, "FORTINET_PEER_CONFIGURATION_2") {
		t.Fatalf("Fortinet reauthentication did not fetch configuration for the new cookie:\n%s", logs)
	}
	closeErr := client.Close()
	if closeErr != nil {
		t.Fatal(E.Cause(closeErr, "close independent Fortinet client"))
	}
	waitM3FortinetPeerMarker(t, ctx, peer, "FORTINET_PEER_LOGOUT", 10*time.Second)
	waitM3FortinetPeerMarker(t, ctx, peer, "FORTINET_PEER_CLIENT_TERMINATE_REQUEST", 10*time.Second)
	expectedClosedBridges := testCase.closedBridges
	if expectedClosedBridges == 0 {
		expectedClosedBridges = 1
	}
	waitM3FortinetPeerMarkerCount(t, ctx, peer, "FORTINET_PEER_PPP_BRIDGE_CLOSED", expectedClosedBridges, 10*time.Second)
	closedLogs := m3FortinetPeerLogs(t, ctx, peer)
	for _, marker := range []string{"FORTINET_PEER_CLIENT_TERMINATE_REQUEST", "FORTINET_PEER_PPP_BRIDGE_CLOSED", "FORTINET_PEER_LOGOUT"} {
		if !strings.Contains(closedLogs, marker) {
			t.Fatalf("independent Fortinet clean close did not report %s:\n%s", marker, closedLogs)
		}
	}
	expectedLogouts := 1
	if testCase.configurationTwo {
		expectedLogouts = 2
	}
	if strings.Count(closedLogs, "FORTINET_PEER_CLIENT_TERMINATE_REQUEST") != 1 ||
		strings.Count(closedLogs, "FORTINET_PEER_PPP_BRIDGE_CLOSED") != expectedClosedBridges ||
		strings.Count(closedLogs, "FORTINET_PEER_LOGOUT") != expectedLogouts {
		t.Fatalf(
			"independent Fortinet peer reported unexpected terminate/bridge/logout counts; expected 1/%d/%d:\n%s",
			expectedClosedBridges,
			expectedLogouts,
			closedLogs,
		)
	}
}

func prepareM3FortinetChangedLoopback(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		return
	}
	probe, probeErr := net.Listen("tcp4", "127.0.0.2:0")
	if probeErr == nil {
		closeErr := probe.Close()
		if closeErr != nil {
			t.Fatal(E.Cause(closeErr, "close existing alternate loopback probe"))
		}
		return
	}
	command := exec.Command("sudo", "-n", "/sbin/ifconfig", "lo0", "alias", "127.0.0.2")
	output, aliasErr := command.CombinedOutput()
	if aliasErr != nil {
		t.Fatal(E.Cause(aliasErr, "create alternate loopback address: ", strings.TrimSpace(string(output))))
	}
	t.Cleanup(func() {
		removeCommand := exec.Command("sudo", "-n", "/sbin/ifconfig", "lo0", "-alias", "127.0.0.2")
		removeOutput, removeErr := removeCommand.CombinedOutput()
		if removeErr != nil {
			t.Errorf("remove alternate loopback address: %v: %s", removeErr, strings.TrimSpace(string(removeOutput)))
		}
	})
}

func answerM3Fortinet405(t *testing.T, ctx context.Context, client *openconnect.Client) {
	t.Helper()
	waitContext, cancelWait := context.WithTimeout(ctx, 15*time.Second)
	defer cancelWait()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		form := client.PendingAuthChallenge()
		if form != nil {
			if form.Browser != nil || form.Form == nil || !strings.Contains(form.Error, "Invalid credentials") {
				t.Fatalf("Fortinet 405 did not publish the invalid-credentials error: %#v", form)
			}
			values := make(map[string]string, len(form.Form.Fields))
			credentialFound := false
			for _, field := range form.Form.Fields {
				value := field.Value
				if field.Name == "credential" {
					if field.Value != "" {
						t.Fatal("Fortinet 405 retained the rejected credential")
					}
					value = "test"
					credentialFound = true
				}
				values[field.SubmissionKey] = value
			}
			if !credentialFound {
				t.Fatal("Fortinet 405 retry form omitted credential")
			}
			completeErr := client.CompleteAuthChallenge(form.ID, openconnect.AuthResponse{Form: &openconnect.AuthFormResponse{Values: values}})
			if completeErr != nil {
				t.Fatal(E.Cause(completeErr, "complete Fortinet 405 retry form"))
			}
			return
		}
		select {
		case <-waitContext.Done():
			t.Fatal(E.Cause(waitContext.Err(), "wait for Fortinet 405 retry form"))
		case <-ticker.C:
		}
	}
}

func waitM3FortinetConfigurationEvent(
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
		if form := client.PendingAuthChallenge(); form != nil {
			t.Fatalf("independent Fortinet peer unexpectedly required interactive authentication: %#v", form)
		}
		select {
		case event := <-events:
			if event.Reason == reason {
				return event
			}
		case <-timer.C:
			t.Fatal("timed out waiting for Fortinet tunnel configuration event " + string(reason))
		case <-ticker.C:
		}
	}
}

func assertM3FortinetConfiguration(t *testing.T, configuration openconnect.TunnelConfiguration, expectedMTU uint32) {
	t.Helper()
	expectedAddresses := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.2/32"),
		netip.MustParsePrefix("fe80::2/64"),
	}
	expectedDNS := []netip.Addr{netip.MustParseAddr("203.0.113.53"), netip.MustParseAddr("203.0.113.54")}
	if configuration.MTU != expectedMTU || !slices.Equal(configuration.Addresses, expectedAddresses) ||
		!slices.Equal(configuration.DNS, expectedDNS) || len(configuration.NBNS) != 0 ||
		!slices.Equal(configuration.SearchDomains, []string{"fortinet.test"}) ||
		len(configuration.SplitDNS) != 0 || len(configuration.SplitDNSRules) != 1 ||
		!slices.Equal(configuration.SplitDNSRules[0].Domains, []string{"internal.fortinet.test", "corp.fortinet.test"}) ||
		!slices.Equal(configuration.SplitDNSRules[0].Servers, []netip.Addr{netip.MustParseAddr("198.51.100.53"), netip.MustParseAddr("198.51.100.54")}) ||
		configuration.IdleTimeout != 15*time.Minute || configuration.AuthenticationExpiration.IsZero() {
		t.Fatalf("unexpected independent Fortinet configuration: %+v", configuration)
	}
	for _, expectedPrefix := range []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	} {
		if !slices.ContainsFunc(configuration.Routes, func(route openconnect.TunnelRoute) bool {
			return route.Prefix == expectedPrefix
		}) {
			t.Fatalf("independent Fortinet configuration omitted route %s: %+v", expectedPrefix, configuration.Routes)
		}
	}
	if !slices.ContainsFunc(configuration.ExcludedRoutes, func(route openconnect.TunnelRoute) bool {
		return route.Prefix == netip.MustParsePrefix("198.51.100.128/25")
	}) {
		t.Fatalf("independent Fortinet configuration omitted excluded route: %+v", configuration.ExcludedRoutes)
	}
}

func exchangeM3FortinetIPv4(t *testing.T, ctx context.Context, client *openconnect.Client, sequence uint16) {
	t.Helper()
	clientAddress := netip.MustParseAddr("192.0.2.2")
	serverAddress := netip.MustParseAddr("192.0.2.1")
	payload := []byte("sing-openconnect-m3-fortinet-ipv4")
	request := buildIPv4ICMPEchoRequest(t, clientAddress, serverAddress, 0x4d35, sequence, payload)
	exchangeM3FortinetPacket(t, ctx, client, request, 4, func(packet []byte) error {
		return validateIPv4ICMPEchoReply(packet, clientAddress, serverAddress, 0x4d35, sequence, payload)
	})
}

func exchangeM3FortinetIPv6(t *testing.T, ctx context.Context, client *openconnect.Client, sequence uint16) {
	t.Helper()
	clientAddress := netip.MustParseAddr("fe80::2")
	serverAddress := netip.MustParseAddr("fe80::1")
	payload := []byte("sing-openconnect-m3-fortinet-ipv6")
	request := buildM2GPIPv6ICMPEchoRequest(t, clientAddress, serverAddress, 0x4d36, sequence, payload)
	exchangeM3FortinetPacket(t, ctx, client, request, 6, func(packet []byte) error {
		return validateM2GPIPv6ICMPEchoReply(packet, clientAddress, serverAddress, 0x4d36, sequence, payload)
	})
}

func exchangeM3FortinetMaximumIPv4(t *testing.T, ctx context.Context, client *openconnect.Client, mtu int, sequence uint16) {
	t.Helper()
	clientAddress := netip.MustParseAddr("192.0.2.2")
	serverAddress := netip.MustParseAddr("192.0.2.1")
	payload := make([]byte, mtu-28)
	for payloadIndex := range payload {
		payload[payloadIndex] = byte(payloadIndex % 251)
	}
	request := buildIPv4ICMPEchoRequest(t, clientAddress, serverAddress, 0x4d37, sequence, payload)
	if len(request) != mtu {
		t.Fatalf("maximum Fortinet IPv4 request has length %d", len(request))
	}
	exchangeM3FortinetPacket(t, ctx, client, request, 4, func(packet []byte) error {
		return validateIPv4ICMPEchoReply(packet, clientAddress, serverAddress, 0x4d37, sequence, payload)
	})
}

func exchangeM3FortinetPacket(
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
			t.Fatal(E.Cause(writeErr, "write IPv", version, " packet through independent Fortinet peer"))
		}
		readContext, cancelRead := context.WithTimeout(exchangeContext, 1500*time.Millisecond)
		for {
			packet, readErr := client.ReadDataPacket(readContext)
			if readErr != nil {
				if readContext.Err() != nil {
					break
				}
				cancelRead()
				t.Fatal(E.Cause(readErr, "read IPv", version, " packet from independent Fortinet peer"))
			}
			if !isM3FortinetICMPEchoReply(packet, version) {
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
		t.Fatal(E.Cause(lastValidationErr, "validate IPv", version, " reply from independent Fortinet peer"))
	}
	t.Fatal(E.Cause(exchangeContext.Err(), "exchange IPv", version, " packet with independent Fortinet peer"))
}

func isM3FortinetICMPEchoReply(packet []byte, version byte) bool {
	if len(packet) == 0 || packet[0]>>4 != version {
		return false
	}
	if version == 4 && len(packet) >= 20 && packet[9] == 1 {
		headerLength := int(packet[0]&0xf) * 4
		return headerLength >= 20 && len(packet) > headerLength && packet[headerLength] == 0
	}
	return version == 6 && len(packet) >= 41 && packet[6] == 58 && packet[40] == 129
}

func createM3FortinetFullPeerCertificateFixture(t *testing.T) m3FortinetFullPeerCertificateFixture {
	t.Helper()
	now := time.Now()
	rootKey, rootKeyErr := rsa.GenerateKey(rand.Reader, 2048)
	if rootKeyErr != nil {
		t.Fatal(E.Cause(rootKeyErr, "generate independent Fortinet root key"))
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sing-openconnect independent Fortinet root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootData, rootCertificate := createSignedInteropCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	serverKey, serverKeyErr := rsa.GenerateKey(rand.Reader, 2048)
	if serverKeyErr != nil {
		t.Fatal(E.Cause(serverKeyErr, "generate independent Fortinet server key"))
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: m3FortinetFullPeerHostname},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{m3FortinetFullPeerHostname},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverData, _ := createSignedInteropCertificate(t, serverTemplate, rootCertificate, serverKey.Public(), rootKey)
	directory := t.TempDir()
	certificateErr := os.WriteFile(filepath.Join(directory, "server-cert.pem"), joinCertificatePEM(serverData), 0o600)
	if certificateErr != nil {
		t.Fatal(E.Cause(certificateErr, "write independent Fortinet server certificate"))
	}
	keyErr := os.WriteFile(filepath.Join(directory, "server-key.pem"), marshalInteropPrivateKey(t, serverKey), 0o600)
	if keyErr != nil {
		t.Fatal(E.Cause(keyErr, "write independent Fortinet server key"))
	}
	untrustedRootKey, untrustedRootKeyErr := rsa.GenerateKey(rand.Reader, 2048)
	if untrustedRootKeyErr != nil {
		t.Fatal(E.Cause(untrustedRootKeyErr, "generate untrusted Fortinet DTLS root key"))
	}
	untrustedRootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "sing-openconnect untrusted Fortinet DTLS root"},
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
		t.Fatal(E.Cause(untrustedServerKeyErr, "generate untrusted Fortinet DTLS server key"))
	}
	untrustedServerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: m3FortinetFullPeerHostname},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{m3FortinetFullPeerHostname},
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
		t.Fatal(E.Cause(untrustedCertificateErr, "write untrusted Fortinet DTLS server certificate"))
	}
	untrustedKeyErr := os.WriteFile(
		filepath.Join(directory, "untrusted-key.pem"),
		marshalInteropPrivateKey(t, untrustedServerKey),
		0o600,
	)
	if untrustedKeyErr != nil {
		t.Fatal(E.Cause(untrustedKeyErr, "write untrusted Fortinet DTLS server key"))
	}
	return m3FortinetFullPeerCertificateFixture{
		directory:       directory,
		rootCertificate: joinCertificatePEM(rootData),
	}
}

func startM3FortinetLocalPeer(
	t *testing.T,
	port uint16,
	fixture m3FortinetFullPeerCertificateFixture,
	environment map[string]string,
) *m3FortinetLocalPeer {
	t.Helper()
	prepareM3FortinetLocalPPPOptions(t)
	scriptPath, pathErr := filepath.Abs(filepath.Join("testdata", "fortinet-peer", "fortinet_peer.py"))
	if pathErr != nil {
		t.Fatal(E.Cause(pathErr, "resolve independent local Fortinet peer path"))
	}
	opensslPath := filepath.Join("/opt/homebrew/opt/openssl@3", "bin", "openssl")
	_, statErr := os.Stat(opensslPath)
	if statErr != nil {
		t.Fatal(E.Cause(statErr, "locate Homebrew OpenSSL for independent Fortinet DTLS peer"))
	}
	versionCommand := exec.Command("sudo", "-n", "/usr/sbin/pppd", "--version")
	versionOutput, versionErr := versionCommand.CombinedOutput()
	if versionErr != nil || !strings.Contains(string(versionOutput), "2.4.2") {
		t.Fatal(E.Errors(E.New("unexpected independent Fortinet system pppd version: ", strings.TrimSpace(string(versionOutput))), versionErr))
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
	logs := &m3FortinetSynchronizedLogs{}
	_, _ = logs.Write([]byte("FORTINET_PEER_PPPD_VERSION " + strings.TrimSpace(string(versionOutput)) + "\n"))
	command := exec.Command("/usr/bin/python3", scriptPath)
	command.Env = append(os.Environ(), environmentValues...)
	command.Stdout = logs
	command.Stderr = logs
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	startErr := command.Start()
	if startErr != nil {
		t.Fatal(E.Cause(startErr, "start independent local Fortinet peer"))
	}
	done := make(chan error, 1)
	go func() {
		done <- command.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		if t.Failed() {
			t.Log("independent local Fortinet peer logs:\n" + logs.String())
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
		if !strings.Contains(closedLogs, "FORTINET_PEER_CHILDREN_REAPED") {
			t.Errorf("independent local Fortinet peer exited without confirming child-process reaping; logs:\n%s", closedLogs)
		}
		assertNoM3LocalPeerProcess(t, "Fortinet", command.Process.Pid, scriptPath)
		assertNoM3LocalOpenSSLProcesses(t, "Fortinet", fixture.directory)
	})
	return &m3FortinetLocalPeer{logs: logs}
}

func prepareM3FortinetLocalPPPOptions(t *testing.T) {
	t.Helper()
	m3FortinetLocalOptionsAccess.Lock()
	defer m3FortinetLocalOptionsAccess.Unlock()
	if m3FortinetLocalOptionsReady {
		return
	}
	optionsInfo, statErr := os.Stat("/etc/ppp/options")
	if statErr == nil {
		if optionsInfo.Size() != 0 {
			t.Fatal("refusing to use nonempty /etc/ppp/options for independent Fortinet real-pppd peer")
		}
		m3FortinetLocalOptionsReady = true
		m3FortinetLocalOptionsOwned = false
		return
	}
	if !os.IsNotExist(statErr) {
		t.Fatal(E.Cause(statErr, "inspect local PPP options for independent Fortinet peer"))
	}
	temporary, temporaryErr := os.CreateTemp("/tmp", "sing-openconnect-fortinet-ppp-options-")
	if temporaryErr != nil {
		t.Fatal(E.Cause(temporaryErr, "create temporary local PPP options for independent Fortinet peer"))
	}
	temporaryPath := temporary.Name()
	closeErr := temporary.Close()
	if closeErr != nil {
		_ = os.Remove(temporaryPath)
		t.Fatal(E.Cause(closeErr, "close temporary local PPP options for independent Fortinet peer"))
	}
	defer os.Remove(temporaryPath)
	moveCommand := exec.Command("sudo", "-n", "/bin/mv", "-n", temporaryPath, "/etc/ppp/options")
	moveOutput, moveErr := moveCommand.CombinedOutput()
	if moveErr != nil {
		t.Fatal(E.Cause(moveErr, "install temporary local PPP options for independent Fortinet peer: ", strings.TrimSpace(string(moveOutput))))
	}
	installedInfo, installedErr := os.Stat("/etc/ppp/options")
	if installedErr != nil {
		t.Fatal(E.Cause(installedErr, "verify temporary local PPP options for independent Fortinet peer"))
	}
	installedStat, loaded := installedInfo.Sys().(*syscall.Stat_t)
	if !loaded || installedInfo.Size() != 0 {
		t.Fatal("temporary local PPP options for independent Fortinet peer is not an empty regular file")
	}
	m3FortinetLocalOptionsReady = true
	m3FortinetLocalOptionsOwned = true
	m3FortinetLocalOptionsInode = installedStat.Ino
	t.Cleanup(func() {
		m3FortinetLocalOptionsAccess.Lock()
		defer m3FortinetLocalOptionsAccess.Unlock()
		if !m3FortinetLocalOptionsOwned {
			m3FortinetLocalOptionsReady = false
			return
		}
		currentInfo, currentErr := os.Stat("/etc/ppp/options")
		if currentErr != nil {
			t.Errorf("temporary local PPP options disappeared before independent Fortinet cleanup: %v", currentErr)
			m3FortinetLocalOptionsReady = false
			m3FortinetLocalOptionsOwned = false
			return
		}
		currentStat, currentLoaded := currentInfo.Sys().(*syscall.Stat_t)
		if !currentLoaded || currentStat.Ino != m3FortinetLocalOptionsInode || currentInfo.Size() != 0 {
			t.Error("temporary local PPP options changed; refusing independent Fortinet cleanup")
			m3FortinetLocalOptionsReady = false
			m3FortinetLocalOptionsOwned = false
			return
		}
		removeCommand := exec.Command("sudo", "-n", "/bin/rm", "/etc/ppp/options")
		removeOutput, removeErr := removeCommand.CombinedOutput()
		if removeErr != nil {
			t.Errorf("remove temporary local PPP options after independent Fortinet peer: %v: %s", removeErr, strings.TrimSpace(string(removeOutput)))
		}
		m3FortinetLocalOptionsReady = false
		m3FortinetLocalOptionsOwned = false
		m3FortinetLocalOptionsInode = 0
	})
}

func (l *m3FortinetSynchronizedLogs) Write(content []byte) (int, error) {
	l.access.Lock()
	defer l.access.Unlock()
	return l.buffer.Write(content)
}

func (l *m3FortinetSynchronizedLogs) String() string {
	l.access.Lock()
	defer l.access.Unlock()
	return l.buffer.String()
}

func reserveM3FortinetFullPeerPort(t *testing.T) uint16 {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		listener, listenErr := net.Listen("tcp4", "127.0.0.1:0")
		if listenErr != nil {
			t.Fatal(E.Cause(listenErr, "reserve independent Fortinet TCP port"))
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
	t.Fatal("could not reserve shared independent Fortinet TCP/UDP port")
	return 0
}

func waitM3FortinetPeerMarker(
	t *testing.T,
	ctx context.Context,
	peer m3FortinetFullPeer,
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
			t.Fatal(E.Cause(waitContext.Err(), "wait for independent Fortinet peer marker ", marker, ": ", logs))
		case <-ticker.C:
		}
	}
}

func waitM3FortinetPeerMarkerCount(
	t *testing.T,
	ctx context.Context,
	peer m3FortinetFullPeer,
	marker string,
	count int,
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
		if logsErr == nil && strings.Count(logs, marker) >= count {
			return
		}
		select {
		case <-waitContext.Done():
			t.Fatal(E.Cause(waitContext.Err(), "wait for ", count, " independent Fortinet peer markers ", marker, ": ", logs))
		case <-ticker.C:
		}
	}
}

func m3FortinetPeerLogs(t *testing.T, ctx context.Context, peer m3FortinetFullPeer) string {
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

func (d *m3FortinetPinnedDialer) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	target := destination
	if destination.Fqdn == m3FortinetFullPeerHostname && destination.Port == d.port {
		if d.hostnameDials.Add(1) > d.maximumDials {
			return nil, E.New("poisoned Fortinet logical DNS after authentication")
		}
		target = M.ParseSocksaddrHostPort("127.0.0.1", d.port)
	}
	useChangedSource := false
	if destination.Fqdn == "" && destination.Addr == netip.MustParseAddr("127.0.0.1") && destination.Port == d.port {
		acceptedDial := d.acceptedDials.Add(1)
		useChangedSource = d.changeSource && acceptedDial > 2
	}
	if useChangedSource && network == N.NetworkTCP {
		netDialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
		return netDialer.DialContext(ctx, network, target.String())
	}
	return N.SystemDialer.DialContext(ctx, network, target)
}

func (d *m3FortinetPinnedDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

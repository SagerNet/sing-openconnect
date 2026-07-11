package test

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"hash/crc32"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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
	anyConnectCSDOriginalToken = "original-host-scan-token"
	anyConnectCSDScanToken     = "token-xml-scan-token"
	anyConnectCSDTicket        = "host-scan-ticket"
)

type anyConnectCSDInteropPeer struct {
	access           sync.Mutex
	markerPath       string
	processName      string
	hostname         string
	operatingSystem  string
	machine          string
	release          string
	listeningPort    string
	phase            int
	tokenRequests    int
	dataRequests     int
	scanRequests     int
	waitRequests     int
	firstWait        time.Time
	completed        chan struct{}
	failures         chan error
	completionAccess sync.Once
	wrapper          bool
	wrapperPath      string
	expectedClient   []byte
	tunnelStarted    chan struct{}
	tunnelClosed     chan error
	expectedPassword string
	authenticated    func()
}

type anyConnectCSDActionOriginPeer struct {
	actionURL     string
	failures      chan error
	requests      atomic.Int64
	deferHostScan bool
}

type anyConnectCSDPinDialer struct {
	access           sync.Mutex
	hostname         string
	primary          M.Socksaddr
	replacement      M.Socksaddr
	switched         bool
	primaryDials     int
	replacementDials int
	pinnedDials      int
}

type anyConnectCSDAuthenticationRequestXML struct {
	XMLName xml.Name
	Type    string `xml:"type,attr"`
	Auth    struct {
		Password string `xml:"password"`
	} `xml:"auth"`
}

type anyConnectCSDReport struct {
	values  map[string]string
	objects map[string]struct{}
}

type anyConnectCERTMCAOriginPeer struct {
	actionURL string
	dialer    *anyConnectCERTMCADialer
	failures  chan error
	requests  atomic.Int64
}

type anyConnectCERTMCADialer struct {
	access       sync.Mutex
	hostname     string
	initial      M.Socksaddr
	backend      M.Socksaddr
	switched     bool
	initialDials int
	backendDials int
}

func TestM1AnyConnectCSDInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	markerContent := []byte("sing-openconnect real CSD file probe\n")
	markerPath := filepath.Join(t.TempDir(), "csd-marker.txt")
	err := os.WriteFile(markerPath, markerContent, 0o600)
	if err != nil {
		t.Fatal(E.Cause(err, "write CSD interop marker"))
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(E.Cause(err, "read CSD interop hostname"))
	}
	operatingSystem := anyConnectCSDUname(t, "-s", runtime.GOOS)
	machine := anyConnectCSDUname(t, "-m", runtime.GOARCH)
	peer := &anyConnectCSDInteropPeer{
		markerPath:      markerPath,
		processName:     filepath.Base(os.Args[0]),
		hostname:        hostname,
		operatingSystem: operatingSystem,
		machine:         machine,
		release:         anyConnectCSDUname(t, "-r", ""),
		completed:       make(chan struct{}),
		failures:        make(chan error, 16),
	}
	server := httptest.NewUnstartedServer(peer)
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(E.Cause(err, "parse CSD interop listener address"))
	}
	peer.listeningPort = port
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
		t.Fatal(E.Cause(err, "create CSD interop client"))
	}
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start CSD interop client"))
	}
	select {
	case <-peer.completed:
	case failure := <-peer.failures:
		closeErr := client.Close()
		if closeErr != nil {
			closeErr = E.Cause(closeErr, "close failed CSD interop client")
		}
		t.Fatal(E.Errors(failure, closeErr))
	case <-ctx.Done():
		closeErr := client.Close()
		if closeErr != nil {
			closeErr = E.Cause(closeErr, "close timed-out CSD interop client")
		}
		t.Fatal(E.Errors(E.Cause(ctx.Err(), "wait for complete CSD interop exchange"), closeErr))
	}
	err = client.Close()
	if err != nil {
		t.Fatal(E.Cause(err, "close CSD interop client"))
	}
	peer.access.Lock()
	tokenRequests := peer.tokenRequests
	dataRequests := peer.dataRequests
	scanRequests := peer.scanRequests
	waitRequests := peer.waitRequests
	phase := peer.phase
	peer.access.Unlock()
	if tokenRequests != 1 || dataRequests != 1 || scanRequests != 1 || waitRequests != 2 || phase != 5 {
		t.Fatalf(
			"incomplete CSD exchange: token=%d data=%d scan=%d wait=%d phase=%d",
			tokenRequests,
			dataRequests,
			scanRequests,
			waitRequests,
			phase,
		)
	}
}

func TestM1AnyConnectCSDActionInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	markerContent := []byte("sing-openconnect real CSD file probe\n")
	markerPath := filepath.Join(t.TempDir(), "csd-action-marker.txt")
	err := os.WriteFile(markerPath, markerContent, 0o600)
	if err != nil {
		t.Fatal(E.Cause(err, "write action CSD interop marker"))
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(E.Cause(err, "read action CSD interop hostname"))
	}
	peer := &anyConnectCSDInteropPeer{
		markerPath:       markerPath,
		processName:      filepath.Base(os.Args[0]),
		hostname:         hostname,
		operatingSystem:  anyConnectCSDUname(t, "-s", runtime.GOOS),
		machine:          anyConnectCSDUname(t, "-m", runtime.GOARCH),
		release:          anyConnectCSDUname(t, "-r", ""),
		expectedPassword: "csd-pin-password",
		completed:        make(chan struct{}),
		failures:         make(chan error, 16),
		tunnelStarted:    make(chan struct{}, 1),
		tunnelClosed:     make(chan error, 1),
	}
	actionServer := httptest.NewUnstartedServer(peer)
	actionServer.EnableHTTP2 = false
	actionAddress := M.SocksaddrFromNet(actionServer.Listener.Addr())
	replacementListener, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(int(actionAddress.Port))))
	if err != nil {
		_ = actionServer.Listener.Close()
		t.Skipf("IPv6 loopback cannot host the CSD resolver-switch peer: %v", err)
	}
	replacementRequests := new(atomic.Int64)
	replacementServer := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		replacementRequests.Add(1)
		reportM1LegacyCertificateError(peer.failures, E.New("CSD resolver switch reached the unpinned IPv6 backend: ", request.URL.String()))
		http.Error(writer, "unpinned CSD backend", http.StatusMisdirectedRequest)
	}))
	replacementServer.EnableHTTP2 = false
	err = replacementServer.Listener.Close()
	if err != nil {
		_ = actionServer.Listener.Close()
		_ = replacementListener.Close()
		t.Fatal(E.Cause(err, "replace CSD resolver-switch listener"))
	}
	replacementServer.Listener = replacementListener
	actionServer.StartTLS()
	defer actionServer.Close()
	replacementServer.StartTLS()
	defer replacementServer.Close()
	_, actionPort, err := net.SplitHostPort(actionServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(E.Cause(err, "parse action CSD listener address"))
	}
	peer.listeningPort = actionPort
	dialer := &anyConnectCSDPinDialer{
		hostname:    "csd-pin.invalid",
		primary:     actionAddress,
		replacement: M.ParseSocksaddr(replacementServer.Listener.Addr().String()),
	}
	peer.authenticated = dialer.switchResolver
	originPeer := &anyConnectCSDActionOriginPeer{
		actionURL:     "https://" + net.JoinHostPort(dialer.hostname, actionPort) + "/auth/csd",
		failures:      peer.failures,
		deferHostScan: true,
	}
	originServer := httptest.NewUnstartedServer(originPeer)
	originServer.EnableHTTP2 = false
	originServer.StartTLS()
	defer originServer.Close()

	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context:  ctx,
		Server:   strings.Replace(originServer.URL, "127.0.0.1", "localhost", 1) + "/origin/start",
		Flavor:   openconnect.FlavorAnyConnect,
		NoUDP:    true,
		Password: peer.expectedPassword,
		Dialer:   dialer,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
		}},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create action CSD interop client"))
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start action CSD interop client"))
	}
	waitForAnyConnectCSDCompletion(t, ctx, client, peer)
	waitForM1LegacyCertificateTunnel(t, ctx, peer.failures, peer.tunnelStarted)
	waitForM1Ready(t, ctx, client)
	closeErr := client.Close()
	if closeErr != nil && !E.IsClosed(closeErr) {
		t.Fatal(E.Cause(closeErr, "close action CSD interop client"))
	}
	waitForM1LegacyCertificateTunnelClose(t, ctx, peer.failures, peer.tunnelClosed)
	peer.access.Lock()
	tokenRequests := peer.tokenRequests
	dataRequests := peer.dataRequests
	scanRequests := peer.scanRequests
	waitRequests := peer.waitRequests
	phase := peer.phase
	peer.access.Unlock()
	if originPeer.requests.Load() != 1 || tokenRequests != 1 || dataRequests != 1 || scanRequests != 1 || waitRequests != 2 || phase != 5 {
		t.Fatalf(
			"incomplete action CSD exchange: origin=%d token=%d data=%d scan=%d wait=%d phase=%d",
			originPeer.requests.Load(),
			tokenRequests,
			dataRequests,
			scanRequests,
			waitRequests,
			phase,
		)
	}
	dialer.assertPinned(t)
	if requests := replacementRequests.Load(); requests != 0 {
		t.Fatalf("CSD resolver switch reached replacement backend %d times", requests)
	}
}

func TestM1AnyConnectCERTMCAActionCSDTunnelInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	markerPath := filepath.Join(t.TempDir(), "cert-mca-csd-marker.txt")
	err := os.WriteFile(markerPath, []byte("sing-openconnect real CSD file probe\n"), 0o600)
	if err != nil {
		t.Fatal(E.Cause(err, "write CERT/MCA/CSD marker"))
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(E.Cause(err, "read CERT/MCA/CSD hostname"))
	}
	peer := &anyConnectCSDInteropPeer{
		markerPath:      markerPath,
		processName:     filepath.Base(os.Args[0]),
		hostname:        hostname,
		operatingSystem: anyConnectCSDUname(t, "-s", runtime.GOOS),
		machine:         anyConnectCSDUname(t, "-m", runtime.GOARCH),
		release:         anyConnectCSDUname(t, "-r", ""),
		phase:           1,
		completed:       make(chan struct{}),
		failures:        make(chan error, 16),
		tunnelStarted:   make(chan struct{}, 1),
		tunnelClosed:    make(chan error, 1),
	}
	actionServer := httptest.NewUnstartedServer(peer)
	actionServer.EnableHTTP2 = false
	actionServer.StartTLS()
	t.Cleanup(actionServer.Close)
	_, actionPort, err := net.SplitHostPort(actionServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(E.Cause(err, "parse CERT/MCA/CSD action listener"))
	}
	peer.listeningPort = actionPort
	actionURL := actionServer.URL + "/auth/csd"

	_, err = dockerOutput(ctx, "version", "--format", "{{.Server.Version}}")
	if err != nil {
		t.Fatal(err)
	}
	_, err = dockerOutput(ctx, "build", "--pull=false", "--tag", fakeCiscoInteropImage, filepath.Join("testdata", "fake-cisco"))
	if err != nil {
		t.Fatal(err)
	}
	fixture := createMultipleCertificateFixture(t, "rsa")
	containerName := "sing-openconnect-m1-cert-mca-csd-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	_, err = dockerOutput(
		ctx,
		"run", "--detach", "--rm", "--name", containerName,
		"--publish", "127.0.0.1::443/tcp",
		"--mount", "type=bind,source="+fixture.directory+",target=/certs,readonly",
		fakeCiscoInteropImage,
		"--enable-multicert",
		"--cafile", "/certs/ca.pem",
		"--client-cafile", "/certs/machine-ca.pem",
		"--expected-hash", "sha512",
		"--expected-certificate-count", "2",
		"--require-client-cert",
		"--post-mca-action-url", actionURL,
		"0.0.0.0", "443", "/certs/server-cert.pem", "/certs/server-key.pem",
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
				t.Log("combined fake Cisco logs:\n" + logs)
			}
		}
		removeContext, cancelRemove := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = dockerOutput(removeContext, "rm", "--force", containerName)
		cancelRemove()
	})
	backendAddress := dockerPublishedAddress(t, ctx, containerName, "443/tcp")
	waitForTCP(t, ctx, backendAddress)
	dialer := &anyConnectCERTMCADialer{
		hostname: "cert-mca-chain.invalid",
		backend:  M.ParseSocksaddr(backendAddress),
	}
	originPeer := &anyConnectCERTMCAOriginPeer{
		actionURL: actionURL,
		dialer:    dialer,
		failures:  peer.failures,
	}
	originServer := httptest.NewUnstartedServer(originPeer)
	originServer.EnableHTTP2 = false
	dialer.initial = M.SocksaddrFromNet(originServer.Listener.Addr())
	originServer.StartTLS()
	t.Cleanup(originServer.Close)
	_, logicalPort, err := net.SplitHostPort(originServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(E.Cause(err, "parse CERT1 logical listener"))
	}
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  "https://" + net.JoinHostPort(dialer.hostname, logicalPort),
		Flavor:  openconnect.FlavorAnyConnect,
		NoUDP:   true,
		Dialer:  dialer,
		TLSConfig: openconnect.ClientTLSOptions{
			Config:         &tls.Config{InsecureSkipVerify: true},
			Certificate:    openconnect.Material{Content: fixture.machineCertificate},
			Key:            openconnect.Material{Content: fixture.machineKey},
			MCACertificate: openconnect.Material{Content: fixture.userCertificate},
			MCAKey:         openconnect.Material{Content: fixture.userKey},
		},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create combined CERT/MCA/CSD client"))
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start combined CERT/MCA/CSD client"))
	}
	waitForAnyConnectCSDCompletion(t, ctx, client, peer)
	waitForM1LegacyCertificateTunnel(t, ctx, peer.failures, peer.tunnelStarted)
	waitForM1Ready(t, ctx, client)
	closeErr := client.Close()
	if closeErr != nil && !E.IsClosed(closeErr) {
		t.Fatal(E.Cause(closeErr, "close combined CERT/MCA/CSD client"))
	}
	waitForM1LegacyCertificateTunnelClose(t, ctx, peer.failures, peer.tunnelClosed)
	logs, err := dockerOutput(ctx, "logs", containerName)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(logs, fakeCiscoAuthenticationMarker) != 1 {
		t.Fatalf("combined peer did not complete exactly one CERT2 signature exchange:\n%s", logs)
	}
	if requests := originPeer.requests.Load(); requests != 1 {
		t.Fatalf("CERT1 origin received %d requests, expected exactly one", requests)
	}
	dialer.assertFreshTLS(t)
	peer.access.Lock()
	tokenRequests := peer.tokenRequests
	dataRequests := peer.dataRequests
	scanRequests := peer.scanRequests
	waitRequests := peer.waitRequests
	phase := peer.phase
	peer.access.Unlock()
	if tokenRequests != 1 || dataRequests != 1 || scanRequests != 1 || waitRequests != 2 || phase != 5 {
		t.Fatalf(
			"combined CERT/MCA action was not applied exactly once before CSD/CSTP: token=%d data=%d scan=%d wait=%d phase=%d",
			tokenRequests,
			dataRequests,
			scanRequests,
			waitRequests,
			phase,
		)
	}
}

func TestM1AnyConnectCSDWrapperInterop(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("external CSD wrappers are not supported on Windows")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, clientCertificatePEM, clientKeyPEM := createM1ClientCertificate(t, "m1-csd-wrapper-machine")
	clientCertificate, err := tls.X509KeyPair(clientCertificatePEM, clientKeyPEM)
	if err != nil {
		t.Fatal(E.Cause(err, "parse CSD wrapper callback identity"))
	}
	_, serverCertificatePEM, serverKeyPEM := createM1ClientCertificate(t, "m1-csd-wrapper-server")
	serverIdentity, err := tls.X509KeyPair(serverCertificatePEM, serverKeyPEM)
	if err != nil {
		t.Fatal(E.Cause(err, "parse CSD wrapper action server identity"))
	}
	wrapperPath := filepath.Join(t.TempDir(), "csd-wrapper")
	wrapperScript := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > \"$0.args\"\n" +
		"printf '%s\\n' \"$CSD_SHA256\" \"$CSD_TOKEN\" \"$CSD_HOSTNAME\" > \"$0.env\"\n" +
		"exit 23\n"
	err = os.WriteFile(wrapperPath, []byte(wrapperScript), 0o700)
	if err != nil {
		t.Fatal(E.Cause(err, "write CSD wrapper executable"))
	}
	peer := &anyConnectCSDInteropPeer{
		wrapper:        true,
		wrapperPath:    wrapperPath,
		expectedClient: append([]byte(nil), clientCertificate.Certificate[0]...),
		phase:          1,
		completed:      make(chan struct{}),
		failures:       make(chan error, 16),
	}
	actionServer := httptest.NewUnstartedServer(peer)
	actionServer.EnableHTTP2 = false
	actionServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverIdentity},
		ClientAuth:   tls.RequestClientCert,
	}
	actionServer.StartTLS()
	defer actionServer.Close()
	originPeer := &anyConnectCSDActionOriginPeer{
		actionURL: strings.Replace(actionServer.URL, "127.0.0.1", "localhost", 1) + "/auth/csd",
		failures:  peer.failures,
	}
	originServer := httptest.NewUnstartedServer(originPeer)
	originServer.EnableHTTP2 = false
	originServer.StartTLS()
	defer originServer.Close()
	if bytes.Equal(originServer.Certificate().Raw, actionServer.Certificate().Raw) {
		t.Fatal("CSD wrapper action peer unexpectedly reused the origin TLS certificate")
	}
	var callbackCalls atomic.Int64
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  strings.Replace(originServer.URL, "127.0.0.1", "localhost", 1) + "/origin/start",
		Flavor:  openconnect.FlavorAnyConnect,
		NoUDP:   true,
		CSD:     &openconnect.CSDOptions{WrapperPath: wrapperPath},
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				callbackCalls.Add(1)
				return &clientCertificate, nil
			},
		}},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create CSD wrapper interop client"))
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start CSD wrapper interop client"))
	}
	waitForAnyConnectCSDCompletion(t, ctx, client, peer)
	if callbackCalls.Load() == 0 {
		t.Fatal("CSD wrapper TLS peer did not request the callback identity")
	}

	argumentsData, err := os.ReadFile(wrapperPath + ".args")
	if err != nil {
		t.Fatal(E.Cause(err, "read CSD wrapper arguments"))
	}
	arguments := strings.Split(strings.TrimSuffix(string(argumentsData), "\n"), "\n")
	serverCertificate := actionServer.Certificate()
	serverMD5 := md5.Sum(serverCertificate.Raw)
	clientMD5 := md5.Sum(clientCertificate.Certificate[0])
	expectedArguments := []string{
		"",
		"-ticket", strconv.Quote(anyConnectCSDTicket),
		"-stub", strconv.Quote("0"),
		"-group", strconv.Quote(""),
		"-certhash", strconv.Quote(strings.ToUpper(hex.EncodeToString(serverMD5[:])) + ":" + strings.ToUpper(hex.EncodeToString(clientMD5[:]))),
		"-url", strconv.Quote(actionServer.URL + "/+CSCOE+/sdesktop/index.html"),
		"-langselen",
	}
	if strings.Join(arguments, "\x00") != strings.Join(expectedArguments, "\x00") {
		t.Fatalf("unexpected CSD wrapper arguments:\nactual:   %#v\nexpected: %#v", arguments, expectedArguments)
	}
	environmentData, err := os.ReadFile(wrapperPath + ".env")
	if err != nil {
		t.Fatal(E.Cause(err, "read CSD wrapper environment"))
	}
	publicKeyHash := sha256.Sum256(serverCertificate.RawSubjectPublicKeyInfo)
	expectedEnvironment := strings.Join([]string{
		base64.StdEncoding.EncodeToString(publicKeyHash[:]),
		anyConnectCSDOriginalToken,
		strings.TrimPrefix(actionServer.URL, "https://"),
		"",
	}, "\n")
	if string(environmentData) != expectedEnvironment {
		t.Fatalf("unexpected CSD wrapper environment: %q, expected %q", environmentData, expectedEnvironment)
	}
	peer.access.Lock()
	waitRequests := peer.waitRequests
	phase := peer.phase
	tokenRequests := peer.tokenRequests
	dataRequests := peer.dataRequests
	scanRequests := peer.scanRequests
	peer.access.Unlock()
	if originPeer.requests.Load() != 1 || waitRequests != 2 || phase != 5 || tokenRequests != 0 || dataRequests != 0 || scanRequests != 0 {
		t.Fatalf("incomplete wrapper CSD exchange: origin=%d token=%d data=%d scan=%d wait=%d phase=%d", originPeer.requests.Load(), tokenRequests, dataRequests, scanRequests, waitRequests, phase)
	}
}

func TestM1AnyConnectCSDWrapperSignalInterop(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("external CSD wrappers are not supported on Windows")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wrapperPath := filepath.Join(t.TempDir(), "csd-wrapper-signal")
	wrapperScript := "#!/bin/sh\n" +
		"printf 'invoked\\n' >> \"$0.invoked\"\n" +
		"kill -TERM $$\n"
	err := os.WriteFile(wrapperPath, []byte(wrapperScript), 0o700)
	if err != nil {
		t.Fatal(E.Cause(err, "write signaled CSD wrapper executable"))
	}
	peer := &anyConnectCSDInteropPeer{
		wrapper:     true,
		wrapperPath: wrapperPath,
		completed:   make(chan struct{}),
		failures:    make(chan error, 16),
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
		CSD:     &openconnect.CSDOptions{WrapperPath: wrapperPath},
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
		}},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create signaled CSD wrapper client"))
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start signaled CSD wrapper client"))
	}
	invocationPath := wrapperPath + ".invoked"
	for {
		_, statErr := os.Stat(invocationPath)
		if statErr == nil {
			break
		}
		if !os.IsNotExist(statErr) {
			t.Fatal(E.Cause(statErr, "inspect signaled CSD wrapper marker"))
		}
		select {
		case failure := <-peer.failures:
			t.Fatal(failure)
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for signaled CSD wrapper"))
		case <-time.After(10 * time.Millisecond):
		}
	}
	_, terminalErr := client.ReadDataPacket(ctx)
	if terminalErr == nil || !strings.Contains(terminalErr.Error(), "terminated abnormally") {
		t.Fatalf("signaled CSD wrapper did not terminate the client: %v", terminalErr)
	}
	timer := time.NewTimer(1200 * time.Millisecond)
	defer timer.Stop()
	<-timer.C
	invocations, err := os.ReadFile(invocationPath)
	if err != nil {
		t.Fatal(E.Cause(err, "read signaled CSD wrapper invocations"))
	}
	if string(invocations) != "invoked\n" {
		t.Fatalf("signaled CSD wrapper was retried: %q", invocations)
	}
	peer.access.Lock()
	waitRequests := peer.waitRequests
	peer.access.Unlock()
	if waitRequests != 0 {
		t.Fatalf("signaled CSD wrapper was ignored and reached wait endpoint %d times", waitRequests)
	}
}

func waitForAnyConnectCSDCompletion(t *testing.T, ctx context.Context, client *openconnect.Client, peer *anyConnectCSDInteropPeer) {
	t.Helper()
	select {
	case <-peer.completed:
	case failure := <-peer.failures:
		closeErr := client.Close()
		t.Fatal(E.Errors(failure, closeErr))
	case <-ctx.Done():
		closeErr := client.Close()
		t.Fatal(E.Errors(E.Cause(ctx.Err(), "wait for CSD wrapper exchange"), closeErr))
	}
}

func (p *anyConnectCSDActionOriginPeer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	body, err := readAnyConnectCSDPeerBody(request)
	if err != nil {
		reportM1LegacyCertificateError(p.failures, err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	document, err := parseAnyConnectCSDAuthenticationRequest(body)
	if err != nil {
		reportM1LegacyCertificateError(p.failures, err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	requestCount := p.requests.Add(1)
	if requestCount != 1 || request.Method != http.MethodPost || request.URL.Path != "/origin/start" || document.Type != "init" {
		reportM1LegacyCertificateError(p.failures, E.New("CSD action origin received an invalid authentication request"))
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	http.SetCookie(writer, &http.Cookie{Name: "obsolete-csd-cookie", Value: "must-not-cross-action", Path: "/", Secure: true})
	hostScan := `<host-scan>
    <host-scan-ticket>` + anyConnectCSDTicket + `</host-scan-ticket>
    <host-scan-token>` + anyConnectCSDOriginalToken + `</host-scan-token>
    <host-scan-base-uri>/+CSCOE+/sdesktop/index.html</host-scan-base-uri>
    <host-scan-wait-uri>/+CSCOE+/sdesktop/wait.xml</host-scan-wait-uri>
  </host-scan>`
	if p.deferHostScan {
		hostScan = ""
	}
	response := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request">
  ` + hostScan + `
  <auth id="main">
    <csdLinux stuburl="/forbidden-csd-stub"/>
    <form method="POST" action="` + p.actionURL + `">
      <input name="missing-type"/>
      <input type="text"/>
      <input type="vendor-biometric" name="vendor-extension"/>
      <input type="password" name="password" label="Password:"/>
    </form>
  </auth>
</config-auth>`
	writer.Header().Set("Content-Type", "text/xml")
	_, err = io.WriteString(writer, response)
	if err != nil {
		reportM1LegacyCertificateError(p.failures, E.Cause(err, "write CSD action challenge"))
	}
}

func (p *anyConnectCSDInteropPeer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodPost && (request.URL.Path == "/" || request.URL.Path == "/auth/csd"):
		p.handleAuthentication(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/+CSCOE+/sdesktop/token.xml":
		p.handleToken(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/CACHE/sdesktop/data.xml":
		p.handleData(writer, request)
	case request.Method == http.MethodPost && request.URL.Path == "/+CSCOE+/sdesktop/scan.xml":
		p.handleScan(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/+CSCOE+/sdesktop/wait.xml":
		p.handleWait(writer, request)
	case request.Method == http.MethodConnect:
		if p.tunnelStarted != nil && p.tunnelClosed != nil {
			p.access.Lock()
			phase := p.phase
			p.access.Unlock()
			cookie, err := request.Cookie("webvpn")
			if phase != 5 || err != nil || cookie.Value != "csd-complete-session-token" {
				p.fail(writer, E.New("action CSD peer received unauthenticated CSTP CONNECT"))
				return
			}
			_, obsoleteCookieErr := request.Cookie("obsolete-csd-cookie")
			if obsoleteCookieErr != http.ErrNoCookie {
				p.fail(writer, E.New("action CSD CSTP CONNECT retained the origin authentication cookie"))
				return
			}
			serveM1LegacyCertificateTunnel(writer, p.failures, p.tunnelStarted, p.tunnelClosed)
			return
		}
		writer.WriteHeader(http.StatusServiceUnavailable)
	default:
		p.fail(writer, E.New("unexpected CSD peer request: ", request.Method, " ", request.URL.String()))
	}
}

func (p *anyConnectCSDInteropPeer) handleAuthentication(writer http.ResponseWriter, request *http.Request) {
	body, err := readAnyConnectCSDPeerBody(request)
	if err != nil {
		p.fail(writer, err)
		return
	}
	document, err := parseAnyConnectCSDAuthenticationRequest(body)
	if err != nil {
		p.fail(writer, err)
		return
	}
	if len(p.expectedClient) > 0 {
		if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 || !bytes.Equal(request.TLS.PeerCertificates[0].Raw, p.expectedClient) {
			p.fail(writer, E.New("CSD wrapper HTTPS peer did not receive the callback client identity"))
			return
		}
	}
	p.access.Lock()
	phase := p.phase
	if phase == 0 {
		p.phase = 1
	} else if phase == 4 {
		p.phase = 5
	}
	p.access.Unlock()
	if phase == 0 {
		validInitialization := document.Type == "init"
		if p.expectedPassword != "" {
			validInitialization = document.Type == "auth-reply" && document.Auth.Password == p.expectedPassword
			_, obsoleteCookieErr := request.Cookie("obsolete-csd-cookie")
			if obsoleteCookieErr != http.ErrNoCookie {
				p.fail(writer, E.New("CSD action authentication retained the origin cookie"))
				return
			}
		}
		if !validInitialization {
			p.fail(writer, E.New("CSD peer received an invalid initial authentication body"))
			return
		}
		writer.Header().Add("Set-Cookie", "obsolete-csd-cookie=must-not-survive; Path=/; Secure; HttpOnly")
		response := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request">
  <host-scan>
    <host-scan-ticket>` + anyConnectCSDTicket + `</host-scan-ticket>
    <host-scan-token>` + anyConnectCSDOriginalToken + `</host-scan-token>
    <host-scan-base-uri>/+CSCOE+/sdesktop/index.html</host-scan-base-uri>
    <host-scan-wait-uri>/+CSCOE+/sdesktop/wait.xml</host-scan-wait-uri>
  </host-scan>
  <auth id="main">
    <csdLinux stuburl="/forbidden-csd-stub"/>
    <form method="POST" action="/"><input type="password" name="password" label="Password:"/></form>
  </auth>
		</config-auth>`
		p.writeXML(writer, response)
		if p.authenticated != nil {
			p.authenticated()
		}
		return
	}
	if phase == 4 && document.Type != "init" {
		p.fail(writer, E.New("CSD authentication refresh was not a config-auth init document"))
		return
	}
	if phase != 4 {
		p.fail(writer, E.New("CSD peer received authentication POST in phase ", phase))
		return
	}
	err = requireAnyConnectCSDCookie(request, anyConnectCSDOriginalToken)
	if err != nil {
		p.fail(writer, E.Cause(err, "CSD authentication refresh"))
		return
	}
	_, obsoleteCookieErr := request.Cookie("obsolete-csd-cookie")
	if obsoleteCookieErr != http.ErrNoCookie {
		p.fail(writer, E.New("CSD authentication refresh retained a pre-CSD cookie"))
		return
	}
	response := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete">
  <session-token>csd-complete-session-token</session-token>
  <host-scan>
    <host-scan-ticket>` + anyConnectCSDTicket + `</host-scan-ticket>
    <host-scan-token>` + anyConnectCSDOriginalToken + `</host-scan-token>
    <host-scan-base-uri>/+CSCOE+/sdesktop/index.html</host-scan-base-uri>
    <host-scan-wait-uri>/+CSCOE+/sdesktop/wait.xml</host-scan-wait-uri>
  </host-scan>
  <auth id="success"/>
</config-auth>`
	p.writeXML(writer, response)
	p.completionAccess.Do(func() {
		close(p.completed)
	})
}

func (p *anyConnectCSDInteropPeer) handleToken(writer http.ResponseWriter, request *http.Request) {
	body, err := readAnyConnectCSDPeerBody(request)
	if err != nil {
		p.fail(writer, err)
		return
	}
	if len(body) != 0 {
		p.fail(writer, E.New("CSD token GET unexpectedly contained a body"))
		return
	}
	p.access.Lock()
	phase := p.phase
	p.tokenRequests++
	p.access.Unlock()
	if phase != 1 {
		p.fail(writer, E.New("CSD token request arrived in phase ", phase))
		return
	}
	if request.URL.Query().Get("ticket") != anyConnectCSDTicket || request.URL.Query().Get("stub") != "0" {
		p.fail(writer, E.New("CSD token request used incorrect ticket or stub query"))
		return
	}
	_, obsoleteCookieErr := request.Cookie("obsolete-csd-cookie")
	if obsoleteCookieErr != http.ErrNoCookie {
		p.fail(writer, E.New("CSD token request received a pre-CSD authentication cookie"))
		return
	}
	p.writeXML(writer, `<?xml version="1.0"?><hostscan><token>`+anyConnectCSDScanToken+`</token></hostscan>`)
}

func (p *anyConnectCSDInteropPeer) handleData(writer http.ResponseWriter, request *http.Request) {
	body, err := readAnyConnectCSDPeerBody(request)
	if err != nil {
		p.fail(writer, err)
		return
	}
	if len(body) != 0 {
		p.fail(writer, E.New("CSD data GET unexpectedly contained a body"))
		return
	}
	p.access.Lock()
	phase := p.phase
	p.dataRequests++
	p.access.Unlock()
	if phase != 1 {
		p.fail(writer, E.New("CSD data request arrived in phase ", phase))
		return
	}
	fileValue := html.EscapeString("'File','marker-file','" + p.markerPath + "'")
	processValue := html.EscapeString("'Process','client-process','" + p.processName + "'")
	response := `<?xml version="1.0"?><data><hostscan><field value="` + fileValue + `"/><field value="` + processValue + `"/></hostscan></data>`
	p.writeXML(writer, response)
}

func (p *anyConnectCSDInteropPeer) handleScan(writer http.ResponseWriter, request *http.Request) {
	body, err := readAnyConnectCSDPeerBody(request)
	if err != nil {
		p.fail(writer, err)
		return
	}
	p.access.Lock()
	phase := p.phase
	tokenRequests := p.tokenRequests
	dataRequests := p.dataRequests
	p.scanRequests++
	if phase == 1 {
		p.phase = 2
	}
	p.access.Unlock()
	if phase != 1 || tokenRequests != 1 || dataRequests != 1 {
		p.fail(writer, E.New("CSD scan arrived before token/data exchange completed"))
		return
	}
	if request.URL.Query().Get("reusebrowser") != "1" {
		p.fail(writer, E.New("CSD scan omitted reusebrowser=1"))
		return
	}
	err = requireAnyConnectCSDCookie(request, anyConnectCSDScanToken)
	if err != nil {
		p.fail(writer, E.Cause(err, "CSD scan submission"))
		return
	}
	if !strings.HasPrefix(request.Header.Get("Content-Type"), "text/xml") {
		p.fail(writer, E.New("CSD scan used unexpected Content-Type: ", request.Header.Get("Content-Type")))
		return
	}
	err = p.validateReport(body)
	if err != nil {
		p.fail(writer, err)
		return
	}
	p.writeXML(writer, `<?xml version="1.0"?><hostscan><status>accepted</status></hostscan>`)
}

func (p *anyConnectCSDInteropPeer) validateReport(report []byte) error {
	parsedReport, err := parseAnyConnectCSDReport(report)
	if err != nil {
		return err
	}
	fileInfo, err := os.Stat(p.markerPath)
	if err != nil {
		return E.Cause(err, "inspect CSD marker for report validation")
	}
	requiredValues := map[string]string{
		"endpoint.os.version":                       p.operatingSystem,
		"endpoint.os.architecture":                  p.machine,
		"endpoint.device.hostname":                  p.hostname,
		`endpoint.file["marker-file"].path`:         p.markerPath,
		`endpoint.file["marker-file"].name`:         filepath.Base(p.markerPath),
		`endpoint.file["marker-file"].exists`:       "true",
		`endpoint.file["marker-file"].timestamp`:    strconv.FormatInt(fileInfo.ModTime().Unix(), 10),
		`endpoint.process["client-process"].name`:   p.processName,
		`endpoint.process["client-process"].exists`: "true",
	}
	if p.release != "" {
		requiredValues["endpoint.os.servicepack"] = p.release
	}
	checksum := crc32.ChecksumIEEE([]byte("sing-openconnect real CSD file probe\n"))
	checksumBytes := []byte{byte(checksum >> 24), byte(checksum >> 16), byte(checksum >> 8), byte(checksum)}
	requiredValues[`endpoint.file["marker-file"].crc32`] = "0x" + hex.EncodeToString(checksumBytes)
	interfaces, err := net.Interfaces()
	if err != nil {
		return E.Cause(err, "list interfaces for CSD report validation")
	}
	for _, networkInterface := range interfaces {
		macAddress := formatAnyConnectCSDTestMAC(networkInterface.HardwareAddr)
		if macAddress != "" {
			requiredValues[`endpoint.device.MAC[`+strconv.Quote(macAddress)+`]`] = "true"
		}
	}
	ipv4Ports := readAnyConnectCSDTestListeningPorts("/proc/net/tcp")
	ipv6Ports := readAnyConnectCSDTestListeningPorts("/proc/net/tcp6")
	lastModifiedSeen := false
	for name, value := range parsedReport.values {
		expectedValue, expected := requiredValues[name]
		if expected {
			if value != expectedValue {
				return E.New("CSD report value for ", name, " = ", value, ", expected ", expectedValue)
			}
			delete(requiredValues, name)
			continue
		}
		if name == `endpoint.file["marker-file"].lastmodified` {
			seconds, parseErr := strconv.ParseInt(value, 10, 64)
			if parseErr != nil || seconds < 0 || seconds > time.Now().Unix()-fileInfo.ModTime().Unix()+2 {
				return E.New("CSD report used an invalid marker lastmodified value: ", value)
			}
			lastModifiedSeen = true
			continue
		}
		handled, portErr := validateAnyConnectCSDReportedPort(name, value, ipv4Ports, ipv6Ports)
		if portErr != nil {
			return portErr
		}
		if handled {
			continue
		}
		if strings.HasPrefix(name, "endpoint.fw[") || strings.HasPrefix(name, "endpoint.av[") ||
			strings.HasPrefix(name, "endpoint.as[") || strings.Contains(name, "disk") ||
			strings.Contains(name, "encryption") || strings.Contains(name, "protection") {
			return E.New("CSD report fabricated an unobserved security posture field: ", name)
		}
		return E.New("CSD report contained an unverified field: ", name)
	}
	if len(requiredValues) > 0 {
		for name := range requiredValues {
			return E.New("CSD report omitted verified value: ", name)
		}
	}
	if !lastModifiedSeen {
		return E.New("CSD report omitted marker lastmodified")
	}
	requiredObjects := map[string]struct{}{
		`endpoint.file["marker-file"]`:       {},
		`endpoint.process["client-process"]`: {},
	}
	for name := range parsedReport.objects {
		if _, expected := requiredObjects[name]; !expected {
			return E.New("CSD report declared an unverified object: ", name)
		}
		delete(requiredObjects, name)
	}
	if len(requiredObjects) != 0 {
		return E.New("CSD report omitted a requested file or process object")
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		portName := `endpoint.device.port[` + strconv.Quote(p.listeningPort) + `]`
		if parsedReport.values[portName] != "true" {
			return E.New("CSD report omitted its observed TLS listening port: ", p.listeningPort)
		}
	}
	return nil
}

func parseAnyConnectCSDAuthenticationRequest(body []byte) (anyConnectCSDAuthenticationRequestXML, error) {
	var document anyConnectCSDAuthenticationRequestXML
	decoder := xml.NewDecoder(bytes.NewReader(body))
	err := decoder.Decode(&document)
	if err != nil {
		return document, E.Cause(err, "strictly parse CSD authentication XML")
	}
	if document.XMLName.Local != "config-auth" {
		return document, E.New("unexpected CSD authentication XML root: ", document.XMLName.Local)
	}
	var extra struct{}
	err = decoder.Decode(&extra)
	if err != io.EOF {
		if err == nil {
			return document, E.New("CSD authentication request contained a second XML document")
		}
		return document, E.Cause(err, "finish strict CSD authentication XML parse")
	}
	return document, nil
}

func parseAnyConnectCSDReport(content []byte) (anyConnectCSDReport, error) {
	report := anyConnectCSDReport{
		values:  make(map[string]string),
		objects: make(map[string]struct{}),
	}
	for lineIndex, rawLine := range strings.Split(string(content), "\n") {
		if rawLine == "" && lineIndex == len(strings.Split(string(content), "\n"))-1 {
			continue
		}
		if rawLine == "" || strings.TrimSpace(rawLine) != rawLine {
			return report, E.New("invalid CSD report line ", lineIndex+1, ": ", rawLine)
		}
		if strings.HasSuffix(rawLine, "={};") {
			name := strings.TrimSuffix(rawLine, "={};")
			if name == "" {
				return report, E.New("empty CSD report object name on line ", lineIndex+1)
			}
			if _, duplicate := report.objects[name]; duplicate {
				return report, E.New("duplicate CSD report object: ", name)
			}
			report.objects[name] = struct{}{}
			continue
		}
		name, encodedValue, found := strings.Cut(rawLine, "=")
		if !found || name == "" || !strings.HasSuffix(encodedValue, ";") {
			return report, E.New("invalid CSD report assignment on line ", lineIndex+1, ": ", rawLine)
		}
		value, err := strconv.Unquote(strings.TrimSuffix(encodedValue, ";"))
		if err != nil {
			return report, E.Cause(err, "decode CSD report value for ", name)
		}
		if previousValue, duplicate := report.values[name]; duplicate {
			if previousValue != value {
				return report, E.New("conflicting duplicate CSD report value: ", name)
			}
			continue
		}
		report.values[name] = value
	}
	return report, nil
}

func validateAnyConnectCSDReportedPort(
	name string,
	value string,
	ipv4Ports map[int]bool,
	ipv6Ports map[int]bool,
) (bool, error) {
	for prefix, ports := range map[string]map[int]bool{
		"endpoint.device.port":     mergeAnyConnectCSDTestPorts(ipv4Ports, ipv6Ports),
		"endpoint.device.tcp4port": ipv4Ports,
		"endpoint.device.tcp6port": ipv6Ports,
	} {
		portText, matched, err := parseAnyConnectCSDReportIndex(name, prefix)
		if err != nil {
			return true, err
		}
		if !matched {
			continue
		}
		port, parseErr := strconv.Atoi(portText)
		if parseErr != nil || !ports[port] || value != "true" {
			return true, E.New("CSD report claimed an unobserved listening port: ", name, "=", value)
		}
		return true, nil
	}
	return false, nil
}

func parseAnyConnectCSDReportIndex(name string, prefix string) (string, bool, error) {
	if !strings.HasPrefix(name, prefix+"[") || !strings.HasSuffix(name, "]") {
		return "", false, nil
	}
	encoded := name[len(prefix)+1 : len(name)-1]
	value, err := strconv.Unquote(encoded)
	if err != nil {
		return "", true, E.Cause(err, "decode CSD report index for ", prefix)
	}
	return value, true, nil
}

func readAnyConnectCSDTestListeningPorts(path string) map[int]bool {
	ports := make(map[int]bool)
	content, err := os.ReadFile(path)
	if err != nil {
		return ports
	}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		separator := strings.LastIndexByte(fields[1], ':')
		if separator < 0 || separator == len(fields[1])-1 {
			continue
		}
		port, parseErr := strconv.ParseUint(fields[1][separator+1:], 16, 16)
		if parseErr == nil && port > 0 {
			ports[int(port)] = true
		}
	}
	return ports
}

func mergeAnyConnectCSDTestPorts(left map[int]bool, right map[int]bool) map[int]bool {
	merged := make(map[int]bool, len(left)+len(right))
	for port := range left {
		merged[port] = true
	}
	for port := range right {
		merged[port] = true
	}
	return merged
}

func formatAnyConnectCSDTestMAC(address net.HardwareAddr) string {
	if len(address) != 6 {
		return ""
	}
	allZero := true
	for _, value := range address {
		if value != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ""
	}
	hexAddress := strings.ToUpper(hex.EncodeToString(address))
	return hexAddress[:4] + "." + hexAddress[4:8] + "." + hexAddress[8:]
}

func (p *anyConnectCSDInteropPeer) handleWait(writer http.ResponseWriter, request *http.Request) {
	body, err := readAnyConnectCSDPeerBody(request)
	if err != nil {
		p.fail(writer, err)
		return
	}
	if len(body) != 0 {
		p.fail(writer, E.New("CSD wait GET unexpectedly contained a body"))
		return
	}
	err = requireAnyConnectCSDCookie(request, anyConnectCSDOriginalToken)
	if err != nil {
		p.fail(writer, E.Cause(err, "CSD wait request"))
		return
	}
	p.access.Lock()
	phase := p.phase
	p.waitRequests++
	waitRequest := p.waitRequests
	firstWaitPhase := 2
	if p.wrapper {
		firstWaitPhase = 1
	}
	if waitRequest == 1 && phase == firstWaitPhase {
		if p.wrapper {
			_, statErr := os.Stat(p.wrapperPath + ".args")
			if statErr != nil {
				p.access.Unlock()
				p.fail(writer, E.Cause(statErr, "CSD wait arrived before wrapper captured arguments"))
				return
			}
		}
		p.firstWait = time.Now()
		p.phase = 3
	} else if waitRequest == 2 && phase == 3 {
		if time.Since(p.firstWait) < 900*time.Millisecond {
			p.access.Unlock()
			p.fail(writer, E.New("CSD wait page was refreshed before the required one-second interval"))
			return
		}
		p.phase = 4
	}
	p.access.Unlock()
	if waitRequest == 1 && phase == firstWaitPhase {
		writer.Header().Set("Content-Type", "text/html")
		p.writeResponse(writer, `<html><head><meta http-equiv="refresh" content="1"></head></html>`)
		return
	}
	if waitRequest == 2 && phase == 3 {
		p.writeXML(writer, `<?xml version="1.0"?><hostscan><status>complete</status></hostscan>`)
		return
	}
	p.fail(writer, E.New("CSD wait request arrived in phase ", phase, " as request ", waitRequest))
}

func (p *anyConnectCSDInteropPeer) writeXML(writer http.ResponseWriter, response string) {
	writer.Header().Set("Content-Type", "text/xml")
	p.writeResponse(writer, response)
}

func (p *anyConnectCSDInteropPeer) writeResponse(writer http.ResponseWriter, response string) {
	n, err := io.WriteString(writer, response)
	if err != nil {
		p.recordFailure(E.Cause(err, "write CSD peer response"))
		return
	}
	if n != len(response) {
		p.recordFailure(E.New("short CSD peer response write: ", n, " of ", len(response)))
	}
}

func (p *anyConnectCSDInteropPeer) fail(writer http.ResponseWriter, err error) {
	p.recordFailure(err)
	http.Error(writer, err.Error(), http.StatusBadRequest)
}

func (p *anyConnectCSDInteropPeer) recordFailure(err error) {
	select {
	case p.failures <- err:
	default:
	}
}

func readAnyConnectCSDPeerBody(request *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(request.Body, 8*1024*1024+1))
	if err != nil {
		return nil, E.Cause(err, "read CSD peer request")
	}
	if len(body) > 8*1024*1024 {
		return nil, E.New("CSD peer request exceeded 8 MiB")
	}
	return body, nil
}

func requireAnyConnectCSDCookie(request *http.Request, expectedToken string) error {
	cookie, err := request.Cookie("sdesktop")
	if err != nil {
		return E.Cause(err, "read sdesktop cookie")
	}
	if cookie.Value != expectedToken {
		return E.New("unexpected sdesktop cookie: ", cookie.Value, ", expected ", expectedToken)
	}
	return nil
}

func (p *anyConnectCERTMCAOriginPeer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	body, err := readAnyConnectCSDPeerBody(request)
	if err != nil {
		reportM1LegacyCertificateError(p.failures, err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	document, err := parseAnyConnectCSDAuthenticationRequest(body)
	if err != nil {
		reportM1LegacyCertificateError(p.failures, err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	requestCount := p.requests.Add(1)
	if requestCount != 1 || request.Method != http.MethodPost || request.URL.Path != "/" || document.Type != "init" ||
		request.TLS == nil || len(request.TLS.PeerCertificates) != 0 {
		reportM1LegacyCertificateError(p.failures, E.New("combined CERT1 origin received an invalid first TLS request"))
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	writer.Header().Set("Content-Type", "application/xml")
	writer.Header().Set("Connection", "close")
	response := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
  <client-cert-request/>
  <host-scan>
    <host-scan-ticket>` + anyConnectCSDTicket + `</host-scan-ticket>
    <host-scan-token>` + anyConnectCSDOriginalToken + `</host-scan-token>
    <host-scan-base-uri>/+CSCOE+/sdesktop/index.html</host-scan-base-uri>
    <host-scan-wait-uri>/+CSCOE+/sdesktop/wait.xml</host-scan-wait-uri>
  </host-scan>
  <auth id="main"><form method="POST" action="` + html.EscapeString(p.actionURL) + `"/></auth>
</config-auth>`
	_, err = io.WriteString(writer, response)
	if err != nil {
		reportM1LegacyCertificateError(p.failures, E.Cause(err, "write combined CERT1 response"))
		return
	}
	p.dialer.switchToBackend()
}

func (d *anyConnectCERTMCADialer) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	if network != N.NetworkTCP || destination.Fqdn != d.hostname {
		return N.SystemDialer.DialContext(ctx, network, destination)
	}
	d.access.Lock()
	target := d.initial
	if d.switched {
		d.backendDials++
		target = d.backend
	} else {
		d.initialDials++
	}
	d.access.Unlock()
	return N.SystemDialer.DialContext(ctx, network, target)
}

func (d *anyConnectCERTMCADialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

func (d *anyConnectCERTMCADialer) switchToBackend() {
	d.access.Lock()
	d.switched = true
	d.access.Unlock()
}

func (d *anyConnectCERTMCADialer) assertFreshTLS(t *testing.T) {
	t.Helper()
	d.access.Lock()
	defer d.access.Unlock()
	if !d.switched || d.initialDials != 1 || d.backendDials == 0 {
		t.Fatalf(
			"combined CERT1 did not switch to a fresh MCA TLS backend: switched=%v initial=%d backend=%d",
			d.switched,
			d.initialDials,
			d.backendDials,
		)
	}
}

func (d *anyConnectCSDPinDialer) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	if network != N.NetworkTCP {
		return N.SystemDialer.DialContext(ctx, network, destination)
	}
	d.access.Lock()
	target := destination
	switch {
	case destination.Fqdn == d.hostname:
		if d.switched {
			d.replacementDials++
			target = d.replacement
		} else {
			d.primaryDials++
			target = d.primary
		}
	case destination.Addr == netip.MustParseAddr("127.0.0.1") && destination.Port == d.primary.Port:
		d.pinnedDials++
		target = d.primary
	}
	d.access.Unlock()
	return N.SystemDialer.DialContext(ctx, network, target)
}

func (d *anyConnectCSDPinDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

func (d *anyConnectCSDPinDialer) switchResolver() {
	d.access.Lock()
	d.switched = true
	d.access.Unlock()
}

func (d *anyConnectCSDPinDialer) assertPinned(t *testing.T) {
	t.Helper()
	d.access.Lock()
	defer d.access.Unlock()
	if !d.switched || d.primaryDials != 1 || d.replacementDials != 0 || d.pinnedDials == 0 {
		t.Fatalf(
			"CSD backend pin was not exercised: switched=%v primary-domain=%d replacement-domain=%d pinned-address=%d",
			d.switched,
			d.primaryDials,
			d.replacementDials,
			d.pinnedDials,
		)
	}
}

func anyConnectCSDUname(t *testing.T, argument string, fallback string) string {
	t.Helper()
	output, err := exec.Command("uname", argument).Output()
	if err != nil {
		return fallback
	}
	return strings.TrimSpace(string(output))
}

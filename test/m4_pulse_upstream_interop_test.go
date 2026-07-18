package test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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
	m4PulseUpstreamHostname = "pulse-upstream.test"
	m4PulseUpstreamUsername = "pulse-user"
	m4PulseUpstreamPassword = "pulse-password"
	m4PulseUpstreamAddress  = "192.0.2.42"
)

type m4PulseUpstreamCase struct {
	name                string
	configuration       url.Values
	expectedPasswordKey string
}

type m4PulseUpstreamFixture struct {
	command       *exec.Cmd
	waitResult    <-chan error
	port          uint16
	roots         *x509.CertPool
	httpClient    *http.Client
	standardError m4PulseUpstreamLog
}

type m4PulseUpstreamLog struct {
	access  sync.Mutex
	content bytes.Buffer
}

type m4PulseUpstreamDialer struct {
	port uint16
}

type m4PulseUpstreamReadResult struct {
	packet []byte
	err    error
}

//nolint:paralleltest // Upstream Pulse fixture binds the fixed UDP port 4500.
func TestM4PulseUpstreamAuthenticationConfigurationAndTLSTunnel(t *testing.T) {
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	fixture := startM4PulseUpstreamFixture(t, ctx)
	testCases := []m4PulseUpstreamCase{
		{
			name:                "direct-password",
			configuration:       url.Values{},
			expectedPasswordKey: "in_pass",
		},
		{
			name: "juniper-2021-password",
			configuration: url.Values{
				"pass_req_type": []string{"juniper2021"},
			},
			expectedPasswordKey: "in_pass_juniper2021",
		},
	}
	for i := range testCases {
		testCase := testCases[i]
		succeeded := t.Run(testCase.name, func(caseTest *testing.T) {
			configureM4PulseUpstreamFixture(caseTest, ctx, fixture, testCase.configuration)
			runM4PulseUpstreamCase(caseTest, ctx, fixture, testCase)
		})
		if !succeeded {
			return
		}
	}
}

func startM4PulseUpstreamFixture(t *testing.T, ctx context.Context) *m4PulseUpstreamFixture {
	t.Helper()
	port := reserveM4PulseUpstreamPort(t)
	certificate, roots := createM2GPPeerCertificate(t, m4PulseUpstreamHostname)
	temporaryDirectory := t.TempDir()
	certificatePath := filepath.Join(temporaryDirectory, "server-cert.pem")
	privateKeyPath := filepath.Join(temporaryDirectory, "server-key.pem")
	certificateContent := make([]byte, 0)
	for i := range certificate.Certificate {
		certificateContent = append(certificateContent, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Certificate[i],
		})...)
	}
	privateKeyData, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(E.Cause(err, "marshal upstream Pulse fake private key"))
	}
	privateKeyContent := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyData})
	err = os.WriteFile(certificatePath, certificateContent, 0o600)
	if err != nil {
		t.Fatal(E.Cause(err, "write upstream Pulse fake certificate"))
	}
	err = os.WriteFile(privateKeyPath, privateKeyContent, 0o600)
	if err != nil {
		t.Fatal(E.Cause(err, "write upstream Pulse fake private key"))
	}
	fixture := &m4PulseUpstreamFixture{
		port:  port,
		roots: roots,
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    roots,
			ServerName: m4PulseUpstreamHostname,
			MinVersion: tls.VersionTLS12,
		},
		DisableKeepAlives: true,
	}
	fixture.httpClient = &http.Client{Transport: transport}
	command := exec.CommandContext(
		ctx,
		"python3",
		filepath.Join("testdata", "fake-pulse", "fake-pulse-server.py"),
		"127.0.0.1",
		strconv.Itoa(int(port)),
		m4PulseUpstreamAddress+"/24",
		certificatePath,
		privateKeyPath,
	)
	command.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	command.Stderr = &fixture.standardError
	err = command.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start upstream Pulse fake"))
	}
	waitResult := make(chan error, 1)
	go func() {
		waitResult <- command.Wait()
	}()
	fixture.command = command
	fixture.waitResult = waitResult
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		_ = fixture.command.Process.Kill()
		<-fixture.waitResult
		if t.Failed() {
			t.Log("upstream Pulse fake logs:\n" + fixture.standardError.String())
		}
	})
	return fixture
}

func reserveM4PulseUpstreamPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(E.Cause(err, "reserve upstream Pulse fake TCP port"))
	}
	tcpAddress, loaded := listener.Addr().(*net.TCPAddr)
	if !loaded || tcpAddress.Port <= 0 || tcpAddress.Port > 65535 {
		_ = listener.Close()
		t.Fatal("upstream Pulse fake listener has no usable TCP port")
	}
	err = listener.Close()
	if err != nil {
		t.Fatal(E.Cause(err, "release upstream Pulse fake TCP port"))
	}
	return uint16(tcpAddress.Port)
}

func configureM4PulseUpstreamFixture(
	t *testing.T,
	ctx context.Context,
	fixture *m4PulseUpstreamFixture,
	configuration url.Values,
) {
	t.Helper()
	configureContext, cancelConfigure := context.WithTimeout(ctx, 10*time.Second)
	defer cancelConfigure()
	configurationBody := configuration.Encode()
	var lastErr error
	for {
		request, requestErr := http.NewRequestWithContext(
			configureContext,
			http.MethodPost,
			"https://127.0.0.1:"+strconv.Itoa(int(fixture.port))+"/CONFIGURE",
			strings.NewReader(configurationBody),
		)
		if requestErr != nil {
			t.Fatal(E.Cause(requestErr, "create upstream Pulse fake configuration request"))
		}
		request.Close = true
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, responseErr := fixture.httpClient.Do(request)
		if responseErr == nil {
			responseBody, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if readErr != nil {
				t.Fatal(E.Cause(readErr, "read upstream Pulse fake configuration response"))
			}
			if closeErr != nil {
				t.Fatal(E.Cause(closeErr, "close upstream Pulse fake configuration response"))
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("upstream Pulse fake returned configuration status %d: %s", response.StatusCode, responseBody)
			}
			returnedConfiguration, parseErr := url.ParseQuery(string(responseBody))
			if parseErr != nil {
				t.Fatal(E.Cause(parseErr, "parse upstream Pulse fake configuration response"))
			}
			if returnedConfiguration.Encode() != configurationBody {
				t.Fatalf("upstream Pulse fake configuration mismatch: %q", responseBody)
			}
			return
		}
		lastErr = responseErr
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-configureContext.Done():
			timer.Stop()
			t.Fatal(E.Errors(
				E.Cause(configureContext.Err(), "wait for upstream Pulse fake HTTPS listener"),
				lastErr,
			))
		case <-timer.C:
		}
	}
}

func runM4PulseUpstreamCase(
	t *testing.T,
	ctx context.Context,
	fixture *m4PulseUpstreamFixture,
	testCase m4PulseUpstreamCase,
) {
	t.Helper()
	caseContext, cancelCase := context.WithTimeout(ctx, 15*time.Second)
	defer cancelCase()
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context:    caseContext,
		Server:     net.JoinHostPort(m4PulseUpstreamHostname, strconv.Itoa(int(fixture.port))),
		Flavor:     openconnect.FlavorPulse,
		Username:   m4PulseUpstreamUsername,
		Password:   m4PulseUpstreamPassword,
		ReportedOS: "linux-64",
		NoUDP:      true,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			RootCAs:    fixture.roots,
			MinVersion: tls.VersionTLS12,
		}},
		Dialer: &m4PulseUpstreamDialer{port: fixture.port},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create upstream Pulse fake client"))
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start upstream Pulse fake client"))
	}
	readResults := make(chan m4PulseUpstreamReadResult, 1)
	go func() {
		packet, readErr := client.ReadDataPacket(caseContext)
		readResults <- m4PulseUpstreamReadResult{packet: packet, err: readErr}
	}()
	readinessTicker := time.NewTicker(10 * time.Millisecond)
	defer readinessTicker.Stop()
	for !client.Ready() {
		pendingForm := client.PendingAuthChallenge()
		if pendingForm != nil {
			t.Fatalf("upstream Pulse fake unexpectedly required interactive input: %#v", pendingForm)
		}
		select {
		case readResult := <-readResults:
			if readResult.err != nil {
				t.Fatal(E.Cause(readResult.err, "upstream Pulse fake client became terminal before readiness"))
			}
			t.Fatal("upstream Pulse fake sent a data packet before tunnel readiness")
		case <-client.AuthChallengeUpdated():
		case <-readinessTicker.C:
		case <-caseContext.Done():
			t.Fatalf("wait for upstream Pulse fake tunnel: %v: %s", caseContext.Err(), fixture.standardError.String())
		}
	}
	configuration := client.TunnelConfiguration()
	if configuration.MTU != 1400 || !slices.Contains(
		configuration.Addresses,
		netip.MustParsePrefix(m4PulseUpstreamAddress+"/24"),
	) {
		t.Fatalf("unexpected upstream Pulse fake tunnel configuration: %#v", configuration)
	}
	echoRequest := []byte{
		0x45, 0x00, 0x00, 0x20, 0x12, 0x34, 0x40, 0x00,
		0x40, 0x01, 0x3c, 0x44, 0xc0, 0x00, 0x02, 0x2a,
		0xc6, 0x33, 0x64, 0x07, 0x08, 0x00, 0x48, 0x2d,
		0x12, 0x34, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef,
	}
	expectedEchoReply := []byte{
		0x45, 0x00, 0x00, 0x20, 0x12, 0x34, 0x40, 0x00,
		0x40, 0x01, 0x3c, 0x44, 0xc6, 0x33, 0x64, 0x07,
		0xc0, 0x00, 0x02, 0x2a, 0x00, 0x00, 0x50, 0x2d,
		0x12, 0x34, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef,
	}
	err = client.WriteDataPacket(echoRequest)
	if err != nil {
		t.Fatal(E.Cause(err, "write upstream Pulse fake ICMP echo request"))
	}
	select {
	case readResult := <-readResults:
		if readResult.err != nil {
			t.Fatal(E.Cause(readResult.err, "read upstream Pulse fake ICMP echo reply"))
		}
		if !bytes.Equal(readResult.packet, expectedEchoReply) {
			t.Fatalf("unexpected upstream Pulse fake ICMP echo reply: %x", readResult.packet)
		}
	case <-caseContext.Done():
		t.Fatalf("wait for upstream Pulse fake ICMP echo reply: %v: %s", caseContext.Err(), fixture.standardError.String())
	}
	err = client.Close()
	if err != nil {
		t.Fatal(E.Cause(err, "close upstream Pulse fake client"))
	}
	status := readM4PulseUpstreamStatus(t, caseContext, fixture)
	if status.Get("in_user") != m4PulseUpstreamUsername ||
		status.Get(testCase.expectedPasswordKey) != m4PulseUpstreamPassword ||
		status.Get("ssl_ping") != "true" {
		t.Fatalf("upstream Pulse fake did not observe the complete authentication and TLS exchange: %v", status)
	}
}

func readM4PulseUpstreamStatus(
	t *testing.T,
	ctx context.Context,
	fixture *m4PulseUpstreamFixture,
) url.Values {
	t.Helper()
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"https://127.0.0.1:"+strconv.Itoa(int(fixture.port))+"/STATUS",
		nil,
	)
	if err != nil {
		t.Fatal(E.Cause(err, "create upstream Pulse fake status request"))
	}
	request.Close = true
	response, err := fixture.httpClient.Do(request)
	if err != nil {
		t.Fatal(E.Cause(err, "read upstream Pulse fake status: ", fixture.standardError.String()))
	}
	responseBody, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil {
		t.Fatal(E.Cause(readErr, "read upstream Pulse fake status response"))
	}
	if closeErr != nil {
		t.Fatal(E.Cause(closeErr, "close upstream Pulse fake status response"))
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("upstream Pulse fake returned status %d: %s", response.StatusCode, responseBody)
	}
	status, err := url.ParseQuery(string(responseBody))
	if err != nil {
		t.Fatal(E.Cause(err, "parse upstream Pulse fake status"))
	}
	return status
}

func (l *m4PulseUpstreamLog) Write(content []byte) (int, error) {
	l.access.Lock()
	defer l.access.Unlock()
	return l.content.Write(content)
}

func (l *m4PulseUpstreamLog) String() string {
	l.access.Lock()
	defer l.access.Unlock()
	return l.content.String()
}

func (d *m4PulseUpstreamDialer) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	if network != N.NetworkTCP || destination.Port != d.port || destination.Fqdn != m4PulseUpstreamHostname {
		return nil, E.New("unexpected upstream Pulse fake dial destination: ", destination)
	}
	return N.SystemDialer.DialContext(
		ctx,
		network,
		M.ParseSocksaddrHostPort("127.0.0.1", d.port),
	)
}

func (d *m4PulseUpstreamDialer) ListenPacket(
	ctx context.Context,
	destination M.Socksaddr,
) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

var _ N.Dialer = (*m4PulseUpstreamDialer)(nil)

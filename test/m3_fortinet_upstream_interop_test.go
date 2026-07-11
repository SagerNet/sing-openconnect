package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	m3FortinetFakeImage        = "sing-openconnect-fake-fortinet:2035601b64a5"
	m3FortinetFakeTunnelMarker = "GET /remote/sslvpn-tunnel"
)

type m3FortinetFakeCase struct {
	name          string
	path          string
	token         bool
	formEntries   []openconnect.FormEntry
	configuration url.Values
}

type m3FortinetFakeCertificateFixture struct {
	directory       string
	rootCertificate []byte
}

type m3FortinetFakeDialer struct {
	port uint16
}

//nolint:paralleltest // The fixed upstream fake owns one process-global configuration object.
func TestM3FortinetUpstreamAuthenticationAndConfigurationMatrix(t *testing.T) {
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	_, dockerErr := dockerOutput(ctx, "version", "--format", "{{.Server.Version}}")
	if dockerErr != nil {
		t.Fatal(dockerErr)
	}
	_, buildErr := dockerOutput(ctx, "build", "--pull=false", "--tag", m3FortinetFakeImage, filepath.Join("testdata", "fake-fortinet"))
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	fixture := createM3FortinetFakeCertificateFixture(t)
	serverPort := reserveM3FortinetFakePort(t)
	serverPortText := strconv.Itoa(int(serverPort))
	containerName := "sing-openconnect-m3-fake-fortinet-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	_, runErr := dockerOutput(
		ctx,
		"run", "--detach", "--rm", "--name", containerName,
		"--publish", "127.0.0.1:"+serverPortText+":"+serverPortText+"/tcp",
		"--mount", "type=bind,source="+fixture.directory+",target=/certs,readonly",
		m3FortinetFakeImage,
		"0.0.0.0", serverPortText, "/certs/server-cert.pem", "/certs/server-key.pem",
	)
	if runErr != nil {
		t.Fatal(runErr)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logsContext, cancelLogs := context.WithTimeout(context.Background(), 5*time.Second)
			logs, logsErr := dockerOutput(logsContext, "logs", containerName)
			cancelLogs()
			if logsErr == nil {
				t.Log("fake Fortinet logs:\n" + logs)
			}
		}
		removeContext, cancelRemove := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = dockerOutput(removeContext, "rm", "--force", containerName)
		cancelRemove()
	})
	publishedAddress := dockerPublishedAddress(t, ctx, containerName, serverPortText+"/tcp")
	waitForTCP(t, ctx, publishedAddress)
	testCases := []m3FortinetFakeCase{
		{name: "default-realm"},
		{name: "nondefault-realm", path: "/fakeRealm"},
		{
			name:          "tokeninfo-default-realm",
			token:         true,
			configuration: url.Values{"want_2fa": []string{"1"}, "type_2fa": []string{"tokeninfo"}},
		},
		{
			name:          "tokeninfo-plus-realm",
			path:          "/fake+Realm",
			token:         true,
			configuration: url.Values{"want_2fa": []string{"1"}, "type_2fa": []string{"tokeninfo"}},
		},
		{
			name: "blank-ftm-push",
			formEntries: []openconnect.FormEntry{{
				FormID: "_challenge",
				Name:   "code",
				Value:  "",
			}},
			configuration: url.Values{"want_2fa": []string{"1"}, "type_2fa": []string{"ftmpush"}},
		},
		{
			name:          "html-2fa",
			token:         true,
			configuration: url.Values{"want_2fa": []string{"1"}, "type_2fa": []string{"html"}},
		},
		{
			name:          "two-tokeninfo-rounds",
			token:         true,
			configuration: url.Values{"want_2fa": []string{"2"}, "type_2fa": []string{"tokeninfo"}},
		},
	}
	//nolint:paralleltest // The fixed upstream fake is reconfigured between cases.
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			configureM3FortinetFake(t, ctx, publishedAddress, fixture.rootCertificate, testCase.configuration)
			runM3FortinetFakeCase(t, ctx, containerName, fixture.rootCertificate, serverPort, testCase)
		})
	}
}

func configureM3FortinetFake(
	t *testing.T,
	ctx context.Context,
	address string,
	rootCertificate []byte,
	configuration url.Values,
) {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: buildM3FortinetFakeTLSConfig(t, rootCertificate)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	waitContext, cancelWait := context.WithTimeout(ctx, 20*time.Second)
	defer cancelWait()
	var lastErr error
	for {
		request, requestErr := http.NewRequestWithContext(
			waitContext,
			http.MethodPost,
			"https://"+address+"/CONFIGURE",
			strings.NewReader(configuration.Encode()),
		)
		if requestErr != nil {
			t.Fatal(E.Cause(requestErr, "create fixed fake Fortinet configuration request"))
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, responseErr := client.Do(request)
		if responseErr == nil {
			closeErr := response.Body.Close()
			if closeErr != nil {
				t.Fatal(E.Cause(closeErr, "close fixed fake Fortinet configuration response"))
			}
			if response.StatusCode != http.StatusCreated {
				t.Fatal("fixed fake Fortinet returned configuration status " + strconv.Itoa(response.StatusCode))
			}
			return
		}
		lastErr = responseErr
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-waitContext.Done():
			timer.Stop()
			t.Fatal(E.Errors(E.Cause(waitContext.Err(), "wait for fixed fake Fortinet HTTPS server"), lastErr))
		case <-timer.C:
		}
	}
}

func runM3FortinetFakeCase(
	t *testing.T,
	ctx context.Context,
	containerName string,
	rootCertificate []byte,
	serverPort uint16,
	testCase m3FortinetFakeCase,
) {
	t.Helper()
	logsBefore, logsErr := dockerOutput(ctx, "logs", containerName)
	if logsErr != nil {
		t.Fatal(logsErr)
	}
	tunnelCount := countM3FortinetFakeTunnelRejections(logsBefore)
	options := openconnect.ClientOptions{
		Context:     ctx,
		Server:      "https://" + net.JoinHostPort("0.0.0.0", strconv.Itoa(int(serverPort))) + testCase.path,
		Flavor:      openconnect.FlavorFortinet,
		Username:    "test",
		Password:    "test",
		NoUDP:       true,
		FormEntries: append([]openconnect.FormEntry(nil), testCase.formEntries...),
		Dialer:      &m3FortinetFakeDialer{port: serverPort},
		TLSConfig: openconnect.ClientTLSOptions{
			CertificateAuthority: openconnect.Material{Content: rootCertificate},
		},
	}
	if testCase.token {
		options.Token = &openconnect.TokenOptions{
			Mode:   openconnect.TokenModeTOTP,
			Secret: "JBSWY3DPEHPK3PXP",
		}
	}
	client, clientErr := openconnect.NewClient(options)
	if clientErr != nil {
		t.Fatal(E.Cause(clientErr, "create fixed fake Fortinet client"))
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	startErr := client.Start()
	if startErr != nil {
		t.Fatal(E.Cause(startErr, "start fixed fake Fortinet client"))
	}
	terminalErrors := make(chan error, 1)
	go func() {
		_, readErr := client.ReadDataPacket(ctx)
		terminalErrors <- readErr
	}()
	waitContext, cancelWait := context.WithTimeout(ctx, 35*time.Second)
	defer cancelWait()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if form := client.PendingAuthForm(); form != nil {
			t.Fatalf("fixed fake Fortinet unexpectedly required interactive input: %#v", form)
		}
		select {
		case <-waitContext.Done():
			logs, currentLogsErr := dockerOutput(ctx, "logs", containerName)
			if currentLogsErr != nil {
				t.Fatal(E.Errors(E.Cause(waitContext.Err(), "wait for fixed fake Fortinet HTTP 403 tunnel rejection"), currentLogsErr))
			}
			t.Fatal(E.Cause(waitContext.Err(), "wait for fixed fake Fortinet HTTP 403 tunnel rejection: ", logs))
		case terminalErr := <-terminalErrors:
			t.Fatal(E.Cause(terminalErr, "fixed fake Fortinet client became terminal before tunnel rejection"))
		case <-ticker.C:
			logs, currentLogsErr := dockerOutput(ctx, "logs", containerName)
			if currentLogsErr != nil {
				continue
			}
			if countM3FortinetFakeTunnelRejections(logs) > tunnelCount {
				closeErr := client.Close()
				if closeErr != nil {
					t.Fatal(E.Cause(closeErr, "close fixed fake Fortinet client"))
				}
				return
			}
		}
	}
}

func createM3FortinetFakeCertificateFixture(t *testing.T) m3FortinetFakeCertificateFixture {
	t.Helper()
	now := time.Now()
	rootKey, rootKeyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if rootKeyErr != nil {
		t.Fatal(E.Cause(rootKeyErr, "generate fixed fake Fortinet root key"))
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sing-openconnect fixed fake Fortinet root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootData, rootCertificate := createSignedInteropCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	serverKey, serverKeyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if serverKeyErr != nil {
		t.Fatal(E.Cause(serverKeyErr, "generate fixed fake Fortinet server key"))
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "sing-openconnect fixed fake Fortinet server"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("0.0.0.0")},
	}
	serverData, _ := createSignedInteropCertificate(t, serverTemplate, rootCertificate, serverKey.Public(), rootKey)
	directory := t.TempDir()
	certificateErr := os.WriteFile(filepath.Join(directory, "server-cert.pem"), joinCertificatePEM(serverData), 0o600)
	if certificateErr != nil {
		t.Fatal(E.Cause(certificateErr, "write fixed fake Fortinet server certificate"))
	}
	keyErr := os.WriteFile(filepath.Join(directory, "server-key.pem"), marshalInteropPrivateKey(t, serverKey), 0o600)
	if keyErr != nil {
		t.Fatal(E.Cause(keyErr, "write fixed fake Fortinet server key"))
	}
	return m3FortinetFakeCertificateFixture{
		directory:       directory,
		rootCertificate: joinCertificatePEM(rootData),
	}
}

func buildM3FortinetFakeTLSConfig(t *testing.T, rootCertificate []byte) *tls.Config {
	t.Helper()
	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(rootCertificate) {
		t.Fatal("load fixed fake Fortinet root certificate")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootPool}
}

func countM3FortinetFakeTunnelRejections(logs string) int {
	count := 0
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, m3FortinetFakeTunnelMarker) && strings.Contains(line, `" 403 `) {
			count++
		}
	}
	return count
}

func reserveM3FortinetFakePort(t *testing.T) uint16 {
	t.Helper()
	listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
	if listenErr != nil {
		t.Fatal(E.Cause(listenErr, "reserve fixed fake Fortinet port"))
	}
	address := M.SocksaddrFromNet(listener.Addr())
	closeErr := listener.Close()
	if closeErr != nil {
		t.Fatal(E.Cause(closeErr, "release fixed fake Fortinet port"))
	}
	return address.Port
}

func (d *m3FortinetFakeDialer) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	target := destination
	if network == N.NetworkTCP && destination.Addr.IsUnspecified() && destination.Port == d.port {
		target = M.ParseSocksaddrHostPort("127.0.0.1", d.port)
	}
	return N.SystemDialer.DialContext(ctx, network, target)
}

func (d *m3FortinetFakeDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

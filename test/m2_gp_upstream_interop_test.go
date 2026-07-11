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
	m2GPFakeImage        = "sing-openconnect-fake-gp:2035601b64a5"
	m2GPFakeTunnelMarker = "GET /ssl-tunnel-connect.sslvpn?"
)

type m2GPFakeCase struct {
	name          string
	serverPath    string
	password      string
	authGroup     string
	token         bool
	configuration url.Values
}

type m2GPFakeCertificateFixture struct {
	directory       string
	rootCertificate []byte
}

type m2GPFakeDialer struct {
	port uint16
}

//nolint:paralleltest // The matrix owns one Docker peer whose configuration is process-global and changed serially.
func TestM2GlobalProtectUpstreamAuthenticationMatrix(t *testing.T) {
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	_, err := dockerOutput(ctx, "version", "--format", "{{.Server.Version}}")
	if err != nil {
		t.Fatal(err)
	}
	_, err = dockerOutput(ctx, "build", "--pull=false", "--tag", m2GPFakeImage, filepath.Join("testdata", "fake-gp"))
	if err != nil {
		t.Fatal(err)
	}
	fixture := createM2GPFakeCertificateFixture(t)
	serverPort := reserveM2GPFakePort(t)
	serverPortText := strconv.Itoa(int(serverPort))
	containerName := "sing-openconnect-m2-fake-gp-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	_, err = dockerOutput(
		ctx,
		"run", "--detach", "--rm", "--name", containerName,
		"--publish", "127.0.0.1:"+serverPortText+":"+serverPortText+"/tcp",
		"--mount", "type=bind,source="+fixture.directory+",target=/certs,readonly",
		m2GPFakeImage,
		"0.0.0.0", serverPortText, "/certs/server-cert.pem", "/certs/server-key.pem",
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
				t.Log("fake GlobalProtect logs:\n" + logs)
			}
		}
		removeContext, cancelRemove := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = dockerOutput(removeContext, "rm", "--force", containerName)
		cancelRemove()
	})
	address := dockerPublishedAddress(t, ctx, containerName, serverPortText+"/tcp")
	waitForTCP(t, ctx, address)

	cases := []m2GPFakeCase{
		{
			name:          "portal-password",
			serverPath:    "/portal",
			password:      "test",
			configuration: url.Values{"esp": []string{"0"}},
		},
		{
			name:          "gateway-password",
			serverPath:    "/gateway",
			password:      "test",
			configuration: url.Values{"esp": []string{"0"}},
		},
		{
			name:       "portal-authgroup",
			serverPath: "/portal",
			password:   "test",
			authGroup:  "bar",
			configuration: url.Values{
				"gateways": []string{"foo,bar,baz"},
				"esp":      []string{"0"},
			},
		},
		{
			name:       "portal-challenge-and-cookie-continuation",
			serverPath: "/portal",
			password:   "test",
			token:      true,
			configuration: url.Values{
				"portal_2fa":    []string{"random"},
				"gw_2fa":        []string{"random"},
				"portal_cookie": []string{"portal-userauthcookie"},
				"esp":           []string{"0"},
			},
		},
		{
			name:       "portal-alternate-secret-saml",
			serverPath: "/portal:prelogin-cookie",
			password:   "prelogin-cookie",
			configuration: url.Values{
				"portal_saml":   []string{"prelogin-cookie"},
				"gateway_saml":  []string{"prelogin-cookie"},
				"portal_cookie": []string{"portal-userauthcookie"},
				"esp":           []string{"0"},
			},
		},
		{
			name:       "gateway-alternate-secret-saml",
			serverPath: "/gateway:prelogin-cookie",
			password:   "prelogin-cookie",
			configuration: url.Values{
				"gateway_saml": []string{"prelogin-cookie"},
				"esp":          []string{"0"},
			},
		},
		{
			name:       "portal-password-gateway-challenge",
			serverPath: "/portal",
			password:   "test",
			token:      true,
			configuration: url.Values{
				"gw_2fa": []string{"random"},
				"esp":    []string{"0"},
			},
		},
	}
	for _, challengeFormat := range []string{"xml", "js", "html"} {
		cases = append(cases, m2GPFakeCase{
			name:       "gateway-challenge-" + challengeFormat,
			serverPath: "/gateway",
			password:   "test",
			token:      true,
			configuration: url.Values{
				"gw_2fa": []string{challengeFormat},
				"esp":    []string{"0"},
			},
		})
	}
	//nolint:paralleltest // The upstream fake exposes one process-global configuration object shared by every connection.
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			configureM2GPFake(t, ctx, address, fixture.rootCertificate, testCase.configuration)
			runM2GPFakeCase(t, ctx, containerName, fixture.rootCertificate, serverPort, testCase)
		})
	}
}

func configureM2GPFake(
	t *testing.T,
	ctx context.Context,
	address string,
	rootCertificate []byte,
	configuration url.Values,
) {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: buildM2GPFakeTLSConfig(t, rootCertificate)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	waitContext, cancelWait := context.WithTimeout(ctx, 20*time.Second)
	defer cancelWait()
	var lastErr error
	for {
		request, err := http.NewRequestWithContext(
			waitContext,
			http.MethodPost,
			"https://"+address+"/CONFIGURE",
			strings.NewReader(configuration.Encode()),
		)
		if err != nil {
			t.Fatal(E.Cause(err, "create fake GlobalProtect configuration request"))
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, requestErr := client.Do(request)
		if requestErr == nil {
			closeErr := response.Body.Close()
			if closeErr != nil {
				t.Fatal(E.Cause(closeErr, "close fake GlobalProtect configuration response"))
			}
			if response.StatusCode != http.StatusCreated {
				t.Fatal("fake GlobalProtect server returned configuration status " + strconv.Itoa(response.StatusCode))
			}
			return
		}
		lastErr = requestErr
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-waitContext.Done():
			timer.Stop()
			t.Fatal(E.Errors(E.Cause(waitContext.Err(), "wait for fake GlobalProtect HTTPS server"), lastErr))
		case <-timer.C:
		}
	}
}

func runM2GPFakeCase(
	t *testing.T,
	ctx context.Context,
	containerName string,
	rootCertificate []byte,
	serverPort uint16,
	testCase m2GPFakeCase,
) {
	t.Helper()
	logsBefore, err := dockerOutput(ctx, "logs", containerName)
	if err != nil {
		t.Fatal(err)
	}
	tunnelCount := countM2GPFakeTunnelRejections(logsBefore)
	options := openconnect.ClientOptions{
		Context:    ctx,
		Server:     "https://" + net.JoinHostPort("0.0.0.0", strconv.Itoa(int(serverPort))) + testCase.serverPath,
		Flavor:     openconnect.FlavorGP,
		Username:   "test",
		Password:   testCase.password,
		AuthGroup:  testCase.authGroup,
		ReportedOS: "linux-64",
		NoUDP:      true,
		Dialer:     &m2GPFakeDialer{port: serverPort},
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
	client, err := openconnect.NewClient(options)
	if err != nil {
		t.Fatal(E.Cause(err, "create fake GlobalProtect client"))
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start fake GlobalProtect client"))
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
			t.Fatalf("fake GlobalProtect case unexpectedly required interactive input: %#v", form)
		}
		select {
		case <-waitContext.Done():
			logs, logsErr := dockerOutput(ctx, "logs", containerName)
			if logsErr != nil {
				t.Fatal(E.Errors(E.Cause(waitContext.Err(), "wait for fake GlobalProtect HTTP 502 tunnel rejection"), logsErr))
			}
			t.Fatal(E.Cause(waitContext.Err(), "wait for fake GlobalProtect HTTP 502 tunnel rejection: ", logs))
		case terminalErr := <-terminalErrors:
			t.Fatal(E.Cause(terminalErr, "fake GlobalProtect client became terminal before tunnel rejection"))
		case <-ticker.C:
			logs, logsErr := dockerOutput(ctx, "logs", containerName)
			if logsErr != nil {
				continue
			}
			if countM2GPFakeTunnelRejections(logs) > tunnelCount {
				closeErr := client.Close()
				if closeErr != nil {
					t.Fatal(E.Cause(closeErr, "close fake GlobalProtect client"))
				}
				return
			}
		}
	}
}

func createM2GPFakeCertificateFixture(t *testing.T) m2GPFakeCertificateFixture {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate fake GlobalProtect root key"))
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sing-openconnect fake GlobalProtect root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootData, rootCertificate := createSignedInteropCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate fake GlobalProtect server key"))
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "sing-openconnect fake GlobalProtect server"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("0.0.0.0")},
	}
	serverData, _ := createSignedInteropCertificate(t, serverTemplate, rootCertificate, serverKey.Public(), rootKey)
	directory := t.TempDir()
	err = os.WriteFile(filepath.Join(directory, "server-cert.pem"), joinCertificatePEM(serverData), 0o600)
	if err != nil {
		t.Fatal(E.Cause(err, "write fake GlobalProtect server certificate"))
	}
	err = os.WriteFile(filepath.Join(directory, "server-key.pem"), marshalInteropPrivateKey(t, serverKey), 0o600)
	if err != nil {
		t.Fatal(E.Cause(err, "write fake GlobalProtect server key"))
	}
	return m2GPFakeCertificateFixture{
		directory:       directory,
		rootCertificate: joinCertificatePEM(rootData),
	}
}

func buildM2GPFakeTLSConfig(t *testing.T, rootCertificate []byte) *tls.Config {
	t.Helper()
	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(rootCertificate) {
		t.Fatal("load fake GlobalProtect root certificate")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootPool,
	}
}

func countM2GPFakeTunnelRejections(logs string) int {
	count := 0
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, m2GPFakeTunnelMarker) && strings.Contains(line, `" 502 `) {
			count++
		}
	}
	return count
}

func reserveM2GPFakePort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(E.Cause(err, "reserve fake GlobalProtect port"))
	}
	address := M.SocksaddrFromNet(listener.Addr())
	err = listener.Close()
	if err != nil {
		t.Fatal(E.Cause(err, "release reserved fake GlobalProtect port"))
	}
	return address.Port
}

func (d *m2GPFakeDialer) DialContext(
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

func (d *m2GPFakeDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

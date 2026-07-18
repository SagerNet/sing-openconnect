package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
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

const m1OcservConfiguration = `%s

tcp-port = 443
udp-port = 443

run-as-user = nobody
run-as-group = nogroup
socket-file = /run/ocserv-socket
use-occtl = true
occtl-socket-file = /run/occtl.socket

server-cert = /etc/ocserv/server-cert.pem
server-key = /etc/ocserv/server-key.pem
tls-priorities = "NORMAL:%%SERVER_PRECEDENCE:%%COMPAT"

isolate-workers = false
max-clients = 8
max-same-clients = 4
rate-limit-ms = 0
max-ban-score = 0
auth-timeout = 30
cookie-timeout = 300
keepalive = %d
dpd = %d
try-mtu-discovery = false

device = vpns
ipv4-network = 192.168.77.0
ipv4-netmask = 255.255.255.0
route = 192.168.77.0/255.255.255.0
ping-leases = false
mtu = 1400

cisco-client-compat = false
dtls-psk = true
dtls-legacy = false
match-tls-dtls-ciphers = false
rekey-time = %d
rekey-method = %s

%s
`

const (
	m1OcservPasswordFile         = "test:tost,group1,group2:$5$i6SNmLDCgBNjyJ7q$SZ4bVJb7I/DLgXo3txHBVohRFBjOtdbxGQZp.DOnrA.\n"
	m1OcservRejectedPasswordFile = "test:tost,group1,group2:!\n"
	m1TOTPSecret                 = "12345678901234567890"
)

type m1OcservOptions struct {
	authentication string
	extra          string
	keepalive      int
	dpd            int
	rekey          int
	rekeyMethod    string
	files          map[string][]byte
}

type m1OcservContainer struct {
	ocservContainer
	name             string
	fixtureDirectory string
}

type m1FailingUDPDialer struct {
	attempts atomic.Uint64
}

type m1ConnectionDroppingDialer struct {
	access         sync.Mutex
	connections    []net.Conn
	replacement    M.Socksaddr
	useReplacement bool
}

type m1RecordingLogger struct {
	t        *testing.T
	warnings chan string
	access   sync.Mutex
}

func TestM1AnyConnectClientAuthenticationInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)
	interactiveUsername := "interactive-group-user"
	prefilledUsername := "prefilled-group-user"
	passwordFile := strings.Replace(m1OcservPasswordFile, ocservUsername+":", interactiveUsername+":", 1) +
		strings.Replace(m1OcservPasswordFile, ocservUsername+":", prefilledUsername+":", 1)
	container := startM1OcservContainer(t, ctx, m1OcservOptions{
		authentication: `auth = "plain[passwd=/fixture/ocpasswd]"`,
		extra:          "select-group = group1[Primary Group]\nselect-group = group2[Secondary Group]",
		keepalive:      60,
		dpd:            30,
		rekeyMethod:    "new-tunnel",
		files:          map[string][]byte{"ocpasswd": []byte(passwordFile)},
	})

	//nolint:paralleltest // The second session must start only after ocserv has removed this first session.
	t.Run("interactive-multiple-rounds-and-authgroup", func(t *testing.T) {
		client := newM1AnyConnectClient(t, ctx, container.tcpAddress, openconnect.ClientOptions{NoUDP: true})
		startM1Client(t, client)
		seenForms := make(map[string]struct{})
		selectedGroup := false
		credentialRound := false
		for !client.Ready() {
			form := waitForM1AuthFormOrReady(t, ctx, client)
			if form == nil {
				break
			}
			if _, exists := seenForms[form.ID]; exists {
				t.Fatalf("authentication form ID was reused: %s", form.ID)
			}
			seenForms[form.ID] = struct{}{}
			if form.Form == nil || form.Browser != nil {
				t.Fatalf("unexpected ocserv authentication challenge: %#v", form)
			}
			values := make(map[string]string, len(form.Form.Fields))
			for _, field := range form.Form.Fields {
				switch field.Name {
				case "group_list":
					selectedGroup = true
					values[field.SubmissionKey] = "group2"
				case "username":
					credentialRound = true
					values[field.SubmissionKey] = interactiveUsername
				case "password":
					credentialRound = true
					values[field.SubmissionKey] = ocservPassword
				default:
					t.Fatalf("unexpected ocserv authentication field: %#v", field)
				}
			}
			err := client.CompleteAuthChallenge(form.ID, openconnect.AuthResponse{Form: &openconnect.AuthFormResponse{Values: values}})
			if err != nil {
				t.Fatal(E.Cause(err, "complete ocserv authentication form"))
			}
			waitForM1ClientStateChange(t, ctx, client)
		}
		if !selectedGroup || !credentialRound || len(seenForms) < 2 {
			t.Fatalf("ocserv did not exercise authgroup and credential rounds: group=%v credentials=%v forms=%d", selectedGroup, credentialRound, len(seenForms))
		}
		assertM1OcservUserGroup(t, ctx, container, interactiveUsername, "group2")
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosed(closeErr) {
			t.Fatal(E.Cause(closeErr, "close interactive authgroup client"))
		}
		waitForM1OcservUserAbsent(t, ctx, container, interactiveUsername)
	})

	//nolint:paralleltest // This session verifies the first same-server session has already exited.
	t.Run("prefilled-credentials-and-authgroup", func(t *testing.T) {
		client := newM1AnyConnectClient(t, ctx, container.tcpAddress, openconnect.ClientOptions{
			Username:  prefilledUsername,
			Password:  ocservPassword,
			AuthGroup: "group1",
			NoUDP:     true,
		})
		startM1Client(t, client)
		waitForM1Ready(t, ctx, client)
		if form := client.PendingAuthChallenge(); form != nil {
			t.Fatalf("prefilled authentication unexpectedly prompted: %#v", form)
		}
		assertM1OcservUserGroup(t, ctx, container, prefilledUsername, "group1")
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosed(closeErr) {
			t.Fatal(E.Cause(closeErr, "close prefilled authgroup client"))
		}
		waitForM1OcservUserAbsent(t, ctx, container, prefilledUsername)
	})
}

func TestM1AnyConnectClientCertificateInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	caCertificate, clientCertificate, clientKey := createM1ClientCertificate(t, "certificate-user")
	container := startM1OcservContainer(t, ctx, m1OcservOptions{
		authentication: "auth = \"certificate\"",
		extra:          "ca-cert = /fixture/client-ca.pem\ncert-user-oid = 2.5.4.3",
		keepalive:      60,
		dpd:            30,
		rekeyMethod:    "new-tunnel",
		files:          map[string][]byte{"client-ca.pem": caCertificate},
	})
	client := newM1AnyConnectClient(t, ctx, container.tcpAddress, openconnect.ClientOptions{
		NoUDP: true,
		TLSConfig: openconnect.ClientTLSOptions{
			Certificate: openconnect.Material{Content: clientCertificate},
			Key:         openconnect.Material{Content: clientKey},
		},
	})
	startM1Client(t, client)
	waitForM1Ready(t, ctx, client)
	if form := client.PendingAuthChallenge(); form != nil {
		t.Fatalf("certificate-only authentication unexpectedly prompted: %#v", form)
	}
	assertM1OcservUsername(t, ctx, container, "certificate-user")
}

func TestM1AnyConnectOATHInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)
	t.Run("totp-liboath", func(t *testing.T) {
		t.Parallel()
		secretHex := strings.ToUpper(hex.EncodeToString([]byte(m1TOTPSecret)))
		container := startM1OcservContainer(t, ctx, m1OcservOptions{
			authentication: `auth = "plain[passwd=/fixture/ocpasswd,otp=/fixture/users.oath]"`,
			keepalive:      60,
			dpd:            30,
			rekeyMethod:    "new-tunnel",
			files: map[string][]byte{
				"ocpasswd":   []byte(m1OcservPasswordFile),
				"users.oath": []byte("HOTP/T30\ttest\t-\t" + secretHex + "\n"),
			},
		})
		client := newM1AnyConnectClient(t, ctx, container.tcpAddress, openconnect.ClientOptions{
			Username: ocservUsername,
			Password: ocservPassword,
			NoUDP:    true,
			Token: &openconnect.TokenOptions{
				Mode:   openconnect.TokenModeTOTP,
				Secret: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(m1TOTPSecret)),
			},
		})
		startM1Client(t, client)
		waitForM1Ready(t, ctx, client)
		if form := client.PendingAuthChallenge(); form != nil {
			t.Fatalf("automatic TOTP unexpectedly prompted: %#v", form)
		}
		assertM1OATHConsumerUpdated(t, container, "HOTP/T30")
	})

	t.Run("hotp-liboath", func(t *testing.T) {
		t.Parallel()
		container := startM1OcservContainer(t, ctx, m1OcservOptions{
			authentication: `auth = "plain[passwd=/fixture/ocpasswd,otp=/fixture/users.oath]"`,
			keepalive:      60,
			dpd:            30,
			rekeyMethod:    "new-tunnel",
			files: map[string][]byte{
				"ocpasswd":   []byte(m1OcservPasswordFile),
				"users.oath": []byte("HOTP\ttest\t-\t00\n"),
			},
		})
		var persistedCounter atomic.Uint64
		client := newM1AnyConnectClient(t, ctx, container.tcpAddress, openconnect.ClientOptions{
			Username: ocservUsername,
			Password: ocservPassword,
			NoUDP:    true,
			Token: &openconnect.TokenOptions{
				Mode:    openconnect.TokenModeHOTP,
				Secret:  "AA",
				Counter: 0,
				UpdateCounter: func(_ context.Context, counter uint64) error {
					persistedCounter.Store(counter)
					return nil
				},
			},
		})
		startM1Client(t, client)
		waitForM1Ready(t, ctx, client)
		if persistedCounter.Load() != 1 {
			t.Fatalf("HOTP counter callback received %d, expected 1", persistedCounter.Load())
		}
		assertM1OATHConsumerUpdated(t, container, "HOTP")
	})
}

func TestM1AnyConnectCSTPFallbackAndLivenessInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)
	container := startM1OcservContainer(t, ctx, m1OcservOptions{
		authentication: `auth = "plain[passwd=/fixture/ocpasswd]"`,
		keepalive:      1,
		dpd:            2,
		rekeyMethod:    "new-tunnel",
		files:          map[string][]byte{"ocpasswd": []byte(m1OcservPasswordFile)},
	})

	t.Run("no-udp-cstp-data-and-idle-liveness", func(t *testing.T) {
		t.Parallel()
		dialer := new(m1FailingUDPDialer)
		client := newM1AnyConnectClient(t, ctx, container.tcpAddress, openconnect.ClientOptions{
			Username: ocservUsername,
			Password: ocservPassword,
			NoUDP:    true,
			Dialer:   dialer,
		})
		startM1Client(t, client)
		waitForM1Ready(t, ctx, client)
		time.Sleep(4 * time.Second)
		if !client.Ready() {
			t.Fatal("CSTP session did not survive negotiated keepalive and DPD intervals")
		}
		if dialer.attempts.Load() != 0 {
			t.Fatalf("NoUDP client attempted UDP %d times", dialer.attempts.Load())
		}
		exchangeM1TunnelEcho(t, ctx, client, 0x4d32, 1, "sing-openconnect-m1-cstp")
	})

	t.Run("udp-dial-failure-falls-back-to-cstp", func(t *testing.T) {
		t.Parallel()
		dialer := new(m1FailingUDPDialer)
		logger := &m1RecordingLogger{t: t, warnings: make(chan string, 16)}
		client := newM1AnyConnectClient(t, ctx, container.tcpAddress, openconnect.ClientOptions{
			Username: ocservUsername,
			Password: ocservPassword,
			Dialer:   dialer,
			Logger:   logger,
		})
		startM1Client(t, client)
		waitForM1Ready(t, ctx, client)
		if dialer.attempts.Load() == 0 {
			t.Fatal("UDP fallback test did not attempt DTLS")
		}
		waitForM1Warning(t, ctx, logger, "DTLS unavailable; retrying while CSTP remains active")
		exchangeM1TunnelEcho(t, ctx, client, 0x4d32, 2, "sing-openconnect-m1-dtls-fallback")
	})
}

func TestM1AnyConnectRekeyAndReconnectInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	t.Cleanup(cancel)

	for _, method := range []string{"new-tunnel", "ssl"} {
		t.Run("rekey-"+method, func(t *testing.T) {
			t.Parallel()
			container := startM1OcservContainer(t, ctx, m1OcservOptions{
				authentication: `auth = "plain[passwd=/fixture/ocpasswd]"`,
				keepalive:      60,
				dpd:            30,
				rekey:          2,
				rekeyMethod:    method,
				files:          map[string][]byte{"ocpasswd": []byte(m1OcservPasswordFile)},
			})
			events := make(chan openconnect.TunnelConfigurationEvent, 16)
			client := newM1AnyConnectClient(t, ctx, container.tcpAddress, openconnect.ClientOptions{
				Username: ocservUsername,
				Password: ocservPassword,
				NoUDP:    true,
				OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
					events <- event
					return nil
				},
			})
			startM1Client(t, client)
			initial := waitForM1ConfigurationEvent(t, ctx, events)
			if initial.Reason != openconnect.TunnelConfigurationEventInitial {
				t.Fatalf("unexpected initial configuration reason: %s", initial.Reason)
			}
			replaceM1OcservPasswordFile(t, ctx, container, m1OcservRejectedPasswordFile)
			rekey := waitForM1ConfigurationEvent(t, ctx, events)
			if rekey.Reason != openconnect.TunnelConfigurationEventRekey {
				t.Fatalf("negotiated %s rekey reported %s", method, rekey.Reason)
			}
			if form := client.PendingAuthChallenge(); form != nil {
				t.Fatalf("rekey did not reuse the ocserv session cookie: %#v", form)
			}
			exchangeM1TunnelEcho(t, ctx, client, 0x4d33, 1, "sing-openconnect-m1-rekey-"+method)
		})
	}

	t.Run("disconnect-cookie-reuse-then-cookie-rejection", func(t *testing.T) {
		container := startM1OcservContainer(t, ctx, m1OcservOptions{
			authentication: `auth = "plain[passwd=/fixture/ocpasswd]"`,
			keepalive:      60,
			dpd:            30,
			rekeyMethod:    "new-tunnel",
			files:          map[string][]byte{"ocpasswd": []byte(m1OcservPasswordFile)},
		})
		rejectedContainer := startM1OcservContainer(t, ctx, m1OcservOptions{
			authentication: `auth = "plain[passwd=/fixture/ocpasswd]"`,
			keepalive:      60,
			dpd:            30,
			rekeyMethod:    "new-tunnel",
			files:          map[string][]byte{"ocpasswd": []byte(m1OcservRejectedPasswordFile)},
		})
		events := make(chan openconnect.TunnelConfigurationEvent, 16)
		dialer := new(m1ConnectionDroppingDialer)
		client := newM1AnyConnectClient(t, ctx, container.tcpAddress, openconnect.ClientOptions{
			Username: ocservUsername,
			Password: ocservPassword,
			NoUDP:    true,
			Dialer:   dialer,
			OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
				events <- event
				return nil
			},
		})
		startM1Client(t, client)
		initial := waitForM1ConfigurationEvent(t, ctx, events)
		if initial.Reason != openconnect.TunnelConfigurationEventInitial {
			t.Fatalf("unexpected initial configuration reason: %s", initial.Reason)
		}
		replaceM1OcservPasswordFile(t, ctx, container, m1OcservRejectedPasswordFile)
		dialer.dropNewest(t)
		reestablishment := waitForM1ConfigurationEvent(t, ctx, events)
		if reestablishment.Reason != openconnect.TunnelConfigurationEventReestablishment {
			t.Fatalf("ordinary disconnect reported %s", reestablishment.Reason)
		}
		if form := client.PendingAuthChallenge(); form != nil {
			t.Fatalf("ordinary reconnect did not reuse the ocserv session cookie: %#v", form)
		}
		exchangeM1TunnelEcho(t, ctx, client, 0x4d33, 2, "sing-openconnect-m1-reconnect")

		dialer.switchToReplacementAndDropNewest(t, M.ParseSocksaddr(rejectedContainer.tcpAddress))
		reauthenticationContext, cancelReauthentication := context.WithTimeout(ctx, 30*time.Second)
		defer cancelReauthentication()
		form := waitForM1AuthForm(t, reauthenticationContext, client)
		if form == nil {
			t.Fatal("invalidated cookie reauthentication completed without prompting")
		}
		passwordField := false
		if form.Form == nil || form.Browser != nil {
			t.Fatalf("invalidated cookie returned a non-form challenge: %#v", form)
		}
		for _, field := range form.Form.Fields {
			if field.Name == "password" {
				passwordField = true
				if field.Value != "" {
					t.Fatalf("rejected cached password remained in the replacement form: %#v", field)
				}
			}
		}
		if !passwordField {
			t.Fatalf("invalidated cookie did not require password authentication: %#v", form)
		}
		assertM1OcservReconnectRequestEvidence(t, ctx, container, rejectedContainer)
	})
}

func assertM1OcservReconnectRequestEvidence(
	t *testing.T,
	ctx context.Context,
	primary m1OcservContainer,
	rejected m1OcservContainer,
) {
	t.Helper()
	primaryLogs, err := dockerOutput(ctx, "logs", primary.name)
	if err != nil {
		t.Fatal(err)
	}
	rejectedLogs, err := dockerOutput(ctx, "logs", rejected.name)
	if err != nil {
		t.Fatal(err)
	}
	primaryConnects := strings.Count(primaryLogs, "HTTP CONNECT /CSCOSSLC/tunnel")
	primaryAuthenticationPosts := strings.Count(primaryLogs, " HTTP POST ")
	rejectedConnects := strings.Count(rejectedLogs, "HTTP CONNECT /CSCOSSLC/tunnel")
	rejectedAuthenticationPosts := strings.Count(rejectedLogs, " HTTP POST ")
	if primaryConnects != 2 || primaryAuthenticationPosts != 3 {
		t.Fatalf(
			"primary ocserv did not authenticate once then reuse its cookie after EOF: CONNECT=%d auth-POST=%d\n%s",
			primaryConnects,
			primaryAuthenticationPosts,
			primaryLogs,
		)
	}
	if rejectedConnects != 1 || rejectedAuthenticationPosts != 3 ||
		strings.Count(rejectedLogs, "failed cookie authentication attempt") != 1 ||
		strings.Count(rejectedLogs, "<password>"+ocservPassword+"</password>") != 1 ||
		strings.Contains(rejectedLogs, "user '"+ocservUsername+"' obtained cookie") {
		t.Fatalf(
			"replacement ocserv did not reject one foreign cookie then one cached password: CONNECT=%d auth-POST=%d\n%s",
			rejectedConnects,
			rejectedAuthenticationPosts,
			rejectedLogs,
		)
	}
}

func startM1OcservContainer(t *testing.T, ctx context.Context, options m1OcservOptions) m1OcservContainer {
	t.Helper()
	_, err := dockerOutput(ctx, "version", "--format", "{{.Server.Version}}")
	if err != nil {
		t.Fatal(err)
	}
	_, err = dockerOutput(ctx, "build", "--pull=false", "--tag", ocservInteropImage, filepath.Join("testdata", "ocserv"))
	if err != nil {
		t.Fatal(err)
	}
	if options.rekeyMethod == "" {
		options.rekeyMethod = "new-tunnel"
	}
	fixtureDirectory := t.TempDir()
	err = os.Chmod(fixtureDirectory, 0o755)
	if err != nil {
		t.Fatal(E.Cause(err, "make ocserv fixture directory readable"))
	}
	configuration := fmt.Sprintf(
		m1OcservConfiguration,
		options.authentication,
		options.keepalive,
		options.dpd,
		options.rekey,
		options.rekeyMethod,
		options.extra,
	)
	writeM1FixtureFile(t, fixtureDirectory, "ocserv.conf", []byte(configuration))
	for name, content := range options.files {
		writeM1FixtureFile(t, fixtureDirectory, name, content)
	}
	containerName := "sing-openconnect-m1-client-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	_, err = dockerOutput(
		ctx,
		"run", "--detach", "--rm", "--name", containerName,
		"--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
		"--publish", "127.0.0.1::443/tcp", "--publish", "127.0.0.1::443/udp",
		"--mount", "type=bind,source="+fixtureDirectory+",target=/fixture",
		"--entrypoint", "ocserv",
		ocservInteropImage,
		"-f", "-d", "4", "-c", "/fixture/ocserv.conf",
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
				t.Log("M1 ocserv logs:\n" + logs)
			}
		}
		removeContext, cancelRemove := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = dockerOutput(removeContext, "rm", "--force", containerName)
		cancelRemove()
	})
	tcpAddress := dockerPublishedAddress(t, ctx, containerName, "443/tcp")
	udpAddress := dockerPublishedAddress(t, ctx, containerName, "443/udp")
	waitForTCP(t, ctx, tcpAddress)
	return m1OcservContainer{
		ocservContainer:  ocservContainer{tcpAddress: tcpAddress, udpAddress: udpAddress},
		name:             containerName,
		fixtureDirectory: fixtureDirectory,
	}
}

func writeM1FixtureFile(t *testing.T, directory string, name string, content []byte) {
	t.Helper()
	err := os.WriteFile(filepath.Join(directory, name), content, 0o644)
	if err != nil {
		t.Fatal(E.Cause(err, "write ocserv fixture ", name))
	}
}

func newM1AnyConnectClient(t *testing.T, ctx context.Context, server string, options openconnect.ClientOptions) *openconnect.Client {
	t.Helper()
	options.Context = ctx
	options.Server = server
	options.Flavor = openconnect.FlavorAnyConnect
	if options.TLSConfig.Config == nil {
		options.TLSConfig.Config = &tls.Config{InsecureSkipVerify: true}
	}
	client, err := openconnect.NewClient(options)
	if err != nil {
		t.Fatal(E.Cause(err, "create M1 AnyConnect client"))
	}
	t.Cleanup(func() {
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosed(closeErr) {
			t.Error(E.Cause(closeErr, "close M1 AnyConnect client"))
		}
	})
	return client
}

func startM1Client(t *testing.T, client *openconnect.Client) {
	t.Helper()
	err := client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start M1 AnyConnect client"))
	}
}

func assertActiveTransport(t *testing.T, client *openconnect.Client, expected string) {
	t.Helper()
	actual := client.ActiveTransport()
	if actual != expected {
		t.Fatalf("unexpected active transport: expected %q, got %q", expected, actual)
	}
}

func waitForActiveTransportUpdate(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	updated <-chan struct{},
	expected string,
) {
	t.Helper()
	waitContext, cancelWait := context.WithTimeout(ctx, 10*time.Second)
	defer cancelWait()
	for {
		select {
		case <-waitContext.Done():
			t.Fatal(E.Cause(waitContext.Err(), "wait for active transport ", expected))
		case <-updated:
			updated = client.ActiveTransportUpdated()
			if client.ActiveTransport() == expected {
				return
			}
		}
	}
}

func waitForActiveTransportLossAndRecovery(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	updated <-chan struct{},
	recovered string,
) {
	t.Helper()
	waitContext, cancelWait := context.WithTimeout(ctx, 20*time.Second)
	defer cancelWait()
	sawLoss := false
	for {
		select {
		case <-waitContext.Done():
			t.Fatal(E.Cause(waitContext.Err(), "wait for active transport loss and recovery to ", recovered, "; loss observed: ", sawLoss))
		case <-updated:
			updated = client.ActiveTransportUpdated()
			activeTransport := client.ActiveTransport()
			if activeTransport == "" {
				sawLoss = true
			} else if sawLoss && activeTransport == recovered {
				return
			}
		}
	}
}

func waitForM1Ready(t *testing.T, ctx context.Context, client *openconnect.Client) {
	t.Helper()
	for !client.Ready() {
		waitForM1ClientStateChange(t, ctx, client)
	}
}

func waitForM1ClientStateChange(t *testing.T, ctx context.Context, client *openconnect.Client) {
	t.Helper()
	updated := client.AuthChallengeUpdated()
	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for M1 AnyConnect client state"))
	case <-updated:
	case <-time.After(20 * time.Millisecond):
	}
}

func waitForM1AuthForm(t *testing.T, ctx context.Context, client *openconnect.Client) *openconnect.AuthChallenge {
	t.Helper()
	return waitForM1AuthFormState(t, ctx, client, false)
}

func waitForM1AuthFormOrReady(t *testing.T, ctx context.Context, client *openconnect.Client) *openconnect.AuthChallenge {
	t.Helper()
	return waitForM1AuthFormState(t, ctx, client, true)
}

func waitForM1AuthFormState(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	allowReady bool,
) *openconnect.AuthChallenge {
	t.Helper()
	for {
		form := client.PendingAuthChallenge()
		if form != nil {
			return form
		}
		if allowReady && client.Ready() {
			return nil
		}
		updated := client.AuthChallengeUpdated()
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for M1 AnyConnect authentication form"))
		case <-updated:
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func waitForM1ConfigurationEvent(
	t *testing.T,
	ctx context.Context,
	events <-chan openconnect.TunnelConfigurationEvent,
) openconnect.TunnelConfigurationEvent {
	t.Helper()
	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for M1 tunnel configuration event"))
	case event := <-events:
		return event
	}
	return openconnect.TunnelConfigurationEvent{}
}

func exchangeM1TunnelEcho(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	identifier uint16,
	sequence uint16,
	payloadText string,
) {
	t.Helper()
	configuration := client.TunnelConfiguration()
	clientAddress := firstIPv4Address(t, configuration.Addresses)
	serverAddress := netip.MustParseAddr(ocservTunnelAddress)
	payload := []byte(payloadText)
	request := buildIPv4ICMPEchoRequest(t, clientAddress, serverAddress, identifier, sequence, payload)
	err := client.WriteDataPacket(request)
	if err != nil {
		t.Fatal(E.Cause(err, "write M1 AnyConnect tunnel echo"))
	}
	readContext, cancelRead := context.WithTimeout(ctx, 10*time.Second)
	defer cancelRead()
	for {
		response, readErr := client.ReadDataPacket(readContext)
		if readErr != nil {
			t.Fatal(E.Cause(readErr, "read M1 AnyConnect tunnel echo"))
		}
		if len(response) == 0 || response[0]>>4 != 4 {
			continue
		}
		err = validateIPv4ICMPEchoReply(response, clientAddress, serverAddress, identifier, sequence, payload)
		if err != nil {
			t.Fatal(err)
		}
		return
	}
}

func assertM1OcservUserGroup(t *testing.T, ctx context.Context, container m1OcservContainer, username string, group string) {
	t.Helper()
	output := runM1Occtl(t, ctx, container, "show", "user", username)
	if !strings.Contains(output, username) || !strings.Contains(output, group) {
		t.Fatalf("ocserv did not record user %q in group %q:\n%s", username, group, output)
	}
}

func waitForM1OcservUserAbsent(t *testing.T, ctx context.Context, container m1OcservContainer, username string) {
	t.Helper()
	waitContext, cancelWait := context.WithTimeout(ctx, 10*time.Second)
	defer cancelWait()
	for {
		output := runM1Occtl(t, waitContext, container, "show", "users")
		if !strings.Contains(output, username) {
			return
		}
		select {
		case <-waitContext.Done():
			t.Fatalf("ocserv retained closed user session %q:\n%s", username, output)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func assertM1OcservUsername(t *testing.T, ctx context.Context, container m1OcservContainer, username string) {
	t.Helper()
	output := runM1Occtl(t, ctx, container, "show", "user", username)
	if !strings.Contains(output, username) {
		t.Fatalf("ocserv did not record certificate username %q:\n%s", username, output)
	}
}

func assertM1OATHConsumerUpdated(t *testing.T, container m1OcservContainer, tokenType string) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(container.fixtureDirectory, "users.oath"))
	if err != nil {
		t.Fatal(E.Cause(err, "read liboath users file"))
	}
	fields := strings.Fields(string(content))
	if len(fields) < 6 || fields[0] != tokenType {
		t.Fatalf("liboath did not accept and record the generated %s code: %q", tokenType, content)
	}
}

func runM1Occtl(t *testing.T, ctx context.Context, container m1OcservContainer, arguments ...string) string {
	t.Helper()
	dockerArguments := []string{"exec", container.name, "occtl", "-s", "/run/occtl.socket"}
	dockerArguments = append(dockerArguments, arguments...)
	output, err := dockerOutput(ctx, dockerArguments...)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func replaceM1OcservPasswordFile(t *testing.T, ctx context.Context, container m1OcservContainer, content string) {
	t.Helper()
	path := filepath.Join(container.fixtureDirectory, "ocpasswd.replacement")
	err := os.WriteFile(path, []byte(content), 0o644)
	if err != nil {
		t.Fatal(E.Cause(err, "write replacement ocserv password file"))
	}
	_, err = dockerOutput(ctx, "cp", path, container.name+":/fixture/ocpasswd")
	if err != nil {
		t.Fatal(err)
	}
}

func createM1ClientCertificate(t *testing.T, username string) ([]byte, []byte, []byte) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate M1 client CA key"))
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sing-openconnect M1 client CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caData, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(E.Cause(err, "create M1 client CA certificate"))
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate M1 TLS client key"))
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: username},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientData, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, clientKey.Public(), caKey)
	if err != nil {
		t.Fatal(E.Cause(err, "create M1 TLS client certificate"))
	}
	clientKeyData, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatal(E.Cause(err, "marshal M1 TLS client key"))
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caData}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientData}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyData})
}

func (d *m1FailingUDPDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network == N.NetworkUDP {
		d.attempts.Add(1)
		return nil, E.New("M1 deliberate UDP dial failure")
	}
	return N.SystemDialer.DialContext(ctx, network, destination)
}

func (d *m1FailingUDPDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

func (d *m1ConnectionDroppingDialer) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	d.access.Lock()
	target := destination
	if d.useReplacement {
		target = d.replacement
	}
	d.access.Unlock()
	conn, err := N.SystemDialer.DialContext(ctx, network, target)
	if err != nil {
		return nil, err
	}
	if network == N.NetworkTCP {
		d.access.Lock()
		d.connections = append(d.connections, conn)
		d.access.Unlock()
	}
	return conn, nil
}

func (d *m1ConnectionDroppingDialer) ListenPacket(
	ctx context.Context,
	destination M.Socksaddr,
) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

func (d *m1ConnectionDroppingDialer) dropNewest(t *testing.T) {
	t.Helper()
	d.access.Lock()
	if len(d.connections) == 0 {
		d.access.Unlock()
		t.Fatal("M1 connection dropper did not observe a TCP connection")
	}
	conn := d.connections[len(d.connections)-1]
	d.connections = d.connections[:len(d.connections)-1]
	d.access.Unlock()
	err := conn.Close()
	if err != nil && !E.IsClosed(err) {
		t.Fatal(E.Cause(err, "drop M1 CSTP connection"))
	}
}

func (d *m1ConnectionDroppingDialer) switchToReplacementAndDropNewest(t *testing.T, replacement M.Socksaddr) {
	t.Helper()
	d.access.Lock()
	if len(d.connections) == 0 {
		d.access.Unlock()
		t.Fatal("no M1 TCP connection available before backend switch")
	}
	d.replacement = replacement
	d.useReplacement = true
	connection := d.connections[len(d.connections)-1]
	d.access.Unlock()
	err := connection.Close()
	if err != nil && !E.IsClosed(err) {
		t.Fatal(E.Cause(err, "drop M1 TCP connection while switching backend"))
	}
}

func waitForM1Warning(t *testing.T, ctx context.Context, logger *m1RecordingLogger, expected string) {
	t.Helper()
	for {
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for M1 warning containing ", expected))
		case warning := <-logger.warnings:
			if strings.Contains(warning, expected) {
				return
			}
		}
	}
}

func (l *m1RecordingLogger) log(arguments ...any) {
	l.access.Lock()
	l.t.Helper()
	l.t.Log(fmt.Sprint(arguments...))
	l.access.Unlock()
}

func (l *m1RecordingLogger) Trace(arguments ...any) { l.log(arguments...) }
func (l *m1RecordingLogger) Debug(arguments ...any) { l.log(arguments...) }
func (l *m1RecordingLogger) Info(arguments ...any)  { l.log(arguments...) }
func (l *m1RecordingLogger) Warn(arguments ...any) {
	message := fmt.Sprint(arguments...)
	l.log(message)
	select {
	case l.warnings <- message:
	default:
	}
}
func (l *m1RecordingLogger) Error(arguments ...any) { l.log(arguments...) }
func (l *m1RecordingLogger) Fatal(arguments ...any) { l.log(arguments...) }
func (l *m1RecordingLogger) Panic(arguments ...any) { l.log(arguments...) }

func (l *m1RecordingLogger) TraceContext(_ context.Context, arguments ...any) {
	l.Trace(arguments...)
}

func (l *m1RecordingLogger) DebugContext(_ context.Context, arguments ...any) {
	l.Debug(arguments...)
}

func (l *m1RecordingLogger) InfoContext(_ context.Context, arguments ...any) {
	l.Info(arguments...)
}

func (l *m1RecordingLogger) WarnContext(_ context.Context, arguments ...any) {
	l.Warn(arguments...)
}

func (l *m1RecordingLogger) ErrorContext(_ context.Context, arguments ...any) {
	l.Error(arguments...)
}

func (l *m1RecordingLogger) FatalContext(_ context.Context, arguments ...any) {
	l.Fatal(arguments...)
}

func (l *m1RecordingLogger) PanicContext(_ context.Context, arguments ...any) {
	l.Panic(arguments...)
}

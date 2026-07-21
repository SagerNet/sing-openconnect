package test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const m4NCESPOracleHostname = "gateway.m4-nc-esp-oracle.test"

type m4NCESPOraclePeer struct {
	server               *httptest.Server
	reservation          *net.UDPConn
	reservationOnce      sync.Once
	port                 uint16
	oracleBinary         string
	oracleReady          chan struct{}
	errors               chan error
	espEnabled           chan struct{}
	espDisabled          chan struct{}
	tunnelClosed         chan struct{}
	logout               chan struct{}
	logoutOnce           sync.Once
	tunnelStarted        atomic.Bool
	serverSPI            uint32
	serverEncryption     []byte
	serverAuthentication []byte
}

type m4NCESPOracleLogger struct {
	logger.ContextLogger
	debugMessages chan string
}

type m4NCESPOracleDialer struct {
	*m4NCDialer
	oracleReady <-chan struct{}
}

func TestM4NetworkConnectONCPESPOracleInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	oracleBinary := buildM4PulseESPOracle(t, ctx)
	reservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(E.Cause(err, "reserve Network Connect ESP oracle port"))
	}
	t.Cleanup(func() { _ = reservation.Close() })
	peer := &m4NCESPOraclePeer{
		reservation:          reservation,
		port:                 uint16(reservation.LocalAddr().(*net.UDPAddr).Port),
		oracleBinary:         oracleBinary,
		oracleReady:          make(chan struct{}),
		errors:               make(chan error, 16),
		espEnabled:           make(chan struct{}),
		espDisabled:          make(chan struct{}),
		tunnelClosed:         make(chan struct{}),
		logout:               make(chan struct{}),
		serverSPI:            0x4e434c5a,
		serverEncryption:     []byte("server-encrypt!!"),
		serverAuthentication: []byte("server-auth-key-1234"),
	}
	rootCertificate, certificates := createM4NCCertificates(t, []string{m4NCESPOracleHostname})
	peer.server = newM2GPTLSServer(t, certificates[0], http.HandlerFunc(peer.serve))
	gatewayAddress := M.SocksaddrFromNet(peer.server.Listener.Addr())
	baseDialer := &m4NCDialer{
		routes: map[string]M.Socksaddr{
			m4NCESPOracleHostname: gatewayAddress,
		},
		gatewayHostname: m4NCESPOracleHostname,
		gatewayAddress:  gatewayAddress,
	}
	dialer := &m4NCESPOracleDialer{m4NCDialer: baseDialer, oracleReady: peer.oracleReady}
	oracleLogger := &m4NCESPOracleLogger{
		ContextLogger: logger.NOP(),
		debugMessages: make(chan string, 64),
	}
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 1)
	serverURL := "https://" + net.JoinHostPort(m4NCESPOracleHostname, strconv.Itoa(int(gatewayAddress.Port)))
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  serverURL + "/start",
		Flavor:  openconnect.FlavorNC,
		Dialer:  dialer,
		Logger:  oracleLogger,
		TLSConfig: openconnect.ClientTLSOptions{
			CertificateAuthority: openconnect.Material{Content: rootCertificate},
		},
		OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
			configurationEvents <- event
			return nil
		},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create Network Connect ESP oracle client"))
	}
	t.Cleanup(func() { _ = client.Close() })
	activeTransportUpdated := client.ActiveTransportUpdated()
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start Network Connect ESP oracle client"))
	}
	select {
	case <-configurationEvents:
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for Network Connect ESP oracle configuration"))
	}
	select {
	case <-peer.espEnabled:
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for Network Connect ESP oracle enable"))
	}
	if client.ActiveTransport() != openconnect.TransportESP {
		waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportESP)
	}
	clientAddress := netip.MustParseAddr("10.47.0.10")
	serverAddress := netip.MustParseAddr("10.47.0.1")
	exchangeM4NCESPOracleEcho(t, ctx, client, oracleLogger, clientAddress, serverAddress, 1, []byte("nc-lzo-compressed"), "")
	testCases := []struct {
		payload       string
		expectedError string
	}{
		{payload: "pulse-lzo-malformed", expectedError: "lzo: input overrun"},
		{payload: "pulse-lzo-trailing", expectedError: "lzo: input not fully consumed"},
		{payload: "pulse-lzo-oversize", expectedError: "lzo: output overrun"},
	}
	for i, testCase := range testCases {
		exchangeM4NCESPOracleEcho(t, ctx, client, oracleLogger, clientAddress, serverAddress, uint16(i+2), []byte(testCase.payload), testCase.expectedError)
		if !client.Ready() {
			t.Fatal("Network Connect session stopped after an invalid LZO ESP payload")
		}
	}
	exchangeM4NCESPOracleEcho(t, ctx, client, oracleLogger, clientAddress, serverAddress, 5, []byte("nc-lzo-after-invalid"), "")
	err = client.Close()
	if err != nil {
		t.Fatal(E.Cause(err, "close Network Connect ESP oracle client"))
	}
	select {
	case <-peer.espDisabled:
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for Network Connect ESP oracle disable"))
	}
	select {
	case <-peer.logout:
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for Network Connect ESP oracle logout"))
	}
}

func exchangeM4NCESPOracleEcho(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	logger *m4NCESPOracleLogger,
	clientAddress netip.Addr,
	serverAddress netip.Addr,
	sequence uint16,
	payload []byte,
	expectedLZOError string,
) {
	t.Helper()
	request := buildIPv4ICMPEchoRequest(t, clientAddress, serverAddress, 0x4e43, sequence, payload)
	err := client.WriteDataPacket(request)
	if err != nil {
		t.Fatal(E.Cause(err, "write Network Connect ESP oracle ICMP echo request"))
	}
	response, err := client.ReadDataPacket(ctx)
	if err != nil {
		t.Fatal(E.Cause(err, "read Network Connect ESP oracle ICMP echo reply"))
	}
	err = validateIPv4ICMPEchoReply(response, clientAddress, serverAddress, 0x4e43, sequence, payload)
	if err != nil {
		t.Fatal(E.Cause(err, "validate Network Connect ESP oracle ICMP echo reply"))
	}
	if expectedLZOError != "" {
		waitForM4NCESPOracleDebug(t, ctx, logger, "Ignoring invalid LZO-compressed ESP payload: ", expectedLZOError)
	}
	waitForM4NCESPOracleDebug(t, ctx, logger, "Ignoring invalid ESP UDP datagram: ESP replay rejected", "")
	duplicateContext, cancel := context.WithTimeout(ctx, 75*time.Millisecond)
	_, duplicateErr := client.ReadDataPacket(duplicateContext)
	cancel()
	if duplicateErr == nil || !E.IsCanceled(duplicateErr) {
		t.Fatalf("Network Connect ESP replay was delivered or returned an unexpected error: %v", duplicateErr)
	}
}

func waitForM4NCESPOracleDebug(t *testing.T, ctx context.Context, logger *m4NCESPOracleLogger, expected string, detail string) {
	t.Helper()
	for {
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for Network Connect ESP debug log containing ", expected, detail))
		case message := <-logger.debugMessages:
			if strings.Contains(message, expected) && strings.Contains(message, detail) {
				return
			}
		}
	}
}

func (p *m4NCESPOraclePeer) serve(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/start":
		http.SetCookie(writer, &http.Cookie{Name: "DSID", Value: "esp-oracle-session", Path: "/", Secure: true})
		_, _ = io.WriteString(writer, "accepted")
	case "/dana/js":
		p.serveTunnel(writer)
	case "/dana-na/auth/logout.cgi":
		select {
		case <-p.espDisabled:
		default:
			p.fail(writer, E.New("Network Connect ESP oracle logout arrived before KMP 303 disable"))
			return
		}
		select {
		case <-p.tunnelClosed:
		default:
			p.fail(writer, E.New("Network Connect ESP oracle logout arrived before TLS close"))
			return
		}
		writer.WriteHeader(http.StatusOK)
		p.logoutOnce.Do(func() { close(p.logout) })
	default:
		p.fail(writer, E.New("unexpected Network Connect ESP oracle path: ", request.URL.Path))
	}
}

func (p *m4NCESPOraclePeer) serveTunnel(writer http.ResponseWriter) {
	if !p.tunnelStarted.CompareAndSwap(false, true) {
		p.fail(writer, E.New("Network Connect ESP oracle received an unsupported second tunnel"))
		return
	}
	hijacker, loaded := writer.(http.Hijacker)
	if !loaded {
		p.fail(writer, E.New("Network Connect ESP oracle cannot hijack TLS"))
		return
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		p.fail(writer, E.Cause(err, "hijack Network Connect ESP oracle TLS connection"))
		return
	}
	defer connection.Close()
	_, err = buffered.WriteString("HTTP/1.1 200 OK\r\n\r\n")
	if err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		p.report(E.Cause(err, "write Network Connect ESP oracle HTTP response"))
		return
	}
	_, err = readM4NCONCPRecord(buffered.Reader)
	if err != nil {
		p.report(err)
		return
	}
	configuration := buildM4NCONCPConfigurationWithESP(p.port, p.serverSPI, p.serverEncryption, p.serverAuthentication)
	err = writeM4NCONCPRecord(buffered.Writer, []byte{0})
	if err == nil {
		err = writeM4NCONCPRecord(buffered.Writer, configuration)
	}
	if err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		p.report(E.Cause(err, "write Network Connect ESP oracle configuration"))
		return
	}
	negotiation, err := readM4NCONCPRecord(buffered.Reader)
	if err != nil {
		p.report(err)
		return
	}
	messages, err := splitM4NCONCPMessages(negotiation, true)
	if err != nil || len(messages) != 2 {
		p.report(E.New("Network Connect ESP oracle negotiation did not contain KMP 303 and KMP 302"))
		return
	}
	err = validateM4NCONCPMTUControl(messages[0], 1300)
	if err != nil {
		p.report(err)
		return
	}
	clientSPI, clientEncryption, clientAuthentication, err := parseM4NCONCPESPResponse(messages[1])
	if err != nil {
		p.report(err)
		return
	}
	defer clear(clientEncryption)
	defer clear(clientAuthentication)
	var reservationErr error
	p.reservationOnce.Do(func() {
		reservationErr = p.reservation.Close()
	})
	if reservationErr != nil && !E.IsClosed(reservationErr) {
		p.report(E.Cause(reservationErr, "release Network Connect ESP oracle port"))
		return
	}
	arguments := []string{
		strconv.Itoa(int(p.port)),
		"aes-128-cbc",
		"sha1",
		strconv.FormatUint(uint64(p.serverSPI), 10),
		strconv.FormatUint(uint64(clientSPI), 10),
		hex.EncodeToString(p.serverEncryption),
		hex.EncodeToString(p.serverAuthentication),
		hex.EncodeToString(clientEncryption),
		hex.EncodeToString(clientAuthentication),
		"zero",
	}
	command := exec.Command(p.oracleBinary, arguments...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		p.report(E.Cause(err, "open Network Connect ESP oracle stdout"))
		return
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	err = command.Start()
	if err != nil {
		p.report(E.Cause(err, "start Network Connect ESP oracle"))
		return
	}
	var stopping atomic.Bool
	done := make(chan struct{})
	go func() {
		waitErr := command.Wait()
		if !stopping.Load() {
			if waitErr == nil {
				p.report(E.New("Network Connect ESP oracle exited unexpectedly: ", strings.TrimSpace(stderr.String())))
			} else {
				p.report(E.Cause(waitErr, "Network Connect ESP oracle exited unexpectedly: ", strings.TrimSpace(stderr.String())))
			}
		}
		close(done)
	}()
	var oracleErr error
	defer func() {
		if oracleErr != nil {
			p.report(oracleErr)
		}
	}()
	defer func() {
		stopping.Store(true)
		_ = command.Process.Kill()
		<-done
	}()
	readyLine, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		oracleErr = E.Cause(err, "read Network Connect ESP oracle readiness")
		return
	}
	expectedReady := "READY " + strconv.Itoa(int(p.port))
	if strings.TrimSpace(readyLine) != expectedReady {
		oracleErr = E.New("Network Connect ESP oracle readiness mismatch: ", strings.TrimSpace(readyLine))
		return
	}
	close(p.oracleReady)
	enableRecord, err := readM4NCONCPRecord(buffered.Reader)
	if err != nil {
		oracleErr = err
		return
	}
	err = validateM4NCONCPESPControl(enableRecord, true)
	if err != nil {
		oracleErr = err
		return
	}
	close(p.espEnabled)
	disableRecord, err := readM4NCONCPRecord(buffered.Reader)
	if err != nil {
		oracleErr = err
		return
	}
	err = validateM4NCONCPESPControl(disableRecord, false)
	if err != nil {
		oracleErr = err
		return
	}
	close(p.espDisabled)
	one := make([]byte, 1)
	_, err = buffered.Reader.Read(one)
	if err != io.EOF && !E.IsClosed(err) {
		oracleErr = E.Cause(err, "wait for Network Connect ESP oracle TLS close")
		return
	}
	close(p.tunnelClosed)
}

func (d *m4NCESPOracleDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network == N.NetworkUDP {
		select {
		case <-d.oracleReady:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return d.m4NCDialer.DialContext(ctx, network, destination)
}

func (p *m4NCESPOraclePeer) fail(writer http.ResponseWriter, err error) {
	p.report(err)
	http.Error(writer, err.Error(), http.StatusInternalServerError)
}

func (p *m4NCESPOraclePeer) report(err error) {
	select {
	case p.errors <- err:
	default:
	}
}

func (l *m4NCESPOracleLogger) Debug(arguments ...any) {
	message := fmt.Sprint(arguments...)
	select {
	case l.debugMessages <- message:
	default:
	}
}

func (l *m4NCESPOracleLogger) DebugContext(_ context.Context, arguments ...any) {
	l.Debug(arguments...)
}

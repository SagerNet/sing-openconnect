package test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	m4NCTNCCWrapperHostname = "gateway.m4-nc-wrapper.test"
	m4NCTNCCWrapperLog      = "M4_NC_TNCC_WRAPPER_LOG"
)

type m4NCTNCCWrapperPeer struct {
	server       *httptest.Server
	errors       chan error
	tunnelClosed chan struct{}
	logout       chan struct{}
	logoutOnce   sync.Once
}

func TestM4NetworkConnectExternalTNCCWrapperPeerInterop(t *testing.T) {
	t.Parallel()
	rootCertificate, certificates := createM4NCCertificates(t, []string{m4NCTNCCWrapperHostname})
	peer := &m4NCTNCCWrapperPeer{
		errors:       make(chan error, 16),
		tunnelClosed: make(chan struct{}),
		logout:       make(chan struct{}),
	}
	peer.server = newM2GPTLSServer(t, certificates[0], http.HandlerFunc(peer.serve))
	gatewayAddress := M.SocksaddrFromNet(peer.server.Listener.Addr())
	dialer := &m4NCDialer{
		routes: map[string]M.Socksaddr{
			m4NCTNCCWrapperHostname: gatewayAddress,
		},
		gatewayHostname: m4NCTNCCWrapperHostname,
		gatewayAddress:  gatewayAddress,
	}
	temporaryDirectory := t.TempDir()
	wrapperLog := filepath.Join(temporaryDirectory, "wrapper.log")
	wrapperPath := createM4NCTNCCWrapperLauncher(t, temporaryDirectory, wrapperLog)
	serverURL := "https://" + net.JoinHostPort(m4NCTNCCWrapperHostname, strconv.Itoa(int(gatewayAddress.Port)))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 1)
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  serverURL + "/start",
		Flavor:  openconnect.FlavorNC,
		NoUDP:   true,
		Dialer:  dialer,
		TLSConfig: openconnect.ClientTLSOptions{
			CertificateAuthority: openconnect.Material{Content: rootCertificate},
		},
		TNCC: &openconnect.TNCCOptions{WrapperPath: wrapperPath},
		OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
			configurationEvents <- event
			return nil
		},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create external TNCC wrapper peer client"))
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start external TNCC wrapper peer client"))
	}
	select {
	case <-configurationEvents:
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for external TNCC wrapper oNCP readiness"))
	}
	waitM4NCTNCCWrapperSetCookieCount(t, ctx, wrapperLog, 2)
	err = client.Close()
	if err != nil {
		t.Fatal(E.Cause(err, "close external TNCC wrapper peer client"))
	}
	select {
	case <-peer.logout:
	case peerErr := <-peer.errors:
		t.Fatal(peerErr)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for external TNCC wrapper logout"))
	}
	assertM4NCTNCCWrapperLog(t, ctx, wrapperLog, certificates[0])
}

func TestM4NetworkConnectExternalTNCCWrapperProcess(t *testing.T) {
	t.Parallel()
	logPath := os.Getenv(m4NCTNCCWrapperLog)
	if logPath == "" {
		t.Skip("external TNCC wrapper helper process")
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	socket := os.NewFile(0, "tncc-wrapper-socket")
	if socket == nil {
		t.Fatal("external TNCC wrapper helper has no descriptor zero")
	}
	defer socket.Close()
	gatewayHostname := os.Args[len(os.Args)-1]
	writeM4NCTNCCWrapperLog(logFile, "gateway", gatewayHostname)
	writeM4NCTNCCWrapperLog(logFile, "sha256", os.Getenv("TNCC_SHA256"))
	writeM4NCTNCCWrapperLog(logFile, "hostname", os.Getenv("TNCC_HOSTNAME"))
	writeM4NCTNCCWrapperLog(logFile, "interval", os.Getenv("TNCC_INTERVAL"))
	reader := bufio.NewReader(socket)
	for lineNumber := 0; lineNumber < 4; lineNumber++ {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		writeM4NCTNCCWrapperLog(logFile, "start", strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"))
	}
	_, err = socket.Write([]byte("200\nignored\nwrapper-checked\n1\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	for {
		line, readErr := reader.ReadString('\n')
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
		writeM4NCTNCCWrapperLog(logFile, "setcookie", strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"))
	}
	writeM4NCTNCCWrapperLog(logFile, "state", "eof")
}

func (p *m4NCTNCCWrapperPeer) serve(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/start":
		if request.Method != http.MethodGet {
			p.fail(writer, E.New("external TNCC wrapper authentication request was not GET"))
			return
		}
		preauthenticationCookie, err := request.Cookie("DSPREAUTH")
		if err != nil {
			http.SetCookie(writer, &http.Cookie{Name: "DSPREAUTH", Value: "wrapper-initial", Path: "/", Secure: true})
			http.SetCookie(writer, &http.Cookie{Name: "DSSIGNIN", Value: "/start", Path: "/", Secure: true})
			writer.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(writer, "<html><body>external Host Checker required</body></html>")
			return
		}
		if preauthenticationCookie.Value != "wrapper-checked" {
			p.fail(writer, E.New("unexpected external TNCC wrapper DSPREAUTH cookie: ", preauthenticationCookie.Value))
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: "DSID", Value: "wrapper-session", Path: "/", Secure: true})
		_, _ = io.WriteString(writer, "<html><body>accepted</body></html>")
	case "/dana-na/auth/logout.cgi":
		select {
		case <-p.tunnelClosed:
		default:
			p.fail(writer, E.New("external TNCC wrapper logout arrived before oNCP TLS close"))
			return
		}
		cookie, err := request.Cookie("DSID")
		if err != nil || cookie.Value != "wrapper-session" {
			p.fail(writer, E.New("external TNCC wrapper logout omitted DSID"))
			return
		}
		writer.WriteHeader(http.StatusOK)
		p.logoutOnce.Do(func() { close(p.logout) })
	case "/dana/js":
		p.serveTunnel(writer)
	default:
		p.fail(writer, E.New("unexpected external TNCC wrapper peer path: ", request.URL.Path))
	}
}

func (p *m4NCTNCCWrapperPeer) serveTunnel(writer http.ResponseWriter) {
	hijacker, loaded := writer.(http.Hijacker)
	if !loaded {
		p.fail(writer, E.New("external TNCC wrapper peer cannot hijack oNCP TLS"))
		return
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		p.fail(writer, E.Cause(err, "hijack external TNCC wrapper oNCP TLS"))
		return
	}
	defer connection.Close()
	_, err = buffered.WriteString("HTTP/1.1 200 OK\r\n\r\n")
	if err == nil {
		err = buffered.Flush()
	}
	if err == nil {
		_, err = readM4NCONCPRecord(buffered.Reader)
	}
	configuration := buildM4NCONCPConfiguration()
	if err == nil {
		err = writeM4NCONCPRecord(buffered.Writer, []byte{0})
	}
	if err == nil {
		err = writeM4NCONCPRecord(buffered.Writer, configuration)
	}
	if err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		p.report(E.Cause(err, "exchange external TNCC wrapper oNCP configuration"))
		return
	}
	control, err := readM4NCONCPRecord(buffered.Reader)
	if err != nil {
		p.report(err)
		return
	}
	err = validateM4NCONCPMTUControl(control, 1300)
	if err != nil {
		p.report(err)
		return
	}
	one := make([]byte, 1)
	_, err = buffered.Reader.Read(one)
	if err != io.EOF && !E.IsClosed(err) {
		p.report(E.Cause(err, "wait for external TNCC wrapper oNCP close"))
		return
	}
	close(p.tunnelClosed)
}

func (p *m4NCTNCCWrapperPeer) fail(writer http.ResponseWriter, err error) {
	p.report(err)
	http.Error(writer, err.Error(), http.StatusInternalServerError)
}

func (p *m4NCTNCCWrapperPeer) report(err error) {
	select {
	case p.errors <- err:
	default:
	}
}

func createM4NCTNCCWrapperLauncher(t *testing.T, directory string, logPath string) string {
	t.Helper()
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(E.Cause(err, "locate external TNCC wrapper helper test binary"))
	}
	wrapperPath := filepath.Join(directory, "tncc-wrapper")
	launcher := "#!/bin/sh\nexport " + m4NCTNCCWrapperLog + "=" + quoteM4NCShell(logPath) + "\nexec " + quoteM4NCShell(testBinary) + " -test.run '^TestM4NetworkConnectExternalTNCCWrapperProcess$' -- \"$@\"\n"
	err = os.WriteFile(wrapperPath, []byte(launcher), 0o700)
	if err != nil {
		t.Fatal(E.Cause(err, "write external TNCC wrapper helper launcher"))
	}
	return wrapperPath
}

func quoteM4NCShell(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func writeM4NCTNCCWrapperLog(writer io.Writer, name string, value string) {
	_, _ = io.WriteString(writer, name+"="+value+"\n")
}

func waitM4NCTNCCWrapperSetCookieCount(t *testing.T, ctx context.Context, logPath string, expected int) {
	t.Helper()
	for {
		content, err := os.ReadFile(logPath)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(E.Cause(err, "read periodic external TNCC wrapper log"))
		}
		if bytes.Count(content, []byte("setcookie=setcookie\n")) >= expected {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for periodic external TNCC wrapper setcookie"))
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func assertM4NCTNCCWrapperLog(t *testing.T, ctx context.Context, logPath string, certificate tls.Certificate) {
	t.Helper()
	var content []byte
	for {
		var err error
		content, err = os.ReadFile(logPath)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(E.Cause(err, "read external TNCC wrapper log"))
		}
		if bytes.Contains(content, []byte("state=eof\n")) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for external TNCC wrapper exit"))
		case <-time.After(10 * time.Millisecond):
		}
	}
	peerCertificate, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(E.Cause(err, "parse external TNCC wrapper peer certificate"))
	}
	digest := sha256.Sum256(peerCertificate.RawSubjectPublicKeyInfo)
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(E.Cause(err, "read hostname for external TNCC wrapper assertion"))
	}
	expectedLines := []string{
		"gateway=" + m4NCTNCCWrapperHostname,
		"sha256=" + base64.StdEncoding.EncodeToString(digest[:]),
		"hostname=" + hostname,
		"interval=0",
		"start=start",
		"start=IC=" + m4NCTNCCWrapperHostname,
		"start=Cookie=wrapper-initial",
		"start=DSSIGNIN=/start",
		"setcookie=setcookie",
		"setcookie=Cookie=wrapper-checked",
		"state=eof",
	}
	actual := string(content)
	for _, expectedLine := range expectedLines {
		if !strings.Contains(actual, expectedLine+"\n") {
			t.Fatalf("external TNCC wrapper log omitted %q:\n%s", expectedLine, actual)
		}
	}
	if bytes.Count(content, []byte("setcookie=setcookie\n")) < 2 || bytes.Count(content, []byte("setcookie=Cookie=wrapper-checked\n")) < 2 {
		t.Fatalf("external TNCC wrapper did not receive its periodic setcookie command:\n%s", actual)
	}
}

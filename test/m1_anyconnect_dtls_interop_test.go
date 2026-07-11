package test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

type productionDTLSObserver struct {
	readPackets          atomic.Uint64
	writtenPackets       atomic.Uint64
	cstpDataToServer     atomic.Uint64
	cstpDataToClient     atomic.Uint64
	udpDialAttempts      atomic.Uint64
	droppedWrites        atomic.Uint64
	largestWrite         atomic.Uint64
	largestAcceptedWrite atomic.Uint64
	udpDialAccess        sync.Mutex
	udpDialTimes         []time.Time
	datagramAccess       sync.Mutex
	readDatagramSizes    []int
	writtenDatagramSizes []int
	firstWriteAccess     sync.Mutex
	firstWrite           []byte
}

type productionDTLSConn struct {
	net.Conn
	observer            *productionDTLSObserver
	maximumDatagramSize int
}

type productionDTLSTestLogger struct {
	t *testing.T
}

func (l productionDTLSTestLogger) log(arguments ...any) {
	l.t.Helper()
	l.t.Log(fmt.Sprint(arguments...))
}

func (l productionDTLSTestLogger) Trace(arguments ...any) { l.log(arguments...) }
func (l productionDTLSTestLogger) Debug(arguments ...any) { l.log(arguments...) }
func (l productionDTLSTestLogger) Info(arguments ...any)  { l.log(arguments...) }
func (l productionDTLSTestLogger) Warn(arguments ...any)  { l.log(arguments...) }
func (l productionDTLSTestLogger) Error(arguments ...any) { l.log(arguments...) }
func (l productionDTLSTestLogger) Fatal(arguments ...any) { l.log(arguments...) }
func (l productionDTLSTestLogger) Panic(arguments ...any) { l.log(arguments...) }

func (l productionDTLSTestLogger) TraceContext(_ context.Context, arguments ...any) {
	l.log(arguments...)
}

func (l productionDTLSTestLogger) DebugContext(_ context.Context, arguments ...any) {
	l.log(arguments...)
}

func (l productionDTLSTestLogger) InfoContext(_ context.Context, arguments ...any) {
	l.log(arguments...)
}

func (l productionDTLSTestLogger) WarnContext(_ context.Context, arguments ...any) {
	l.log(arguments...)
}

func (l productionDTLSTestLogger) ErrorContext(_ context.Context, arguments ...any) {
	l.log(arguments...)
}

func (l productionDTLSTestLogger) FatalContext(_ context.Context, arguments ...any) {
	l.log(arguments...)
}

func (l productionDTLSTestLogger) PanicContext(_ context.Context, arguments ...any) {
	l.log(arguments...)
}

type productionInteropDialer struct {
	observer               *productionDTLSObserver
	udpDestination         M.Socksaddr
	rewriteHeaders         []string
	rewriteResponseHeaders []string
	appendResponseHeaders  []string
	removeResponseHeaders  []string
	promoteResponseDTLS12  bool
	remainingUDPFailures   atomic.Int64
	maximumUDPDatagramSize int
	removedResponseHeaders atomic.Uint64
	cstpConnects           atomic.Uint64
	certificate            tls.Certificate
	proxyErrors            chan error
}

type productionDTLSRunOptions struct {
	rewriteHeaders         []string
	rewriteResponseHeaders []string
	appendResponseHeaders  []string
	removeResponseHeaders  []string
	promoteResponseDTLS12  bool
	expectedVersion        [2]byte
	verifyDPD              bool
	udpDialFailures        int64
	maximumUDPDatagramSize int
	allowInsecureCrypto    bool
	expectPathMTUEvent     bool
	expectMinimumPathMTU   bool
	expectDTLSOnlyRekey    bool
	expectCSTPBeforeDTLS   bool
}

type noAppIDDTLSPeer struct {
	ctx           context.Context
	listener      net.Listener
	pskAccess     sync.RWMutex
	psk           []byte
	failures      chan error
	tunnelStarted chan struct{}
	probeDPD      chan struct{}
	dpdResponse   chan struct{}
	dataPackets   atomic.Uint64
}

func TestM1AnyConnectProductionDTLSInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)

	modernContainer := startOcservContainer(t, ctx)
	var peerAccess sync.Mutex
	t.Run("modern-psk", func(t *testing.T) {
		t.Parallel()
		peerAccess.Lock()
		defer peerAccess.Unlock()
		runProductionAnyConnectDTLS(t, ctx, modernContainer, productionDTLSRunOptions{expectedVersion: [2]byte{0xfe, 0xfd}})
	})
	t.Run("modern-psk-recovers-after-udp-dial-failures", func(t *testing.T) {
		t.Parallel()
		peerAccess.Lock()
		defer peerAccess.Unlock()
		runProductionAnyConnectDTLS(t, ctx, modernContainer, productionDTLSRunOptions{
			expectedVersion:      [2]byte{0xfe, 0xfd},
			udpDialFailures:      2,
			expectCSTPBeforeDTLS: true,
		})
	})
	t.Run("modern-psk-path-mtu", func(t *testing.T) {
		t.Parallel()
		peerAccess.Lock()
		defer peerAccess.Unlock()
		runProductionAnyConnectDTLS(t, ctx, modernContainer, productionDTLSRunOptions{
			expectedVersion:        [2]byte{0xfe, 0xfd},
			udpDialFailures:        1,
			maximumUDPDatagramSize: 1100,
			expectPathMTUEvent:     true,
		})
	})
	t.Run("modern-psk-path-mtu-ipv4-minimum", func(t *testing.T) {
		t.Parallel()
		peerAccess.Lock()
		defer peerAccess.Unlock()
		runProductionAnyConnectDTLS(t, ctx, modernContainer, productionDTLSRunOptions{
			expectedVersion:        [2]byte{0xfe, 0xfd},
			udpDialFailures:        1,
			maximumUDPDatagramSize: 605,
			expectPathMTUEvent:     true,
			expectMinimumPathMTU:   true,
		})
	})

	legacyContainer := startLegacyOcservContainer(t, ctx)
	t.Run("injected-dtls12-last-header-wins", func(t *testing.T) {
		t.Parallel()
		peerAccess.Lock()
		defer peerAccess.Unlock()
		runProductionAnyConnectDTLS(t, ctx, legacyContainer, productionDTLSRunOptions{
			rewriteHeaders: []string{
				"X-DTLS12-CipherSuite: AES128-GCM-SHA256",
			},
			rewriteResponseHeaders: []string{
				"X-DTLS-CipherSuite: AES128-SHA",
				"X-DTLS12-CipherSuite: AES128-GCM-SHA256",
			},
			expectedVersion: [2]byte{0xfe, 0xfd},
		})
	})
	t.Run("injected-dtls12-ecdhe-companion-headers", func(t *testing.T) {
		t.Parallel()
		peerAccess.Lock()
		defer peerAccess.Unlock()
		runProductionAnyConnectDTLS(t, ctx, legacyContainer, productionDTLSRunOptions{
			rewriteHeaders: []string{
				"X-DTLS12-CipherSuite: ECDHE-RSA-AES128-GCM-SHA256",
			},
			promoteResponseDTLS12: true,
			expectedVersion:       [2]byte{0xfe, 0xfd},
		})
	})
	t.Run("injected-dtls12-ecdhe-aes256-gcm", func(t *testing.T) {
		t.Parallel()
		peerAccess.Lock()
		defer peerAccess.Unlock()
		runProductionAnyConnectDTLS(t, ctx, legacyContainer, productionDTLSRunOptions{
			rewriteHeaders: []string{
				"X-DTLS12-CipherSuite: ECDHE-RSA-AES256-GCM-SHA384",
			},
			promoteResponseDTLS12: true,
			expectedVersion:       [2]byte{0xfe, 0xfd},
		})
	})
	t.Run("injected-dtls12-aes256-gcm-sha384", func(t *testing.T) {
		t.Parallel()
		peerAccess.Lock()
		defer peerAccess.Unlock()
		runProductionAnyConnectDTLS(t, ctx, legacyContainer, productionDTLSRunOptions{
			rewriteHeaders:        []string{"X-DTLS12-CipherSuite: AES256-GCM-SHA384"},
			promoteResponseDTLS12: true,
			expectedVersion:       [2]byte{0xfe, 0xfd},
		})
	})
	t.Run("owned-cisco-dtls09-last-header-wins", func(t *testing.T) {
		t.Parallel()
		peerAccess.Lock()
		defer peerAccess.Unlock()
		runProductionAnyConnectDTLS(t, ctx, legacyContainer, productionDTLSRunOptions{
			rewriteHeaders: []string{"X-DTLS-CipherSuite: AES128-SHA"},
			rewriteResponseHeaders: []string{
				"X-DTLS12-CipherSuite: AES128-GCM-SHA256",
				"X-DTLS-CipherSuite: AES128-SHA",
			},
			expectedVersion: [2]byte{0x01, 0x00},
		})
	})
	t.Run("owned-cisco-dtls09-aes-cbc", func(t *testing.T) {
		t.Parallel()
		peerAccess.Lock()
		defer peerAccess.Unlock()
		runProductionAnyConnectDTLS(t, ctx, legacyContainer, productionDTLSRunOptions{
			rewriteHeaders:  []string{"X-DTLS-CipherSuite: AES128-SHA"},
			expectedVersion: [2]byte{0x01, 0x00},
			verifyDPD:       true,
		})
	})
	t.Run("owned-cisco-dtls09-aes256-cbc", func(t *testing.T) {
		t.Parallel()
		peerAccess.Lock()
		defer peerAccess.Unlock()
		runProductionAnyConnectDTLS(t, ctx, legacyContainer, productionDTLSRunOptions{
			rewriteHeaders:  []string{"X-DTLS-CipherSuite: AES256-SHA"},
			expectedVersion: [2]byte{0x01, 0x00},
		})
	})
	t.Run("owned-cisco-dtls09-ssl-rekey-stays-on-cstp", func(t *testing.T) {
		t.Parallel()
		peerAccess.Lock()
		defer peerAccess.Unlock()
		runProductionAnyConnectDTLS(t, ctx, legacyContainer, productionDTLSRunOptions{
			rewriteHeaders: []string{"X-DTLS-CipherSuite: AES128-SHA"},
			removeResponseHeaders: []string{
				"X-CSTP-Rekey-Time",
				"X-CSTP-Rekey-Method",
				"X-DTLS-Rekey-Time",
				"X-DTLS-Rekey-Method",
			},
			appendResponseHeaders: []string{
				"X-CSTP-Rekey-Method: none",
				"X-DTLS-Rekey-Time: 5",
				"X-DTLS-Rekey-Method: ssl",
			},
			expectedVersion:     [2]byte{0x01, 0x00},
			expectDTLSOnlyRekey: true,
		})
	})
	t.Run("owned-cisco-dtls09-3des-disabled-terminal", func(t *testing.T) {
		t.Parallel()
		peerAccess.Lock()
		defer peerAccess.Unlock()
		runProductionAnyConnectDeprecatedDTLSRejected(t, ctx, legacyContainer)
	})
	t.Run("owned-cisco-dtls09-3des-opt-in", func(t *testing.T) {
		t.Parallel()
		peerAccess.Lock()
		defer peerAccess.Unlock()
		runProductionAnyConnectDTLS(t, ctx, legacyContainer, productionDTLSRunOptions{
			rewriteHeaders:      []string{"X-DTLS-CipherSuite: DES-CBC3-SHA"},
			expectedVersion:     [2]byte{0x01, 0x00},
			verifyDPD:           true,
			allowInsecureCrypto: true,
		})
	})
}

func runProductionAnyConnectDeprecatedDTLSRejected(t *testing.T, ctx context.Context, container ocservContainer) {
	t.Helper()
	observer := new(productionDTLSObserver)
	dialer := &productionInteropDialer{
		observer:       observer,
		udpDestination: M.ParseSocksaddr(container.udpAddress),
		rewriteHeaders: []string{"X-DTLS-CipherSuite: DES-CBC3-SHA"},
		proxyErrors:    make(chan error, 8),
	}
	certificate, err := tls.LoadX509KeyPair(
		filepath.Join("testdata", "ocserv", "server-cert.pem"),
		filepath.Join("testdata", "ocserv", "server-key.pem"),
	)
	if err != nil {
		t.Fatal(E.Cause(err, "load TLS observer certificate for rejected 3DES"))
	}
	dialer.certificate = certificate
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context:  ctx,
		Server:   container.tcpAddress,
		Flavor:   openconnect.FlavorAnyConnect,
		Username: ocservUsername,
		Password: ocservPassword,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
		}},
		Dialer: dialer,
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create production AnyConnect client for rejected 3DES"))
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start production AnyConnect client for rejected 3DES"))
	}
	terminalContext, cancelTerminal := context.WithTimeout(ctx, 10*time.Second)
	defer cancelTerminal()
	for err == nil {
		// ocserv may emit unsolicited tunnel traffic before the DTLS failure is
		// delivered. Keep reading until the client reports the terminal error.
		_, err = client.ReadDataPacket(terminalContext)
	}
	if !E.IsMulti(err, openconnect.ErrDeprecatedCryptoDisabled) {
		t.Fatalf("3DES without AllowInsecureCrypto was not terminal ErrDeprecatedCryptoDisabled: %v", err)
	}
	if client.Ready() {
		t.Fatal("3DES without AllowInsecureCrypto established a ready tunnel")
	}
	if observer.writtenPackets.Load() != 0 || observer.readPackets.Load() != 0 {
		t.Fatalf(
			"3DES without AllowInsecureCrypto exchanged UDP data: writes=%d reads=%d",
			observer.writtenPackets.Load(),
			observer.readPackets.Load(),
		)
	}
	udpDials := observer.udpDialAttempts.Load()
	cstpConnects := dialer.cstpConnects.Load()
	time.Sleep(1200 * time.Millisecond)
	if observer.udpDialAttempts.Load() != udpDials || dialer.cstpConnects.Load() != cstpConnects {
		t.Fatalf(
			"terminal rejected 3DES retried: UDP %d->%d CSTP %d->%d",
			udpDials,
			observer.udpDialAttempts.Load(),
			cstpConnects,
			dialer.cstpConnects.Load(),
		)
	}
	select {
	case proxyErr := <-dialer.proxyErrors:
		t.Fatal(proxyErr)
	default:
	}
}

func TestM1AnyConnectModernPSKWithoutAppIDInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	peer := &noAppIDDTLSPeer{
		ctx:           ctx,
		failures:      make(chan error, 8),
		tunnelStarted: make(chan struct{}, 1),
		probeDPD:      make(chan struct{}),
		dpdResponse:   make(chan struct{}),
	}
	dtlsListener, err := dtls.ListenWithOptions(
		"udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		dtls.WithPSK(func([]byte) ([]byte, error) {
			peer.pskAccess.RLock()
			psk := append([]byte(nil), peer.psk...)
			peer.pskAccess.RUnlock()
			if len(psk) == 0 {
				return nil, E.New("no-App-ID DTLS peer has no exported PSK")
			}
			return psk, nil
		}),
		dtls.WithPSKIdentityHint([]byte("psk")),
		dtls.WithCipherSuites(dtls.TLS_PSK_WITH_AES_128_GCM_SHA256),
	)
	if err != nil {
		t.Fatal(E.Cause(err, "listen for no-App-ID DTLS peer"))
	}
	peer.listener = dtlsListener
	defer dtlsListener.Close()
	go peer.serveDTLS()
	observer := new(productionDTLSObserver)
	dialer := &productionInteropDialer{
		observer:       observer,
		udpDestination: M.ParseSocksaddr(dtlsListener.Addr().String()),
		proxyErrors:    make(chan error, 1),
	}

	dtlsPort := dtlsListener.Addr().(*net.UDPAddr).Port
	httpsPeer := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			peer.reportFailure(E.Cause(readErr, "read no-App-ID HTTPS peer request"))
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/" && strings.Contains(string(body), `type="init"`):
			http.SetCookie(writer, &http.Cookie{Name: "webvpn", Value: "no-app-id-session", Path: "/", Secure: true})
			writer.Header().Set("Content-Type", "application/xml")
			_, writeErr := io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>no-app-id-session</session-token><auth id="success" />
</config-auth>`)
			if writeErr != nil {
				peer.reportFailure(E.Cause(writeErr, "write no-App-ID authentication response"))
			}
		case request.Method == http.MethodConnect:
			peer.serveCSTP(writer, dtlsPort)
		default:
			peer.reportFailure(E.New("no-App-ID HTTPS peer received unexpected request: ", request.Method, " ", request.URL.Path))
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	httpsPeer.EnableHTTP2 = false
	httpsPeer.StartTLS()
	defer httpsPeer.Close()

	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  strings.TrimPrefix(httpsPeer.URL, "https://"),
		Flavor:  openconnect.FlavorAnyConnect,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
		}},
		Dialer: dialer,
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create no-App-ID AnyConnect client"))
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start no-App-ID AnyConnect client"))
	}
	waitContext, cancelWait := context.WithTimeout(ctx, 15*time.Second)
	defer cancelWait()
	for !client.Ready() {
		select {
		case <-waitContext.Done():
			t.Fatal(E.Cause(waitContext.Err(), "wait for no-App-ID AnyConnect client"))
		case failure := <-peer.failures:
			t.Fatal(failure)
		case <-time.After(10 * time.Millisecond):
		}
	}
	select {
	case <-peer.tunnelStarted:
	case failure := <-peer.failures:
		t.Fatal(failure)
	case <-waitContext.Done():
		t.Fatal(E.Cause(waitContext.Err(), "wait for no-App-ID CSTP tunnel"))
	}

	payload := []byte("real no-App-ID DTLS-PSK application packet")
	err = client.WriteDataPacket(payload)
	if err != nil {
		t.Fatal(E.Cause(err, "write no-App-ID DTLS packet"))
	}
	response, err := client.ReadDataPacket(waitContext)
	if err != nil {
		t.Fatal(E.Cause(err, "read no-App-ID DTLS packet"))
	}
	if string(response) != string(payload) || peer.dataPackets.Load() == 0 {
		t.Fatalf("no-App-ID DTLS peer did not consume and echo the application packet: %q packets=%d", response, peer.dataPackets.Load())
	}
	select {
	case <-peer.probeDPD:
	case failure := <-peer.failures:
		t.Fatal(failure)
	case <-waitContext.Done():
		t.Fatal(E.Cause(waitContext.Err(), "wait for single-byte DTLS DPD response during MTU probing"))
	}
	select {
	case <-peer.dpdResponse:
	case failure := <-peer.failures:
		t.Fatal(failure)
	case <-waitContext.Done():
		t.Fatal(E.Cause(waitContext.Err(), "wait for single-byte DTLS DPD response"))
	}
	assertNoAppIDClientHello(t, observer)
	select {
	case failure := <-peer.failures:
		t.Fatal(failure)
	default:
	}
}

func (p *noAppIDDTLSPeer) serveCSTP(writer http.ResponseWriter, dtlsPort int) {
	hijacker, supported := writer.(http.Hijacker)
	if !supported {
		p.reportFailure(E.New("no-App-ID HTTPS peer cannot hijack CSTP CONNECT"))
		return
	}
	connection, readWriter, err := hijacker.Hijack()
	if err != nil {
		p.reportFailure(E.Cause(err, "hijack no-App-ID CSTP connection"))
		return
	}
	defer connection.Close()
	tlsConnection, loaded := connection.(*tls.Conn)
	if !loaded {
		p.reportFailure(E.New("no-App-ID CSTP connection is not TLS"))
		return
	}
	connectionState := tlsConnection.ConnectionState()
	psk, err := connectionState.ExportKeyingMaterial(dtlsPSKExporterLabel, nil, 32)
	if err != nil {
		p.reportFailure(E.Cause(err, "export no-App-ID DTLS PSK"))
		return
	}
	p.pskAccess.Lock()
	p.psk = append([]byte(nil), psk...)
	p.pskAccess.Unlock()
	_, err = readWriter.WriteString("HTTP/1.1 200 CONNECTED\r\n" +
		"X-CSTP-MTU: 1400\r\n" +
		"X-CSTP-Address: 192.0.2.30\r\n" +
		"X-CSTP-Netmask: 255.255.255.0\r\n" +
		"X-CSTP-DPD: 30\r\n" +
		"X-CSTP-Keepalive: 30\r\n" +
		"X-CSTP-Rekey-Method: none\r\n" +
		"X-DTLS-Port: " + strconv.Itoa(dtlsPort) + "\r\n" +
		"X-DTLS-DPD: 30\r\n" +
		"X-DTLS-Keepalive: 30\r\n" +
		"X-DTLS-Session-ID: " + strings.Repeat("01", 32) + "\r\n" +
		"X-DTLS-CipherSuite: PSK-NEGOTIATE\r\n\r\n")
	if err == nil {
		err = readWriter.Flush()
	}
	if err != nil {
		p.reportFailure(E.Cause(err, "write no-App-ID CSTP response"))
		return
	}
	p.tunnelStarted <- struct{}{}
	_, err = io.Copy(io.Discard, readWriter)
	if err != nil && !E.IsClosed(err) && p.ctx.Err() == nil {
		p.reportFailure(E.Cause(err, "consume no-App-ID CSTP tunnel"))
	}
}

func (p *noAppIDDTLSPeer) serveDTLS() {
	connection, err := p.listener.Accept()
	if err != nil {
		if p.ctx.Err() == nil {
			p.reportFailure(E.Cause(err, "accept no-App-ID DTLS connection"))
		}
		return
	}
	defer connection.Close()
	buffer := make([]byte, 64*1024)
	probeDPDInjected := false
	serverDPDPending := false
	for {
		n, readErr := connection.Read(buffer)
		if readErr != nil {
			if !E.IsClosed(readErr) && p.ctx.Err() == nil {
				p.reportFailure(E.Cause(readErr, "read no-App-ID DTLS packet"))
			}
			return
		}
		if n == 0 {
			continue
		}
		packet := append([]byte(nil), buffer[:n]...)
		switch packet[0] {
		case anyConnectPacketDPDRequest:
			if !probeDPDInjected {
				paddedDPD := append([]byte{anyConnectPacketDPDRequest}, bytes.Repeat([]byte{0x33}, 255)...)
				n, err = connection.Write(paddedDPD)
				if err != nil {
					p.reportFailure(E.Cause(err, "write concurrent padded no-App-ID DTLS DPD request"))
					return
				}
				if n != len(paddedDPD) {
					p.reportFailure(E.New("short concurrent padded no-App-ID DTLS DPD write: ", n, " of ", len(paddedDPD)))
					return
				}
				n, readErr = connection.Read(buffer)
				if readErr != nil {
					p.reportFailure(E.Cause(readErr, "read no-App-ID DTLS DPD response during MTU probing"))
					return
				}
				if n != 1 || buffer[0] != anyConnectPacketDPDResponse {
					p.reportFailure(E.New("no-App-ID DTLS DPD response during MTU probing was not one byte: ", append([]byte(nil), buffer[:n]...)))
					return
				}
				close(p.probeDPD)
				probeDPDInjected = true
			}
			packet[0] = anyConnectPacketDPDResponse
		case anyConnectPacketData:
			p.dataPackets.Add(1)
			n, err = connection.Write(packet)
			if err != nil {
				p.reportFailure(E.Cause(err, "echo no-App-ID DTLS data packet"))
				return
			}
			if n != len(packet) {
				p.reportFailure(E.New("short no-App-ID DTLS data packet write: ", n, " of ", len(packet)))
				return
			}
			paddedDPD := append([]byte{anyConnectPacketDPDRequest}, bytes.Repeat([]byte{0x44}, 255)...)
			n, err = connection.Write(paddedDPD)
			if err != nil {
				p.reportFailure(E.Cause(err, "write padded no-App-ID DTLS DPD request"))
				return
			}
			if n != len(paddedDPD) {
				p.reportFailure(E.New("short padded no-App-ID DTLS DPD write: ", n, " of ", len(paddedDPD)))
				return
			}
			serverDPDPending = true
			continue
		case anyConnectPacketDPDResponse:
			if serverDPDPending {
				if len(packet) != 1 {
					p.reportFailure(E.New("no-App-ID DTLS DPD response echoed request payload: ", len(packet), " bytes"))
					return
				}
				close(p.dpdResponse)
				serverDPDPending = false
			}
			continue
		case anyConnectPacketKeepalive:
			continue
		default:
			p.reportFailure(E.New("no-App-ID DTLS peer received unexpected packet type: ", packet[0]))
			return
		}
		n, err = connection.Write(packet)
		if err != nil {
			p.reportFailure(E.Cause(err, "echo no-App-ID DTLS packet"))
			return
		}
		if n != len(packet) {
			p.reportFailure(E.New("short no-App-ID DTLS packet write: ", n, " of ", len(packet)))
			return
		}
	}
}

func (p *noAppIDDTLSPeer) reportFailure(err error) {
	select {
	case p.failures <- err:
	default:
	}
}

func assertNoAppIDClientHello(t *testing.T, observer *productionDTLSObserver) {
	t.Helper()
	observer.firstWriteAccess.Lock()
	firstWrite := append([]byte(nil), observer.firstWrite...)
	observer.firstWriteAccess.Unlock()
	records, err := recordlayer.UnpackDatagram(firstWrite)
	if err != nil {
		t.Fatal(E.Cause(err, "unpack no-App-ID DTLS ClientHello datagram"))
	}
	if len(records) == 0 {
		t.Fatal("no-App-ID DTLS client sent no ClientHello record")
	}
	var record recordlayer.RecordLayer
	err = record.Unmarshal(records[0])
	if err != nil {
		t.Fatal(E.Cause(err, "decode no-App-ID DTLS ClientHello record"))
	}
	handshakeRecord, loaded := record.Content.(*handshake.Handshake)
	if !loaded {
		t.Fatal("no-App-ID DTLS first record was not a handshake")
	}
	clientHello, loaded := handshakeRecord.Message.(*handshake.MessageClientHello)
	if !loaded {
		t.Fatal("no-App-ID DTLS first handshake was not ClientHello")
	}
	if len(clientHello.SessionID) != 0 {
		t.Fatalf("no-App-ID DTLS ClientHello unexpectedly reused X-DTLS-Session-ID: %x", clientHello.SessionID)
	}
}

func interopEnabled() bool {
	return strings.TrimSpace(os.Getenv(openConnectInteropEnvironment)) != ""
}

func runProductionAnyConnectDTLS(
	t *testing.T,
	ctx context.Context,
	container ocservContainer,
	options productionDTLSRunOptions,
) {
	t.Helper()
	observer := new(productionDTLSObserver)
	dialer := &productionInteropDialer{
		observer:               observer,
		udpDestination:         M.ParseSocksaddr(container.udpAddress),
		rewriteHeaders:         options.rewriteHeaders,
		rewriteResponseHeaders: options.rewriteResponseHeaders,
		appendResponseHeaders:  options.appendResponseHeaders,
		removeResponseHeaders:  options.removeResponseHeaders,
		promoteResponseDTLS12:  options.promoteResponseDTLS12,
		maximumUDPDatagramSize: options.maximumUDPDatagramSize,
		proxyErrors:            make(chan error, 16),
	}
	dialer.remainingUDPFailures.Store(options.udpDialFailures)
	observeCSTP := len(options.rewriteHeaders) > 0 ||
		len(options.rewriteResponseHeaders) > 0 ||
		len(options.appendResponseHeaders) > 0 ||
		len(options.removeResponseHeaders) > 0 ||
		options.promoteResponseDTLS12
	if observeCSTP {
		certificate, err := tls.LoadX509KeyPair(
			filepath.Join("testdata", "ocserv", "server-cert.pem"),
			filepath.Join("testdata", "ocserv", "server-key.pem"),
		)
		if err != nil {
			t.Fatal(E.Cause(err, "load TLS observer certificate"))
		}
		dialer.certificate = certificate
	}
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 16)

	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context:  ctx,
		Server:   container.tcpAddress,
		Flavor:   openconnect.FlavorAnyConnect,
		Username: ocservUsername,
		Password: ocservPassword,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
		}},
		Dialer:              dialer,
		Logger:              productionDTLSTestLogger{t: t},
		AllowInsecureCrypto: options.allowInsecureCrypto,
		OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
			configurationEvents <- event
			return nil
		},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create production AnyConnect client"))
	}
	defer client.Close()
	activeTransportUpdated := client.ActiveTransportUpdated()
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start production AnyConnect client"))
	}
	if options.expectCSTPBeforeDTLS {
		waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportCSTP)
		activeTransportUpdated = client.ActiveTransportUpdated()
	}
	waitForProductionClient(t, ctx, client, dialer.proxyErrors)
	waitForProductionDTLSConnection(t, ctx, observer, options.udpDialFailures, dialer.proxyErrors)
	waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportDTLS)
	if options.udpDialFailures > 0 {
		assertProductionUDPDialBackoff(t, observer, options.udpDialFailures)
	}
	if options.expectDTLSOnlyRekey {
		waitForProductionDTLSOnlyRekey(t, ctx, client, observer, dialer, configurationEvents)
	}
	var pathMTUConfiguration openconnect.TunnelConfiguration
	if options.expectPathMTUEvent {
		pathMTUConfiguration = waitForProductionPathMTUEvent(t, ctx, configurationEvents, dialer.proxyErrors)
	}

	configuration := client.TunnelConfiguration()
	if options.maximumUDPDatagramSize > 0 {
		largestAcceptedWrite := observer.largestAcceptedWrite.Load()
		if observer.droppedWrites.Load() == 0 || observer.largestWrite.Load() <= uint64(options.maximumUDPDatagramSize) {
			t.Fatalf(
				"DTLS path did not exercise the datagram ceiling: dropped=%d largest=%d ceiling=%d",
				observer.droppedWrites.Load(),
				observer.largestWrite.Load(),
				options.maximumUDPDatagramSize,
			)
		}
		if configuration.MTU >= uint32(options.maximumUDPDatagramSize) {
			t.Fatalf("DTLS path MTU was not reduced below the raw datagram ceiling: %d >= %d", configuration.MTU, options.maximumUDPDatagramSize)
		}
		if options.expectMinimumPathMTU {
			if pathMTUConfiguration.MTU != 576 {
				t.Fatalf("DTLS path-MTU event did not report the IPv4 minimum: %d", pathMTUConfiguration.MTU)
			}
			if configuration.MTU != 576 {
				t.Fatalf("DTLS path MTU did not fall back to the IPv4 minimum: %d", configuration.MTU)
			}
		} else {
			if configuration.MTU < 900 {
				t.Fatalf("DTLS path MTU collapsed instead of converging near the 1100-byte ceiling: %d", configuration.MTU)
			}
			if largestAcceptedWrite > uint64(options.maximumUDPDatagramSize) ||
				largestAcceptedWrite+128 < uint64(options.maximumUDPDatagramSize) {
				t.Fatalf(
					"DTLS path-MTU probes did not approach the largest accepted raw datagram: accepted=%d ceiling=%d",
					largestAcceptedWrite,
					options.maximumUDPDatagramSize,
				)
			}
		}
	}
	if len(options.removeResponseHeaders) > 0 && dialer.removedResponseHeaders.Load() == 0 {
		t.Fatal("CSTP proxy did not remove the requested response header")
	}
	clientAddress := firstIPv4Address(t, configuration.Addresses)
	serverAddress := netip.MustParseAddr(ocservTunnelAddress)
	request := buildIPv4ICMPEchoRequest(
		t,
		clientAddress,
		serverAddress,
		0x4d31,
		1,
		[]byte("sing-openconnect-m1-production-dtls"),
	)
	readsBefore := observer.readPackets.Load()
	writesBefore := observer.writtenPackets.Load()
	readDatagramsBefore, writtenDatagramsBefore := observer.snapshotDatagramSizes()
	cstpWritesBefore := observer.cstpDataToServer.Load()
	cstpReadsBefore := observer.cstpDataToClient.Load()
	var channelLogsBefore string
	if !observeCSTP {
		channelLogsBefore, err = dockerOutput(ctx, "logs", "--tail", "5000", container.name)
		if err != nil {
			t.Fatal(E.Cause(err, "read ocserv channel logs before production DTLS data"))
		}
	}
	err = client.WriteDataPacket(request)
	if err != nil {
		t.Fatal(E.Cause(err, "write production AnyConnect data packet"))
	}
	readContext, cancelRead := context.WithTimeout(ctx, 10*time.Second)
	defer cancelRead()
	for {
		response, readErr := client.ReadDataPacket(readContext)
		if readErr != nil {
			t.Fatal(E.Cause(readErr, "read production AnyConnect data packet"))
		}
		if len(response) == 0 || response[0]>>4 != 4 {
			continue
		}
		err = validateIPv4ICMPEchoReply(
			response,
			clientAddress,
			serverAddress,
			0x4d31,
			1,
			[]byte("sing-openconnect-m1-production-dtls"),
		)
		if err != nil {
			t.Fatal(err)
		}
		break
	}
	if observer.writtenPackets.Load() <= writesBefore || observer.readPackets.Load() <= readsBefore {
		t.Fatalf(
			"production packet used CSTP fallback instead of DTLS: writes %d->%d reads %d->%d",
			writesBefore,
			observer.writtenPackets.Load(),
			readsBefore,
			observer.readPackets.Load(),
		)
	}
	if observeCSTP && (observer.cstpDataToServer.Load() != cstpWritesBefore || observer.cstpDataToClient.Load() != cstpReadsBefore) {
		t.Fatalf(
			"production packet crossed CSTP instead of staying on DTLS: writes %d->%d reads %d->%d",
			cstpWritesBefore,
			observer.cstpDataToServer.Load(),
			cstpReadsBefore,
			observer.cstpDataToClient.Load(),
		)
	}
	readDatagramsAfter, writtenDatagramsAfter := observer.snapshotDatagramSizes()
	if !hasProductionApplicationDatagram(writtenDatagramsAfter[len(writtenDatagramsBefore):], len(request)) ||
		!hasProductionApplicationDatagram(readDatagramsAfter[len(readDatagramsBefore):], len(request)) {
		t.Fatalf(
			"production ICMP did not produce application-sized DTLS datagrams: writes=%v reads=%v minimum=%d",
			writtenDatagramsAfter[len(writtenDatagramsBefore):],
			readDatagramsAfter[len(readDatagramsBefore):],
			len(request),
		)
	}
	if !observeCSTP {
		assertProductionOcservDTLSData(t, ctx, container, channelLogsBefore, len(request))
	}
	if options.verifyDPD {
		waitForProductionDTLSDPD(t, ctx, container)
	}
	observer.firstWriteAccess.Lock()
	firstWrite := append([]byte(nil), observer.firstWrite...)
	observer.firstWriteAccess.Unlock()
	if len(firstWrite) < 3 || firstWrite[1] != options.expectedVersion[0] || firstWrite[2] != options.expectedVersion[1] {
		t.Fatalf("unexpected production DTLS record version: %x", firstWrite)
	}
	select {
	case proxyErr := <-dialer.proxyErrors:
		t.Fatal(proxyErr)
	default:
	}
}

func waitForProductionPathMTUEvent(
	t *testing.T,
	ctx context.Context,
	events <-chan openconnect.TunnelConfigurationEvent,
	proxyErrors <-chan error,
) openconnect.TunnelConfiguration {
	t.Helper()
	waitContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		select {
		case <-waitContext.Done():
			t.Fatal(E.Cause(waitContext.Err(), "wait for production DTLS path-MTU configuration event"))
		case proxyErr := <-proxyErrors:
			t.Fatal(proxyErr)
		case event := <-events:
			if event.Reason == openconnect.TunnelConfigurationEventPathMTU {
				return event.Configuration
			}
		}
	}
}

func waitForProductionDTLSDPD(t *testing.T, ctx context.Context, container ocservContainer) {
	t.Helper()
	const logMessage = "received DTLS DPD; sent response"
	logsBefore, err := dockerOutput(ctx, "logs", "--tail", "5000", container.name)
	if err != nil {
		t.Fatal(E.Cause(err, "read ocserv logs before DTLS DPD"))
	}
	responsesBefore := strings.Count(logsBefore, logMessage)
	waitContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-waitContext.Done():
			t.Fatal(E.Cause(waitContext.Err(), "wait for ocserv to identify an active DTLS DPD request after response count ", responsesBefore))
		case <-ticker.C:
			logs, logsErr := dockerOutput(waitContext, "logs", "--tail", "5000", container.name)
			if logsErr != nil {
				if waitContext.Err() != nil {
					continue
				}
				t.Fatal(E.Cause(logsErr, "read ocserv logs while waiting for DTLS DPD"))
			}
			if strings.Count(logs, logMessage) > responsesBefore {
				return
			}
		}
	}
}

func waitForProductionDTLSOnlyRekey(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	observer *productionDTLSObserver,
	dialer *productionInteropDialer,
	events <-chan openconnect.TunnelConfigurationEvent,
) {
	t.Helper()
	assertActiveTransport(t, client, openconnect.TransportDTLS)
	activeTransportUpdated := client.ActiveTransportUpdated()
	initialUDPAttempts := observer.udpDialAttempts.Load()
	initialDialTimes := observer.snapshotUDPDialTimes()
	initialReads := observer.readPackets.Load()
	initialCSTPConnects := dialer.cstpConnects.Load()
	dialer.remainingUDPFailures.Store(1)
	waitContext, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	minimumWait := time.NewTimer(8 * time.Second)
	defer minimumWait.Stop()
	minimumElapsed := false
	sawCSTPFallback := false
	sawReplacementDTLS := false
	for !minimumElapsed || observer.udpDialAttempts.Load() <= initialUDPAttempts || observer.readPackets.Load() <= initialReads || !sawReplacementDTLS {
		select {
		case <-waitContext.Done():
			t.Fatal(E.Cause(waitContext.Err(), "wait for DTLS-only SSL rekey"))
		case <-activeTransportUpdated:
			activeTransportUpdated = client.ActiveTransportUpdated()
			activeTransport := client.ActiveTransport()
			if activeTransport == openconnect.TransportCSTP {
				sawCSTPFallback = true
			} else if sawCSTPFallback && activeTransport == openconnect.TransportDTLS {
				sawReplacementDTLS = true
			}
		case proxyErr := <-dialer.proxyErrors:
			t.Fatal(proxyErr)
		case event := <-events:
			if event.Reason == openconnect.TunnelConfigurationEventRekey {
				t.Fatal("DTLS-only SSL rekey emitted a main-tunnel rekey event")
			}
		case <-ticker.C:
			if dialer.cstpConnects.Load() != initialCSTPConnects {
				t.Fatalf("DTLS-only SSL rekey replaced CSTP: %d -> %d", initialCSTPConnects, dialer.cstpConnects.Load())
			}
		case <-minimumWait.C:
			minimumElapsed = true
		}
	}
	if dialer.cstpConnects.Load() != initialCSTPConnects {
		t.Fatalf("DTLS-only SSL rekey replaced CSTP: %d -> %d", initialCSTPConnects, dialer.cstpConnects.Load())
	}
	if !sawCSTPFallback || !sawReplacementDTLS {
		t.Fatalf("DTLS-only SSL rekey did not report DTLS to CSTP to DTLS: fallback=%v replacement=%v", sawCSTPFallback, sawReplacementDTLS)
	}
	dialTimes := observer.snapshotUDPDialTimes()
	if initialUDPAttempts == 0 || len(initialDialTimes) != int(initialUDPAttempts) || len(dialTimes) <= int(initialUDPAttempts) {
		t.Fatalf("missing initial/rekey DTLS UDP dial timestamps: initial=%v final=%v", initialDialTimes, dialTimes)
	}
	rekeyDelay := dialTimes[initialUDPAttempts].Sub(initialDialTimes[len(initialDialTimes)-1])
	if rekeyDelay < 5*time.Second {
		t.Fatalf("DTLS SSL rekey opened a replacement UDP channel before the negotiated five-second window: %s", rekeyDelay)
	}
}

func waitForProductionClient(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	proxyErrors <-chan error,
) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for !client.Ready() {
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for production AnyConnect client"))
		case proxyErr := <-proxyErrors:
			t.Fatal(proxyErr)
		case <-ticker.C:
		}
	}
}

func waitForProductionDTLSConnection(
	t *testing.T,
	ctx context.Context,
	observer *productionDTLSObserver,
	failedDials int64,
	proxyErrors <-chan error,
) {
	t.Helper()
	waitContext, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for observer.udpDialAttempts.Load() <= uint64(failedDials) || observer.readPackets.Load() == 0 {
		select {
		case <-waitContext.Done():
			t.Fatal(E.Cause(
				waitContext.Err(),
				"wait for production DTLS connection after ", failedDials,
				" failed UDP dials; attempts=", observer.udpDialAttempts.Load(),
				" reads=", observer.readPackets.Load(),
			))
		case proxyErr := <-proxyErrors:
			t.Fatal(proxyErr)
		case <-ticker.C:
		}
	}
}

func assertProductionUDPDialBackoff(t *testing.T, observer *productionDTLSObserver, failedDials int64) {
	t.Helper()
	dialTimes := observer.snapshotUDPDialTimes()
	if len(dialTimes) < int(failedDials)+1 {
		t.Fatalf("missing DTLS UDP dial timestamps: failures=%d timestamps=%v", failedDials, dialTimes)
	}
	expectedDelay := time.Second
	for index := 0; index < int(failedDials); index++ {
		delay := dialTimes[index+1].Sub(dialTimes[index])
		minimum := expectedDelay * 4 / 5
		maximum := expectedDelay * 5 / 2
		if delay < minimum || delay > maximum {
			t.Fatalf(
				"DTLS UDP retry %d ignored exponential backoff: delay=%s expected=%s bounds=[%s,%s]",
				index+1,
				delay,
				expectedDelay,
				minimum,
				maximum,
			)
		}
		expectedDelay *= 2
	}
}

func hasProductionApplicationDatagram(sizes []int, minimum int) bool {
	for _, size := range sizes {
		if size >= minimum {
			return true
		}
	}
	return false
}

func assertProductionOcservDTLSData(
	t *testing.T,
	ctx context.Context,
	container ocservContainer,
	logsBefore string,
	payloadSize int,
) {
	t.Helper()
	tlsDataLog := "received " + strconv.Itoa(payloadSize+8) + " byte(s) (TLS)"
	dtlsDataLog := "received " + strconv.Itoa(payloadSize+1) + " byte(s) (DTLS)"
	tunDataLog := "writing " + strconv.Itoa(payloadSize) + " byte(s) to TUN"
	tlsBefore := strings.Count(logsBefore, tlsDataLog)
	dtlsBefore := strings.Count(logsBefore, dtlsDataLog)
	tunBefore := strings.Count(logsBefore, tunDataLog)
	waitContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-waitContext.Done():
			t.Fatal(E.Cause(waitContext.Err(), "wait for ocserv DTLS channel log after ICMP"))
		case <-ticker.C:
			logs, err := dockerOutput(waitContext, "logs", "--tail", "5000", container.name)
			if err != nil {
				if waitContext.Err() != nil {
					continue
				}
				t.Fatal(E.Cause(err, "read ocserv channel logs after production DTLS data"))
			}
			tlsAfter := strings.Count(logs, tlsDataLog)
			dtlsAfter := strings.Count(logs, dtlsDataLog)
			tunAfter := strings.Count(logs, tunDataLog)
			if tlsAfter != tlsBefore {
				t.Fatalf("ocserv received the %d-byte ICMP over CSTP: exact TLS data records %d->%d", payloadSize, tlsBefore, tlsAfter)
			}
			if dtlsAfter > dtlsBefore && tunAfter > tunBefore {
				return
			}
		}
	}
}

func firstIPv4Address(t *testing.T, addresses []netip.Prefix) netip.Addr {
	t.Helper()
	for _, prefix := range addresses {
		if prefix.Addr().Is4() {
			return prefix.Addr()
		}
	}
	t.Fatal("production AnyConnect tunnel has no IPv4 address")
	return netip.Addr{}
}

func (d *productionInteropDialer) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	if network == N.NetworkUDP {
		d.observer.recordUDPDial()
		for {
			remainingFailures := d.remainingUDPFailures.Load()
			if remainingFailures <= 0 {
				break
			}
			if d.remainingUDPFailures.CompareAndSwap(remainingFailures, remainingFailures-1) {
				return nil, E.New("injected production DTLS UDP dial failure")
			}
		}
		conn, err := N.SystemDialer.DialContext(ctx, network, d.udpDestination)
		if err != nil {
			return nil, err
		}
		return &productionDTLSConn{
			Conn:                conn,
			observer:            d.observer,
			maximumDatagramSize: d.maximumUDPDatagramSize,
		}, nil
	}
	if len(d.certificate.Certificate) == 0 {
		return N.SystemDialer.DialContext(ctx, network, destination)
	}
	clientConn, proxyConn := net.Pipe()
	go d.proxyTLS(ctx, proxyConn, destination)
	return clientConn, nil
}

func (d *productionInteropDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

func (d *productionInteropDialer) proxyTLS(ctx context.Context, clientConn net.Conn, destination M.Socksaddr) {
	defer clientConn.Close()
	clientTLS := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{d.certificate},
		NextProtos:   []string{"http/1.1"},
	})
	err := clientTLS.HandshakeContext(ctx)
	if err != nil {
		d.reportProxyError(E.Cause(err, "handshake client side of CSTP header rewriting proxy"))
		return
	}
	serverConn, err := N.SystemDialer.DialContext(ctx, N.NetworkTCP, destination)
	if err != nil {
		d.reportProxyError(E.Cause(err, "connect server side of CSTP header rewriting proxy"))
		return
	}
	defer serverConn.Close()
	serverTLS := tls.Client(serverConn, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	err = serverTLS.HandshakeContext(ctx)
	if err != nil {
		d.reportProxyError(E.Cause(err, "handshake server side of CSTP header rewriting proxy"))
		return
	}
	reader := bufio.NewReader(clientTLS)
	header, err := readHTTPHeader(reader)
	if err != nil {
		d.reportProxyError(E.Cause(err, "read first request in CSTP header rewriting proxy"))
		return
	}
	isCSTP := strings.HasPrefix(header, "CONNECT ")
	if isCSTP {
		d.cstpConnects.Add(1)
	}
	if isCSTP && len(d.rewriteHeaders) > 0 {
		header = rewriteDTLSCipherHeaders(header, d.rewriteHeaders)
	}
	err = writeAll(serverTLS, []byte(header))
	if err != nil {
		d.reportProxyError(E.Cause(err, "forward first request through CSTP header rewriting proxy"))
		return
	}
	requestCopyDone := make(chan struct{})
	go func() {
		if isCSTP {
			_ = copyProductionCSTPRecords(serverTLS, reader, &d.observer.cstpDataToServer)
		} else {
			_, _ = io.Copy(serverTLS, reader)
		}
		_ = serverTLS.Close()
		close(requestCopyDone)
	}()
	serverReader := bufio.NewReader(serverTLS)
	responseHeader, err := readHTTPHeader(serverReader)
	if err != nil {
		d.reportProxyError(E.Cause(err, "read first response in CSTP header rewriting proxy"))
		return
	}
	if isCSTP && len(d.rewriteResponseHeaders) > 0 {
		responseHeader = rewriteDTLSCipherHeaders(responseHeader, d.rewriteResponseHeaders)
	}
	if isCSTP && d.promoteResponseDTLS12 {
		responseHeader = promoteDTLS12ResponseHeaders(responseHeader)
	}
	if isCSTP && len(d.removeResponseHeaders) > 0 {
		var removed int
		responseHeader, removed = removeHTTPHeaders(responseHeader, d.removeResponseHeaders)
		d.removedResponseHeaders.Add(uint64(removed))
	}
	if isCSTP && len(d.appendResponseHeaders) > 0 {
		responseHeader = strings.TrimSuffix(responseHeader, "\r\n\r\n") + "\r\n" +
			strings.Join(d.appendResponseHeaders, "\r\n") + "\r\n\r\n"
	}
	err = writeAll(clientTLS, []byte(responseHeader))
	if err != nil {
		d.reportProxyError(E.Cause(err, "forward first response through CSTP header rewriting proxy"))
		return
	}
	if isCSTP {
		_ = copyProductionCSTPRecords(clientTLS, serverReader, &d.observer.cstpDataToClient)
	} else {
		_, _ = io.Copy(clientTLS, serverReader)
	}
	_ = serverTLS.Close()
	<-requestCopyDone
}

func (d *productionInteropDialer) reportProxyError(err error) {
	select {
	case d.proxyErrors <- err:
	default:
	}
}

func copyProductionCSTPRecords(destination io.Writer, source io.Reader, dataPackets *atomic.Uint64) error {
	var header [8]byte
	for {
		_, err := io.ReadFull(source, header[:])
		if err != nil {
			return err
		}
		if !bytes.Equal(header[:4], []byte{'S', 'T', 'F', 1}) || header[7] != 0 {
			return E.New("invalid CSTP record in production DTLS observer: ", header[:])
		}
		payload := make([]byte, int(binary.BigEndian.Uint16(header[4:6])))
		_, err = io.ReadFull(source, payload)
		if err != nil {
			return err
		}
		if header[6] == anyConnectPacketData {
			dataPackets.Add(1)
		}
		record := make([]byte, 0, len(header)+len(payload))
		record = append(record, header[:]...)
		record = append(record, payload...)
		err = writeAll(destination, record)
		if err != nil {
			return err
		}
	}
}

func (c *productionDTLSConn) Read(buffer []byte) (int, error) {
	n, err := c.Conn.Read(buffer)
	if n > 0 {
		c.observer.readPackets.Add(1)
		c.observer.datagramAccess.Lock()
		c.observer.readDatagramSizes = append(c.observer.readDatagramSizes, n)
		c.observer.datagramAccess.Unlock()
	}
	return n, err
}

func (c *productionDTLSConn) Write(buffer []byte) (int, error) {
	for {
		largestWrite := c.observer.largestWrite.Load()
		if uint64(len(buffer)) <= largestWrite || c.observer.largestWrite.CompareAndSwap(largestWrite, uint64(len(buffer))) {
			break
		}
	}
	if c.maximumDatagramSize > 0 && len(buffer) > c.maximumDatagramSize {
		c.observer.writtenPackets.Add(1)
		c.observer.droppedWrites.Add(1)
		return len(buffer), nil
	}
	n, err := c.Conn.Write(buffer)
	if n > 0 {
		for {
			largestAcceptedWrite := c.observer.largestAcceptedWrite.Load()
			if uint64(n) <= largestAcceptedWrite || c.observer.largestAcceptedWrite.CompareAndSwap(largestAcceptedWrite, uint64(n)) {
				break
			}
		}
		c.observer.writtenPackets.Add(1)
		c.observer.datagramAccess.Lock()
		c.observer.writtenDatagramSizes = append(c.observer.writtenDatagramSizes, n)
		c.observer.datagramAccess.Unlock()
		c.observer.firstWriteAccess.Lock()
		if len(c.observer.firstWrite) == 0 {
			c.observer.firstWrite = append([]byte(nil), buffer[:n]...)
		}
		c.observer.firstWriteAccess.Unlock()
	}
	return n, err
}

func (o *productionDTLSObserver) recordUDPDial() {
	o.udpDialAttempts.Add(1)
	o.udpDialAccess.Lock()
	o.udpDialTimes = append(o.udpDialTimes, time.Now())
	o.udpDialAccess.Unlock()
}

func (o *productionDTLSObserver) snapshotUDPDialTimes() []time.Time {
	o.udpDialAccess.Lock()
	defer o.udpDialAccess.Unlock()
	return append([]time.Time(nil), o.udpDialTimes...)
}

func (o *productionDTLSObserver) snapshotDatagramSizes() (read []int, written []int) {
	o.datagramAccess.Lock()
	defer o.datagramAccess.Unlock()
	return append([]int(nil), o.readDatagramSizes...), append([]int(nil), o.writtenDatagramSizes...)
}

func readHTTPHeader(reader *bufio.Reader) (string, error) {
	var header strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		header.WriteString(line)
		if line == "\r\n" {
			return header.String(), nil
		}
	}
}

// Upstream cstp.c applies X-DTLS-CipherSuite and X-DTLS12-CipherSuite response headers in arrival order, so the last one selects the mode and cipher.
func rewriteDTLSCipherHeaders(header string, replacements []string) string {
	lines := strings.Split(strings.TrimSuffix(header, "\r\n\r\n"), "\r\n")
	filtered := make([]string, 0, len(lines)+len(replacements))
	for _, line := range lines {
		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, "x-dtls-ciphersuite:") || strings.HasPrefix(lowerLine, "x-dtls12-ciphersuite:") {
			continue
		}
		filtered = append(filtered, line)
	}
	filtered = append(filtered, replacements...)
	return strings.Join(filtered, "\r\n") + "\r\n\r\n"
}

func promoteDTLS12ResponseHeaders(header string) string {
	lines := strings.Split(strings.TrimSuffix(header, "\r\n\r\n"), "\r\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "x-dtls-") {
			lines[i] = "X-DTLS12-" + line[len("X-DTLS-"):]
		}
	}
	return strings.Join(lines, "\r\n") + "\r\n\r\n"
}

func removeHTTPHeaders(header string, names []string) (string, int) {
	removed := 0
	lines := strings.Split(strings.TrimSuffix(header, "\r\n\r\n"), "\r\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		separator := strings.IndexByte(line, ':')
		remove := false
		if separator > 0 {
			name := strings.TrimSpace(line[:separator])
			for _, target := range names {
				if strings.EqualFold(name, target) {
					remove = true
					break
				}
			}
		}
		if remove {
			removed++
			continue
		}
		filtered = append(filtered, line)
	}
	return strings.Join(filtered, "\r\n") + "\r\n\r\n", removed
}

func writeAll(w io.Writer, content []byte) error {
	for len(content) > 0 {
		n, err := w.Write(content)
		if err != nil {
			return err
		}
		if n == 0 {
			return E.New("short write in CSTP header rewriting proxy")
		}
		content = content[n:]
	}
	return nil
}

func startLegacyOcservContainer(t *testing.T, ctx context.Context) ocservContainer {
	t.Helper()
	_, err := dockerOutput(ctx, "version", "--format", "{{.Server.Version}}")
	if err != nil {
		t.Fatal(err)
	}
	_, err = dockerOutput(ctx, "build", "--pull=false", "--tag", ocservInteropImage, filepath.Join("testdata", "ocserv"))
	if err != nil {
		t.Fatal(err)
	}
	containerName := "sing-openconnect-m1-legacy-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	_, err = dockerOutput(
		ctx,
		"run", "--detach", "--rm", "--name", containerName,
		"--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
		"--publish", "127.0.0.1::443/tcp", "--publish", "127.0.0.1::443/udp",
		"--entrypoint", "ocserv",
		ocservInteropImage,
		"-f", "-d", "5", "-c", "/etc/ocserv/ocserv-legacy.conf",
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
				t.Log("legacy ocserv logs:\n" + logs)
			}
		}
		removeContext, cancelRemove := context.WithTimeout(context.Background(), 5*time.Second)
		_, _ = dockerOutput(removeContext, "rm", "--force", containerName)
		cancelRemove()
	})
	tcpAddress := dockerPublishedAddress(t, ctx, containerName, "443/tcp")
	udpAddress := dockerPublishedAddress(t, ctx, containerName, "443/udp")
	waitForTCP(t, ctx, tcpAddress)
	return ocservContainer{name: containerName, tcpAddress: tcpAddress, udpAddress: udpAddress}
}

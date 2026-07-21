package test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

const (
	m1DTLS09HelloVerifyImage  = "sing-openconnect-dtls09-helloverify:2035601"
	m1DTLS09SessionCookie     = "dtls09-helloverify-session"
	m1DTLS09OracleReady       = "DTLS09_READY port=4433 cookie=000102030405060708090a0b0c0d0e0f10111213"
	m1DTLS09HandshakeComplete = "DTLS09_HANDSHAKE_OK first_cookie=empty retry_cookie=000102030405060708090a0b0c0d0e0f10111213 client_ccs=verified client_finished=verified"
	m1DTLS09DataComplete      = "DTLS09_COMPLETE client_data=verified server_data=sent dpd_request=sent dpd_response=verified path="
)

type m1DTLS09HelloVerifyDialer struct {
	access          sync.RWMutex
	udpTarget       M.Socksaddr
	udpDestinations []M.Socksaddr
	udpDials        atomic.Uint64
}

type m1DTLS09HelloVerifyPeer struct {
	ctx              context.Context
	sessionID        []byte
	cipherSuite      string
	containerName    string
	dialer           *m1DTLS09HelloVerifyDialer
	failures         chan error
	cstpStarted      chan struct{}
	cstpClosed       chan error
	containerAccess  sync.Mutex
	containerStarted bool
	udpAddress       string
	cstpDataPackets  atomic.Uint64
}

// OpenConnect bad_dtls_test.c at 2035601b64a5360a46d18e08937e7f654b3230f2 defines the Cisco DTLS 0.9 wire contract; OpenConnect 9.21 openssl-dtls.c defines the retained DES-CBC-SHA suite.
func TestM1AnyConnectDTLS09HelloVerifyInterop(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)
	_, buildErr := dockerOutput(
		ctx,
		"build", "--pull=false", "--tag", m1DTLS09HelloVerifyImage,
		filepath.Join("testdata", "dtls09-helloverify"),
	)
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	for _, testCase := range []struct {
		name                string
		cipherSuite         string
		allowInsecureCrypto bool
	}{
		{name: "aes128", cipherSuite: "AES128-SHA"},
		{name: "single-des-opt-in", cipherSuite: "DES-CBC-SHA", allowInsecureCrypto: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			sessionID := make([]byte, 32)
			_, err := rand.Read(sessionID)
			if err != nil {
				t.Fatal(E.Cause(err, "generate DTLS0.9 HelloVerify session ID"))
			}
			dialer := new(m1DTLS09HelloVerifyDialer)
			peer := &m1DTLS09HelloVerifyPeer{
				ctx:           ctx,
				sessionID:     sessionID,
				cipherSuite:   testCase.cipherSuite,
				containerName: "sing-openconnect-dtls09-helloverify-" + testCase.name + "-" + strconv.FormatInt(time.Now().UnixNano(), 10),
				dialer:        dialer,
				failures:      make(chan error, 8),
				cstpStarted:   make(chan struct{}, 1),
				cstpClosed:    make(chan error, 1),
			}
			t.Cleanup(func() {
				peer.containerAccess.Lock()
				containerStarted := peer.containerStarted
				peer.containerAccess.Unlock()
				if !containerStarted {
					return
				}
				if t.Failed() {
					logsContext, cancelLogs := context.WithTimeout(context.Background(), 5*time.Second)
					logs, logsErr := dockerOutput(logsContext, "logs", peer.containerName)
					cancelLogs()
					if logsErr == nil {
						t.Log("DTLS0.9 HelloVerify oracle logs:\n" + logs)
					}
				}
				removeContext, cancelRemove := context.WithTimeout(context.Background(), 5*time.Second)
				_, _ = dockerOutput(removeContext, "rm", "--force", peer.containerName)
				cancelRemove()
			})

			httpsPeer := httptest.NewUnstartedServer(peer)
			httpsPeer.EnableHTTP2 = false
			httpsPeer.StartTLS()
			t.Cleanup(httpsPeer.Close)
			client, err := openconnect.NewClient(openconnect.ClientOptions{
				Context:             ctx,
				Server:              strings.TrimPrefix(httpsPeer.URL, "https://"),
				Flavor:              openconnect.FlavorAnyConnect,
				Dialer:              dialer,
				AllowInsecureCrypto: testCase.allowInsecureCrypto,
				TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
					InsecureSkipVerify: true,
				}},
			})
			if err != nil {
				t.Fatal(E.Cause(err, "create DTLS0.9 HelloVerify client"))
			}
			t.Cleanup(func() {
				closeErr := client.Close()
				if closeErr != nil && !E.IsClosed(closeErr) {
					t.Error(E.Cause(closeErr, "cleanup DTLS0.9 HelloVerify client"))
				}
			})
			err = client.Start()
			if err != nil {
				t.Fatal(E.Cause(err, "start DTLS0.9 HelloVerify client"))
			}
			select {
			case <-ctx.Done():
				t.Fatal(E.Cause(ctx.Err(), "wait for DTLS0.9 HelloVerify CSTP negotiation"))
			case peerErr := <-peer.failures:
				t.Fatal(peerErr)
			case <-peer.cstpStarted:
			}
			waitForM1DTLS09OracleLog(t, ctx, peer, m1DTLS09HandshakeComplete)
			for !client.Ready() {
				select {
				case <-ctx.Done():
					t.Fatal(E.Cause(ctx.Err(), "wait for DTLS0.9 HelloVerify channel"))
				case peerErr := <-peer.failures:
					t.Fatal(peerErr)
				case <-time.After(10 * time.Millisecond):
				}
			}
			err = client.WriteDataPacket([]byte("dtls09-client-data"))
			if err != nil {
				t.Fatal(E.Cause(err, "write DTLS0.9 application DATA"))
			}
			readContext, cancelRead := context.WithTimeout(ctx, 10*time.Second)
			payload, err := client.ReadDataPacket(readContext)
			cancelRead()
			if err != nil {
				t.Fatal(E.Cause(err, "read DTLS0.9 application DATA"))
			}
			if string(payload) != "dtls09-server-data" {
				t.Fatalf("unexpected DTLS0.9 server DATA: %q", payload)
			}
			oracleLogs := waitForM1DTLS09OracleLog(t, ctx, peer, m1DTLS09DataComplete)
			if peer.cstpDataPackets.Load() != 0 {
				t.Fatalf("DTLS0.9 application DATA fell back to CSTP: %d packets", peer.cstpDataPackets.Load())
			}
			udpDials, udpDestinations := dialer.snapshot()
			if udpDials == 0 || uint64(len(udpDestinations)) != udpDials {
				t.Fatalf("unexpected DTLS0.9 UDP path attempts: dials=%d destinations=%v", udpDials, udpDestinations)
			}
			for _, destination := range udpDestinations[1:] {
				if destination != udpDestinations[0] {
					t.Fatalf("DTLS0.9 retry changed negotiated UDP destination: %v", udpDestinations)
				}
			}
			peer.containerAccess.Lock()
			udpAddress := peer.udpAddress
			peer.containerAccess.Unlock()
			pathPosition := strings.Index(oracleLogs, m1DTLS09DataComplete)
			pathLine := oracleLogs[pathPosition:]
			if newlinePosition := strings.IndexByte(pathLine, '\n'); newlinePosition >= 0 {
				pathLine = pathLine[:newlinePosition]
			}
			t.Log("verified real DTLS0.9 packet path: client negotiation " + udpDestinations[0].String() + " -> host " + udpAddress + " -> oracle " + pathLine)
			closeErr := client.Close()
			if closeErr != nil && !E.IsClosed(closeErr) {
				t.Fatal(E.Cause(closeErr, "close DTLS0.9 HelloVerify client"))
			}
			select {
			case <-ctx.Done():
				t.Fatal(E.Cause(ctx.Err(), "wait for DTLS0.9 HelloVerify CSTP close"))
			case peerErr := <-peer.failures:
				t.Fatal(peerErr)
			case cstpErr := <-peer.cstpClosed:
				if cstpErr != nil {
					t.Fatal(cstpErr)
				}
			}
			stopConnection, err := net.DialTimeout("udp", udpAddress, time.Second)
			if err != nil {
				t.Fatal(E.Cause(err, "connect DTLS0.9 HelloVerify oracle shutdown path"))
			}
			_, err = stopConnection.Write([]byte("DTLS09_STOP"))
			closeStopErr := stopConnection.Close()
			if err != nil {
				t.Fatal(E.Cause(err, "write DTLS0.9 HelloVerify oracle shutdown marker"))
			}
			if closeStopErr != nil {
				t.Fatal(E.Cause(closeStopErr, "close DTLS0.9 HelloVerify oracle shutdown path"))
			}
			waitOutput, err := dockerOutput(ctx, "wait", peer.containerName)
			if err != nil {
				t.Fatal(E.Cause(err, "wait for DTLS0.9 HelloVerify oracle exit"))
			}
			if strings.TrimSpace(waitOutput) != "0" {
				t.Fatalf("DTLS0.9 HelloVerify oracle exited with status %s", strings.TrimSpace(waitOutput))
			}
		})
	}
}

func (p *m1DTLS09HelloVerifyPeer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		p.fail(writer, E.Cause(err, "read DTLS0.9 HelloVerify control request"))
		return
	}
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/" && strings.Contains(string(body), `type="init"`):
		http.SetCookie(writer, &http.Cookie{Name: "webvpn", Value: m1DTLS09SessionCookie, Path: "/", Secure: true})
		writer.Header().Set("Content-Type", "application/xml")
		_, err = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>`+m1DTLS09SessionCookie+`</session-token><auth id="success" />
</config-auth>`)
		if err != nil {
			p.recordFailure(E.Cause(err, "write DTLS0.9 HelloVerify authentication response"))
		}
	case request.Method == http.MethodConnect:
		p.serveCSTP(writer, request)
	default:
		p.fail(writer, E.New("DTLS0.9 HelloVerify peer received unexpected request: ", request.Method, " ", request.URL.Path))
	}
}

func (p *m1DTLS09HelloVerifyPeer) serveCSTP(writer http.ResponseWriter, request *http.Request) {
	if request.RequestURI != "/CSCOSSLC/tunnel" || request.Header.Get("Cookie") != "webvpn="+m1DTLS09SessionCookie {
		p.fail(writer, E.New("DTLS0.9 HelloVerify peer received invalid CSTP CONNECT"))
		return
	}
	masterSecretHex := request.Header.Get("X-DTLS-Master-Secret")
	masterSecret, err := hex.DecodeString(masterSecretHex)
	if err != nil || len(masterSecret) != 48 {
		p.fail(writer, E.New("DTLS0.9 HelloVerify peer received invalid X-DTLS-Master-Secret"))
		return
	}
	cipherOffered := false
	for _, cipherSuite := range strings.Split(request.Header.Get("X-DTLS-CipherSuite"), ":") {
		if cipherSuite == p.cipherSuite {
			cipherOffered = true
			break
		}
	}
	if !cipherOffered {
		p.fail(writer, E.New("DTLS0.9 HelloVerify client did not offer ", p.cipherSuite))
		return
	}
	dtlsPort, err := p.startOracle(strings.ToLower(masterSecretHex))
	if err != nil {
		p.fail(writer, err)
		return
	}
	hijacker, supported := writer.(http.Hijacker)
	if !supported {
		p.fail(writer, E.New("DTLS0.9 HelloVerify response writer cannot hijack CSTP"))
		return
	}
	connection, readWriter, err := hijacker.Hijack()
	if err != nil {
		p.recordFailure(E.Cause(err, "hijack DTLS0.9 HelloVerify CSTP connection"))
		return
	}
	defer connection.Close()
	_, err = readWriter.WriteString("HTTP/1.1 200 CONNECTED\r\n" +
		"X-CSTP-MTU: 576\r\n" +
		"X-CSTP-Address: 192.0.2.90\r\n" +
		"X-CSTP-Netmask: 255.255.255.0\r\n" +
		"X-CSTP-DPD: 30\r\n" +
		"X-CSTP-Keepalive: 30\r\n" +
		"X-CSTP-Rekey-Method: none\r\n" +
		"X-DTLS-MTU: 576\r\n" +
		"X-DTLS-Port: " + strconv.Itoa(dtlsPort) + "\r\n" +
		"X-DTLS-DPD: 30\r\n" +
		"X-DTLS-Keepalive: 30\r\n" +
		"X-DTLS-Session-ID: " + strings.ToUpper(hex.EncodeToString(p.sessionID)) + "\r\n" +
		"X-DTLS-CipherSuite: " + p.cipherSuite + "\r\n\r\n")
	if err == nil {
		err = readWriter.Flush()
	}
	if err != nil {
		p.recordFailure(E.Cause(err, "write DTLS0.9 HelloVerify CSTP response"))
		p.cstpClosed <- err
		return
	}
	p.cstpStarted <- struct{}{}
	for {
		packetType, payload, readErr := readM1CSTPWireRecord(readWriter)
		if readErr != nil {
			if E.IsClosed(readErr) || p.ctx.Err() != nil {
				p.cstpClosed <- nil
				return
			}
			readErr = E.Cause(readErr, "read DTLS0.9 HelloVerify CSTP record")
			p.recordFailure(readErr)
			p.cstpClosed <- readErr
			return
		}
		switch packetType {
		case anyConnectPacketData:
			p.cstpDataPackets.Add(1)
			dataErr := E.New("DTLS0.9 DATA crossed CSTP instead of the UDP oracle: ", payload)
			p.recordFailure(dataErr)
		case anyConnectPacketDPDRequest:
			writeErr := writeM1CSTPWireRecord(readWriter, anyConnectPacketDPDResponse, nil)
			if writeErr != nil {
				p.recordFailure(writeErr)
				p.cstpClosed <- writeErr
				return
			}
		case 5:
			if string(payload) != "\xb0Client disconnect" {
				closeErr := E.New("DTLS0.9 HelloVerify peer received invalid CSTP close: ", payload)
				p.recordFailure(closeErr)
				p.cstpClosed <- closeErr
				return
			}
			p.cstpClosed <- nil
			return
		}
	}
}

func (p *m1DTLS09HelloVerifyPeer) startOracle(masterSecretHex string) (int, error) {
	_, err := dockerOutput(
		p.ctx,
		"run", "--detach", "--name", p.containerName,
		"--publish", "127.0.0.1::4433/udp",
		m1DTLS09HelloVerifyImage,
		hex.EncodeToString(p.sessionID), masterSecretHex, p.cipherSuite,
	)
	if err != nil {
		return 0, err
	}
	p.containerAccess.Lock()
	p.containerStarted = true
	p.containerAccess.Unlock()
	readyDeadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(readyDeadline) {
		logs, logsErr := dockerOutput(p.ctx, "logs", p.containerName)
		if logsErr == nil && strings.Contains(logs, m1DTLS09OracleReady) {
			break
		}
		if logsErr == nil && strings.Contains(logs, "DTLS09_ERROR") {
			return 0, E.New("DTLS0.9 HelloVerify oracle failed during startup: ", logs)
		}
		select {
		case <-p.ctx.Done():
			return 0, p.ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	logs, err := dockerOutput(p.ctx, "logs", p.containerName)
	if err != nil {
		return 0, err
	}
	if !strings.Contains(logs, m1DTLS09OracleReady) {
		return 0, E.New("DTLS0.9 HelloVerify oracle did not become ready: ", logs)
	}
	portOutput, err := dockerOutput(p.ctx, "port", p.containerName, "4433/udp")
	if err != nil {
		return 0, err
	}
	udpAddress := strings.TrimSpace(portOutput)
	_, portText, err := net.SplitHostPort(udpAddress)
	if err != nil {
		return 0, E.Cause(err, "parse DTLS0.9 HelloVerify Docker UDP address: ", udpAddress)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return 0, E.Cause(err, "parse DTLS0.9 HelloVerify Docker UDP port")
	}
	p.containerAccess.Lock()
	p.udpAddress = udpAddress
	p.containerAccess.Unlock()
	p.dialer.setUDPTarget(M.ParseSocksaddr(udpAddress))
	return int(port), nil
}

func waitForM1DTLS09OracleLog(
	t *testing.T,
	ctx context.Context,
	peer *m1DTLS09HelloVerifyPeer,
	marker string,
) string {
	t.Helper()
	for {
		logs, err := dockerOutput(ctx, "logs", peer.containerName)
		if err == nil && strings.Contains(logs, marker) {
			return logs
		}
		if err == nil && strings.Contains(logs, "DTLS09_ERROR") {
			t.Fatal(E.New("DTLS0.9 HelloVerify oracle failed: ", logs))
		}
		select {
		case <-ctx.Done():
			if err != nil {
				t.Fatal(E.Errors(E.Cause(ctx.Err(), "wait for DTLS0.9 HelloVerify oracle marker ", marker), err))
			}
			t.Fatal(E.Cause(ctx.Err(), "wait for DTLS0.9 HelloVerify oracle marker ", marker, ": ", logs))
		case peerErr := <-peer.failures:
			t.Fatal(peerErr)
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (p *m1DTLS09HelloVerifyPeer) fail(writer http.ResponseWriter, err error) {
	p.recordFailure(err)
	http.Error(writer, err.Error(), http.StatusBadRequest)
}

func (p *m1DTLS09HelloVerifyPeer) recordFailure(err error) {
	select {
	case p.failures <- err:
	default:
	}
}

func (d *m1DTLS09HelloVerifyDialer) setUDPTarget(target M.Socksaddr) {
	d.access.Lock()
	d.udpTarget = target
	d.access.Unlock()
}

func (d *m1DTLS09HelloVerifyDialer) snapshot() (uint64, []M.Socksaddr) {
	d.access.RLock()
	destinations := append([]M.Socksaddr(nil), d.udpDestinations...)
	d.access.RUnlock()
	return d.udpDials.Load(), destinations
}

func (d *m1DTLS09HelloVerifyDialer) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	if network != N.NetworkUDP {
		return N.SystemDialer.DialContext(ctx, network, destination)
	}
	d.access.Lock()
	target := d.udpTarget
	d.udpDestinations = append(d.udpDestinations, destination)
	d.access.Unlock()
	if target.Port == 0 {
		return nil, E.New("DTLS0.9 HelloVerify UDP oracle target is not ready")
	}
	d.udpDials.Add(1)
	return N.SystemDialer.DialContext(ctx, network, target)
}

func (d *m1DTLS09HelloVerifyDialer) ListenPacket(
	ctx context.Context,
	destination M.Socksaddr,
) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

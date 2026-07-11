package openconnect

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const certificateDTLSTestServerName = "vpn.dtls.test"

type certificateDTLSTestPKI struct {
	caPath            string
	serverCertPath    string
	serverKeyPath     string
	ecdsaCertPath     string
	ecdsaKeyPath      string
	caSubject         []byte
	rootCAs           *x509.CertPool
	clientCertificate tls.Certificate
}

type certificateDTLSTestSigner struct {
	crypto.Signer
}

type certificateDTLSTestPeerOutput struct {
	access    sync.Mutex
	buffer    bytes.Buffer
	listening chan struct{}
	once      sync.Once
}

type certificateDTLSTestDialer struct {
	maximumWrite                atomic.Uint64
	fragmentedClientCertificate atomic.Bool
	remainingDrops              atomic.Int64
	droppedWrites               atomic.Uint64
	dropFinalFlight             atomic.Bool
	droppingFinalFlight         atomic.Bool
	droppedFinalFlightDatagrams atomic.Uint64
}

type certificateDTLSTestConn struct {
	net.Conn
	observer *certificateDTLSTestDialer
}

type certificateDTLSTestVersionRelay struct {
	listener      *net.UDPConn
	legacyAddress *net.UDPAddr
	modernAddress *net.UDPAddr
	access        sync.Mutex
	backend       *net.UDPConn
	clientAddress *net.UDPAddr
	legacy        bool
	legacyPackets atomic.Uint64
	modernPackets atomic.Uint64
	waitGroup     sync.WaitGroup
	closeOnce     sync.Once
}

func (d *certificateDTLSTestDialer) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	conn, err := N.SystemDialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return &certificateDTLSTestConn{Conn: conn, observer: d}, nil
}

func (d *certificateDTLSTestDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

func (c *certificateDTLSTestConn) Write(payload []byte) (int, error) {
	for {
		maximum := c.observer.maximumWrite.Load()
		if uint64(len(payload)) <= maximum || c.observer.maximumWrite.CompareAndSwap(maximum, uint64(len(payload))) {
			break
		}
	}
	clientCertificateFragment := len(payload) >= 25 && payload[0] == legacyDTLSContentHandshake &&
		binary.BigEndian.Uint16(payload[1:3]) == certificateDTLSVersion10 &&
		binary.BigEndian.Uint16(payload[3:5]) == 0 && payload[13] == certificateDTLSHandshakeCertificate
	if clientCertificateFragment && readUint24(payload[19:22]) > 0 {
		c.observer.fragmentedClientCertificate.Store(true)
	}
	if clientCertificateFragment && readUint24(payload[19:22]) == 0 && c.observer.dropFinalFlight.CompareAndSwap(true, false) {
		c.observer.droppingFinalFlight.Store(true)
	}
	if c.observer.droppingFinalFlight.Load() {
		c.observer.droppedFinalFlightDatagrams.Add(1)
		if len(payload) >= 5 && payload[0] == legacyDTLSContentHandshake && binary.BigEndian.Uint16(payload[3:5]) == 1 {
			c.observer.droppingFinalFlight.Store(false)
		}
		return len(payload), nil
	}
	for {
		remaining := c.observer.remainingDrops.Load()
		if remaining <= 0 {
			break
		}
		if c.observer.remainingDrops.CompareAndSwap(remaining, remaining-1) {
			c.observer.droppedWrites.Add(1)
			return len(payload), nil
		}
	}
	return c.Conn.Write(payload)
}

func startCertificateDTLSTestVersionRelay(
	t *testing.T,
	legacyPort int,
	modernPort int,
) *certificateDTLSTestVersionRelay {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(E.Cause(err, "start certificate DTLS version relay"))
	}
	relay := &certificateDTLSTestVersionRelay{
		listener:      listener,
		legacyAddress: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: legacyPort},
		modernAddress: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: modernPort},
	}
	relay.waitGroup.Add(1)
	go relay.clientLoop()
	t.Cleanup(func() { _ = relay.Close() })
	return relay
}

func (r *certificateDTLSTestVersionRelay) Address() string {
	return r.listener.LocalAddr().String()
}

func (r *certificateDTLSTestVersionRelay) clientLoop() {
	defer r.waitGroup.Done()
	buffer := make([]byte, 64*1024)
	for {
		n, clientAddress, err := r.listener.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		r.access.Lock()
		if r.backend == nil {
			if n < 27 || buffer[0] != legacyDTLSContentHandshake || buffer[13] != certificateDTLSHandshakeClientHello {
				r.access.Unlock()
				continue
			}
			version := binary.BigEndian.Uint16(buffer[25:27])
			target := r.modernAddress
			if version == certificateDTLSVersion10 {
				r.legacy = true
				target = r.legacyAddress
			}
			backend, dialErr := net.DialUDP("udp4", nil, target)
			if dialErr != nil {
				r.access.Unlock()
				return
			}
			r.backend = backend
			r.clientAddress = clientAddress
			r.waitGroup.Add(1)
			go r.backendLoop(backend)
		}
		backend := r.backend
		legacy := r.legacy
		r.access.Unlock()
		if legacy {
			r.legacyPackets.Add(1)
		} else {
			r.modernPackets.Add(1)
		}
		_, err = backend.Write(buffer[:n])
		if err != nil {
			return
		}
	}
}

func (r *certificateDTLSTestVersionRelay) backendLoop(backend *net.UDPConn) {
	defer r.waitGroup.Done()
	buffer := make([]byte, 64*1024)
	for {
		n, err := backend.Read(buffer)
		if err != nil {
			return
		}
		r.access.Lock()
		clientAddress := r.clientAddress
		r.access.Unlock()
		_, err = r.listener.WriteToUDP(buffer[:n], clientAddress)
		if err != nil {
			return
		}
	}
}

func (r *certificateDTLSTestVersionRelay) Close() error {
	var closeErr error
	r.closeOnce.Do(func() {
		listenerErr := r.listener.Close()
		r.access.Lock()
		backend := r.backend
		r.access.Unlock()
		var backendErr error
		if backend != nil {
			backendErr = backend.Close()
		}
		closeErr = E.Errors(listenerErr, backendErr)
		r.waitGroup.Wait()
	})
	return closeErr
}

func newCertificateDTLSTestPeerOutput() *certificateDTLSTestPeerOutput {
	return &certificateDTLSTestPeerOutput{listening: make(chan struct{})}
}

func (o *certificateDTLSTestPeerOutput) Write(content []byte) (int, error) {
	o.access.Lock()
	n, err := o.buffer.Write(content)
	listening := strings.Contains(o.buffer.String(), "LISTENING")
	o.access.Unlock()
	if listening {
		o.once.Do(func() { close(o.listening) })
	}
	return n, err
}

func (o *certificateDTLSTestPeerOutput) String() string {
	o.access.Lock()
	defer o.access.Unlock()
	return o.buffer.String()
}

func TestCertificateDTLSOpenSSLInterop(t *testing.T) {
	if os.Getenv("OPENCONNECT_IT") != "1" {
		t.Skip("set OPENCONNECT_IT=1 to run the OpenSSL certificate DTLS peer")
	}
	t.Parallel()
	peerPath := buildCertificateDTLSTestPeer(t)
	pki := buildCertificateDTLSTestPKI(t)
	for _, testCase := range []struct {
		name                 string
		version              string
		cipher               string
		cipherSuite          uint16
		legacy               bool
		requireClient        bool
		expectedVersion      uint16
		expectedPeerCertText string
		dropFirstWrite       bool
		dropFinalFlight      bool
		curvePreferences     []tls.CurveID
		serverGroups         string
		defaultCipherSuites  bool
		ecdsaServer          bool
	}{
		{
			name:                 "dtls12-ecdhe-rsa-gcm-mutual-certificate",
			version:              "1.2",
			cipher:               "ECDHE-RSA-AES128-GCM-SHA256",
			cipherSuite:          tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			requireClient:        true,
			expectedVersion:      certificateDTLSVersion12,
			expectedPeerCertText: "peer-cert=1",
			dropFirstWrite:       true,
		},
		{
			name:                 "dtls12-ecdhe-ecdsa-gcm-server-certificate",
			version:              "1.2",
			cipher:               "ECDHE-ECDSA-AES128-GCM-SHA256",
			cipherSuite:          tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			expectedVersion:      certificateDTLSVersion12,
			expectedPeerCertText: "peer-cert=0",
			ecdsaServer:          true,
		},
		{
			name:                 "dtls12-ecdhe-ecdsa-aes256-cbc-server-certificate",
			version:              "1.2",
			cipher:               "ECDHE-ECDSA-AES256-SHA",
			cipherSuite:          tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			expectedVersion:      certificateDTLSVersion12,
			expectedPeerCertText: "peer-cert=0",
			ecdsaServer:          true,
		},
		{
			name:                 "dtls12-ecdhe-rsa-aes256-cbc-default-policy",
			version:              "1.2",
			cipher:               "ECDHE-RSA-AES256-SHA",
			cipherSuite:          tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			expectedVersion:      certificateDTLSVersion12,
			expectedPeerCertText: "peer-cert=0",
			defaultCipherSuites:  true,
		},
		{
			name:                 "dtls10-ecdhe-rsa-cbc-server-certificate",
			version:              "1.0",
			cipher:               "ECDHE-RSA-AES128-SHA",
			cipherSuite:          tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			legacy:               true,
			requireClient:        true,
			expectedVersion:      certificateDTLSVersion10,
			expectedPeerCertText: "peer-cert=1",
			dropFinalFlight:      true,
		},
		{
			name:                 "dtls10-ecdhe-rsa-aes256-cbc-server-certificate",
			version:              "1.0",
			cipher:               "ECDHE-RSA-AES256-SHA",
			cipherSuite:          tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			legacy:               true,
			expectedVersion:      certificateDTLSVersion10,
			expectedPeerCertText: "peer-cert=0",
			dropFirstWrite:       true,
			curvePreferences:     []tls.CurveID{tls.CurveP384},
			serverGroups:         "P-384",
		},
		{
			name:                 "dtls10-rsa-aes128-cbc-server-certificate",
			version:              "1.0",
			cipher:               "AES128-SHA",
			cipherSuite:          tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			legacy:               true,
			expectedVersion:      certificateDTLSVersion10,
			expectedPeerCertText: "peer-cert=0",
		},
		{
			name:                 "dtls10-ecdhe-rsa-aes128-cbc-p521-server-certificate",
			version:              "1.0",
			cipher:               "ECDHE-RSA-AES128-SHA",
			cipherSuite:          tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			legacy:               true,
			expectedVersion:      certificateDTLSVersion10,
			expectedPeerCertText: "peer-cert=0",
			curvePreferences:     []tls.CurveID{tls.CurveP521},
			serverGroups:         "P-521",
		},
		{
			name:                 "dtls10-rsa-aes256-cbc-server-certificate",
			version:              "1.0",
			cipher:               "AES256-SHA",
			cipherSuite:          tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			legacy:               true,
			expectedVersion:      certificateDTLSVersion10,
			expectedPeerCertText: "peer-cert=0",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			runCertificateDTLSInterop(t, peerPath, pki, testCase.version, testCase.cipher, testCase.cipherSuite,
				testCase.legacy, testCase.requireClient, testCase.expectedVersion, testCase.expectedPeerCertText,
				testCase.dropFirstWrite, testCase.dropFinalFlight, testCase.curvePreferences, testCase.serverGroups,
				testCase.defaultCipherSuites, testCase.ecdsaServer)
		})
	}
}

func TestCertificateDTLSOpenSSLNoSharedCipher(t *testing.T) {
	if os.Getenv("OPENCONNECT_IT") != "1" {
		t.Skip("set OPENCONNECT_IT=1 to run the OpenSSL certificate DTLS peer")
	}
	t.Parallel()
	peerPath := buildCertificateDTLSTestPeer(t)
	pki := buildCertificateDTLSTestPKI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	port := reserveCertificateDTLSTestPort(t)
	command, output := startCertificateDTLSTestPeer(
		t,
		ctx,
		peerPath,
		pki,
		port,
		"1.2",
		"ECDHE-RSA-AES128-GCM-SHA256",
		false,
		false,
		"",
	)
	_, err := connectCertificateDTLS(ctx, certificateDTLSNegotiation{
		Address:    net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		ServerName: certificateDTLSTestServerName,
		TLSConfig: &tls.Config{
			RootCAs:      pki.rootCAs,
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		},
		MTU: 1200,
	})
	if err == nil {
		t.Fatal("certificate DTLS unexpectedly negotiated without a shared cipher")
	}
	waitErr := command.Wait()
	if waitErr == nil {
		t.Fatalf("OpenSSL peer unexpectedly accepted cipher mismatch: %s", output.String())
	}
}

func TestCertificateDTLSOpenSSLNoSharedLegacyCurve(t *testing.T) {
	if os.Getenv("OPENCONNECT_IT") != "1" {
		t.Skip("set OPENCONNECT_IT=1 to run the OpenSSL certificate DTLS peer")
	}
	t.Parallel()
	peerPath := buildCertificateDTLSTestPeer(t)
	pki := buildCertificateDTLSTestPKI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	port := reserveCertificateDTLSTestPort(t)
	command, output := startCertificateDTLSTestPeer(
		t,
		ctx,
		peerPath,
		pki,
		port,
		"1.0",
		"ECDHE-RSA-AES256-SHA",
		false,
		false,
		"P-256",
	)
	_, err := connectCertificateDTLS(ctx, certificateDTLSNegotiation{
		Address:    net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		ServerName: certificateDTLSTestServerName,
		TLSConfig: &tls.Config{
			RootCAs:          pki.rootCAs,
			CipherSuites:     []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA},
			CurvePreferences: []tls.CurveID{tls.CurveP384},
		},
		MTU:               1200,
		LegacyVersion:     true,
		AllowLegacyCrypto: true,
	})
	if err == nil {
		t.Fatal("legacy certificate DTLS unexpectedly negotiated without a shared curve")
	}
	waitErr := command.Wait()
	if waitErr == nil {
		t.Fatalf("OpenSSL peer unexpectedly accepted legacy curve mismatch: %s", output.String())
	}
}

func TestCertificateDTLSOpenSSLRejectsUntrustedCertificate(t *testing.T) {
	if os.Getenv("OPENCONNECT_IT") != "1" {
		t.Skip("set OPENCONNECT_IT=1 to run the OpenSSL certificate DTLS peer")
	}
	t.Parallel()
	peerPath := buildCertificateDTLSTestPeer(t)
	pki := buildCertificateDTLSTestPKI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	port := reserveCertificateDTLSTestPort(t)
	command, output := startCertificateDTLSTestPeer(
		t,
		ctx,
		peerPath,
		pki,
		port,
		"1.2",
		"ECDHE-RSA-AES128-GCM-SHA256",
		false,
		false,
		"",
	)
	_, err := connectCertificateDTLS(ctx, certificateDTLSNegotiation{
		Address:    net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		ServerName: certificateDTLSTestServerName,
		TLSConfig: &tls.Config{
			RootCAs:      x509.NewCertPool(),
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		},
		MTU: 1200,
	})
	if err == nil {
		t.Fatal("certificate DTLS unexpectedly trusted the unrecognized OpenSSL certificate")
	}
	_, unknownAuthority := E.Cast[x509.UnknownAuthorityError](err)
	if !unknownAuthority {
		t.Fatalf("certificate DTLS did not retain the trust failure: %v", err)
	}
	waitErr := command.Wait()
	if waitErr == nil {
		t.Fatalf("OpenSSL peer unexpectedly completed an untrusted handshake: %s", output.String())
	}
}

func TestCertificateDTLSLegacyVersionSentinel(t *testing.T) {
	if os.Getenv("OPENCONNECT_IT") != "1" {
		t.Skip("set OPENCONNECT_IT=1 to run the OpenSSL certificate DTLS peer")
	}
	t.Parallel()
	peerPath := buildCertificateDTLSTestPeer(t)
	pki := buildCertificateDTLSTestPKI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	legacyPort := reserveCertificateDTLSTestPort(t)
	modernPort := reserveCertificateDTLSTestPort(t)
	legacyCommand, legacyOutput := startCertificateDTLSTestPeer(
		t, ctx, peerPath, pki, legacyPort, "1.0", "ECDHE-RSA-AES128-SHA", false, false, "",
	)
	modernCommand, modernOutput := startCertificateDTLSTestPeer(
		t, ctx, peerPath, pki, modernPort, "1.2", "ECDHE-RSA-AES128-GCM-SHA256", false, false, "",
	)
	relay := startCertificateDTLSTestVersionRelay(t, legacyPort, modernPort)
	conn, err := connectCertificateDTLS(ctx, certificateDTLSNegotiation{
		Address:    relay.Address(),
		ServerName: certificateDTLSTestServerName,
		TLSConfig: &tls.Config{
			RootCAs:      pki.rootCAs,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		},
		MTU:               1200,
		LegacyVersion:     true,
		AllowLegacyCrypto: true,
	})
	if err != nil {
		t.Fatal(E.Cause(err, "connect through certificate DTLS legacy version sentinel"))
	}
	payload := certificateDTLSTestPayload(conn.DataMTU())
	n, err := conn.Write(payload)
	if err != nil {
		_ = conn.Close()
		t.Fatal(E.Cause(err, "write through certificate DTLS legacy version sentinel"))
	}
	if n != len(payload) {
		_ = conn.Close()
		t.Fatalf("short certificate DTLS sentinel write: %d of %d", n, len(payload))
	}
	err = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		_ = conn.Close()
		t.Fatal(E.Cause(err, "set certificate DTLS sentinel read deadline"))
	}
	response := make([]byte, 2048)
	n, err = conn.Read(response)
	if err != nil || !equalBytes(response[:n], payload) {
		_ = conn.Close()
		if err != nil {
			_ = legacyCommand.Wait()
			t.Fatal(E.Cause(err, "read through certificate DTLS legacy version sentinel: ", legacyOutput.String()))
		}
		t.Fatalf("unexpected certificate DTLS sentinel response: %q", response[:n])
	}
	err = conn.Close()
	if err != nil {
		t.Fatal(E.Cause(err, "close certificate DTLS legacy version sentinel connection"))
	}
	err = legacyCommand.Wait()
	if err != nil {
		t.Fatal(E.Cause(err, "wait for certificate DTLS legacy sentinel peer: ", legacyOutput.String()))
	}
	err = relay.Close()
	if err != nil && !E.IsClosed(err) {
		t.Fatal(E.Cause(err, "close certificate DTLS version relay"))
	}
	_ = modernCommand.Process.Kill()
	_ = modernCommand.Wait()
	if relay.legacyPackets.Load() == 0 || relay.modernPackets.Load() != 0 {
		t.Fatalf("certificate DTLS version sentinel routed legacy=%d modern=%d packets",
			relay.legacyPackets.Load(), relay.modernPackets.Load())
	}
	if !strings.Contains(legacyOutput.String(), "READY version=DTLSv1") ||
		!strings.Contains(legacyOutput.String(), "CLOSED") ||
		!strings.Contains(modernOutput.String(), "LISTENING") || strings.Contains(modernOutput.String(), "READY") {
		t.Fatalf("certificate DTLS version sentinels observed unexpected state: legacy=%s modern=%s",
			legacyOutput.String(), modernOutput.String())
	}
}

func TestAnyConnectDTLS12CBCOpenSSLInjectedResumeInterop(t *testing.T) {
	if os.Getenv("OPENCONNECT_IT") != "1" {
		t.Skip("set OPENCONNECT_IT=1 to run the OpenSSL injected DTLS peer")
	}
	t.Parallel()
	peerPath := buildCertificateDTLSResumeTestPeer(t)
	for _, testCase := range []struct {
		name   string
		cipher string
	}{
		{name: "rsa-aes128-cbc", cipher: "AES128-SHA"},
		{name: "rsa-aes256-cbc", cipher: "AES256-SHA"},
		{name: "dhe-rsa-aes128-cbc", cipher: "DHE-RSA-AES128-SHA"},
		{name: "dhe-rsa-aes256-cbc", cipher: "DHE-RSA-AES256-SHA"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			t.Cleanup(cancel)
			port := reserveCertificateDTLSTestPort(t)
			sessionID := make([]byte, 32)
			masterSecret := make([]byte, 48)
			_, err := rand.Read(sessionID)
			if err != nil {
				t.Fatal(E.Cause(err, "generate OpenSSL injected DTLS session ID"))
			}
			_, err = rand.Read(masterSecret)
			if err != nil {
				t.Fatal(E.Cause(err, "generate OpenSSL injected DTLS master secret"))
			}
			t.Cleanup(func() {
				clear(sessionID)
				clear(masterSecret)
			})
			command, output := startCertificateDTLSResumeTestPeer(
				t, ctx, peerPath, port, testCase.cipher, sessionID, masterSecret,
			)
			channel := newAnyConnectDTLS(ctx, cstpDTLSNegotiation{
				Address:      net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
				CipherSuite:  testCase.cipher,
				DTLS12:       true,
				SessionID:    append([]byte(nil), sessionID...),
				MasterSecret: append([]byte(nil), masterSecret...),
			}, nil)
			conn, err := channel.connect()
			if err != nil {
				_ = command.Process.Kill()
				_ = command.Wait()
				t.Fatal(E.Cause(err, "connect OpenSSL injected DTLS peer: ", output.String()))
			}
			payload := certificateDTLSTestPayload(1000)
			n, err := conn.Write(payload)
			if err != nil {
				_ = conn.Close()
				_ = command.Wait()
				t.Fatal(E.Cause(err, "write OpenSSL injected DTLS application data"))
			}
			if n != len(payload) {
				_ = conn.Close()
				_ = command.Wait()
				t.Fatalf("short OpenSSL injected DTLS write: %d of %d", n, len(payload))
			}
			err = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			if err != nil {
				_ = conn.Close()
				_ = command.Wait()
				t.Fatal(E.Cause(err, "set OpenSSL injected DTLS read deadline"))
			}
			response := make([]byte, len(payload)+32)
			n, err = conn.Read(response)
			if err != nil {
				_ = conn.Close()
				_ = command.Wait()
				t.Fatal(E.Cause(err, "read OpenSSL injected DTLS application data"))
			}
			if !equalBytes(response[:n], payload) {
				_ = conn.Close()
				_ = command.Wait()
				t.Fatal("OpenSSL injected DTLS peer did not echo the complete CBC record")
			}
			err = conn.Close()
			if err != nil {
				_ = command.Wait()
				t.Fatal(E.Cause(err, "close OpenSSL injected DTLS connection"))
			}
			err = command.Wait()
			if err != nil {
				t.Fatal(E.Cause(err, "wait for OpenSSL injected DTLS peer: ", output.String()))
			}
			if !strings.Contains(output.String(), "READY version=DTLSv1.2") ||
				!strings.Contains(output.String(), "cipher="+testCase.cipher) ||
				!strings.Contains(output.String(), "resumed=1") || !strings.Contains(output.String(), "CLOSED") {
				t.Fatalf("OpenSSL did not observe the complete injected DTLS CBC exchange: %s", output.String())
			}
		})
	}
}

func runCertificateDTLSInterop(
	t *testing.T,
	peerPath string,
	pki certificateDTLSTestPKI,
	version string,
	cipher string,
	cipherSuite uint16,
	legacy bool,
	requireClient bool,
	expectedVersion uint16,
	expectedPeerCertText string,
	dropFirstWrite bool,
	dropFinalFlight bool,
	curvePreferences []tls.CurveID,
	serverGroups string,
	defaultCipherSuites bool,
	ecdsaServer bool,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	port := reserveCertificateDTLSTestPort(t)
	command, output := startCertificateDTLSTestPeer(
		t, ctx, peerPath, pki, port, version, cipher, requireClient, ecdsaServer, serverGroups,
	)
	var peerVerificationCalls atomic.Uint64
	var connectionVerificationCalls atomic.Uint64
	var timeCalls atomic.Uint64
	var clientCertificateCalls atomic.Uint64
	tlsConfig := &tls.Config{
		RootCAs:          pki.rootCAs,
		CurvePreferences: append([]tls.CurveID(nil), curvePreferences...),
		Time: func() time.Time {
			timeCalls.Add(1)
			return time.Now()
		},
		VerifyPeerCertificate: func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(verifiedChains) != 1 || len(verifiedChains[0]) != 2 {
				return E.New("OpenSSL certificate DTLS peer did not produce the expected verified chain")
			}
			peerVerificationCalls.Add(1)
			return nil
		},
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.HandshakeComplete || state.ServerName != certificateDTLSTestServerName || state.CipherSuite != cipherSuite ||
				state.NegotiatedProtocol != "" {
				return E.New("OpenSSL certificate DTLS connection state did not preserve TLS policy")
			}
			connectionVerificationCalls.Add(1)
			return nil
		},
	}
	if !defaultCipherSuites {
		tlsConfig.CipherSuites = []uint16{cipherSuite}
	}
	if requireClient {
		clientCertificate := pki.clientCertificate
		if legacy {
			clientCertificate.PrivateKey = certificateDTLSTestSigner{Signer: clientCertificate.PrivateKey.(crypto.Signer)}
		}
		expectedCallbackVersion := uint16(tls.VersionTLS12)
		var expectedSignatureSchemes []tls.SignatureScheme
		if legacy {
			expectedCallbackVersion = tls.VersionTLS11
			expectedSignatureSchemes = []tls.SignatureScheme{tls.PKCS1WithSHA1}
		}
		tlsConfig.GetClientCertificate = func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			clientCertificateCalls.Add(1)
			if request.Version != expectedCallbackVersion || !slices.Equal(request.SignatureSchemes, expectedSignatureSchemes) {
				return nil, E.New("OpenSSL certificate DTLS request did not preserve version/signature semantics")
			}
			caMatched := false
			for _, acceptableCA := range request.AcceptableCAs {
				if bytes.Equal(acceptableCA, pki.caSubject) {
					caMatched = true
					break
				}
			}
			if !caMatched {
				return nil, E.New("OpenSSL certificate DTLS request did not preserve the acceptable CA")
			}
			return &clientCertificate, nil
		}
	}
	dialer := new(certificateDTLSTestDialer)
	if dropFirstWrite {
		dialer.remainingDrops.Store(1)
	}
	if dropFinalFlight {
		dialer.dropFinalFlight.Store(true)
	}
	conn, err := connectCertificateDTLS(ctx, certificateDTLSNegotiation{
		Address:           net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		ServerName:        certificateDTLSTestServerName,
		TLSConfig:         tlsConfig,
		Dialer:            dialer,
		MTU:               1200,
		LegacyVersion:     legacy,
		AllowLegacyCrypto: legacy,
	})
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(E.Cause(err, "connect OpenSSL certificate DTLS peer: ", output.String()))
	}
	if conn.Version() != expectedVersion || conn.CipherSuite() != cipherSuite || conn.DataMTU() < 1000 {
		_ = conn.Close()
		_ = command.Wait()
		t.Fatalf("unexpected certificate DTLS capabilities: version=%04x cipher=%04x mtu=%d output=%s",
			conn.Version(), conn.CipherSuite(), conn.DataMTU(), output.String())
	}
	if peerVerificationCalls.Load() != 1 || connectionVerificationCalls.Load() != 1 || timeCalls.Load() == 0 {
		_ = conn.Close()
		_ = command.Wait()
		t.Fatalf("certificate verification policy was not preserved: peer=%d connection=%d time=%d",
			peerVerificationCalls.Load(), connectionVerificationCalls.Load(), timeCalls.Load())
	}
	if requireClient && clientCertificateCalls.Load() != 1 {
		_ = conn.Close()
		_ = command.Wait()
		t.Fatalf("certificate DTLS did not select mTLS identity exactly once: %d", clientCertificateCalls.Load())
	}
	if dialer.maximumWrite.Load() > 1200 {
		_ = conn.Close()
		_ = command.Wait()
		t.Fatalf("certificate DTLS wrote an oversized UDP datagram: %d bytes", dialer.maximumWrite.Load())
	}
	if legacy && requireClient && !dialer.fragmentedClientCertificate.Load() {
		_ = conn.Close()
		_ = command.Wait()
		t.Fatal("legacy certificate DTLS did not fragment the client certificate handshake")
	}
	if dropFirstWrite && dialer.droppedWrites.Load() != 1 {
		_ = conn.Close()
		_ = command.Wait()
		t.Fatalf("certificate DTLS did not recover from exactly one dropped handshake datagram: %d", dialer.droppedWrites.Load())
	}
	if dropFinalFlight && (dialer.droppedFinalFlightDatagrams.Load() == 0 || dialer.droppingFinalFlight.Load()) {
		_ = conn.Close()
		_ = command.Wait()
		t.Fatalf("certificate DTLS did not recover from a dropped final handshake flight: datagrams=%d active=%v",
			dialer.droppedFinalFlightDatagrams.Load(), dialer.droppingFinalFlight.Load())
	}
	oversizedPayload := certificateDTLSTestPayload(conn.DataMTU() + 1)
	n, err := conn.Write(oversizedPayload)
	if n != 0 || !E.IsMulti(err, syscall.EMSGSIZE) {
		_ = conn.Close()
		_ = command.Wait()
		t.Fatalf("certificate DTLS accepted payload above data MTU: wrote=%d error=%v", n, err)
	}
	payload := certificateDTLSTestPayload(conn.DataMTU())
	n, err = conn.Write(payload)
	if err != nil {
		_ = conn.Close()
		_ = command.Wait()
		t.Fatal(E.Cause(err, "write OpenSSL certificate DTLS application datagram"))
	}
	if n != len(payload) {
		_ = conn.Close()
		_ = command.Wait()
		t.Fatalf("short OpenSSL certificate DTLS application datagram write: %d of %d", n, len(payload))
	}
	if dialer.maximumWrite.Load() > 1200 {
		_ = conn.Close()
		_ = command.Wait()
		t.Fatalf("certificate DTLS data boundary exceeded the UDP MTU: %d bytes", dialer.maximumWrite.Load())
	}
	err = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		_ = conn.Close()
		_ = command.Wait()
		t.Fatal(E.Cause(err, "set OpenSSL certificate DTLS read deadline"))
	}
	response := make([]byte, conn.DataMTU()+1)
	n, err = conn.Read(response)
	if err != nil {
		_ = conn.Close()
		_ = command.Wait()
		t.Fatal(E.Cause(err, "read OpenSSL certificate DTLS application datagram: ", output.String()))
	}
	if !equalBytes(response[:n], payload) {
		_ = conn.Close()
		_ = command.Wait()
		t.Fatalf("unexpected OpenSSL certificate DTLS response: %q", response[:n])
	}
	if legacy {
		err = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if err != nil {
			_ = conn.Close()
			_ = command.Wait()
			t.Fatal(E.Cause(err, "set OpenSSL certificate DTLS authenticated-close deadline"))
		}
		n, err = conn.Read(response)
		if n != 0 || err != io.EOF {
			_ = conn.Close()
			_ = command.Wait()
			t.Fatalf("legacy OpenSSL certificate DTLS did not authenticate peer close_notify: read=%d error=%v", n, err)
		}
	}
	closeErr := conn.Close()
	if closeErr != nil {
		_ = command.Wait()
		t.Fatal(E.Cause(closeErr, "close OpenSSL certificate DTLS connection"))
	}
	waitErr := command.Wait()
	if waitErr != nil {
		t.Fatal(E.Cause(waitErr, "wait for OpenSSL certificate DTLS peer: ", output.String()))
	}
	peerOutput := output.String()
	peerObservedExchange := strings.Contains(peerOutput, "READY") && strings.Contains(peerOutput, "CLOSED") &&
		strings.Contains(peerOutput, "sni="+certificateDTLSTestServerName) && strings.Contains(peerOutput, expectedPeerCertText) &&
		strings.Contains(peerOutput, "data-mtu="+strconv.Itoa(conn.DataMTU()))
	expectedServerGroup := serverGroups
	switch serverGroups {
	case "P-256":
		expectedServerGroup = "prime256v1"
	case "P-384":
		expectedServerGroup = "secp384r1"
	case "P-521":
		expectedServerGroup = "secp521r1"
	}
	if expectedServerGroup != "" && !strings.Contains(peerOutput, "group="+expectedServerGroup) {
		peerObservedExchange = false
	}
	if legacy && !strings.Contains(peerOutput, "INJECTED-UNAUTHENTICATED-DATAGRAMS") {
		peerObservedExchange = false
	}
	if !peerObservedExchange {
		t.Fatalf("OpenSSL peer did not observe the complete certificate DTLS exchange: %s", peerOutput)
	}
}

func certificateDTLSTestPayload(length int) []byte {
	payload := make([]byte, length)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	return payload
}

func buildCertificateDTLSTestPeer(t *testing.T) string {
	t.Helper()
	peerPath := filepath.Join(t.TempDir(), "certificate-dtls-peer")
	flagsOutput, err := exec.Command("pkg-config", "--cflags", "--libs", "openssl").Output()
	if err != nil {
		t.Fatalf("OpenSSL development files unavailable: %v", err)
	}
	args := append([]string{
		"-Wall", "-Wextra", "-Werror", "-o", peerPath,
		filepath.Join("test", "testdata", "certificate-dtls-peer", "peer.c"),
	}, strings.Fields(string(flagsOutput))...)
	command := exec.Command("cc", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("compile OpenSSL certificate DTLS peer: %v: %s", err, output)
	}
	return peerPath
}

func buildCertificateDTLSResumeTestPeer(t *testing.T) string {
	t.Helper()
	peerPath := filepath.Join(t.TempDir(), "certificate-dtls-resume-peer")
	flagsOutput, err := exec.Command("pkg-config", "--cflags", "--libs", "openssl").Output()
	if err != nil {
		t.Fatalf("OpenSSL development files unavailable: %v", err)
	}
	args := append([]string{
		"-Wall", "-Wextra", "-Werror", "-o", peerPath,
		filepath.Join("test", "testdata", "certificate-dtls-peer", "resume_peer.c"),
	}, strings.Fields(string(flagsOutput))...)
	command := exec.Command("cc", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("compile OpenSSL injected DTLS peer: %v: %s", err, output)
	}
	return peerPath
}

func startCertificateDTLSTestPeer(
	t *testing.T,
	ctx context.Context,
	peerPath string,
	pki certificateDTLSTestPKI,
	port int,
	version string,
	cipher string,
	requireClient bool,
	ecdsaServer bool,
	groups string,
) (*exec.Cmd, *certificateDTLSTestPeerOutput) {
	t.Helper()
	requireClientText := "0"
	if requireClient {
		requireClientText = "1"
	}
	groupList := "-"
	if groups != "" {
		groupList = groups
	}
	serverCertPath := pki.serverCertPath
	serverKeyPath := pki.serverKeyPath
	if ecdsaServer {
		serverCertPath = pki.ecdsaCertPath
		serverKeyPath = pki.ecdsaKeyPath
	}
	command := exec.CommandContext(ctx, peerPath,
		strconv.Itoa(port), version, cipher, serverCertPath, serverKeyPath,
		pki.caPath, requireClientText, certificateDTLSTestServerName, groupList)
	output := newCertificateDTLSTestPeerOutput()
	command.Stdout = output
	command.Stderr = output
	err := command.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start OpenSSL certificate DTLS peer"))
	}
	select {
	case <-ctx.Done():
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(E.Cause(ctx.Err(), "wait for OpenSSL certificate DTLS peer to listen: ", output.String()))
	case <-output.listening:
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("OpenSSL certificate DTLS peer did not begin listening: " + output.String())
	}
	t.Cleanup(func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	return command, output
}

func startCertificateDTLSResumeTestPeer(
	t *testing.T,
	ctx context.Context,
	peerPath string,
	port int,
	cipher string,
	sessionID []byte,
	masterSecret []byte,
) (*exec.Cmd, *certificateDTLSTestPeerOutput) {
	t.Helper()
	command := exec.CommandContext(ctx, peerPath,
		strconv.Itoa(port), cipher, hex.EncodeToString(sessionID), hex.EncodeToString(masterSecret))
	output := newCertificateDTLSTestPeerOutput()
	command.Stdout = output
	command.Stderr = output
	err := command.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start OpenSSL injected DTLS peer"))
	}
	select {
	case <-ctx.Done():
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(E.Cause(ctx.Err(), "wait for OpenSSL injected DTLS peer to listen: ", output.String()))
	case <-output.listening:
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("OpenSSL injected DTLS peer did not begin listening: " + output.String())
	}
	t.Cleanup(func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	return command, output
}

func reserveCertificateDTLSTestPort(t *testing.T) int {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(E.Cause(err, "reserve OpenSSL certificate DTLS UDP port"))
	}
	port := listener.LocalAddr().(*net.UDPAddr).Port
	err = listener.Close()
	if err != nil {
		t.Fatal(E.Cause(err, "release OpenSSL certificate DTLS UDP port"))
	}
	return port
}

func buildCertificateDTLSTestPKI(t *testing.T) certificateDTLSTestPKI {
	t.Helper()
	directory := t.TempDir()
	now := time.Now()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(E.Cause(err, "generate OpenSSL certificate DTLS CA key"))
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "certificate DTLS test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(E.Cause(err, "create OpenSSL certificate DTLS CA"))
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(E.Cause(err, "parse OpenSSL certificate DTLS CA"))
	}
	serverCertificatePEM, serverKeyPEM := createCertificateDTLSTestIdentity(t, caCertificate, caKey, 2,
		certificateDTLSTestServerName, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false)
	ecdsaCertificatePEM, ecdsaKeyPEM := createCertificateDTLSTestIdentity(t, caCertificate, caKey, 4,
		certificateDTLSTestServerName, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, true)
	clientCertificatePEM, clientKeyPEM := createCertificateDTLSTestIdentity(t, caCertificate, caKey, 3,
		"certificate DTLS test client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, false)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caPath := filepath.Join(directory, "ca.pem")
	serverCertPath := filepath.Join(directory, "server.pem")
	serverKeyPath := filepath.Join(directory, "server-key.pem")
	ecdsaCertPath := filepath.Join(directory, "server-ecdsa.pem")
	ecdsaKeyPath := filepath.Join(directory, "server-ecdsa-key.pem")
	for path, content := range map[string][]byte{
		caPath:         caPEM,
		serverCertPath: append(serverCertificatePEM, caPEM...),
		serverKeyPath:  serverKeyPEM,
		ecdsaCertPath:  append(ecdsaCertificatePEM, caPEM...),
		ecdsaKeyPath:   ecdsaKeyPEM,
	} {
		err = os.WriteFile(path, content, 0o600)
		if err != nil {
			t.Fatal(E.Cause(err, "write OpenSSL certificate DTLS test identity"))
		}
	}
	clientCertificate, err := tls.X509KeyPair(append(clientCertificatePEM, caPEM...), clientKeyPEM)
	if err != nil {
		t.Fatal(E.Cause(err, "parse OpenSSL certificate DTLS client identity"))
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(caCertificate)
	return certificateDTLSTestPKI{
		caPath:            caPath,
		serverCertPath:    serverCertPath,
		serverKeyPath:     serverKeyPath,
		ecdsaCertPath:     ecdsaCertPath,
		ecdsaKeyPath:      ecdsaKeyPath,
		caSubject:         append([]byte(nil), caCertificate.RawSubject...),
		rootCAs:           rootCAs,
		clientCertificate: clientCertificate,
	}
}

func createCertificateDTLSTestIdentity(
	t *testing.T,
	caCertificate *x509.Certificate,
	caKey *rsa.PrivateKey,
	serial int64,
	commonName string,
	usages []x509.ExtKeyUsage,
	ecdsaIdentity bool,
) ([]byte, []byte) {
	t.Helper()
	var privateKey crypto.Signer
	var err error
	if ecdsaIdentity {
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatal(E.Cause(err, "generate OpenSSL certificate DTLS identity key"))
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  usages,
	}
	if commonName == certificateDTLSTestServerName {
		template.DNSNames = []string{certificateDTLSTestServerName}
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, caCertificate, privateKey.Public(), caKey)
	if err != nil {
		t.Fatal(E.Cause(err, "create OpenSSL certificate DTLS identity"))
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(E.Cause(err, "marshal OpenSSL certificate DTLS identity key"))
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
}

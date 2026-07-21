package test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
)

type m1ReconnectTimeoutPeer struct {
	access            sync.Mutex
	connectRequests   int
	failures          chan error
	dropFirstTunnel   chan struct{}
	secondStarted     chan struct{}
	secondCanceled    chan struct{}
	releaseSecond     chan struct{}
	thirdStarted      chan struct{}
	secondStartedOnce sync.Once
	secondCancelOnce  sync.Once
	thirdStartedOnce  sync.Once
}

func TestM1ReconnectTimeoutBudgetsFailedAttemptBackoffInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	peer := &m1ReconnectTimeoutPeer{
		failures:        make(chan error, 4),
		dropFirstTunnel: make(chan struct{}),
		secondStarted:   make(chan struct{}),
		secondCanceled:  make(chan struct{}),
		releaseSecond:   make(chan struct{}),
		thirdStarted:    make(chan struct{}),
	}
	server := httptest.NewUnstartedServer(peer)
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 1)
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context:          ctx,
		Server:           server.URL,
		Flavor:           openconnect.FlavorAnyConnect,
		NoUDP:            true,
		ReconnectTimeout: 500 * time.Millisecond,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
		}},
		OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
			configurationEvents <- event
			return nil
		},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create reconnect timeout interop client"))
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start reconnect timeout interop client"))
	}
	select {
	case <-configurationEvents:
		close(peer.dropFirstTunnel)
	case failure := <-peer.failures:
		t.Fatal(failure)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for initial reconnect timeout tunnel"))
	}
	select {
	case <-peer.secondStarted:
	case failure := <-peer.failures:
		t.Fatal(failure)
	case <-time.After(750 * time.Millisecond):
		t.Fatal("first reconnect attempt was not immediate")
	}
	select {
	case <-peer.secondCanceled:
		t.Fatal("reconnect timeout canceled an in-progress attempt")
	case <-time.After(750 * time.Millisecond):
	}
	close(peer.releaseSecond)
	select {
	case <-peer.thirdStarted:
	case failure := <-peer.failures:
		t.Fatal(failure)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for reconnect attempt after budgeted backoff"))
	}
	_, err = client.ReadDataPacket(ctx)
	if !errors.Is(err, openconnect.ErrReconnectTimeout) {
		t.Fatalf("failed reconnect attempts did not exhaust the backoff budget: %v", err)
	}
}

func (p *m1ReconnectTimeoutPeer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/":
		http.SetCookie(writer, &http.Cookie{Name: "webvpn", Value: "reconnect-timeout-session", Path: "/", Secure: true})
		writer.Header().Set("Content-Type", "application/xml")
		_, err := io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>reconnect-timeout-session</session-token><auth id="success" />
</config-auth>`)
		if err != nil {
			p.recordFailure(E.Cause(err, "write reconnect timeout authentication response"))
		}
	case request.Method == http.MethodConnect && request.URL.Path == "/CSCOSSLC/tunnel":
		p.access.Lock()
		p.connectRequests++
		connectRequest := p.connectRequests
		p.access.Unlock()
		if connectRequest == 1 {
			p.serveInitialTunnel(writer)
			return
		}
		switch connectRequest {
		case 2:
			p.secondStartedOnce.Do(func() { close(p.secondStarted) })
			select {
			case <-p.releaseSecond:
				http.Error(writer, "retry", http.StatusServiceUnavailable)
			case <-request.Context().Done():
				p.secondCancelOnce.Do(func() { close(p.secondCanceled) })
			}
		case 3:
			p.thirdStartedOnce.Do(func() { close(p.thirdStarted) })
			http.Error(writer, "retry", http.StatusServiceUnavailable)
		default:
			p.recordFailure(E.New("reconnect timeout peer received excess tunnel attempt: ", connectRequest))
			http.Error(writer, "unexpected reconnect", http.StatusBadRequest)
		}
	default:
		p.recordFailure(E.New("reconnect timeout peer received unexpected request: ", request.Method, " ", request.URL.Path))
		http.Error(writer, "unexpected request", http.StatusBadRequest)
	}
}

func (p *m1ReconnectTimeoutPeer) serveInitialTunnel(writer http.ResponseWriter) {
	hijacker, supported := writer.(http.Hijacker)
	if !supported {
		p.recordFailure(E.New("reconnect timeout peer cannot hijack CONNECT"))
		return
	}
	connection, readWriter, err := hijacker.Hijack()
	if err != nil {
		p.recordFailure(E.Cause(err, "hijack initial reconnect timeout tunnel"))
		return
	}
	defer connection.Close()
	_, err = readWriter.WriteString("HTTP/1.1 200 CONNECTED\r\n" +
		"X-CSTP-MTU: 1200\r\n" +
		"X-CSTP-Address: 192.0.2.90\r\n" +
		"X-CSTP-Netmask: 255.255.255.0\r\n" +
		"X-CSTP-DPD: 0\r\n" +
		"X-CSTP-Keepalive: 0\r\n" +
		"X-CSTP-Rekey-Method: none\r\n\r\n")
	if err == nil {
		err = readWriter.Flush()
	}
	if err != nil {
		p.recordFailure(E.Cause(err, "write initial reconnect timeout tunnel response"))
		return
	}
	<-p.dropFirstTunnel
}

func (p *m1ReconnectTimeoutPeer) recordFailure(err error) {
	select {
	case p.failures <- err:
	default:
	}
}

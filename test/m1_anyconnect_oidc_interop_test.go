package test

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	m1OIDCBearerToken      = "enterprise-oidc-access-token"
	m1OIDCCookie           = "oidc-authenticated-session"
	m1OIDCDefaultUserAgent = "AnyConnect-compatible OpenConnect VPN Agent v9.21"
)

type m1OIDCPeer struct {
	ctx            context.Context
	failures       chan error
	authentication atomic.Uint32
}

func TestM1AnyConnectOIDCBearerInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	peer := &m1OIDCPeer{ctx: ctx, failures: make(chan error, 2)}
	server := httptest.NewUnstartedServer(peer)
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 1)
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  server.URL,
		Flavor:  openconnect.FlavorAnyConnect,
		NoUDP:   true,
		Token: &openconnect.TokenOptions{
			Mode:   openconnect.TokenModeOIDC,
			Secret: m1OIDCBearerToken,
		},
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
		}},
		OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
			configurationEvents <- event
			return nil
		},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create AnyConnect OIDC interop client"))
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start AnyConnect OIDC interop client"))
	}
	select {
	case <-configurationEvents:
		if peer.authentication.Load() != 2 {
			t.Fatalf("OIDC peer received %d authentication requests, expected challenge and retry", peer.authentication.Load())
		}
	case failure := <-peer.failures:
		t.Fatal(failure)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for AnyConnect OIDC tunnel"))
	}
}

func TestM1AnyConnectDirectCookieInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	peer := &m1OIDCPeer{ctx: ctx, failures: make(chan error, 2)}
	server := httptest.NewUnstartedServer(peer)
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()
	configurationEvents := make(chan openconnect.TunnelConfigurationEvent, 1)
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  server.URL,
		Flavor:  openconnect.FlavorAnyConnect,
		Cookie:  "webvpn=" + m1OIDCCookie + "; enterprise-routing-cookie=retained",
		NoUDP:   true,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
		}},
		OnTunnelConfiguration: func(event openconnect.TunnelConfigurationEvent) error {
			configurationEvents <- event
			return nil
		},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create AnyConnect direct-cookie interop client"))
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start AnyConnect direct-cookie interop client"))
	}
	select {
	case <-configurationEvents:
		if peer.authentication.Load() != 0 {
			t.Fatalf("direct cookie unexpectedly performed %d authentication requests", peer.authentication.Load())
		}
	case failure := <-peer.failures:
		t.Fatal(failure)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for AnyConnect direct-cookie tunnel"))
	}
}

func TestM1AnyConnectPasswordAuthenticationDisabledInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	failures := make(chan error, 2)
	var requests atomic.Uint32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != http.MethodPost || request.URL.Path != "/" {
			select {
			case failures <- E.New("no-passwd peer received an unexpected request"):
			default:
			}
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.Copy(io.Discard, request.Body)
		writer.Header().Set("Content-Type", "application/xml")
		_, err := io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<auth id="main"><message>Enterprise password required.</message>
<form method="post" action="/auth"><input type="password" name="password" label="Password:" /></form>
</auth></config-auth>`)
		if err != nil {
			select {
			case failures <- E.Cause(err, "write no-passwd authentication form"):
			default:
			}
		}
	}))
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context:                        ctx,
		Server:                         server.URL,
		Flavor:                         openconnect.FlavorAnyConnect,
		NoUDP:                          true,
		PasswordAuthenticationDisabled: true,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
		}},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create AnyConnect no-passwd interop client"))
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start AnyConnect no-passwd interop client"))
	}
	terminalErrors := make(chan error, 1)
	go func() {
		_, readErr := client.ReadDataPacket(ctx)
		terminalErrors <- readErr
	}()
	select {
	case terminalErr := <-terminalErrors:
		if !E.IsMulti(terminalErr, openconnect.ErrAuthenticationFailed) {
			t.Fatal(E.Cause(terminalErr, "unexpected AnyConnect no-passwd result"))
		}
		if client.PendingAuthChallenge() != nil {
			t.Fatal("AnyConnect no-passwd published a password form")
		}
		if requests.Load() != 1 {
			t.Fatalf("AnyConnect no-passwd made %d requests, expected one", requests.Load())
		}
	case failure := <-failures:
		t.Fatal(failure)
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for AnyConnect no-passwd failure"))
	}
}

func (p *m1OIDCPeer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/":
		if request.Header.Get("User-Agent") != m1OIDCDefaultUserAgent {
			p.fail(writer, E.New("OIDC authentication request used an unexpected default user agent"))
			return
		}
		p.authentication.Add(1)
		_, err := io.Copy(io.Discard, request.Body)
		if err != nil {
			p.fail(writer, E.Cause(err, "read OIDC authentication request"))
			return
		}
		authorization := request.Header.Get("Authorization")
		if authorization == "" {
			writer.Header().Set("WWW-Authenticate", `Digest realm="legacy,edge", qop="auth", Bearer realm="vpn", error_description="fresh,token"`)
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(writer, "bearer token required")
			return
		}
		if authorization != "Bearer "+m1OIDCBearerToken {
			p.fail(writer, E.New("OIDC peer received an unexpected authorization header"))
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: "webvpn", Value: m1OIDCCookie, Path: "/", Secure: true})
		writer.Header().Set("Content-Type", "application/xml")
		_, err = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>`+m1OIDCCookie+`</session-token><auth id="success" />
</config-auth>`)
		if err != nil {
			p.recordFailure(E.Cause(err, "write OIDC authentication response"))
		}
	case request.Method == http.MethodConnect && request.URL.Path == "/CSCOSSLC/tunnel":
		if request.Header.Get("User-Agent") != m1OIDCDefaultUserAgent {
			p.fail(writer, E.New("OIDC tunnel request used an unexpected default user agent"))
			return
		}
		if request.Header.Get("Cookie") != "webvpn="+m1OIDCCookie {
			p.fail(writer, E.New("OIDC tunnel request omitted the authenticated cookie"))
			return
		}
		if request.Header.Get("Authorization") != "" {
			p.fail(writer, E.New("OIDC bearer token leaked into the cookie-authenticated tunnel request"))
			return
		}
		p.serveTunnel(writer)
	default:
		p.fail(writer, E.New("OIDC peer received unexpected request: ", request.Method, " ", request.URL.Path))
	}
}

func (p *m1OIDCPeer) serveTunnel(writer http.ResponseWriter) {
	hijacker, supported := writer.(http.Hijacker)
	if !supported {
		p.recordFailure(E.New("OIDC peer cannot hijack the CSTP connection"))
		return
	}
	connection, readWriter, err := hijacker.Hijack()
	if err != nil {
		p.recordFailure(E.Cause(err, "hijack OIDC CSTP connection"))
		return
	}
	defer connection.Close()
	_, err = readWriter.WriteString("HTTP/1.1 200 CONNECTED\r\n" +
		"X-CSTP-MTU: 1300\r\n" +
		"X-CSTP-Address: 192.0.2.90\r\n" +
		"X-CSTP-Netmask: 255.255.255.0\r\n" +
		"X-CSTP-DPD: 30\r\n" +
		"X-CSTP-Keepalive: 0\r\n" +
		"X-CSTP-Rekey-Method: none\r\n\r\n")
	if err == nil {
		err = readWriter.Flush()
	}
	if err != nil {
		p.recordFailure(E.Cause(err, "write OIDC CSTP response"))
		return
	}
	<-p.ctx.Done()
}

func (p *m1OIDCPeer) fail(writer http.ResponseWriter, err error) {
	p.recordFailure(err)
	http.Error(writer, err.Error(), http.StatusBadRequest)
}

func (p *m1OIDCPeer) recordFailure(err error) {
	select {
	case p.failures <- err:
	default:
	}
}

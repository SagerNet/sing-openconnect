package openconnect

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	f5SAMLTestSession = "0123456789abcdef0123456789abcdef"
	f5SAMLTestProfile = `<?xml version="1.0" encoding="utf-8"?>
<favorites type="VPN" limited="NO"><favorite id="/Common/na"><caption>na</caption><name>/Common/na</name><params>resourcename=/Common/na</params></favorite></favorites>`
	f5SAMLTestOptions = `<?xml version="1.0" encoding="utf-8"?>
<favorite id="/Common/na"><object ID="ID_PARAMS"><ur_Z>urz</ur_Z><Session_ID>sid</Session_ID><IPV4_0>1</IPV4_0><IPV6_0>0</IPV6_0><DNS0>192.0.2.53</DNS0></object></favorite>`
)

type f5SAMLTestGateway struct {
	gateway     *httptest.Server
	idp         *httptest.Server
	idpRequests atomic.Int32
	f5ST        string
}

func newF5SAMLTestGateway(t *testing.T, redirectBinding bool) *f5SAMLTestGateway {
	t.Helper()
	g := &f5SAMLTestGateway{
		f5ST: "1z1z1z" + strconv.FormatInt(time.Now().Unix(), 10) + "z3600",
	}
	g.idp = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		g.idpRequests.Add(1)
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte(`<html><body><form id="login" method="post" action="/login"><input type="text" name="j_username"><input type="password" name="j_password"></form></body></html>`))
	}))
	t.Cleanup(g.idp.Close)
	g.gateway = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/":
			http.SetCookie(writer, &http.Cookie{Name: "MRHSession", Value: "anonymous", Path: "/", Secure: true})
			http.Redirect(writer, request, "/my.policy", http.StatusFound)
		case "/my.policy":
			if redirectBinding {
				http.Redirect(writer, request, g.idp.URL+"/sso/SSORedirect?SAMLRequest=fZJdT4MwFIb%2FCun9oFAQ&RelayState=x", http.StatusFound)
				return
			}
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte(`<html><body onload="document.forms[0].submit()"><form method="POST" action="` + g.idp.URL + `/sso/SSOPOST"><div><input type="hidden" name="SAMLRequest" value="PHNhbWxwOkF1dGhuUmVxdWVzdC8+"/><input type="hidden" name="RelayState" value="x"/></div><noscript><input type="submit" value="Continue"/></noscript></form></body></html>`))
		case "/vdesk/vpn/index.php3", "/vdesk/vpn/connect.php3":
			session, sessionErr := request.Cookie("MRHSession")
			f5ST, f5STErr := request.Cookie("F5_ST")
			if sessionErr != nil || session.Value != f5SAMLTestSession || f5STErr != nil || f5ST.Value != g.f5ST {
				http.Redirect(writer, request, "/my.policy", http.StatusFound)
				return
			}
			writer.Header().Set("Content-Type", "text/xml")
			if request.URL.Path == "/vdesk/vpn/index.php3" {
				_, _ = writer.Write([]byte(f5SAMLTestProfile))
			} else {
				_, _ = writer.Write([]byte(f5SAMLTestOptions))
			}
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(g.gateway.Close)
	return g
}

func newF5SAMLTestClient(t *testing.T, g *f5SAMLTestGateway) *Client {
	t.Helper()
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(g.gateway.Certificate())
	rootCAs.AddCert(g.idp.Certificate())
	client, err := NewClient(ClientOptions{
		Server:        g.gateway.URL,
		Flavor:        FlavorF5,
		LocalHostname: "test",
		TLSConfig:     ClientTLSOptions{Config: &tls.Config{RootCAs: rootCAs}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		client.httpTransport.CloseIdleConnections()
	})
	return client
}

func TestF5SAMLBrowserChallenge(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name            string
		redirectBinding bool
	}{
		{name: "post binding"},
		{name: "redirect binding", redirectBinding: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			g := newF5SAMLTestGateway(t, testCase.redirectBinding)
			client := newF5SAMLTestClient(t, g)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			continuation := client.frontend.BeginAuthentication()
			defer continuation.Close()
			session, request, err := continuation.Advance(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if session != nil || request == nil || request.Browser == nil {
				t.Fatalf("expected a browser request, got session %v request %+v", session, request)
			}
			if g.idpRequests.Load() != 0 {
				t.Fatal("client contacted the identity provider itself")
			}

			type awaitResult struct {
				response authenticationResponse
				err      error
			}
			challengeUpdated := client.AuthChallengeUpdated()
			awaitDone := make(chan awaitResult, 1)
			go func() {
				response, awaitErr := client.awaitAuthChallenge(ctx, *request, continuation)
				awaitDone <- awaitResult{response, awaitErr}
			}()
			select {
			case <-challengeUpdated:
			case <-ctx.Done():
				t.Fatal("browser challenge was not published")
			}
			challenge := client.PendingAuthChallenge()
			if challenge == nil || challenge.Browser == nil || challenge.Form != nil {
				t.Fatalf("expected a pending browser challenge, got %+v", challenge)
			}
			browser := challenge.Browser
			if browser.URL != g.gateway.URL {
				t.Fatalf("browser URL = %q, want the gateway login URL %q", browser.URL, g.gateway.URL)
			}
			if browser.FinalURL != "" {
				t.Fatalf("browser final URL = %q, want none", browser.FinalURL)
			}
			if !slices.Equal(browser.CookieNames, []string{"MRHSession", "F5_ST"}) {
				t.Fatalf("browser cookie names = %q", browser.CookieNames)
			}
			if len(browser.CallbackURLPrefixes) != 0 || len(browser.HeaderNames) != 0 || len(browser.EarlyCookieNames) != 0 {
				t.Fatalf("browser request mixes completion modes: %+v", browser)
			}
			if challenge.Message == "" {
				t.Fatal("browser challenge has no sign-in message")
			}

			// MRHSession alone is the anonymous pre-login session: the
			// challenge only completes once F5_ST is there too.
			err = client.CompleteAuthChallenge(challenge.ID, AuthResponse{Browser: &BrowserResult{
				Cookies: []BrowserCookie{{Name: "MRHSession", Value: f5SAMLTestSession}},
			}})
			if !errors.Is(err, ErrInvalidBrowserAuthentication) {
				t.Fatalf("expected an incomplete browser result to be rejected, got %v", err)
			}
			if pending := client.PendingAuthChallenge(); pending == nil || pending.ID != challenge.ID {
				t.Fatal("rejected browser result withdrew the challenge")
			}

			err = client.CompleteAuthChallenge(challenge.ID, AuthResponse{Browser: &BrowserResult{
				FinalURL: browser.FinalURL,
				Cookies: []BrowserCookie{
					{Name: "MRHSession", Value: f5SAMLTestSession},
					{Name: "F5_ST", Value: g.f5ST},
				},
			}})
			if err != nil {
				t.Fatal(err)
			}
			result := <-awaitDone
			if result.err != nil {
				t.Fatal(result.err)
			}
			session, request, err = continuation.Advance(ctx, &result.response)
			if err != nil {
				t.Fatal(err)
			}
			if request != nil {
				t.Fatalf("expected a session after the browser answer, got request %+v", request)
			}
			state, isF5Session := session.(*f5SessionState)
			if !isF5Session {
				t.Fatalf("session type = %T", session)
			}
			defer state.Close()
			if state.mrhSession != f5SAMLTestSession || state.f5ST != g.f5ST || state.authenticationExpiration.IsZero() {
				t.Fatalf("session state = %q %q %v", state.mrhSession, state.f5ST, state.authenticationExpiration)
			}
			configuration, err := state.loadConfiguration(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if configuration.sessionID != "sid" || configuration.urZ != "urz" || !configuration.wantIPv4 {
				t.Fatalf("tunnel configuration = %+v", configuration)
			}
			if !configuration.configuration.RemoteAddress.IsLoopback() {
				t.Fatalf("accepted address = %v", configuration.configuration.RemoteAddress)
			}
			if g.idpRequests.Load() != 0 {
				t.Fatal("client contacted the identity provider itself")
			}
		})
	}
}

func TestF5SAMLBrowserResultRequiresMRHSession(t *testing.T) {
	t.Parallel()
	g := newF5SAMLTestGateway(t, false)
	client := newF5SAMLTestClient(t, g)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	continuation := client.frontend.BeginAuthentication()
	defer continuation.Close()
	_, request, err := continuation.Advance(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if request == nil || request.Browser == nil {
		t.Fatalf("expected a browser request, got %+v", request)
	}
	_, _, err = continuation.Advance(ctx, &authenticationResponse{BrowserResult: &BrowserResult{
		FinalURL: request.Browser.FinalURL,
		Cookies:  []BrowserCookie{{Name: "F5_ST", Value: g.f5ST}},
	}})
	if err == nil || !strings.Contains(err.Error(), "MRHSession") {
		t.Fatalf("expected a missing MRHSession error, got %v", err)
	}
}

func TestF5SAMLExternalAuthDisabled(t *testing.T) {
	t.Parallel()
	g := newF5SAMLTestGateway(t, false)
	client := newF5SAMLTestClient(t, g)
	client.options.ExternalAuthDisabled = true
	continuation := client.frontend.BeginAuthentication()
	defer continuation.Close()
	_, request, err := continuation.Advance(context.Background(), nil)
	if err == nil || request != nil {
		t.Fatalf("expected external authentication to be refused, got request %+v error %v", request, err)
	}
}

func TestF5FirstFormWithoutSAMLRequest(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name      string
		document  string
		formID    string
		errorText string
	}{
		{
			name:     "native logon form",
			document: `<html><body><form id="auth_form" method="post" action="/my.policy"><input type="text" name="username"><input type="password" name="password"></form></body></html>`,
			formID:   "auth_form",
		},
		{
			name:      "unknown form",
			document:  `<html><body><form method="post" action="/other"><input type="text" name="user"></form></body></html>`,
			errorText: "unexpected first F5 HTML form ID: unknown",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			gateway := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "text/html")
				_, _ = writer.Write([]byte(testCase.document))
			}))
			defer gateway.Close()
			rootCAs := x509.NewCertPool()
			rootCAs.AddCert(gateway.Certificate())
			client, err := NewClient(ClientOptions{
				Server:        gateway.URL,
				Flavor:        FlavorF5,
				LocalHostname: "test",
				TLSConfig:     ClientTLSOptions{Config: &tls.Config{RootCAs: rootCAs}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.httpTransport.CloseIdleConnections()
			continuation := client.frontend.BeginAuthentication()
			defer continuation.Close()
			_, request, err := continuation.Advance(context.Background(), nil)
			if testCase.errorText != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.errorText) {
					t.Fatalf("expected %q, got request %+v error %v", testCase.errorText, request, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if request == nil || request.Browser != nil || request.FormID != testCase.formID {
				t.Fatalf("expected native form %q, got %+v", testCase.formID, request)
			}
		})
	}
}

func advanceF5SAMLTestBrowser(t *testing.T, g *f5SAMLTestGateway, cookies []BrowserCookie) (*f5SessionState, error) {
	t.Helper()
	client := newF5SAMLTestClient(t, g)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	continuation := client.frontend.BeginAuthentication()
	t.Cleanup(func() { _ = continuation.Close() })
	_, request, err := continuation.Advance(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if request == nil || request.Browser == nil {
		t.Fatalf("expected a browser request, got %+v", request)
	}
	session, _, err := continuation.Advance(ctx, &authenticationResponse{BrowserResult: &BrowserResult{
		FinalURL: request.Browser.FinalURL,
		Cookies:  cookies,
	}})
	if err != nil {
		return nil, err
	}
	state := session.(*f5SessionState)
	t.Cleanup(func() { _ = state.Close() })
	_, err = state.loadConfiguration(ctx)
	return state, err
}

func TestF5SAMLBrowserResultPastedPairs(t *testing.T) {
	t.Parallel()
	g := newF5SAMLTestGateway(t, false)
	state, err := advanceF5SAMLTestBrowser(t, g, []BrowserCookie{
		{Name: "MRHSession", Value: " MRHSession=" + f5SAMLTestSession + "\n"},
		{Name: "F5_ST", Value: "F5_ST=" + g.f5ST},
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.mrhSession != f5SAMLTestSession || state.f5ST != g.f5ST {
		t.Fatalf("session state = %q %q", state.mrhSession, state.f5ST)
	}
}

func TestF5SAMLBrowserResultRejectedSessionIsRetryable(t *testing.T) {
	t.Parallel()
	g := newF5SAMLTestGateway(t, false)
	_, err := advanceF5SAMLTestBrowser(t, g, []BrowserCookie{
		{Name: "MRHSession", Value: "fedcba9876543210fedcba9876543210"},
		{Name: "F5_ST", Value: g.f5ST},
	})
	if !E.IsMulti(err, ErrSessionRejected) || classifyClientSessionError(err) == clientSessionErrorTerminal {
		t.Fatalf("expected a retryable session rejection, got %v", err)
	}
}

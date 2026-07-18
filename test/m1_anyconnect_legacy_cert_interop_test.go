package test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/pem"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
)

type m1LegacyFallbackMode string

const (
	m1LegacyFallbackHTTPRejection m1LegacyFallbackMode = "http-rejection"
	m1LegacyFallbackLocalRedirect m1LegacyFallbackMode = "local-redirect"
)

type m1LegacyFallbackPeer struct {
	mode                  m1LegacyFallbackMode
	errors                chan error
	tunnelStarted         chan struct{}
	tunnelClosed          chan error
	access                sync.Mutex
	phase                 int
	initialRequests       int
	legacyRequests        int
	legacyFormSubmissions int
}

type m1CERT1Mode string

const (
	m1CERT1Accepted             m1CERT1Mode = "accepted-on-fresh-tls"
	m1CERT1Missing              m1CERT1Mode = "missing"
	m1CERT1ConfiguredUnaccepted m1CERT1Mode = "configured-unaccepted"
)

type m1CERT1InitialRequest struct {
	XMLName                  xml.Name  `xml:"config-auth"`
	Type                     string    `xml:"type,attr"`
	ClientCertificateFailure *struct{} `xml:"client-cert-fail"`
}

type m1CERT1Peer struct {
	mode                         m1CERT1Mode
	expectedCertificate          []byte
	errors                       chan error
	tunnelStarted                chan struct{}
	tunnelClosed                 chan error
	access                       sync.Mutex
	initialRequests              int
	clientCertificateFailures    int
	legacyRequests               int
	legacyFormSubmissions        int
	initialAuthenticationRemotes []string
	authenticationComplete       bool
}

type m1CrossHostAuthenticationReply struct {
	XMLName xml.Name `xml:"config-auth"`
	Type    string   `xml:"type,attr"`
	Auth    struct {
		Username  string   `xml:"username"`
		Passwords []string `xml:"password"`
	} `xml:"auth"`
}

type m1CrossHostAuthenticationPeer struct {
	errors        chan error
	tunnelStarted chan struct{}
	tunnelClosed  chan error
	access        sync.Mutex
	phase         int
	originBody    []byte
}

func TestM1AnyConnectLegacyFallbackInterop(t *testing.T) {
	t.Parallel()
	for _, fallbackMode := range []m1LegacyFallbackMode{
		m1LegacyFallbackHTTPRejection,
		m1LegacyFallbackLocalRedirect,
	} {
		t.Run(string(fallbackMode), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			t.Cleanup(cancel)
			peer := &m1LegacyFallbackPeer{
				mode:          fallbackMode,
				errors:        make(chan error, 8),
				tunnelStarted: make(chan struct{}, 1),
				tunnelClosed:  make(chan error, 1),
			}
			server := httptest.NewUnstartedServer(peer)
			server.EnableHTTP2 = false
			server.StartTLS()
			t.Cleanup(server.Close)

			client := newM1AnyConnectClient(t, ctx, server.URL+"/vpn/start", openconnect.ClientOptions{NoUDP: true})
			startM1Client(t, client)
			form := waitForM1AuthForm(t, ctx, client)
			if form.Browser != nil || form.Form == nil || len(form.Form.Fields) != 3 {
				t.Fatalf("legacy authentication-complete form was not exposed with all visible instances: %#v", form)
			}
			values := make(map[string]string, len(form.Form.Fields))
			seenSubmissionKeys := make(map[string]struct{}, len(form.Form.Fields))
			for _, field := range form.Form.Fields {
				if _, exists := seenSubmissionKeys[field.SubmissionKey]; exists {
					t.Fatalf("legacy duplicate field instance reused submission key %q", field.SubmissionKey)
				}
				seenSubmissionKeys[field.SubmissionKey] = struct{}{}
				switch field.Label {
				case "Legacy username:":
					values[field.SubmissionKey] = "legacy user+&"
				case "First instance:":
					values[field.SubmissionKey] = "first/value"
				case "Second instance:":
					values[field.SubmissionKey] = "second value"
				default:
					t.Fatalf("unexpected legacy visible field: %#v", field)
				}
			}
			err := client.CompleteAuthChallenge(form.ID, openconnect.AuthResponse{Form: &openconnect.AuthFormResponse{Values: values}})
			if err != nil {
				t.Fatal(E.Cause(err, "complete legacy authentication-complete form"))
			}
			waitForM1LegacyCertificateTunnel(t, ctx, peer.errors, peer.tunnelStarted)
			waitForM1Ready(t, ctx, client)
			closeErr := client.Close()
			if closeErr != nil && !E.IsClosed(closeErr) {
				t.Fatal(E.Cause(closeErr, "close established legacy CSTP tunnel"))
			}
			waitForM1LegacyCertificateTunnelClose(t, ctx, peer.errors, peer.tunnelClosed)
			peer.access.Lock()
			initialRequests := peer.initialRequests
			legacyRequests := peer.legacyRequests
			legacyFormSubmissions := peer.legacyFormSubmissions
			phase := peer.phase
			peer.access.Unlock()
			if initialRequests != 1 || legacyRequests != 1 || legacyFormSubmissions != 1 || phase != 3 {
				t.Fatalf(
					"incomplete legacy exchange: initial=%d get=%d form=%d phase=%d",
					initialRequests,
					legacyRequests,
					legacyFormSubmissions,
					phase,
				)
			}
		})
	}
}

func TestM1AnyConnectCrossHostRedirectCredentialInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	peer := &m1CrossHostAuthenticationPeer{
		errors:        make(chan error, 8),
		tunnelStarted: make(chan struct{}, 1),
		tunnelClosed:  make(chan error, 1),
	}
	destination := httptest.NewUnstartedServer(peer)
	destination.EnableHTTP2 = false
	destination.StartTLS()
	t.Cleanup(destination.Close)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, loaded := readM1LegacyCertificateRequest(peer.errors, writer, request)
		if !loaded {
			return
		}
		_, cookieErr := request.Cookie("origin-only")
		peer.access.Lock()
		validPhase := peer.phase == 0
		peer.phase = 1
		peer.originBody = append([]byte(nil), body...)
		peer.access.Unlock()
		if !validPhase || request.Method != http.MethodPost || request.URL.Path != "/vpn/start" ||
			cookieErr == nil || !strings.Contains(string(body), `type="init"`) {
			peer.fail(writer, E.New("cross-host origin received an invalid XMLPOST initialization"))
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: "origin-only", Value: "must-not-cross-port", Path: "/", Secure: true})
		writer.Header().Set("Location", destination.URL+"/redirected/login")
		writer.WriteHeader(http.StatusFound)
	}))
	origin.EnableHTTP2 = false
	origin.StartTLS()
	t.Cleanup(origin.Close)

	client := newM1AnyConnectClient(t, ctx, origin.URL+"/vpn/start", openconnect.ClientOptions{NoUDP: true})
	startM1Client(t, client)
	firstForm := waitForM1CrossHostAuthForm(t, ctx, client, peer.errors)
	if firstForm.Browser != nil || firstForm.Form == nil || len(firstForm.Form.Fields) != 3 {
		t.Fatalf("cross-host first authentication form was incomplete: %#v", firstForm)
	}
	firstValues := make(map[string]string, len(firstForm.Form.Fields))
	for _, field := range firstForm.Form.Fields {
		switch field.Name {
		case "username":
			firstValues[field.SubmissionKey] = "redirect-user"
		case "password":
			firstValues[field.SubmissionKey] = "stable-password"
		case "answer":
			firstValues[field.SubmissionKey] = "first-one-shot"
		default:
			t.Fatalf("cross-host first form exposed an unexpected field: %#v", field)
		}
	}
	err := client.CompleteAuthChallenge(firstForm.ID, openconnect.AuthResponse{Form: &openconnect.AuthFormResponse{Values: firstValues}})
	if err != nil {
		t.Fatal(E.Cause(err, "complete cross-host first authentication form"))
	}
	secondForm := waitForM1CrossHostAuthForm(t, ctx, client, peer.errors)
	if secondForm.ID == firstForm.ID || secondForm.Browser != nil || secondForm.Form == nil || len(secondForm.Form.Fields) != 3 {
		t.Fatalf("stable credentials were not reused independently of the one-shot answer: first=%#v second=%#v", firstForm, secondForm)
	}
	secondValues := make(map[string]string, len(secondForm.Form.Fields))
	for _, field := range secondForm.Form.Fields {
		switch field.Name {
		case "username":
			if field.Value != "redirect-user" {
				t.Fatalf("stable username was not retained: %#v", field)
			}
			secondValues[field.SubmissionKey] = field.Value
		case "password":
			if field.Value != "stable-password" {
				t.Fatalf("stable password was not retained: %#v", field)
			}
			secondValues[field.SubmissionKey] = field.Value
		case "answer":
			if field.Value != "" {
				t.Fatalf("one-shot answer was incorrectly retained: %#v", field)
			}
			secondValues[field.SubmissionKey] = "second-one-shot"
		default:
			t.Fatalf("cross-host second form exposed an unexpected field: %#v", field)
		}
	}
	err = client.CompleteAuthChallenge(secondForm.ID, openconnect.AuthResponse{Form: &openconnect.AuthFormResponse{Values: secondValues}})
	if err != nil {
		t.Fatal(E.Cause(err, "complete cross-host second authentication form"))
	}
	waitForM1LegacyCertificateTunnel(t, ctx, peer.errors, peer.tunnelStarted)
	waitForM1Ready(t, ctx, client)
	closeErr := client.Close()
	if closeErr != nil && !E.IsClosed(closeErr) {
		t.Fatal(E.Cause(closeErr, "close established cross-host CSTP tunnel"))
	}
	waitForM1LegacyCertificateTunnelClose(t, ctx, peer.errors, peer.tunnelClosed)
	peer.access.Lock()
	phase := peer.phase
	peer.access.Unlock()
	if phase != 5 {
		t.Fatalf("cross-host authentication exchange stopped in phase %d", phase)
	}
}

func TestM1AnyConnectCERT1FreshTLSInterop(t *testing.T) {
	t.Parallel()
	runM1AnyConnectCERT1FreshTLSInterop(t, false)
}

func TestM1AnyConnectCERT1GetClientCertificateInterop(t *testing.T) {
	t.Parallel()
	runM1AnyConnectCERT1FreshTLSInterop(t, true)
}

func runM1AnyConnectCERT1FreshTLSInterop(t *testing.T, callbackIdentity bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	_, clientCertificate, clientKey := createM1ClientCertificate(t, "m1-cert1-machine")
	certificateBlock, _ := pem.Decode(clientCertificate)
	if certificateBlock == nil {
		t.Fatal("decode CERT1 client certificate")
	}
	peer := &m1CERT1Peer{
		mode:                m1CERT1Accepted,
		expectedCertificate: append([]byte(nil), certificateBlock.Bytes...),
		errors:              make(chan error, 8),
		tunnelStarted:       make(chan struct{}, 1),
		tunnelClosed:        make(chan error, 1),
	}
	server := httptest.NewUnstartedServer(peer)
	server.EnableHTTP2 = false
	var handshakes atomic.Int64
	server.TLS = &tls.Config{
		GetConfigForClient: func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			configuration := server.TLS.Clone()
			configuration.GetConfigForClient = nil
			if handshakes.Add(1) > 1 {
				configuration.ClientAuth = tls.RequestClientCert
			}
			return configuration, nil
		},
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	clientOptions := openconnect.ClientOptions{
		NoUDP: true,
		TLSConfig: openconnect.ClientTLSOptions{
			Config: &tls.Config{InsecureSkipVerify: true},
		},
	}
	if callbackIdentity {
		certificate, err := tls.X509KeyPair(clientCertificate, clientKey)
		if err != nil {
			t.Fatal(E.Cause(err, "parse CERT1 callback identity"))
		}
		clientOptions.TLSConfig.Config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &certificate, nil
		}
	} else {
		clientOptions.TLSConfig.Certificate = openconnect.Material{Content: clientCertificate}
		clientOptions.TLSConfig.Key = openconnect.Material{Content: clientKey}
	}
	client := newM1AnyConnectClient(t, ctx, server.URL, clientOptions)
	startM1Client(t, client)
	waitForM1LegacyCertificateTunnel(t, ctx, peer.errors, peer.tunnelStarted)
	waitForM1Ready(t, ctx, client)
	closeErr := client.Close()
	if closeErr != nil && !E.IsClosed(closeErr) {
		t.Fatal(E.Cause(closeErr, "close established CERT1 CSTP tunnel"))
	}
	waitForM1LegacyCertificateTunnelClose(t, ctx, peer.errors, peer.tunnelClosed)
	peer.access.Lock()
	initialRequests := peer.initialRequests
	failureRequests := peer.clientCertificateFailures
	remotes := append([]string(nil), peer.initialAuthenticationRemotes...)
	authenticationComplete := peer.authenticationComplete
	peer.access.Unlock()
	if initialRequests != 2 || failureRequests != 0 || len(remotes) != 2 || remotes[0] == remotes[1] || !authenticationComplete {
		t.Fatalf(
			"CERT1 did not retry on a fresh authenticated TLS connection: initial=%d failures=%d remotes=%v complete=%v",
			initialRequests,
			failureRequests,
			remotes,
			authenticationComplete,
		)
	}
}

func TestM1AnyConnectCERT1FailureFallbackInterop(t *testing.T) {
	t.Parallel()
	for _, certMode := range []m1CERT1Mode{m1CERT1Missing, m1CERT1ConfiguredUnaccepted} {
		t.Run(string(certMode), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			t.Cleanup(cancel)
			peer := &m1CERT1Peer{
				mode:          certMode,
				errors:        make(chan error, 8),
				tunnelStarted: make(chan struct{}, 1),
				tunnelClosed:  make(chan error, 1),
			}
			server := httptest.NewUnstartedServer(peer)
			server.EnableHTTP2 = false
			server.StartTLS()
			t.Cleanup(server.Close)
			options := openconnect.ClientOptions{NoUDP: true}
			if certMode == m1CERT1ConfiguredUnaccepted {
				_, clientCertificate, clientKey := createM1ClientCertificate(t, "m1-cert1-unaccepted")
				options.TLSConfig.Certificate = openconnect.Material{Content: clientCertificate}
				options.TLSConfig.Key = openconnect.Material{Content: clientKey}
			}
			client := newM1AnyConnectClient(t, ctx, server.URL, options)
			startM1Client(t, client)
			waitForM1LegacyCertificateTunnel(t, ctx, peer.errors, peer.tunnelStarted)
			waitForM1Ready(t, ctx, client)
			closeErr := client.Close()
			if closeErr != nil && !E.IsClosed(closeErr) {
				t.Fatal(E.Cause(closeErr, "close established CERT1 fallback CSTP tunnel"))
			}
			waitForM1LegacyCertificateTunnelClose(t, ctx, peer.errors, peer.tunnelClosed)
			peer.access.Lock()
			initialRequests := peer.initialRequests
			failureRequests := peer.clientCertificateFailures
			legacyRequests := peer.legacyRequests
			legacyFormSubmissions := peer.legacyFormSubmissions
			remotes := append([]string(nil), peer.initialAuthenticationRemotes...)
			authenticationComplete := peer.authenticationComplete
			peer.access.Unlock()
			expectedInitialRequests := 1
			if certMode == m1CERT1ConfiguredUnaccepted {
				expectedInitialRequests = 2
			}
			if initialRequests != expectedInitialRequests ||
				failureRequests != 1 ||
				legacyRequests != 1 ||
				legacyFormSubmissions != 1 ||
				!authenticationComplete {
				t.Fatalf(
					"invalid CERT1 failure fallback: initial=%d failures=%d get=%d form=%d remotes=%v complete=%v",
					initialRequests,
					failureRequests,
					legacyRequests,
					legacyFormSubmissions,
					remotes,
					authenticationComplete,
				)
			}
		})
	}
}

func (peer *m1LegacyFallbackPeer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/vpn/start":
		body, loaded := readM1LegacyCertificateRequest(peer.errors, writer, request)
		if !loaded {
			return
		}
		peer.access.Lock()
		validPhase := peer.phase == 0
		peer.phase = 1
		peer.initialRequests++
		peer.access.Unlock()
		if !validPhase || !strings.Contains(string(body), `type="init"`) || strings.Contains(string(body), "client-cert-fail") {
			peer.fail(writer, E.New("legacy peer received an invalid XMLPOST probe"))
			return
		}
		if peer.mode == m1LegacyFallbackLocalRedirect {
			writer.Header().Set("Location", "/vpn/xmlpost-unsupported")
			writer.WriteHeader(http.StatusFound)
			return
		}
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(writer, "XMLPOST unsupported")
	case request.Method == http.MethodGet && request.URL.Path == "/vpn/start":
		body, loaded := readM1LegacyCertificateRequest(peer.errors, writer, request)
		if !loaded {
			return
		}
		peer.access.Lock()
		validPhase := peer.phase == 1
		peer.phase = 2
		peer.legacyRequests++
		peer.access.Unlock()
		if !validPhase || len(body) != 0 {
			peer.fail(writer, E.New("legacy peer received an invalid fallback GET"))
			return
		}
		writer.Header().Set("Content-Type", "application/xml")
		_, err := io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<auth id="legacy-main">
<authentication-complete />
<form method="post" action="submit">
<input type="hidden" name="state" value="server state&amp;=+" />
<input type="text" name="username" label="Legacy username:" />
<input type="text" name="instance" label="First instance:" />
<input type="text" name="instance" label="Second instance:" />
</form>
</auth>`)
		if err != nil {
			reportM1LegacyCertificateError(peer.errors, E.Cause(err, "write legacy authentication form"))
		}
	case request.Method == http.MethodPost && request.URL.Path == "/vpn/submit":
		body, loaded := readM1LegacyCertificateRequest(peer.errors, writer, request)
		if !loaded {
			return
		}
		peer.access.Lock()
		validPhase := peer.phase == 2
		peer.phase = 3
		peer.legacyFormSubmissions++
		peer.access.Unlock()
		expectedBody := "state=server%20state%26%3d%2b&username=legacy%20user%2b%26&instance=first%2fvalue&instance=second%20value"
		if !validPhase || string(body) != expectedBody || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			peer.fail(writer, E.New("legacy peer rejected encoded form body: ", string(body)))
			return
		}
		writeM1LegacyCertificateAuthenticationSuccess(writer, "legacy-session-cookie")
	case request.Method == http.MethodConnect:
		peer.access.Lock()
		validPhase := peer.phase == 3
		peer.access.Unlock()
		if !validPhase || !strings.Contains(request.Header.Get("Cookie"), "webvpn=legacy-session-cookie") {
			peer.fail(writer, E.New("legacy peer received CSTP CONNECT before successful authentication"))
			return
		}
		serveM1LegacyCertificateTunnel(writer, peer.errors, peer.tunnelStarted, peer.tunnelClosed)
	default:
		peer.fail(writer, E.New("legacy peer received unexpected request: ", request.Method, " ", request.URL.Path))
	}
}

func (peer *m1LegacyFallbackPeer) fail(writer http.ResponseWriter, err error) {
	reportM1LegacyCertificateError(peer.errors, err)
	writer.WriteHeader(http.StatusInternalServerError)
}

func (peer *m1CrossHostAuthenticationPeer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/redirected/login":
		peer.handleInitialization(writer, request)
	case request.Method == http.MethodPost && request.URL.Path == "/redirected/submit":
		peer.handleSubmission(writer, request)
	case request.Method == http.MethodConnect:
		peer.access.Lock()
		validPhase := peer.phase == 4
		if validPhase {
			peer.phase = 5
		}
		peer.access.Unlock()
		webVPNCookie, webVPNCookieErr := request.Cookie("webvpn")
		_, originCookieErr := request.Cookie("origin-only")
		if !validPhase || webVPNCookieErr != nil || webVPNCookie.Value != "cross-host-session" || originCookieErr == nil {
			peer.fail(writer, E.New("cross-host peer received CSTP CONNECT with invalid authentication cookies"))
			return
		}
		serveM1LegacyCertificateTunnel(writer, peer.errors, peer.tunnelStarted, peer.tunnelClosed)
	default:
		peer.fail(writer, E.New("cross-host peer received unexpected request: ", request.Method, " ", request.URL.Path))
	}
}

func (peer *m1CrossHostAuthenticationPeer) handleInitialization(writer http.ResponseWriter, request *http.Request) {
	body, loaded := readM1LegacyCertificateRequest(peer.errors, writer, request)
	if !loaded {
		return
	}
	_, originCookieErr := request.Cookie("origin-only")
	peer.access.Lock()
	validPhase := peer.phase == 1
	peer.phase = 2
	originBody := append([]byte(nil), peer.originBody...)
	peer.access.Unlock()
	if !validPhase || originCookieErr == nil || !bytes.Equal(body, originBody) {
		peer.fail(writer, E.New("cross-host redirect retained an origin cookie or changed the XMLPOST body"))
		return
	}
	http.SetCookie(writer, &http.Cookie{Name: "destination-only", Value: "redirect-state", Path: "/", Secure: true})
	writeM1CrossHostAuthenticationForm(writer)
}

func (peer *m1CrossHostAuthenticationPeer) handleSubmission(writer http.ResponseWriter, request *http.Request) {
	body, loaded := readM1LegacyCertificateRequest(peer.errors, writer, request)
	if !loaded {
		return
	}
	var reply m1CrossHostAuthenticationReply
	err := xml.Unmarshal(body, &reply)
	if err != nil {
		peer.fail(writer, E.Cause(err, "parse cross-host authentication reply"))
		return
	}
	destinationCookie, destinationCookieErr := request.Cookie("destination-only")
	_, originCookieErr := request.Cookie("origin-only")
	peer.access.Lock()
	phase := peer.phase
	validPhase := phase == 2 || phase == 3
	if validPhase {
		peer.phase++
	}
	peer.access.Unlock()
	expectedAnswer := "first-one-shot"
	if phase == 3 {
		expectedAnswer = "second-one-shot"
	}
	if !validPhase || reply.XMLName.Local != "config-auth" || reply.Type != "auth-reply" ||
		reply.Auth.Username != "redirect-user" || len(reply.Auth.Passwords) != 2 ||
		reply.Auth.Passwords[0] != "stable-password" || reply.Auth.Passwords[1] != expectedAnswer ||
		destinationCookieErr != nil || destinationCookie.Value != "redirect-state" || originCookieErr == nil {
		peer.fail(writer, E.New("cross-host peer rejected authentication reply in phase ", phase))
		return
	}
	if phase == 2 {
		writeM1CrossHostAuthenticationForm(writer)
		return
	}
	writeM1LegacyCertificateAuthenticationSuccess(writer, "cross-host-session")
}

func (peer *m1CrossHostAuthenticationPeer) fail(writer http.ResponseWriter, err error) {
	reportM1LegacyCertificateError(peer.errors, err)
	writer.WriteHeader(http.StatusInternalServerError)
}

func writeM1CrossHostAuthenticationForm(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<auth id="cross-host-main">
<form method="post" action="submit">
<input type="text" name="username" label="Redirect username:" />
<input type="password" name="password" label="Stable password:" />
<input type="password" name="answer" label="One-shot answer:" />
</form>
</auth>
</config-auth>`)
}

func (peer *m1CERT1Peer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/":
		peer.handleInitialRequest(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/":
		peer.handleLegacyRequest(writer, request)
	case request.Method == http.MethodPost && request.URL.Path == "/cert-submit":
		peer.handleLegacyFormSubmission(writer, request)
	case request.Method == http.MethodConnect:
		peer.access.Lock()
		authenticationComplete := peer.authenticationComplete
		peer.access.Unlock()
		if !authenticationComplete || !strings.Contains(request.Header.Get("Cookie"), "webvpn=cert1-session-cookie") {
			peer.fail(writer, E.New("CERT1 peer received CSTP CONNECT before successful authentication"))
			return
		}
		serveM1LegacyCertificateTunnel(writer, peer.errors, peer.tunnelStarted, peer.tunnelClosed)
	default:
		peer.fail(writer, E.New("CERT1 peer received unexpected request: ", request.Method, " ", request.URL.Path))
	}
}

func (peer *m1CERT1Peer) handleInitialRequest(writer http.ResponseWriter, request *http.Request) {
	body, loaded := readM1LegacyCertificateRequest(peer.errors, writer, request)
	if !loaded {
		return
	}
	var initialRequest m1CERT1InitialRequest
	err := xml.Unmarshal(body, &initialRequest)
	if err != nil {
		peer.fail(writer, E.Cause(err, "parse CERT1 XMLPOST initialization"))
		return
	}
	if initialRequest.XMLName.Local != "config-auth" || initialRequest.Type != "init" {
		peer.fail(writer, E.New("CERT1 peer received an invalid XMLPOST initialization"))
		return
	}
	hasFailureMarker := initialRequest.ClientCertificateFailure != nil
	peer.access.Lock()
	if peer.remoteAlreadyUsed(request.RemoteAddr) {
		peer.access.Unlock()
		peer.fail(writer, E.New("CERT1 authentication request reused TLS connection ", request.RemoteAddr))
		return
	}
	peer.initialAuthenticationRemotes = append(peer.initialAuthenticationRemotes, request.RemoteAddr)
	if hasFailureMarker {
		peer.clientCertificateFailures++
	} else {
		peer.initialRequests++
	}
	initialRequests := peer.initialRequests
	failureRequests := peer.clientCertificateFailures
	peer.access.Unlock()
	if peer.mode == m1CERT1Accepted {
		if hasFailureMarker || failureRequests != 0 || initialRequests > 2 {
			peer.fail(writer, E.New("CERT1 accepted peer received an unexpected client-cert-fail exchange"))
			return
		}
		if initialRequests == 1 {
			if request.TLS == nil || len(request.TLS.PeerCertificates) != 0 {
				peer.fail(writer, E.New("CERT1 first TLS connection unexpectedly carried a client certificate"))
				return
			}
			writeM1CERT1Request(writer)
			return
		}
		if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 ||
			!bytes.Equal(request.TLS.PeerCertificates[0].Raw, peer.expectedCertificate) {
			peer.fail(writer, E.New("CERT1 fresh TLS connection omitted the configured machine certificate"))
			return
		}
		peer.access.Lock()
		peer.authenticationComplete = true
		peer.access.Unlock()
		writeM1CERT1AuthenticationSuccess(writer)
		return
	}
	if request.TLS == nil || len(request.TLS.PeerCertificates) != 0 {
		peer.fail(writer, E.New("CERT1 failure peer unexpectedly received a TLS client certificate"))
		return
	}
	expectedInitialRequests := 1
	if peer.mode == m1CERT1ConfiguredUnaccepted {
		expectedInitialRequests = 2
	}
	if initialRequests > expectedInitialRequests || failureRequests > 1 ||
		(hasFailureMarker && initialRequests != expectedInitialRequests) {
		peer.fail(writer, E.New("CERT1 failure peer detected a retry loop"))
		return
	}
	writeM1CERT1Request(writer)
}

func (peer *m1CERT1Peer) handleLegacyRequest(writer http.ResponseWriter, request *http.Request) {
	body, loaded := readM1LegacyCertificateRequest(peer.errors, writer, request)
	if !loaded {
		return
	}
	peer.access.Lock()
	expectedInitialRequests := 1
	if peer.mode == m1CERT1ConfiguredUnaccepted {
		expectedInitialRequests = 2
	}
	validState := peer.mode != m1CERT1Accepted &&
		peer.initialRequests == expectedInitialRequests &&
		peer.clientCertificateFailures == 1 &&
		peer.legacyRequests == 0
	peer.legacyRequests++
	peer.access.Unlock()
	if !validState || len(body) != 0 {
		peer.fail(writer, E.New("CERT1 peer entered legacy authentication before exactly one client-cert-fail"))
		return
	}
	writer.Header().Set("Content-Type", "application/xml")
	_, err := io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<auth id="cert1-legacy">
<form method="post" action="cert-submit">
<input type="hidden" name="cert-state" value="fallback accepted" />
</form>
</auth>`)
	if err != nil {
		reportM1LegacyCertificateError(peer.errors, E.Cause(err, "write CERT1 legacy fallback form"))
	}
}

func (peer *m1CERT1Peer) handleLegacyFormSubmission(writer http.ResponseWriter, request *http.Request) {
	body, loaded := readM1LegacyCertificateRequest(peer.errors, writer, request)
	if !loaded {
		return
	}
	peer.access.Lock()
	validState := peer.legacyRequests == 1 && peer.legacyFormSubmissions == 0 && peer.clientCertificateFailures == 1
	peer.legacyFormSubmissions++
	if validState {
		peer.authenticationComplete = true
	}
	peer.access.Unlock()
	if !validState || string(body) != "cert-state=fallback%20accepted" {
		peer.fail(writer, E.New("CERT1 peer rejected legacy fallback form: ", string(body)))
		return
	}
	writeM1LegacyCertificateAuthenticationSuccess(writer, "cert1-session-cookie")
}

func (peer *m1CERT1Peer) remoteAlreadyUsed(remote string) bool {
	for _, previousRemote := range peer.initialAuthenticationRemotes {
		if previousRemote == remote {
			return true
		}
	}
	return false
}

func (peer *m1CERT1Peer) fail(writer http.ResponseWriter, err error) {
	reportM1LegacyCertificateError(peer.errors, err)
	writer.WriteHeader(http.StatusInternalServerError)
}

func readM1LegacyCertificateRequest(
	errors chan<- error,
	writer http.ResponseWriter,
	request *http.Request,
) ([]byte, bool) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		reportM1LegacyCertificateError(errors, E.Cause(err, "read legacy/CERT1 consumer request"))
		writer.WriteHeader(http.StatusInternalServerError)
		return nil, false
	}
	return body, true
}

func writeM1CERT1Request(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<client-cert-request />
</config-auth>`)
}

func writeM1CERT1AuthenticationSuccess(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{Name: "webvpn", Value: "cert1-session-cookie", Path: "/", Secure: true})
	writer.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>cert1-session-cookie</session-token>
<client-cert-request />
<cert-authenticated />
<auth id="success" />
</config-auth>`)
}

func writeM1LegacyCertificateAuthenticationSuccess(writer http.ResponseWriter, cookie string) {
	http.SetCookie(writer, &http.Cookie{Name: "webvpn", Value: cookie, Path: "/", Secure: true})
	writer.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>`+cookie+`</session-token>
<auth id="success" />
</config-auth>`)
}

func serveM1LegacyCertificateTunnel(
	writer http.ResponseWriter,
	errors chan<- error,
	started chan<- struct{},
	closed chan<- error,
) {
	hijacker, supported := writer.(http.Hijacker)
	if !supported {
		err := E.New("legacy/CERT1 consumer response writer cannot hijack CSTP CONNECT")
		reportM1LegacyCertificateError(errors, err)
		closed <- err
		return
	}
	connection, readWriter, err := hijacker.Hijack()
	if err != nil {
		err = E.Cause(err, "hijack legacy/CERT1 CSTP connection")
		reportM1LegacyCertificateError(errors, err)
		closed <- err
		return
	}
	defer connection.Close()
	_, err = readWriter.WriteString("HTTP/1.1 200 CONNECTED\r\n" +
		"X-CSTP-MTU: 1400\r\n" +
		"X-CSTP-Address: 192.0.2.20\r\n" +
		"X-CSTP-Netmask: 255.255.255.0\r\n" +
		"X-CSTP-DPD: 30\r\n" +
		"X-CSTP-Keepalive: 30\r\n" +
		"X-CSTP-Rekey-Method: none\r\n\r\n")
	if err == nil {
		err = readWriter.Flush()
	}
	if err != nil {
		err = E.Cause(err, "write legacy/CERT1 CSTP response")
		reportM1LegacyCertificateError(errors, err)
		closed <- err
		return
	}
	started <- struct{}{}
	header := make([]byte, 8)
	_, err = io.ReadFull(readWriter, header)
	if err == nil && (!bytes.Equal(header[:4], []byte{'S', 'T', 'F', 1}) || header[6] != 5 || header[7] != 0) {
		err = E.New("legacy/CERT1 consumer received an invalid CSTP disconnect header")
	}
	if err == nil {
		payload := make([]byte, int(binary.BigEndian.Uint16(header[4:6])))
		_, err = io.ReadFull(readWriter, payload)
		if err == nil && (len(payload) == 0 || payload[0] != 0xb0) {
			err = E.New("legacy/CERT1 consumer received an invalid CSTP disconnect payload")
		}
	}
	if err != nil {
		err = E.Cause(err, "consume active legacy/CERT1 CSTP close")
		reportM1LegacyCertificateError(errors, err)
	}
	closed <- err
}

func waitForM1LegacyCertificateTunnel(
	t *testing.T,
	ctx context.Context,
	errors <-chan error,
	started <-chan struct{},
) {
	t.Helper()
	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for legacy/CERT1 CSTP tunnel"))
	case err := <-errors:
		t.Fatal(err)
	case <-started:
	}
}

func waitForM1LegacyCertificateTunnelClose(
	t *testing.T,
	ctx context.Context,
	errors <-chan error,
	closed <-chan error,
) {
	t.Helper()
	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for active legacy/CERT1 CSTP close"))
	case err := <-errors:
		t.Fatal(err)
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	}
}

func waitForM1CrossHostAuthForm(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	errors <-chan error,
) *openconnect.AuthChallenge {
	t.Helper()
	for {
		form := client.PendingAuthChallenge()
		if form != nil {
			return form
		}
		updated := client.AuthChallengeUpdated()
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for cross-host authentication form"))
		case err := <-errors:
			t.Fatal(err)
		case <-updated:
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func reportM1LegacyCertificateError(errors chan<- error, err error) {
	select {
	case errors <- err:
	default:
	}
}

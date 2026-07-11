package test

import (
	"context"
	"crypto/tls"
	"encoding/base32"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
)

type m1SSOBrowser struct {
	requests chan openconnect.BrowserRequest
	release  chan struct{}
}

type m1SSOSubmission struct {
	XMLName xml.Name `xml:"config-auth"`
	Type    string   `xml:"type,attr"`
	Auth    struct {
		Username          string `xml:"username"`
		State             string `xml:"state"`
		SecondaryPassword string `xml:"secondary_password"`
		Token             string `xml:"sso_token"`
	} `xml:"auth"`
}

func TestM1AnyConnectSSOCompanionInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	consumerErrors := make(chan error, 8)
	tunnelStarted := make(chan struct{}, 1)
	clientDataObserved := make(chan struct{}, 1)
	tunnelClosed := make(chan error, 1)
	var persistedCounter atomic.Uint64
	var consumerURL string
	consumer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			select {
			case consumerErrors <- E.Cause(err, "read SSO consumer request"):
			default:
			}
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/" && strings.Contains(string(body), `type="init"`):
			writer.Header().Set("Content-Type", "application/xml")
			_, err = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<auth id="sso-main">
<message>Complete the companion identity field, then sign in.</message>
<sso-v2-login>/browser/login</sso-v2-login>
<sso-v2-login-final>/browser/final</sso-v2-login-final>
<sso-v2-token-cookie-name>sso-token</sso-v2-token-cookie-name>
<sso-v2-error-cookie-name>sso-error</sso-v2-error-cookie-name>
<form method="post" action="/auth">
<input type="text" name="username" label="Companion username:" />
<input type="hidden" name="state" value="server-state" />
<input type="password" name="secondary_password" label="One-time password:" />
<input type="sso" name="sso_token" label="SSO token:" />
</form>
</auth>
</config-auth>`)
			if err != nil {
				select {
				case consumerErrors <- E.Cause(err, "write SSO challenge"):
				default:
				}
			}
		case request.Method == http.MethodPost && request.URL.Path == "/auth":
			var submission m1SSOSubmission
			err = xml.Unmarshal(body, &submission)
			if err != nil {
				select {
				case consumerErrors <- E.Cause(err, "parse SSO authentication reply"):
				default:
				}
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			if submission.Type != "auth-reply" ||
				submission.Auth.Username != "companion-user" ||
				submission.Auth.State != "server-state" ||
				submission.Auth.SecondaryPassword != "755224" ||
				submission.Auth.Token != "browser-token" {
				select {
				case consumerErrors <- E.New(
					"SSO consumer rejected authentication reply: type=", submission.Type,
					" username=", submission.Auth.Username,
					" state=", submission.Auth.State,
					" secondary_password=", submission.Auth.SecondaryPassword,
					" token=", submission.Auth.Token,
				):
				default:
				}
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.SetCookie(writer, &http.Cookie{Name: "webvpn", Value: "sso-session-cookie", Path: "/", Secure: true})
			writer.Header().Set("Content-Type", "application/xml")
			_, err = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>sso-session-cookie</session-token>
<auth id="success" />
</config-auth>`)
			if err != nil {
				select {
				case consumerErrors <- E.Cause(err, "write SSO authentication success"):
				default:
				}
				return
			}
		case request.Method == http.MethodConnect:
			if request.RequestURI != "/CSCOSSLC/tunnel" || request.URL.Path != "/CSCOSSLC/tunnel" || request.URL.RawQuery != "" {
				reportM1SSOConsumerError(consumerErrors, E.New("SSO consumer received CSTP CONNECT at unexpected target: ", request.RequestURI))
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			cookieHeaders := request.Header.Values("Cookie")
			if len(cookieHeaders) != 1 || cookieHeaders[0] != "webvpn=sso-session-cookie" {
				reportM1SSOConsumerError(consumerErrors, E.New("SSO consumer received unexpected CSTP cookie headers: ", strings.Join(cookieHeaders, ", ")))
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			serveM1SSOCSTPTunnel(writer, consumerErrors, tunnelStarted, clientDataObserved, tunnelClosed)
		default:
			reportM1SSOConsumerError(consumerErrors, E.New("SSO consumer received unexpected request: ", request.Method, " ", request.URL.Path, " at ", consumerURL))
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	consumerURL = consumer.URL
	t.Cleanup(consumer.Close)

	browser := &m1SSOBrowser{
		requests: make(chan openconnect.BrowserRequest, 1),
		release:  make(chan struct{}),
	}
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  strings.TrimPrefix(consumer.URL, "https://"),
		Flavor:  openconnect.FlavorAnyConnect,
		NoUDP:   true,
		Browser: browser,
		Token: &openconnect.TokenOptions{
			Mode:    openconnect.TokenModeHOTP,
			Secret:  base32.StdEncoding.EncodeToString([]byte("12345678901234567890")),
			Counter: 0,
			UpdateCounter: func(_ context.Context, counter uint64) error {
				persistedCounter.Store(counter)
				return nil
			},
		},
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
		}},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create AnyConnect SSO client"))
	}
	t.Cleanup(func() {
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosed(closeErr) {
			t.Error(E.Cause(closeErr, "close AnyConnect SSO client"))
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start AnyConnect SSO client"))
	}
	companionForm := waitForM1AuthForm(t, ctx, client)
	if companionForm.URL != "" || len(companionForm.Fields) != 1 || companionForm.Fields[0].Name != "username" {
		t.Fatalf("SSO companion stage was not a standalone visible form: %#v", companionForm)
	}
	err = client.CompleteAuthForm(companionForm.ID, map[string]string{
		companionForm.Fields[0].SubmissionKey: "companion-user",
	})
	if err != nil {
		t.Fatal(E.Cause(err, "complete AnyConnect SSO companion form"))
	}

	var browserRequest openconnect.BrowserRequest
	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for AnyConnect BrowserRequest"))
	case consumerErr := <-consumerErrors:
		t.Fatal(consumerErr)
	case browserRequest = <-browser.requests:
	}
	expectedLoginURL := consumer.URL + "/browser/login"
	expectedFinalURL := consumer.URL + "/browser/final"
	if browserRequest.URL != expectedLoginURL || browserRequest.FinalURL != expectedFinalURL {
		t.Fatalf("unexpected AnyConnect BrowserRequest URLs: %#v", browserRequest)
	}
	if len(browserRequest.CookieNames) != 2 || browserRequest.CookieNames[0] != "sso-token" || browserRequest.CookieNames[1] != "sso-error" {
		t.Fatalf("unexpected AnyConnect BrowserRequest cookies: %#v", browserRequest.CookieNames)
	}
	if len(browserRequest.HeaderNames) != 0 {
		t.Fatalf("unexpected AnyConnect BrowserRequest headers: %#v", browserRequest.HeaderNames)
	}
	browserForm := client.PendingAuthForm()
	if browserForm == nil || browserForm.URL != expectedLoginURL || len(browserForm.Fields) != 0 {
		t.Fatalf("SSO browser stage was not published through PendingAuthForm: %#v", browserForm)
	}
	if persistedCounter.Load() != 0 {
		t.Fatalf("HOTP counter advanced before browser completion: %d", persistedCounter.Load())
	}
	close(browser.release)

	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for SSO consumer CSTP tunnel"))
	case consumerErr := <-consumerErrors:
		t.Fatal(consumerErr)
	case <-tunnelStarted:
	}
	waitForM1SSOStableReady(t, ctx, client, consumerErrors)
	if persistedCounter.Load() != 1 {
		t.Fatalf("HOTP counter after SSO submission is %d, expected 1", persistedCounter.Load())
	}
	readContext, cancelRead := context.WithTimeout(ctx, 5*time.Second)
	serverPayload, err := client.ReadDataPacket(readContext)
	cancelRead()
	if err != nil {
		t.Fatal(E.Cause(err, "read SSO CSTP server data"))
	}
	if string(serverPayload) != "sso-server-cstp-data" {
		t.Fatalf("unexpected SSO CSTP server data: %q", serverPayload)
	}
	err = client.WriteDataPacket([]byte("sso-client-cstp-data"))
	if err != nil {
		t.Fatal(E.Cause(err, "write SSO CSTP client data"))
	}
	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for SSO consumer CSTP client data"))
	case consumerErr := <-consumerErrors:
		t.Fatal(consumerErr)
	case <-clientDataObserved:
	}
	const closeCallerCount = 16
	startClose := make(chan struct{})
	closeResults := make(chan error, closeCallerCount)
	for i := 0; i < closeCallerCount; i++ {
		go func() {
			<-startClose
			closeResults <- client.Close()
		}()
	}
	close(startClose)
	for i := 0; i < closeCallerCount; i++ {
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for concurrent AnyConnect SSO Client.Close calls"))
		case closeErr := <-closeResults:
			if closeErr != nil && !E.IsClosed(closeErr) {
				t.Fatal(E.Cause(closeErr, "close established AnyConnect SSO tunnel"))
			}
		}
	}
	if client.Ready() {
		t.Fatal("AnyConnect SSO client remained Ready after Client.Close")
	}
	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for SSO consumer CSTP close"))
	case consumerErr := <-consumerErrors:
		t.Fatal(consumerErr)
	case tunnelErr := <-tunnelClosed:
		if tunnelErr != nil {
			t.Fatal(tunnelErr)
		}
	}
	if client.Ready() {
		t.Fatal("AnyConnect SSO client republished Ready after its CSTP tunnel closed")
	}
}

func (b *m1SSOBrowser) Authenticate(ctx context.Context, request openconnect.BrowserRequest) (openconnect.BrowserResult, error) {
	select {
	case <-ctx.Done():
		return openconnect.BrowserResult{}, ctx.Err()
	case b.requests <- request:
	}
	select {
	case <-ctx.Done():
		return openconnect.BrowserResult{}, ctx.Err()
	case <-b.release:
	}
	return openconnect.BrowserResult{
		FinalURL: request.FinalURL,
		Cookies:  []openconnect.BrowserCookie{{Name: "sso-token", Value: "browser-token"}},
		Header:   http.Header{"X-Sso-Consumer-Proof": []string{"browser-proof"}},
	}, nil
}

func reportM1SSOConsumerError(errors chan<- error, err error) {
	select {
	case errors <- err:
	default:
	}
}

func waitForM1SSOStableReady(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	consumerErrors <-chan error,
) {
	t.Helper()
	var readySince time.Time
	for {
		now := time.Now()
		if client.Ready() {
			if readySince.IsZero() {
				readySince = now
			} else if now.Sub(readySince) >= 50*time.Millisecond {
				return
			}
		} else {
			readySince = time.Time{}
		}
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for stable AnyConnect SSO readiness"))
		case consumerErr := <-consumerErrors:
			t.Fatal(consumerErr)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func serveM1SSOCSTPTunnel(
	writer http.ResponseWriter,
	errors chan<- error,
	started chan<- struct{},
	clientDataObserved chan<- struct{},
	closed chan<- error,
) {
	hijacker, supported := writer.(http.Hijacker)
	if !supported {
		err := E.New("SSO consumer response writer cannot hijack CSTP CONNECT")
		reportM1SSOConsumerError(errors, err)
		closed <- err
		return
	}
	connection, readWriter, err := hijacker.Hijack()
	if err != nil {
		err = E.Cause(err, "hijack SSO CSTP connection")
		reportM1SSOConsumerError(errors, err)
		closed <- err
		return
	}
	defer connection.Close()
	err = connection.SetDeadline(time.Now().Add(15 * time.Second))
	if err == nil {
		_, err = readWriter.WriteString("HTTP/1.1 200 CONNECTED\r\n" +
			"X-CSTP-MTU: 1400\r\n" +
			"X-CSTP-Address: 192.0.2.10\r\n" +
			"X-CSTP-Netmask: 255.255.255.0\r\n" +
			"X-CSTP-DPD: 30\r\n" +
			"X-CSTP-Keepalive: 30\r\n" +
			"X-CSTP-Rekey-Method: none\r\n\r\n")
	}
	if err == nil {
		err = readWriter.Flush()
	}
	if err == nil {
		err = writeM1CSTPWireRecord(readWriter, anyConnectPacketData, []byte("sso-server-cstp-data"))
	}
	if err != nil {
		err = E.Cause(err, "establish SSO CSTP tunnel")
		reportM1SSOConsumerError(errors, err)
		closed <- err
		return
	}
	started <- struct{}{}
	packetType, payload, err := readM1CSTPWireRecord(readWriter)
	if err == nil && (packetType != anyConnectPacketData || string(payload) != "sso-client-cstp-data") {
		err = E.New("SSO consumer received unexpected CSTP client data: type=", packetType, " payload=", string(payload))
	}
	if err != nil {
		err = E.Cause(err, "consume SSO CSTP client data")
		reportM1SSOConsumerError(errors, err)
		closed <- err
		return
	}
	clientDataObserved <- struct{}{}
	packetType, payload, err = readM1CSTPWireRecord(readWriter)
	if err == nil && (packetType != 5 || string(payload) != "\xb0Client disconnect") {
		err = E.New("SSO consumer received unexpected CSTP close: type=", packetType, " payload=", string(payload))
	}
	if err != nil {
		err = E.Cause(err, "consume SSO CSTP client close")
		reportM1SSOConsumerError(errors, err)
	}
	closed <- err
}

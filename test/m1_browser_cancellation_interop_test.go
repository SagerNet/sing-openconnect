package test

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
)

type m1IgnoringContextBrowser struct {
	requests chan openconnect.BrowserRequest
	release  chan struct{}
	returned chan struct{}
}

func TestM1BrowserCancellationDoesNotBlockClientClose(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	consumerErrors := make(chan error, 4)
	consumer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			reportM1LegacyCertificateError(consumerErrors, E.Cause(err, "read browser cancellation consumer request"))
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		if request.Method != http.MethodPost || request.URL.Path != "/" || !strings.Contains(string(body), `type="init"`) {
			reportM1LegacyCertificateError(consumerErrors, E.New("browser cancellation consumer received an unexpected request"))
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/xml")
		_, err = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<auth id="browser-cancel">
<sso-v2-login>/browser/login</sso-v2-login>
<sso-v2-login-final>/browser/final</sso-v2-login-final>
<sso-v2-token-cookie-name>sso-token</sso-v2-token-cookie-name>
<sso-v2-error-cookie-name>sso-error</sso-v2-error-cookie-name>
<form method="post" action="/auth">
<input type="sso" name="sso_token" label="SSO token:" />
</form>
</auth>
</config-auth>`)
		if err != nil {
			reportM1LegacyCertificateError(consumerErrors, E.Cause(err, "write browser cancellation SSO challenge"))
		}
	}))
	t.Cleanup(consumer.Close)

	browser := &m1IgnoringContextBrowser{
		requests: make(chan openconnect.BrowserRequest, 1),
		release:  make(chan struct{}),
		returned: make(chan struct{}),
	}
	var releaseOnce sync.Once
	releaseBrowser := func() {
		releaseOnce.Do(func() {
			close(browser.release)
		})
	}
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  consumer.URL,
		Flavor:  openconnect.FlavorAnyConnect,
		NoUDP:   true,
		Browser: browser,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
		}},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create browser cancellation client"))
	}
	t.Cleanup(func() {
		releaseBrowser()
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosed(closeErr) {
			t.Error(E.Cause(closeErr, "cleanup browser cancellation client"))
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start browser cancellation client"))
	}
	var browserRequest openconnect.BrowserRequest
	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for context-ignoring browser adapter"))
	case consumerErr := <-consumerErrors:
		t.Fatal(consumerErr)
	case browserRequest = <-browser.requests:
	}
	expectedLoginURL := consumer.URL + "/browser/login"
	if browserRequest.URL != expectedLoginURL {
		t.Fatalf("context-ignoring browser received unexpected request: %#v", browserRequest)
	}
	form := waitForM1AuthForm(t, ctx, client)
	if form.URL != expectedLoginURL || len(form.Fields) != 0 {
		t.Fatalf("browser cancellation form was not published: %#v", form)
	}
	err = client.CancelAuthForm(form.ID)
	if err != nil {
		t.Fatal(E.Cause(err, "cancel context-ignoring browser form"))
	}
	if pendingForm := client.PendingAuthForm(); pendingForm != nil {
		t.Fatalf("canceled browser form remained pending: %#v", pendingForm)
	}
	select {
	case <-browser.returned:
		t.Fatal("context-ignoring browser returned before terminal cancellation was observed")
	default:
	}
	readContext, cancelRead := context.WithTimeout(ctx, 2*time.Second)
	_, readErr := client.ReadDataPacket(readContext)
	cancelRead()
	if !E.IsMulti(readErr, openconnect.ErrAuthFormCanceled) {
		t.Fatalf("CancelAuthForm did not immediately make ReadDataPacket terminal: %v", readErr)
	}
	select {
	case <-browser.returned:
		t.Fatal("context-ignoring browser returned while terminal cancellation was observed")
	default:
	}
	closeResult := make(chan error, 1)
	go func() {
		closeResult <- client.Close()
	}()
	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "close client with context-ignoring browser adapter"))
	case <-time.After(2 * time.Second):
		t.Fatal("Client.Close blocked on a context-ignoring browser adapter")
	case closeErr := <-closeResult:
		if closeErr != nil && !E.IsClosed(closeErr) {
			t.Fatal(E.Cause(closeErr, "close browser cancellation client"))
		}
	}
	select {
	case <-browser.returned:
		t.Fatal("context-ignoring browser returned before the test released it")
	default:
	}
	releaseBrowser()
	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "release context-ignoring browser adapter"))
	case <-browser.returned:
	}
}

func (browser *m1IgnoringContextBrowser) Authenticate(
	_ context.Context,
	request openconnect.BrowserRequest,
) (openconnect.BrowserResult, error) {
	browser.requests <- request
	<-browser.release
	close(browser.returned)
	return openconnect.BrowserResult{
		FinalURL: request.FinalURL,
		Cookies:  []openconnect.BrowserCookie{{Name: "sso-token", Value: "too-late"}},
	}, nil
}

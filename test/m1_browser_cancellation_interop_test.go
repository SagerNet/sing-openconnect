package test

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
)

func TestM1BrowserChallengeCancellationDoesNotBlockClientClose(t *testing.T) {
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

	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: ctx,
		Server:  consumer.URL,
		Flavor:  openconnect.FlavorAnyConnect,
		NoUDP:   true,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			InsecureSkipVerify: true,
		}},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create browser cancellation client"))
	}
	t.Cleanup(func() {
		closeErr := client.Close()
		if closeErr != nil && !E.IsClosed(closeErr) {
			t.Error(E.Cause(closeErr, "cleanup browser cancellation client"))
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start browser cancellation client"))
	}
	form := waitForM1AuthForm(t, ctx, client)
	expectedLoginURL := consumer.URL + "/browser/login"
	if form.Form != nil || form.Browser == nil || form.Browser.URL != expectedLoginURL {
		t.Fatalf("browser cancellation form was not published: %#v", form)
	}
	err = client.CancelAuthChallenge(form.ID)
	if err != nil {
		t.Fatal(E.Cause(err, "cancel context-ignoring browser form"))
	}
	if pendingForm := client.PendingAuthChallenge(); pendingForm != nil {
		t.Fatalf("canceled browser form remained pending: %#v", pendingForm)
	}
	readContext, cancelRead := context.WithTimeout(ctx, 2*time.Second)
	_, readErr := client.ReadDataPacket(readContext)
	cancelRead()
	if !E.IsMulti(readErr, openconnect.ErrAuthChallengeCanceled) {
		t.Fatalf("CancelAuthChallenge did not immediately make ReadDataPacket terminal: %v", readErr)
	}
	closeResult := make(chan error, 1)
	go func() {
		closeResult <- client.Close()
	}()
	select {
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "close client with a canceled browser challenge"))
	case <-time.After(2 * time.Second):
		t.Fatal("Client.Close blocked on a context-ignoring browser adapter")
	case closeErr := <-closeResult:
		if closeErr != nil && !E.IsClosed(closeErr) {
			t.Fatal(E.Cause(closeErr, "close browser cancellation client"))
		}
	}
}

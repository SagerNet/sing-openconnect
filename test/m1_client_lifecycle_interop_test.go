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

func TestM1SessionRejectionBackoffAndConcurrentClose(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	consumerErrors := make(chan error, 8)
	connectAttempts := make(chan time.Time, 8)
	consumer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodPost:
			body, err := io.ReadAll(request.Body)
			if err != nil {
				reportM1LifecycleConsumerError(consumerErrors, E.Cause(err, "read session rejection authentication request"))
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			if request.URL.Path != "/" || !strings.Contains(string(body), `type="init"`) {
				reportM1LifecycleConsumerError(consumerErrors, E.New("session rejection consumer received an unexpected authentication request"))
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			http.SetCookie(writer, &http.Cookie{Name: "webvpn", Value: "rejected-session", Path: "/", Secure: true})
			writer.Header().Set("Content-Type", "application/xml")
			_, err = io.WriteString(writer, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-token>rejected-session</session-token>
<auth id="success" />
</config-auth>`)
			if err != nil {
				reportM1LifecycleConsumerError(consumerErrors, E.Cause(err, "write session rejection authentication response"))
			}
		case http.MethodConnect:
			if request.URL.Path != "/CSCOSSLC/tunnel" || !strings.Contains(request.Header.Get("Cookie"), "webvpn=rejected-session") {
				reportM1LifecycleConsumerError(consumerErrors, E.New("session rejection consumer received an invalid CSTP CONNECT"))
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			select {
			case connectAttempts <- time.Now():
			default:
			}
			writer.WriteHeader(http.StatusUnauthorized)
		default:
			reportM1LifecycleConsumerError(consumerErrors, E.New("session rejection consumer received an unexpected method: ", request.Method))
			writer.WriteHeader(http.StatusMethodNotAllowed)
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
		t.Fatal(E.Cause(err, "create session rejection client"))
	}
	t.Cleanup(func() {
		closeErr := client.Close()
		if closeErr != nil {
			t.Error(E.Cause(closeErr, "cleanup session rejection client"))
		}
	})
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start session rejection client"))
	}

	attemptTimes := make([]time.Time, 0, 3)
	for len(attemptTimes) < 3 {
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for rejected CSTP CONNECT attempts"))
		case consumerErr := <-consumerErrors:
			t.Fatal(consumerErr)
		case attemptTime := <-connectAttempts:
			attemptTimes = append(attemptTimes, attemptTime)
		}
	}
	firstDelay := attemptTimes[1].Sub(attemptTimes[0])
	secondDelay := attemptTimes[2].Sub(attemptTimes[1])
	if firstDelay < 800*time.Millisecond || secondDelay < 1600*time.Millisecond {
		t.Fatalf("consecutive CSTP session rejection retries did not back off exponentially: first=%s second=%s", firstDelay, secondDelay)
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
	closeDeadline := time.NewTimer(500 * time.Millisecond)
	defer closeDeadline.Stop()
	for i := 0; i < closeCallerCount; i++ {
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for concurrent Client.Close calls"))
		case <-closeDeadline.C:
			t.Fatal("concurrent Client.Close calls did not cancel the reconnect backoff promptly")
		case closeErr := <-closeResults:
			if closeErr != nil {
				t.Fatal(E.Cause(closeErr, "close session rejection client"))
			}
		}
	}
	select {
	case consumerErr := <-consumerErrors:
		t.Fatal(consumerErr)
	default:
	}
}

func reportM1LifecycleConsumerError(errors chan<- error, err error) {
	select {
	case errors <- err:
	default:
	}
}

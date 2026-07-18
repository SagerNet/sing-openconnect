package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	m4NCGatewayHostname  = "gateway.m4-nc-auth.test"
	m4NCIdentityHostname = "identity.m4-nc-auth.test"
	m4NCUsername         = "network user"
	m4NCPassword         = "network password"
)

type m4NCAuthenticationPeer struct {
	access        sync.Mutex
	gateway       *httptest.Server
	identity      *httptest.Server
	lure          *httptest.Server
	gatewayURL    string
	identityURL   string
	dialer        *m4NCDialer
	errors        chan error
	logout        chan struct{}
	logoutOnce    sync.Once
	roleSelection string
	lureRequests  int
	connections   map[net.Conn]http.ConnState
}

type m4NCDialer struct {
	access                   sync.Mutex
	routes                   map[string]M.Socksaddr
	gatewayHostname          string
	gatewayAddress           M.Socksaddr
	lureAddress              M.Socksaddr
	poisoned                 bool
	hostnameDialsAfterPoison int
	pinnedDialsAfterPoison   int
}

func TestM4NetworkConnectAuthenticationPeerInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	rootCertificate, serverCertificates := createM4NCCertificates(t, []string{
		m4NCGatewayHostname,
		m4NCIdentityHostname,
		m4NCGatewayHostname,
	})
	peer := &m4NCAuthenticationPeer{
		errors:      make(chan error, 16),
		logout:      make(chan struct{}),
		connections: make(map[net.Conn]http.ConnState),
	}
	peer.gateway = httptest.NewUnstartedServer(http.HandlerFunc(peer.serveGateway))
	peer.gateway.Config.ConnState = peer.recordConnectionState
	peer.gateway.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCertificates[0]}}
	peer.gateway.StartTLS()
	t.Cleanup(peer.gateway.Close)
	peer.identity = newM2GPTLSServer(t, serverCertificates[1], http.HandlerFunc(peer.serveIdentity))
	peer.lure = newM2GPTLSServer(t, serverCertificates[2], http.HandlerFunc(peer.serveLure))
	gatewayAddress := M.SocksaddrFromNet(peer.gateway.Listener.Addr())
	identityAddress := M.SocksaddrFromNet(peer.identity.Listener.Addr())
	lureAddress := M.SocksaddrFromNet(peer.lure.Listener.Addr())
	peer.gatewayURL = "https://" + net.JoinHostPort(m4NCGatewayHostname, strconv.Itoa(int(gatewayAddress.Port)))
	peer.identityURL = "https://" + net.JoinHostPort(m4NCIdentityHostname, strconv.Itoa(int(identityAddress.Port)))
	peer.dialer = &m4NCDialer{
		routes: map[string]M.Socksaddr{
			m4NCGatewayHostname:  gatewayAddress,
			m4NCIdentityHostname: identityAddress,
		},
		gatewayHostname: m4NCGatewayHostname,
		gatewayAddress:  gatewayAddress,
		lureAddress:     lureAddress,
	}
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context:   ctx,
		Server:    peer.gatewayURL + "/start",
		Flavor:    openconnect.FlavorNC,
		Username:  m4NCUsername,
		Password:  m4NCPassword,
		AuthGroup: "Realm B",
		Token: &openconnect.TokenOptions{
			Mode:   openconnect.TokenModeTOTP,
			Secret: "JBSWY3DPEHPK3PXP",
		},
		NoUDP:  true,
		Dialer: peer.dialer,
		TLSConfig: openconnect.ClientTLSOptions{
			CertificateAuthority: openconnect.Material{Content: rootCertificate},
		},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create Network Connect authentication peer client"))
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start Network Connect authentication peer client"))
	}
	terminalErrors := make(chan error, 1)
	go func() {
		_, readErr := client.ReadDataPacket(ctx)
		terminalErrors <- readErr
	}()
	for {
		form := client.PendingAuthChallenge()
		if form != nil {
			if form.Browser != nil || form.Form == nil || form.Banner != "frmSelectRoles" || len(form.Form.Fields) != 1 {
				t.Fatalf("unexpected Network Connect authentication form: %#v", form)
			}
			selected := ""
			for _, choice := range form.Form.Fields[0].Options {
				if choice.Label == "Role B" {
					selected = choice.Value
				}
			}
			if selected == "" {
				t.Fatal("Network Connect role form omitted Role B")
			}
			err = client.CompleteAuthChallenge(form.ID, openconnect.AuthResponse{Form: &openconnect.AuthFormResponse{Values: map[string]string{form.Form.Fields[0].SubmissionKey: selected}}})
			if err != nil {
				t.Fatal(E.Cause(err, "complete Network Connect role selection"))
			}
		}
		select {
		case peerErr := <-peer.errors:
			t.Fatal(peerErr)
		case terminalErr := <-terminalErrors:
			if terminalErr == nil {
				t.Fatal("Network Connect authentication ended without a terminal error")
			}
			if !strings.Contains(terminalErr.Error(), "oNCP endpoint returned HTTP 500") {
				t.Fatal(E.Cause(terminalErr, "unexpected Network Connect authentication terminal result"))
			}
			select {
			case <-peer.logout:
			case <-ctx.Done():
				t.Fatal(E.Cause(ctx.Err(), "wait for pinned Network Connect logout"))
			}
			peer.assertResults(t, ctx)
			return
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for Network Connect authentication peer"))
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (p *m4NCAuthenticationPeer) serveGateway(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/start":
		if request.Method != http.MethodGet {
			p.fail(writer, E.New("Network Connect initial request was not GET"))
			return
		}
		http.Redirect(writer, request, "/welcome", http.StatusFound)
	case "/welcome":
		writer.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(writer, `<html><body><form name="frmLogin" method="post" action="/login">
<input type="text" name="username"/>
<input type="password" name="password"/>
<input type="password" name="token_as_second_password"/>
<input type="submit" value="Sign In" name="btnSubmit"/>
<select name="realm"><option value="0">Realm A</option><option value="1">Realm B</option></select>
</form></body></html>`)
	case "/login":
		body, valid := p.requirePOST(writer, request)
		if !valid {
			return
		}
		values, err := url.ParseQuery(body)
		if err != nil {
			p.fail(writer, E.Cause(err, "parse Network Connect login form"))
			return
		}
		tokenPattern := regexp.MustCompile(`^\d{6}$`)
		if values.Get("username") != m4NCUsername || values.Get("password") != m4NCPassword || values.Get("realm") != "1" || !tokenPattern.MatchString(values.Get("token_as_second_password")) || values.Get("btnSubmit") != "Sign In" {
			p.fail(writer, E.New("Network Connect login form values were not preserved"))
			return
		}
		http.Redirect(writer, request, "/roles", http.StatusFound)
	case "/roles":
		writer.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(writer, `<html><body><form name="frmSelectRoles"><table id="TABLE_SelectRole_1">
<tr><td><a href="/role-selected?role=0">Role A</a></td></tr>
<tr><td><a href="/role-selected?role=1">Role B</a></td></tr>
</table></form></body></html>`)
	case "/role-selected":
		if request.Method != http.MethodGet || request.URL.Query().Get("role") != "1" {
			p.fail(writer, E.New("Network Connect selected the wrong role URL"))
			return
		}
		p.access.Lock()
		p.roleSelection = request.URL.Query().Get("role")
		p.access.Unlock()
		writer.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(writer, `<html><body><form name="frmConfirmation" method="post" action="/confirm">
<input type="hidden" name="confirmation" value="accepted"/>
<input type="submit" name="btnContinue" value="Continue"/>
</form></body></html>`)
	case "/confirm":
		body, valid := p.requirePOST(writer, request)
		if !valid {
			return
		}
		if body != "confirmation=accepted&btnContinue=Continue" {
			p.fail(writer, E.New("Network Connect confirmation form changed ordered hidden fields: ", body))
			return
		}
		writer.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(writer, `<html><body><form name="hiddenform" method="post" action="`+p.identityURL+`/saml">
<input type="hidden" name="RelayState" value="gateway"/>
<input type="hidden" name="SAMLResponse" value="assertion"/>
<input type="submit" value="Submit"/>
</form></body></html>`)
	case "/saml-consumer":
		body, valid := p.requirePOST(writer, request)
		if !valid {
			return
		}
		if body != "RelayState=first&RelayState=second&SAMLResponse=identity-assertion" {
			p.fail(writer, E.New("Network Connect SAML form did not preserve duplicate ordered names: ", body))
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: "DSFirstAccess", Value: "first", Path: "/", Secure: true})
		http.SetCookie(writer, &http.Cookie{Name: "DSLastAccess", Value: "last", Path: "/", Secure: true})
		http.SetCookie(writer, &http.Cookie{Name: "DSSignInUrl", Value: "/start", Path: "/", Secure: true})
		http.SetCookie(writer, &http.Cookie{Name: "DSID", Value: "accepted-session", Path: "/", Secure: true})
		p.dialer.poison()
		writer.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(writer, "landing page forbidden after successful login")
	case "/dana-na/auth/logout.cgi":
		cookie, err := request.Cookie("DSID")
		if err != nil || cookie.Value != "accepted-session" {
			p.fail(writer, E.New("Network Connect pinned logout omitted DSID"))
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "logged out")
		p.logoutOnce.Do(func() {
			close(p.logout)
		})
	case "/dana/js":
		writer.WriteHeader(http.StatusInternalServerError)
	default:
		p.fail(writer, E.New("unexpected Network Connect gateway path: ", request.URL.Path))
	}
}

func (p *m4NCAuthenticationPeer) serveIdentity(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/saml" {
		p.fail(writer, E.New("unexpected Network Connect identity path: ", request.URL.Path))
		return
	}
	body, valid := p.requirePOST(writer, request)
	if !valid {
		return
	}
	if body != "RelayState=gateway&SAMLResponse=assertion" {
		p.fail(writer, E.New("Network Connect cross-origin SAML request changed hidden values: ", body))
		return
	}
	writer.Header().Set("Content-Type", "text/html")
	_, _ = io.WriteString(writer, `<html><body><form id="formSAMLSSO" method="post" action="`+p.gatewayURL+`/saml-consumer">
<input type="hidden" name="RelayState" value="first"/>
<input type="hidden" name="RelayState" value="second"/>
<input type="hidden" name="SAMLResponse" value="identity-assertion"/>
<input type="submit" value="Continue"/>
</form></body></html>`)
}

func (p *m4NCAuthenticationPeer) serveLure(writer http.ResponseWriter, _ *http.Request) {
	p.access.Lock()
	p.lureRequests++
	p.access.Unlock()
	p.fail(writer, E.New("Network Connect followed poisoned DNS after accepting DSID"))
}

func (p *m4NCAuthenticationPeer) requirePOST(writer http.ResponseWriter, request *http.Request) (string, bool) {
	if request.Method != http.MethodPost {
		p.fail(writer, E.New("Network Connect form request was not POST: ", request.URL.Path))
		return "", false
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		p.fail(writer, E.Cause(err, "read Network Connect form request"))
		return "", false
	}
	if (len(body)+len(request.Header.Get("X-Pad")))%64 != 0 || request.Header.Get("X-Pad") == "" {
		p.fail(writer, E.New("Network Connect form request omitted source-compatible X-Pad"))
		return "", false
	}
	return string(body), true
}

func (p *m4NCAuthenticationPeer) fail(writer http.ResponseWriter, err error) {
	select {
	case p.errors <- err:
	default:
	}
	http.Error(writer, err.Error(), http.StatusInternalServerError)
}

func (p *m4NCAuthenticationPeer) assertResults(t *testing.T, ctx context.Context) {
	t.Helper()
	for {
		p.access.Lock()
		connectionCount := len(p.connections)
		p.access.Unlock()
		if connectionCount == 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for Network Connect authentication sockets to close"))
		case <-time.After(10 * time.Millisecond):
		}
	}
	p.access.Lock()
	roleSelection := p.roleSelection
	lureRequests := p.lureRequests
	p.access.Unlock()
	if roleSelection != "1" || lureRequests != 0 {
		t.Fatalf("Network Connect peer result mismatch: role=%q lure requests=%d", roleSelection, lureRequests)
	}
	p.dialer.access.Lock()
	hostnameDials := p.dialer.hostnameDialsAfterPoison
	pinnedDials := p.dialer.pinnedDialsAfterPoison
	p.dialer.access.Unlock()
	if hostnameDials != 0 || pinnedDials == 0 {
		t.Fatalf("Network Connect did not pin logout: poisoned hostname dials=%d pinned dials=%d", hostnameDials, pinnedDials)
	}
}

func (p *m4NCAuthenticationPeer) recordConnectionState(connection net.Conn, state http.ConnState) {
	p.access.Lock()
	if state == http.StateClosed || state == http.StateHijacked {
		delete(p.connections, connection)
	} else {
		p.connections[connection] = state
	}
	p.access.Unlock()
}

func (d *m4NCDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	target := destination
	if network == N.NetworkTCP {
		d.access.Lock()
		if destination.Fqdn != "" {
			route, loaded := d.routes[destination.Fqdn]
			if loaded {
				target = route
			}
			if d.poisoned && destination.Fqdn == d.gatewayHostname {
				d.hostnameDialsAfterPoison++
				target = d.lureAddress
			}
		} else if d.poisoned && destination.Addr == d.gatewayAddress.Addr && destination.Port == d.gatewayAddress.Port {
			d.pinnedDialsAfterPoison++
		}
		d.access.Unlock()
	}
	return N.SystemDialer.DialContext(ctx, network, target)
}

func (d *m4NCDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

func (d *m4NCDialer) poison() {
	d.access.Lock()
	d.poisoned = true
	d.access.Unlock()
}

func createM4NCCertificates(t *testing.T, hostnames []string) ([]byte, []tls.Certificate) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "M4 NC test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCertificate, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	encodedRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	certificates := make([]tls.Certificate, 0, len(hostnames))
	for certificateIndex, hostname := range hostnames {
		serverKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		serverTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(int64(certificateIndex + 2)),
			Subject:      pkix.Name{CommonName: hostname},
			DNSNames:     []string{hostname},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		serverDER, createErr := x509.CreateCertificate(rand.Reader, serverTemplate, rootCertificate, &serverKey.PublicKey, rootKey)
		if createErr != nil {
			t.Fatal(createErr)
		}
		certificates = append(certificates, tls.Certificate{
			Certificate: [][]byte{serverDER, rootDER},
			PrivateKey:  serverKey,
		})
	}
	return encodedRoot, certificates
}

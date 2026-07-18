package test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	m2GPAuthPeerUserAgent      = "sing-openconnect-gp-auth-peer"
	m2GPAuthPeerPortalCookie   = "cross-gateway-cookie"
	m2GPAuthPeerGatewayCookie  = "selected-gateway-cookie"
	m2GPAuthPeerAuthCookie     = "auth%cookie+opaque%ZZ"
	m2GPAuthPeerPortal         = "Portal name"
	m2GPAuthPeerDomain         = "(empty_domain)"
	m2GPAuthPeerPreferredIPv4  = "192.0.2.10"
	m2GPAuthPeerPreferredIPv6  = "2001:db8::10"
	m2GPAuthPeerNormalUser     = "normal user"
	m2GPAuthPeerNormalPassword = "normal password"
	m2GPAuthPeerBrowserUser    = "browser user"
	m2GPAuthPeerBrowserToken   = "browser token"
	m2GPAuthPeerPortalHostname = "portal.m2-gp-auth.test"
	m2GPAuthPeerSelectedHost   = "selected.m2-gp-auth.test"
	m2GPAuthPeerRegionalHost   = "regional.m2-gp-auth.test"
)

type m2GPAuthPeerScenario struct {
	name                      string
	authGroup                 string
	selectedLabel             string
	samlMethod                string
	samlCookieHeader          string
	reauthenticateAfterTunnel bool
}

type m2GPAuthPeer struct {
	scenario           m2GPAuthPeerScenario
	portal             *httptest.Server
	selectedGateway    *m2GPRawHTTPSServer
	regionalGateway    *httptest.Server
	lure               *httptest.Server
	portalURL          string
	gatewayHosts       [2]string
	dialer             *m2GPAuthPeerDialer
	errors             chan error
	events             chan string
	expectedBrowserURL string
	sequenceAccess     sync.Mutex
	portalConfigs      int
	gatewayLogins      int
	tunnels            int
}

type m2GPAuthPeerDialer struct {
	access                   sync.Mutex
	routes                   map[string]M.Socksaddr
	selectedHostname         string
	selectedAddress          M.Socksaddr
	lureAddress              M.Socksaddr
	poisoned                 bool
	afterTunnel              bool
	hostnameDialsAfterPoison uint64
	pinnedDialsAfterTunnel   uint64
}

type m2GPRawHTTPSServer struct {
	listener    net.Listener
	handler     http.Handler
	failures    chan<- error
	access      sync.Mutex
	connections map[net.Conn]struct{}
	waitGroup   sync.WaitGroup
}

func TestM2GlobalProtectAuthenticationPeerInterop(t *testing.T) {
	t.Parallel()
	scenarios := []m2GPAuthPeerScenario{
		{
			name:          "region-order-and-explicit-selection",
			selectedLabel: "selected-gateway",
		},
		{
			name:      "authgroup-selects-different-port",
			authGroup: "selected-gateway",
		},
		{
			name:             "saml-redirect-prelogin-cookie",
			authGroup:        "selected-gateway",
			samlMethod:       "REDIRECT",
			samlCookieHeader: "prelogin-cookie",
		},
		{
			name:             "saml-post-portal-userauthcookie",
			authGroup:        "selected-gateway",
			samlMethod:       "POST",
			samlCookieHeader: "portal-userauthcookie",
		},
		{
			name:                      "preferred-addresses-on-reauthentication",
			authGroup:                 "selected-gateway",
			reauthenticateAfterTunnel: true,
		},
	}
	for _, scenario := range scenarios {
		testScenario := scenario
		t.Run(testScenario.name, func(t *testing.T) {
			t.Parallel()
			runM2GPAuthPeerScenario(t, testScenario)
		})
	}
}

func runM2GPAuthPeerScenario(t *testing.T, scenario m2GPAuthPeerScenario) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	hostnames := []string{
		m2GPAuthPeerPortalHostname,
		m2GPAuthPeerSelectedHost,
		m2GPAuthPeerRegionalHost,
		m2GPAuthPeerSelectedHost,
	}
	rootCertificate, serverCertificates := createM2GPAuthPeerCertificates(t, hostnames)
	peer := &m2GPAuthPeer{
		scenario: scenario,
		errors:   make(chan error, 16),
		events:   make(chan string, 32),
	}
	peer.selectedGateway = newM2GPRawHTTPSServer(t, serverCertificates[1], peer.errors, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		peer.serveGateway(0, writer, request)
	}))
	peer.regionalGateway = newM2GPTLSServer(t, serverCertificates[2], http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		peer.serveGateway(1, writer, request)
	}))
	peer.lure = newM2GPTLSServer(t, serverCertificates[3], http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		peer.fail(writer, E.New("GlobalProtect followed poisoned DNS after authenticating the selected gateway"))
	}))
	peer.portal = newM2GPTLSServer(t, serverCertificates[0], http.HandlerFunc(peer.servePortal))
	portalAddress := M.SocksaddrFromNet(peer.portal.Listener.Addr())
	selectedAddress := M.SocksaddrFromNet(peer.selectedGateway.listener.Addr())
	regionalAddress := M.SocksaddrFromNet(peer.regionalGateway.Listener.Addr())
	lureAddress := M.SocksaddrFromNet(peer.lure.Listener.Addr())
	peer.portalURL = "https://" + net.JoinHostPort(m2GPAuthPeerPortalHostname, strconv.Itoa(int(portalAddress.Port)))
	peer.gatewayHosts[0] = net.JoinHostPort(m2GPAuthPeerSelectedHost, strconv.Itoa(int(selectedAddress.Port)))
	peer.gatewayHosts[1] = net.JoinHostPort(m2GPAuthPeerRegionalHost, strconv.Itoa(int(regionalAddress.Port)))
	peer.dialer = &m2GPAuthPeerDialer{
		routes: map[string]M.Socksaddr{
			m2GPAuthPeerPortalHostname: portalAddress,
			m2GPAuthPeerSelectedHost:   selectedAddress,
			m2GPAuthPeerRegionalHost:   regionalAddress,
		},
		selectedHostname: m2GPAuthPeerSelectedHost,
		selectedAddress:  selectedAddress,
		lureAddress:      lureAddress,
	}
	if scenario.samlMethod == "REDIRECT" {
		peer.expectedBrowserURL = "https://identity.invalid/global-protect"
	} else if scenario.samlMethod == "POST" {
		postDocument := "<html><body>GlobalProtect SAML POST</body></html>"
		peer.expectedBrowserURL = "data:text/html;base64," + base64.StdEncoding.EncodeToString([]byte(postDocument))
	}

	options := openconnect.ClientOptions{
		Context:   ctx,
		Server:    peer.portalURL + "/portal",
		Flavor:    openconnect.FlavorGP,
		Username:  m2GPAuthPeerNormalUser,
		Password:  m2GPAuthPeerNormalPassword,
		AuthGroup: scenario.authGroup,
		UserAgent: m2GPAuthPeerUserAgent,
		NoUDP:     true,
		Dialer:    peer.dialer,
		TLSConfig: openconnect.ClientTLSOptions{
			CertificateAuthority: openconnect.Material{Content: rootCertificate},
		},
	}
	client, err := openconnect.NewClient(options)
	if err != nil {
		t.Fatal(E.Cause(err, "create GlobalProtect authentication peer client"))
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	err = client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start GlobalProtect authentication peer client"))
	}
	terminalErrors := make(chan error, 1)
	go func() {
		_, readErr := client.ReadDataPacket(ctx)
		terminalErrors <- readErr
	}()
	if scenario.samlMethod != "" {
		challenge := waitForM2GPAuthPeerForm(t, ctx, client, peer.errors, terminalErrors)
		if challenge.Form != nil || challenge.Browser == nil || challenge.Browser.URL != peer.expectedBrowserURL || len(challenge.Browser.HeaderNames) != 3 {
			t.Fatalf("GlobalProtect browser challenge omitted the SAML URL or completion headers: %#v", challenge)
		}
		err = client.CompleteAuthChallenge(challenge.ID, openconnect.AuthResponse{Browser: &openconnect.BrowserResult{
			FinalURL: "https://identity.invalid/complete",
			Header: http.Header{
				"sAmL-UsErNaMe":           []string{m2GPAuthPeerBrowserUser},
				scenario.samlCookieHeader: []string{m2GPAuthPeerBrowserToken},
			},
		}})
		if err != nil {
			t.Fatal(E.Cause(err, "complete GlobalProtect browser challenge"))
		}
	}
	if scenario.selectedLabel != "" {
		form := waitForM2GPAuthPeerForm(t, ctx, client, peer.errors, terminalErrors)
		if form.Browser != nil || form.Form == nil || form.Message != "Please select GlobalProtect gateway." || len(form.Form.Fields) != 1 || len(form.Form.Fields[0].Options) != 2 {
			t.Fatalf("GlobalProtect gateway selection form is incomplete: %#v", form)
		}
		if form.Form.Fields[0].Options[0].Label != "regional-first" || form.Form.Fields[0].Options[1].Label != "selected-gateway" {
			t.Fatalf("GlobalProtect region priority did not order gateways: %#v", form.Form.Fields[0].Options)
		}
		selection := ""
		for _, option := range form.Form.Fields[0].Options {
			if option.Label == scenario.selectedLabel {
				selection = option.Value
				break
			}
		}
		if selection == "" {
			t.Fatal("GlobalProtect gateway selection form omitted the requested gateway")
		}
		err = client.CompleteAuthChallenge(form.ID, openconnect.AuthResponse{Form: &openconnect.AuthFormResponse{Values: map[string]string{form.Form.Fields[0].SubmissionKey: selection}}})
		if err != nil {
			t.Fatal(E.Cause(err, "complete GlobalProtect gateway selection form"))
		}
	}
	waitForM2GPAuthPeerCompletion(t, ctx, peer, terminalErrors)
	peer.dialer.assertPinnedLogout(t)
	err = client.Close()
	if err != nil {
		t.Fatal(E.Cause(err, "close GlobalProtect authentication peer client"))
	}
}

func (p *m2GPAuthPeer) servePortal(writer http.ResponseWriter, request *http.Request) {
	if request.TLS == nil || request.TLS.ServerName != m2GPAuthPeerPortalHostname {
		p.fail(writer, E.New("GlobalProtect portal TLS did not use the portal certificate hostname as SNI"))
		return
	}
	if request.Header.Get("User-Agent") != m2GPAuthPeerUserAgent {
		p.fail(writer, E.New("GlobalProtect portal received unexpected User-Agent"))
		return
	}
	switch request.URL.Path {
	case "/global-protect/prelogin.esp":
		if request.Method != http.MethodPost ||
			request.URL.Query().Get("tmp") != "tmp" ||
			request.URL.Query().Get("clientVer") != "4100" ||
			request.URL.Query().Get("clientos") == "" {
			p.fail(writer, E.New("GlobalProtect portal received invalid prelogin request"))
			return
		}
		err := request.ParseForm()
		if err != nil {
			p.fail(writer, E.Cause(err, "parse GlobalProtect portal prelogin form"))
			return
		}
		if request.PostForm.Get("cas-support") != "yes" {
			p.fail(writer, E.New("GlobalProtect portal prelogin omitted cas-support"))
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: "portal-origin", Value: "must-not-cross-port", Path: "/", Secure: true})
		saml := ""
		if p.scenario.samlMethod == "REDIRECT" {
			saml = "<saml-auth-method>REDIRECT</saml-auth-method><saml-request>" +
				base64.StdEncoding.EncodeToString([]byte(p.expectedBrowserURL)) + "</saml-request>"
		} else if p.scenario.samlMethod == "POST" {
			encodedDocument := strings.TrimPrefix(p.expectedBrowserURL, "data:text/html;base64,")
			saml = "<saml-auth-method>POST</saml-auth-method><saml-request>" + encodedDocument + "</saml-request>"
		}
		p.write(writer, `<prelogin-response><status>Success</status><authentication-message>Authenticate to the independent portal.</authentication-message><username-label>Username</username-label><password-label>Password</password-label><region>EARTH</region>`+saml+`</prelogin-response>`)
	case "/global-protect/getconfig.esp":
		p.servePortalConfiguration(writer, request)
	default:
		p.fail(writer, E.New("GlobalProtect portal received unexpected request path: ", request.URL.Path))
	}
}

func (p *m2GPAuthPeer) servePortalConfiguration(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		p.fail(writer, E.New("GlobalProtect portal configuration request was not POST"))
		return
	}
	originCookie, cookieErr := request.Cookie("portal-origin")
	if cookieErr != nil || originCookie.Value != "must-not-cross-port" {
		p.fail(writer, E.New("GlobalProtect portal configuration lost its origin cookie"))
		return
	}
	err := request.ParseForm()
	if err != nil {
		p.fail(writer, E.Cause(err, "parse GlobalProtect portal configuration form"))
		return
	}
	expectedUser := m2GPAuthPeerNormalUser
	expectedSecretName := "passwd"
	expectedSecret := m2GPAuthPeerNormalPassword
	if p.scenario.samlMethod != "" {
		expectedUser = m2GPAuthPeerBrowserUser
		expectedSecretName = p.scenario.samlCookieHeader
		expectedSecret = m2GPAuthPeerBrowserToken
	}
	if request.PostForm.Get("user") != expectedUser || request.PostForm.Get(expectedSecretName) != expectedSecret {
		p.fail(writer, E.New("GlobalProtect portal did not consume the expected credentials or BrowserResult headers"))
		return
	}
	err = validateM2GPLoginCommon(request.PostForm)
	if err != nil {
		p.fail(writer, err)
		return
	}
	attempt := p.nextPortalConfiguration()
	if p.scenario.reauthenticateAfterTunnel {
		err = validateM2GPReauthenticationAddresses(request.PostForm, attempt)
		if err != nil {
			p.fail(writer, err)
			return
		}
		if attempt == 2 {
			p.signal("preferred-portal-reauth")
		}
	}
	policy := `<policy><version> 6.7.8-9 </version><gateways><external><list>` +
		`<entry name="` + p.gatewayHosts[0] + `"><description>selected-gateway</description><priority-rule><entry name="Any"><priority>5</priority></entry></priority-rule></entry>` +
		`<entry name="` + p.gatewayHosts[1] + `"><description>regional-first</description><priority-rule><entry name="EARTH"><priority>1</priority></entry></priority-rule></entry>` +
		`</list></external></gateways><hip-collection><hip-report-interval>600</hip-report-interval></hip-collection>` +
		`<portal-userauthcookie>` + m2GPAuthPeerPortalCookie + `</portal-userauthcookie></policy>`
	p.signal("portal-config")
	p.write(writer, policy)
}

func (p *m2GPAuthPeer) serveGateway(index int, writer http.ResponseWriter, request *http.Request) {
	if index != 0 {
		p.fail(writer, E.New("GlobalProtect contacted the unselected gateway on a different port"))
		return
	}
	if request.TLS == nil || request.TLS.ServerName != m2GPAuthPeerSelectedHost {
		p.fail(writer, E.New("GlobalProtect gateway TLS did not use the selected gateway certificate hostname as SNI"))
		return
	}
	if request.URL.Path != "/ssl-tunnel-connect.sslvpn" && request.Header.Get("User-Agent") != m2GPAuthPeerUserAgent {
		p.fail(writer, E.New("GlobalProtect gateway received unexpected User-Agent"))
		return
	}
	switch request.URL.Path {
	case "/ssl-vpn/prelogin.esp":
		p.fail(writer, E.New("GlobalProtect performed gateway prelogin instead of portal-cookie blind continuation"))
	case "/ssl-vpn/login.esp":
		p.serveGatewayLogin(writer, request)
	case "/ssl-vpn/getconfig.esp":
		p.serveGatewayConfiguration(writer, request)
	case "/ssl-vpn/hipreportcheck.esp":
		p.serveGatewayHIPCheck(writer, request)
	case "/ssl-tunnel-connect.sslvpn":
		p.serveGatewayTunnel(writer, request)
	case "/ssl-vpn/logout.esp":
		p.serveGatewayLogout(writer, request)
	default:
		p.fail(writer, E.New("GlobalProtect selected gateway received unexpected path: ", request.URL.Path))
	}
}

func (p *m2GPAuthPeer) serveGatewayLogin(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		p.fail(writer, E.New("GlobalProtect gateway login request was not POST"))
		return
	}
	_, originCookieErr := request.Cookie("portal-origin")
	if originCookieErr == nil {
		p.fail(writer, E.New("GlobalProtect portal cookie jar crossed to a different gateway port"))
		return
	}
	err := request.ParseForm()
	if err != nil {
		p.fail(writer, E.Cause(err, "parse GlobalProtect gateway login form"))
		return
	}
	expectedUser := m2GPAuthPeerNormalUser
	expectedSecretName := "passwd"
	expectedSecret := m2GPAuthPeerNormalPassword
	if p.scenario.samlMethod != "" {
		expectedUser = m2GPAuthPeerBrowserUser
		expectedSecretName = p.scenario.samlCookieHeader
		expectedSecret = m2GPAuthPeerBrowserToken
	}
	validSecret := request.PostForm.Get(expectedSecretName) == expectedSecret
	if expectedSecretName == "portal-userauthcookie" {
		portalValues := request.PostForm[expectedSecretName]
		validSecret = len(portalValues) == 2 && portalValues[0] == m2GPAuthPeerPortalCookie && portalValues[1] == expectedSecret
	}
	if request.PostForm.Get("user") != expectedUser || !validSecret || request.PostForm.Get("portal-userauthcookie") != m2GPAuthPeerPortalCookie {
		p.fail(writer, E.New("GlobalProtect selected gateway received incorrect portal continuation fields"))
		return
	}
	err = validateM2GPLoginCommon(request.PostForm)
	if err != nil {
		p.fail(writer, err)
		return
	}
	attempt := p.nextGatewayLogin()
	if p.scenario.reauthenticateAfterTunnel {
		err = validateM2GPReauthenticationAddresses(request.PostForm, attempt)
		if err != nil {
			p.fail(writer, err)
			return
		}
		if attempt == 2 {
			p.signal("preferred-gateway-reauth")
		}
	}
	http.SetCookie(writer, &http.Cookie{Name: "gateway-session", Value: m2GPAuthPeerGatewayCookie, Path: "/", Secure: true})
	userArgument := strings.ReplaceAll(expectedUser, " ", "%20")
	response := `<?xml version="1.0"?><jnlp><application-desc>` +
		`<argument>(null)</argument>` +
		`<argument>auth%25cookie%2bopaque%ZZ</argument>` +
		`<argument>persistent</argument>` +
		`<argument>Portal%20name</argument>` +
		`<argument>` + userArgument + `</argument>` +
		`<argument>TestAuth</argument>` +
		`<argument>vsys1</argument>` +
		`<argument>%28empty_domain%29</argument>` +
		`<argument>(null)</argument><argument/><argument/><argument/>` +
		`<argument>tunnel</argument><argument>-1</argument><argument>4100</argument>` +
		`<argument>` + m2GPAuthPeerPreferredIPv4 + `</argument>` +
		`<argument>` + m2GPAuthPeerPortalCookie + `</argument><argument/>` +
		`<argument>2001%3adb8%3a%3a10</argument>` +
		`<argument>4</argument><argument>unknown</argument>` +
		`<argument>future-extension</argument><argument/>` +
		`</application-desc></jnlp>`
	if !p.scenario.reauthenticateAfterTunnel || attempt == 2 {
		p.dialer.poisonSelectedDNS()
	}
	p.signal("gateway-login")
	p.write(writer, response)
}

func (p *m2GPAuthPeer) serveGatewayConfiguration(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		p.fail(writer, E.New("GlobalProtect gateway configuration request was not POST"))
		return
	}
	err := p.validateAuthenticatedGatewayRequest(request)
	if err != nil {
		p.fail(writer, err)
		return
	}
	p.signal("gateway-config")
	p.write(writer, `<response><ip-address>`+m2GPAuthPeerPreferredIPv4+`</ip-address><ip-address-v6>`+m2GPAuthPeerPreferredIPv6+`/128</ip-address-v6><netmask>255.255.255.255</netmask><mtu>1300</mtu><ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url></response>`)
}

func (p *m2GPAuthPeer) serveGatewayHIPCheck(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		p.fail(writer, E.New("GlobalProtect HIP check request was not POST"))
		return
	}
	err := p.validateAuthenticatedGatewayRequest(request)
	if err != nil {
		p.fail(writer, err)
		return
	}
	p.signal("hip-check")
	p.write(writer, `<response><hip-report-needed>no</hip-report-needed></response>`)
}

func (p *m2GPAuthPeer) serveGatewayTunnel(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		p.fail(writer, E.New("GlobalProtect raw tunnel request was not GET"))
		return
	}
	query := request.URL.Query()
	if len(query) != 2 || query.Get("user") != p.expectedUser() || query.Get("authcookie") != m2GPAuthPeerAuthCookie {
		p.fail(writer, E.New("GlobalProtect raw tunnel did not contain exactly user and authcookie"))
		return
	}
	attempt := p.nextTunnel()
	if p.scenario.reauthenticateAfterTunnel && attempt == 1 {
		p.signal("tunnel-502")
		http.Error(writer, "GPST cookie is intentionally rejected once", http.StatusBadGateway)
		return
	}
	if p.scenario.reauthenticateAfterTunnel && attempt != 2 {
		p.fail(writer, E.New("GlobalProtect opened an unexpected number of tunnels during reauthentication: ", attempt))
		return
	}
	p.signal("tunnel-405")
	p.dialer.startLogoutPinAudit()
	http.Error(writer, "GPST is intentionally unsupported by this authentication peer", http.StatusMethodNotAllowed)
}

func (p *m2GPAuthPeer) serveGatewayLogout(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		p.fail(writer, E.New("GlobalProtect logout request was not POST"))
		return
	}
	err := p.validateAuthenticatedGatewayRequest(request)
	if err != nil {
		p.fail(writer, err)
		return
	}
	if request.PostForm.Get("computer") == "" {
		p.fail(writer, E.New("GlobalProtect logout omitted matching computer"))
		return
	}
	if p.scenario.reauthenticateAfterTunnel && p.tunnelCount() != 2 {
		p.fail(writer, E.New("GlobalProtect logged out the rejected authentication state before reauthenticating"))
		return
	}
	p.signal("logout")
	p.write(writer, `<response status="success"/>`)
}

func (p *m2GPAuthPeer) validateAuthenticatedGatewayRequest(request *http.Request) error {
	gatewayCookie, cookieErr := request.Cookie("gateway-session")
	if cookieErr != nil || gatewayCookie.Value != m2GPAuthPeerGatewayCookie {
		return E.New("GlobalProtect shared gateway cookie jar was not used by config, HIP, tunnel, or logout")
	}
	err := request.ParseForm()
	if err != nil {
		return E.Cause(err, "parse authenticated GlobalProtect gateway form")
	}
	if request.PostForm.Get("authcookie") != m2GPAuthPeerAuthCookie ||
		request.PostForm.Get("portal") != m2GPAuthPeerPortal ||
		request.PostForm.Get("user") != p.expectedUser() ||
		request.PostForm.Get("domain") != m2GPAuthPeerDomain ||
		request.PostForm.Get("preferred-ip") != m2GPAuthPeerPreferredIPv4 ||
		request.PostForm.Get("preferred-ipv6") != m2GPAuthPeerPreferredIPv6 {
		return E.New("GlobalProtect authenticated request changed the opaque JNLP query fields")
	}
	return nil
}

func (p *m2GPAuthPeer) expectedUser() string {
	if p.scenario.samlMethod != "" {
		return m2GPAuthPeerBrowserUser
	}
	return m2GPAuthPeerNormalUser
}

func validateM2GPLoginCommon(form url.Values) error {
	if form.Get("jnlpReady") != "jnlpReady" ||
		form.Get("ok") != "Login" ||
		form.Get("direct") != "yes" ||
		form.Get("clientVer") != "4100" ||
		form.Get("prot") != "https:" ||
		form.Get("internal") != "no" ||
		form.Get("ipv6-support") != "yes" ||
		form.Get("clientos") == "" ||
		form.Get("os-version") == "" ||
		form.Get("server") == "" ||
		form.Get("computer") == "" {
		return E.New("GlobalProtect login omitted required common fields")
	}
	return nil
}

func validateM2GPReauthenticationAddresses(form url.Values, attempt int) error {
	switch attempt {
	case 1:
		if form.Get("preferred-ip") != "" || form.Get("preferred-ipv6") != "" {
			return E.New("GlobalProtect sent preferred addresses before receiving its first tunnel configuration")
		}
	case 2:
		if form.Get("preferred-ip") != m2GPAuthPeerPreferredIPv4 || form.Get("preferred-ipv6") != m2GPAuthPeerPreferredIPv6 {
			return E.New("GlobalProtect reauthentication omitted the previously assigned IPv4 or IPv6 address")
		}
	default:
		return E.New("GlobalProtect made an unexpected authentication attempt: ", attempt)
	}
	return nil
}

func (p *m2GPAuthPeer) nextPortalConfiguration() int {
	p.sequenceAccess.Lock()
	defer p.sequenceAccess.Unlock()
	p.portalConfigs++
	return p.portalConfigs
}

func (p *m2GPAuthPeer) nextGatewayLogin() int {
	p.sequenceAccess.Lock()
	defer p.sequenceAccess.Unlock()
	p.gatewayLogins++
	return p.gatewayLogins
}

func (p *m2GPAuthPeer) nextTunnel() int {
	p.sequenceAccess.Lock()
	defer p.sequenceAccess.Unlock()
	p.tunnels++
	return p.tunnels
}

func (p *m2GPAuthPeer) tunnelCount() int {
	p.sequenceAccess.Lock()
	defer p.sequenceAccess.Unlock()
	return p.tunnels
}

func (p *m2GPAuthPeer) fail(writer http.ResponseWriter, err error) {
	select {
	case p.errors <- err:
	default:
	}
	http.Error(writer, err.Error(), http.StatusInternalServerError)
}

func (p *m2GPAuthPeer) write(writer http.ResponseWriter, content string) {
	_, err := io.WriteString(writer, content)
	if err != nil {
		select {
		case p.errors <- E.Cause(err, "write independent GlobalProtect peer response"):
		default:
		}
	}
}

func (p *m2GPAuthPeer) signal(event string) {
	select {
	case p.events <- event:
	default:
	}
}

func (d *m2GPAuthPeerDialer) DialContext(
	ctx context.Context,
	network string,
	destination M.Socksaddr,
) (net.Conn, error) {
	target := destination
	if network == N.NetworkTCP {
		d.access.Lock()
		if destination.Fqdn != "" {
			route, loaded := d.routes[destination.Fqdn]
			if loaded {
				target = route
			}
			if d.poisoned && destination.Fqdn == d.selectedHostname {
				d.hostnameDialsAfterPoison++
				target = d.lureAddress
			}
		} else if d.afterTunnel && destination.Addr == d.selectedAddress.Addr && destination.Port == d.selectedAddress.Port {
			d.pinnedDialsAfterTunnel++
		}
		d.access.Unlock()
	}
	return N.SystemDialer.DialContext(ctx, network, target)
}

func (d *m2GPAuthPeerDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

func (d *m2GPAuthPeerDialer) poisonSelectedDNS() {
	d.access.Lock()
	d.poisoned = true
	d.access.Unlock()
}

func (d *m2GPAuthPeerDialer) startLogoutPinAudit() {
	d.access.Lock()
	d.afterTunnel = true
	d.pinnedDialsAfterTunnel = 0
	d.access.Unlock()
}

func (d *m2GPAuthPeerDialer) assertPinnedLogout(t *testing.T) {
	t.Helper()
	d.access.Lock()
	defer d.access.Unlock()
	if d.hostnameDialsAfterPoison != 0 || d.pinnedDialsAfterTunnel == 0 {
		t.Fatalf(
			"GlobalProtect did not pin post-authentication gateway traffic: poisoned hostname dials=%d pinned dials after tunnel=%d",
			d.hostnameDialsAfterPoison,
			d.pinnedDialsAfterTunnel,
		)
	}
}

func waitForM2GPAuthPeerForm(
	t *testing.T,
	ctx context.Context,
	client *openconnect.Client,
	peerErrors <-chan error,
	terminalErrors <-chan error,
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
			t.Fatal(E.Cause(ctx.Err(), "wait for GlobalProtect gateway selection form"))
		case err := <-peerErrors:
			t.Fatal(err)
		case err := <-terminalErrors:
			t.Fatal(E.Cause(err, "GlobalProtect client became terminal before gateway selection"))
		case <-updated:
		}
	}
}

func waitForM2GPAuthPeerCompletion(
	t *testing.T,
	ctx context.Context,
	peer *m2GPAuthPeer,
	terminalErrors <-chan error,
) {
	t.Helper()
	required := map[string]bool{
		"portal-config":  false,
		"gateway-login":  false,
		"gateway-config": false,
		"hip-check":      false,
		"tunnel-405":     false,
		"logout":         false,
	}
	if peer.scenario.reauthenticateAfterTunnel {
		required["tunnel-502"] = false
		required["preferred-portal-reauth"] = false
		required["preferred-gateway-reauth"] = false
	}
	remaining := len(required)
	for remaining > 0 {
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for complete GlobalProtect authentication peer sequence: ", required))
		case err := <-peer.errors:
			t.Fatal(err)
		case err := <-terminalErrors:
			t.Fatal(E.Cause(err, "GlobalProtect client became terminal before the peer sequence completed"))
		case event := <-peer.events:
			seen, known := required[event]
			if known && !seen {
				required[event] = true
				remaining--
			}
		}
	}
}

func createM2GPAuthPeerCertificates(t *testing.T, hostnames []string) ([]byte, []tls.Certificate) {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(E.Cause(err, "generate GlobalProtect authentication peer root key"))
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sing-openconnect GlobalProtect authentication peer root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootData, rootCertificate := createSignedInteropCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	serverCertificates := make([]tls.Certificate, 0, len(hostnames))
	for i, hostname := range hostnames {
		serverKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			t.Fatal(E.Cause(keyErr, "generate GlobalProtect authentication peer server key"))
		}
		serverTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)),
			Subject:      pkix.Name{CommonName: "sing-openconnect GlobalProtect authentication peer"},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{hostname},
		}
		serverData, _ := createSignedInteropCertificate(t, serverTemplate, rootCertificate, serverKey.Public(), rootKey)
		certificate, certificateErr := tls.X509KeyPair(joinCertificatePEM(serverData), marshalInteropPrivateKey(t, serverKey))
		if certificateErr != nil {
			t.Fatal(E.Cause(certificateErr, "load GlobalProtect authentication peer server certificate"))
		}
		serverCertificates = append(serverCertificates, certificate)
	}
	return joinCertificatePEM(rootData), serverCertificates
}

func newM2GPTLSServer(t *testing.T, certificate tls.Certificate, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = false
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func newM2GPRawHTTPSServer(
	t *testing.T,
	certificate tls.Certificate,
	failures chan<- error,
	handler http.Handler,
) *m2GPRawHTTPSServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(E.Cause(err, "listen for raw GlobalProtect HTTPS peer"))
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	})
	server := &m2GPRawHTTPSServer{
		listener:    tlsListener,
		handler:     handler,
		failures:    failures,
		connections: make(map[net.Conn]struct{}),
	}
	server.waitGroup.Add(1)
	go server.acceptLoop()
	t.Cleanup(func() {
		closeErr := server.Close()
		if closeErr != nil {
			t.Error(E.Cause(closeErr, "close raw GlobalProtect HTTPS peer"))
		}
	})
	return server
}

func (s *m2GPRawHTTPSServer) acceptLoop() {
	defer s.waitGroup.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if !E.IsClosed(err) {
				s.report(E.Cause(err, "accept raw GlobalProtect HTTPS connection"))
			}
			return
		}
		s.access.Lock()
		s.connections[conn] = struct{}{}
		s.access.Unlock()
		s.waitGroup.Add(1)
		go s.serveConnection(conn)
	}
}

func (s *m2GPRawHTTPSServer) serveConnection(conn net.Conn) {
	defer s.waitGroup.Done()
	defer func() {
		s.access.Lock()
		delete(s.connections, conn)
		s.access.Unlock()
		_ = conn.Close()
	}()
	tlsConnection, loaded := conn.(*tls.Conn)
	if !loaded {
		s.report(E.New("raw GlobalProtect HTTPS peer accepted a non-TLS connection"))
		return
	}
	err := tlsConnection.Handshake()
	if err != nil {
		if !E.IsClosed(err) {
			s.report(E.Cause(err, "handshake raw GlobalProtect HTTPS connection"))
		}
		return
	}
	connectionState := tlsConnection.ConnectionState()
	reader := bufio.NewReader(tlsConnection)
	writer := bufio.NewWriter(tlsConnection)
	for {
		request, readErr := readM2GPRawHTTPRequest(reader)
		if readErr != nil {
			if readErr != io.EOF && !E.IsClosed(readErr) {
				s.report(readErr)
			}
			return
		}
		request.RemoteAddr = conn.RemoteAddr().String()
		request.TLS = &connectionState
		recorder := httptest.NewRecorder()
		s.handler.ServeHTTP(recorder, request)
		response := recorder.Result()
		writeErr := writeM2GPRawHTTPResponse(writer, response)
		closeErr := response.Body.Close()
		if writeErr != nil {
			s.report(writeErr)
			return
		}
		if closeErr != nil {
			s.report(E.Cause(closeErr, "close raw GlobalProtect HTTP response body"))
			return
		}
		if request.Close || response.Close {
			return
		}
	}
}

func readM2GPRawHTTPRequest(reader *bufio.Reader) (*http.Request, error) {
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	requestLine = strings.TrimSuffix(strings.TrimSuffix(requestLine, "\n"), "\r")
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] != "HTTP/1.1" {
		return nil, E.New("raw GlobalProtect HTTPS peer received invalid request line: ", requestLine)
	}
	requestURL, err := url.ParseRequestURI(parts[1])
	if err != nil {
		return nil, E.Cause(err, "parse raw GlobalProtect request target")
	}
	header := make(http.Header)
	for {
		headerLine, readErr := reader.ReadString('\n')
		if readErr != nil {
			return nil, E.Cause(readErr, "read raw GlobalProtect HTTP header")
		}
		headerLine = strings.TrimSuffix(strings.TrimSuffix(headerLine, "\n"), "\r")
		if headerLine == "" {
			break
		}
		separator := strings.IndexByte(headerLine, ':')
		if separator <= 0 {
			return nil, E.New("raw GlobalProtect HTTPS peer received malformed header: ", headerLine)
		}
		header.Add(strings.TrimSpace(headerLine[:separator]), strings.TrimSpace(headerLine[separator+1:]))
	}
	contentLength := int64(0)
	if header.Get("Content-Length") != "" {
		contentLength, err = strconv.ParseInt(header.Get("Content-Length"), 10, 64)
		if err != nil || contentLength < 0 || contentLength > 16*1024*1024 {
			return nil, E.New("raw GlobalProtect HTTPS peer received invalid Content-Length")
		}
	}
	body := make([]byte, int(contentLength))
	if contentLength > 0 {
		_, err = io.ReadFull(reader, body)
		if err != nil {
			return nil, E.Cause(err, "read raw GlobalProtect HTTP request body")
		}
	}
	request := &http.Request{
		Method:        parts[0],
		URL:           requestURL,
		Proto:         parts[2],
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(string(body))),
		ContentLength: contentLength,
		Host:          header.Get("Host"),
		RequestURI:    parts[1],
		Close:         strings.EqualFold(header.Get("Connection"), "close"),
	}
	return request, nil
}

func writeM2GPRawHTTPResponse(writer *bufio.Writer, response *http.Response) error {
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return E.Cause(err, "read raw GlobalProtect peer response body")
	}
	response.Header.Del("Transfer-Encoding")
	response.Header.Set("Content-Length", strconv.Itoa(len(body)))
	_, err = io.WriteString(writer, "HTTP/1.1 "+strconv.Itoa(response.StatusCode)+" "+http.StatusText(response.StatusCode)+"\r\n")
	if err != nil {
		return E.Cause(err, "write raw GlobalProtect HTTP status")
	}
	for name, values := range response.Header {
		for _, value := range values {
			_, err = io.WriteString(writer, name+": "+value+"\r\n")
			if err != nil {
				return E.Cause(err, "write raw GlobalProtect HTTP header")
			}
		}
	}
	_, err = io.WriteString(writer, "\r\n")
	if err != nil {
		return E.Cause(err, "write raw GlobalProtect HTTP header terminator")
	}
	_, err = writer.Write(body)
	if err != nil {
		return E.Cause(err, "write raw GlobalProtect HTTP response body")
	}
	err = writer.Flush()
	if err != nil {
		return E.Cause(err, "flush raw GlobalProtect HTTP response")
	}
	return nil
}

func (s *m2GPRawHTTPSServer) report(err error) {
	select {
	case s.failures <- err:
	default:
	}
}

func (s *m2GPRawHTTPSServer) Close() error {
	listenerErr := s.listener.Close()
	s.access.Lock()
	connections := make([]net.Conn, 0, len(s.connections))
	for conn := range s.connections {
		connections = append(connections, conn)
	}
	s.access.Unlock()
	var closeErrors []error
	if listenerErr != nil && !E.IsClosed(listenerErr) {
		closeErrors = append(closeErrors, listenerErr)
	}
	for _, conn := range connections {
		closeErr := conn.Close()
		if closeErr != nil && !E.IsClosed(closeErr) {
			closeErrors = append(closeErrors, closeErr)
		}
	}
	s.waitGroup.Wait()
	return E.Errors(closeErrors...)
}

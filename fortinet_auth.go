package openconnect

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/publicsuffix"
)

const (
	fortinetMaximumAuthenticationBody      = 16 * 1024 * 1024
	fortinetMaximumAuthenticationRequests  = 64
	fortinetMaximumAuthenticationRedirects = 10
	fortinetLogoutTimeout                  = 5 * time.Second
	fortinetProtocolUserAgent              = "Mozilla/5.0 SV1"
)

type fortinetFrontend struct {
	client *Client
}

type fortinetAuthentication struct {
	access            sync.Mutex
	frontend          *fortinetFrontend
	initializationErr error
	httpClient        *http.Client
	jar               http.CookieJar
	currentURL        *url.URL
	currentAddress    netip.Addr
	realm             string
	username          string
	currentForm       *fortinetAuthenticationForm
	tokenGenerator    *softwareTokenGenerator
	requests          int
	started           bool
	completed         bool
	closed            bool
	advancing         bool
	currentInitial    bool
}

type fortinetHTTPResponse struct {
	statusCode int
	header     http.Header
	body       []byte
	requestURL *url.URL
	address    netip.Addr
}

type fortinetSessionState struct {
	access               sync.RWMutex
	frontend             *fortinetFrontend
	serverURL            *url.URL
	acceptedAddress      netip.Addr
	jar                  http.CookieJar
	svpnCookie           string
	configurationOnce    sync.Once
	configuration        *fortinetTunnelConfiguration
	configurationErr     error
	activeSession        *pppSession
	previousIPv4         netip.Prefix
	previousIPv6         netip.Prefix
	hasPreviousAddresses bool
	connectedOnce        bool
	initialSourceAddress netip.Addr
	droppedAt            time.Time
	skipInitialDTLS      bool
	closeOnce            sync.Once
	closeErr             error
}

type fortinetSessionSnapshot struct {
	serverURL            *url.URL
	acceptedAddress      netip.Addr
	jar                  http.CookieJar
	svpnCookie           string
	previousIPv4         netip.Prefix
	previousIPv6         netip.Prefix
	hasPreviousAddresses bool
	connectedOnce        bool
	initialSourceAddress netip.Addr
	droppedAt            time.Time
	skipInitialDTLS      bool
}

func (f *fortinetFrontend) BeginAuthentication() authContinuation {
	f.client.httpTransport.CloseIdleConnections()
	jar, initializationErr := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	authenticationClient := &http.Client{
		Transport: f.client.httpTransport,
		Jar:       jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &fortinetAuthentication{
		frontend:          f,
		initializationErr: initializationErr,
		httpClient:        authenticationClient,
		jar:               jar,
		currentURL:        cloneFortinetURL(f.client.serverURL),
		tokenGenerator:    newSoftwareTokenGenerator(f.client.options.Token),
	}
}

func (a *fortinetAuthentication) Done() <-chan error {
	return nil
}

func (a *fortinetAuthentication) Close() error {
	a.access.Lock()
	if a.closed {
		a.access.Unlock()
		return nil
	}
	a.closed = true
	if !a.completed {
		a.jar = nil
		a.httpClient.Jar = nil
	}
	if a.currentForm != nil {
		for fieldIndex := range a.currentForm.fields {
			a.currentForm.fields[fieldIndex].value = ""
			a.currentForm.fields[fieldIndex].rawPair = ""
		}
	}
	a.currentForm = nil
	a.username = ""
	a.access.Unlock()
	return nil
}

func (a *fortinetAuthentication) Advance(
	ctx context.Context,
	response *authFormResponse,
) (obtainedSession, *authFormRequest, error) {
	a.access.Lock()
	if a.closed {
		a.access.Unlock()
		return nil, nil, ErrAuthFormCanceled
	}
	if a.initializationErr != nil {
		initializationErr := a.initializationErr
		a.access.Unlock()
		return nil, nil, initializationErr
	}
	if a.completed {
		a.access.Unlock()
		return nil, nil, E.Extend(ErrProtocolNotSupported, "Fortinet authentication continuation is already complete")
	}
	if a.advancing {
		a.access.Unlock()
		return nil, nil, E.Extend(ErrProtocolNotSupported, "Fortinet authentication continuation is already advancing")
	}
	a.advancing = true
	started := a.started
	currentForm := a.currentForm
	currentInitial := a.currentInitial
	if !started {
		a.started = true
	}
	a.access.Unlock()
	defer func() {
		a.access.Lock()
		a.advancing = false
		a.access.Unlock()
	}()
	if !started {
		if response != nil {
			return nil, nil, E.Extend(ErrProtocolNotSupported, "unexpected form response before Fortinet authentication")
		}
		return a.beginAuthentication(ctx)
	}
	if response == nil || currentForm == nil {
		return nil, nil, E.Extend(ErrProtocolNotSupported, "missing Fortinet authentication form response")
	}
	a.access.Lock()
	realm := a.realm
	a.access.Unlock()
	encodedForm, _, encodeErr := encodeFortinetAuthenticationResponse(currentForm, response, realm, currentInitial)
	if encodeErr != nil {
		return nil, nil, encodeErr
	}
	if currentInitial {
		usernameField := currentForm.fields[0]
		username := response.Values[usernameField.submissionKey]
		a.access.Lock()
		a.username = username
		a.access.Unlock()
	}
	requestURL, requestURLErr := a.authenticationPostURL(currentForm)
	if requestURLErr != nil {
		return nil, nil, requestURLErr
	}
	for fieldIndex := range currentForm.fields {
		if currentForm.fields[fieldIndex].kind == AuthFormFieldPassword || currentForm.fields[fieldIndex].name == "code" {
			currentForm.fields[fieldIndex].value = ""
		}
	}
	httpResponse, requestErr := a.doAuthenticationRequest(ctx, http.MethodPost, requestURL, encodedForm)
	if requestErr != nil {
		return nil, nil, requestErr
	}
	return a.processAuthenticationResponse(httpResponse, currentForm, currentInitial)
}

func (a *fortinetAuthentication) beginAuthentication(
	ctx context.Context,
) (obtainedSession, *authFormRequest, error) {
	currentURL := cloneFortinetURL(a.currentURL)
	for redirectNumber := 0; ; redirectNumber++ {
		if redirectNumber > fortinetMaximumAuthenticationRedirects {
			return nil, nil, markTerminal(E.New("Fortinet authentication exceeded ", fortinetMaximumAuthenticationRedirects, " redirects"))
		}
		httpResponse, requestErr := a.doAuthenticationRequest(ctx, http.MethodGet, currentURL, "")
		if requestErr != nil {
			return nil, nil, requestErr
		}
		a.rememberHTTPResponse(httpResponse)
		locationHeader := httpResponse.header.Get("Location")
		if isFortinetRedirectStatus(httpResponse.statusCode) && locationHeader != "" {
			location, locationErr := httpResponse.requestURL.Parse(locationHeader)
			if locationErr != nil {
				return nil, nil, markTerminal(E.Cause(locationErr, "parse Fortinet authentication redirect"))
			}
			prepareErr := a.prepareAuthenticationRedirect(httpResponse.requestURL, location)
			if prepareErr != nil {
				return nil, nil, prepareErr
			}
			currentURL = location
			continue
		}
		javascriptLocation, loaded, javascriptErr := parseFortinetTopLocation(httpResponse.body)
		if javascriptErr != nil {
			return nil, nil, markTerminal(javascriptErr)
		}
		if loaded {
			location, locationErr := httpResponse.requestURL.Parse(javascriptLocation)
			if locationErr != nil {
				return nil, nil, markTerminal(E.Cause(locationErr, "parse Fortinet JavaScript authentication redirect"))
			}
			prepareErr := a.prepareAuthenticationRedirect(httpResponse.requestURL, location)
			if prepareErr != nil {
				return nil, nil, prepareErr
			}
			currentURL = location
			continue
		}
		if httpResponse.statusCode < http.StatusOK || httpResponse.statusCode >= http.StatusMultipleChoices {
			return nil, nil, markTerminal(E.New("Fortinet login page returned HTTP ", httpResponse.statusCode))
		}
		realm := httpResponse.requestURL.Query().Get("realm")
		form := staticFortinetAuthenticationForm()
		a.access.Lock()
		a.currentURL = cloneFortinetURL(httpResponse.requestURL)
		a.realm = realm
		a.currentForm = form
		a.currentInitial = true
		a.access.Unlock()
		return nil, a.buildAuthenticationRequest(form, true, ""), nil
	}
}

func (a *fortinetAuthentication) processAuthenticationResponse(
	httpResponse fortinetHTTPResponse,
	previousForm *fortinetAuthenticationForm,
	previousInitial bool,
) (obtainedSession, *authFormRequest, error) {
	a.rememberHTTPResponse(httpResponse)
	state, cookieErr := a.sessionFromCookies(httpResponse.requestURL)
	if cookieErr != nil {
		return nil, nil, cookieErr
	}
	if state != nil {
		a.access.Lock()
		a.completed = true
		a.currentForm = nil
		a.access.Unlock()
		return state, nil, nil
	}
	switch httpResponse.statusCode {
	case http.StatusOK:
		a.access.Lock()
		username := a.username
		a.access.Unlock()
		form, parseErr := parseFortinetTokenInfo(httpResponse.body, username)
		if parseErr != nil {
			return nil, nil, markTerminal(parseErr)
		}
		a.access.Lock()
		a.currentForm = form
		a.currentInitial = false
		a.access.Unlock()
		return nil, a.buildAuthenticationRequest(form, false, ""), nil
	case http.StatusUnauthorized:
		form, parseErr := parseFortinetHTMLChallenge(httpResponse.body)
		if parseErr != nil {
			return nil, nil, markTerminal(parseErr)
		}
		a.access.Lock()
		a.currentForm = form
		a.currentInitial = false
		a.access.Unlock()
		return nil, a.buildAuthenticationRequest(form, false, ""), nil
	case http.StatusMethodNotAllowed:
		for fieldIndex := range previousForm.fields {
			field := &previousForm.fields[fieldIndex]
			if field.kind == AuthFormFieldPassword || field.name == "code" {
				field.value = ""
			}
		}
		a.access.Lock()
		a.currentForm = previousForm
		a.currentInitial = previousInitial
		a.access.Unlock()
		return nil, a.buildAuthenticationRequest(previousForm, previousInitial, "Invalid credentials; try again."), nil
	default:
		if isFortinetRedirectStatus(httpResponse.statusCode) || httpResponse.statusCode == http.StatusForbidden {
			if previousInitial {
				return nil, nil, newRetryableAuthenticationError(E.New("Fortinet gateway rejected the primary credentials"), authCachePassword)
			}
			return nil, nil, E.New("Fortinet gateway rejected the authentication continuation")
		}
		return nil, nil, markTerminal(E.New("Fortinet logincheck returned HTTP ", httpResponse.statusCode))
	}
}

func (a *fortinetAuthentication) buildAuthenticationRequest(
	form *fortinetAuthenticationForm,
	initial bool,
	errorMessage string,
) *authFormRequest {
	request := &authFormRequest{
		FormID:  form.id,
		Message: form.message,
		Error:   errorMessage,
	}
	if initial && errorMessage != "" {
		request.ClearCacheKeys = []string{authCachePassword}
	}
	for _, field := range form.fields {
		requestField := authFormRequestField{
			SubmissionKey: field.submissionKey,
			Name:          field.name,
			Label:         field.label,
			Kind:          field.kind,
			Value:         field.value,
		}
		if initial && field.name == "username" {
			requestField.CacheKey = authCacheUsername
		}
		if initial && field.name == "credential" {
			requestField.CacheKey = authCachePassword
		}
		if !initial && (field.name == "code" || field.name == "credential") && field.kind == AuthFormFieldPassword && a.tokenGenerator.CanGenerate(form.message) {
			requestField.Kind = authFormFieldToken
			tokenMessage := form.message
			requestField.Automatic = func(ctx context.Context) (string, error) {
				return a.tokenGenerator.Generate(ctx, tokenMessage)
			}
		}
		request.Fields = append(request.Fields, requestField)
	}
	return request
}

func (a *fortinetAuthentication) authenticationPostURL(form *fortinetAuthenticationForm) (*url.URL, error) {
	a.access.Lock()
	currentURL := cloneFortinetURL(a.currentURL)
	a.access.Unlock()
	if currentURL == nil {
		return nil, markTerminal(E.New("Fortinet authentication endpoint is empty"))
	}
	requestURL := cloneFortinetURL(currentURL)
	requestURL.Path = "/remote/logincheck"
	requestURL.RawPath = ""
	requestURL.RawQuery = ""
	if form.action != "" {
		resolvedURL, resolveErr := currentURL.Parse(form.action)
		if resolveErr != nil {
			return nil, markTerminal(E.Cause(resolveErr, "resolve Fortinet HTML challenge action"))
		}
		if !equalFortinetEndpoint(currentURL, resolvedURL) {
			return nil, markTerminal(E.New("Fortinet HTML challenge action changed the accepted origin"))
		}
		requestURL = resolvedURL
	}
	validationErr := validateHTTPSRequestURL(requestURL)
	if validationErr != nil {
		return nil, markTerminal(validationErr)
	}
	return requestURL, nil
}

func (a *fortinetAuthentication) doAuthenticationRequest(
	ctx context.Context,
	method string,
	requestURL *url.URL,
	encodedForm string,
) (fortinetHTTPResponse, error) {
	a.access.Lock()
	a.requests++
	requestNumber := a.requests
	a.access.Unlock()
	if requestNumber > fortinetMaximumAuthenticationRequests {
		return fortinetHTTPResponse{}, markTerminal(E.New("Fortinet authentication exceeded ", fortinetMaximumAuthenticationRequests, " wire requests"))
	}
	var body io.Reader
	if method == http.MethodPost {
		body = bytes.NewBufferString(encodedForm)
	}
	request, requestErr := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if requestErr != nil {
		return fortinetHTTPResponse{}, markTerminal(E.Cause(requestErr, "create Fortinet authentication request"))
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", fortinetProtocolUserAgent)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	var acceptedAddress netip.Addr
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			acceptedAddress = parseFortinetRemoteAddress(info.Conn.RemoteAddr())
		},
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
	response, responseErr := a.httpClient.Do(request)
	if responseErr != nil {
		requestFailure := E.Cause(responseErr, "send Fortinet authentication request")
		if response != nil && response.Body != nil {
			closeErr := response.Body.Close()
			if closeErr != nil {
				requestFailure = E.Errors(requestFailure, E.Cause(closeErr, "close failed Fortinet authentication response"))
			}
		}
		return fortinetHTTPResponse{}, requestFailure
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, fortinetMaximumAuthenticationBody+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		return fortinetHTTPResponse{}, E.Errors(E.Cause(readErr, "read Fortinet authentication response"), closeErr)
	}
	if closeErr != nil {
		return fortinetHTTPResponse{}, E.Cause(closeErr, "close Fortinet authentication response")
	}
	if len(responseBody) > fortinetMaximumAuthenticationBody {
		return fortinetHTTPResponse{}, markTerminal(E.New("Fortinet authentication response exceeds ", fortinetMaximumAuthenticationBody, " bytes"))
	}
	return fortinetHTTPResponse{
		statusCode: response.StatusCode,
		header:     response.Header.Clone(),
		body:       responseBody,
		requestURL: cloneFortinetURL(request.URL),
		address:    acceptedAddress,
	}, nil
}

func (a *fortinetAuthentication) rememberHTTPResponse(response fortinetHTTPResponse) {
	a.access.Lock()
	a.currentURL = cloneFortinetURL(response.requestURL)
	if response.address.IsValid() {
		a.currentAddress = response.address
	}
	a.access.Unlock()
}

func (a *fortinetAuthentication) prepareAuthenticationRedirect(currentURL *url.URL, location *url.URL) error {
	validationErr := validateHTTPSRequestURL(location)
	if validationErr != nil {
		return markTerminal(validationErr)
	}
	if equalFortinetEndpoint(currentURL, location) {
		return nil
	}
	jar, jarErr := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if jarErr != nil {
		return markTerminal(E.Cause(jarErr, "create Fortinet redirected authentication cookie jar"))
	}
	a.frontend.client.httpTransport.CloseIdleConnections()
	a.access.Lock()
	a.jar = jar
	a.httpClient.Jar = jar
	a.currentAddress = netip.Addr{}
	a.access.Unlock()
	return nil
}

func (a *fortinetAuthentication) sessionFromCookies(requestURL *url.URL) (*fortinetSessionState, error) {
	a.access.Lock()
	jar := a.jar
	acceptedAddress := a.currentAddress
	a.access.Unlock()
	if jar == nil {
		return nil, nil
	}
	var svpnCookie string
	for _, cookie := range jar.Cookies(requestURL) {
		if cookie.Name == "SVPNCOOKIE" {
			svpnCookie = cookie.Value
			break
		}
	}
	if svpnCookie == "" {
		return nil, nil
	}
	if !acceptedAddress.IsValid() {
		return nil, markTerminal(E.New("Fortinet authenticated endpoint has no accepted peer address"))
	}
	return &fortinetSessionState{
		frontend:        a.frontend,
		serverURL:       cloneFortinetURL(requestURL),
		acceptedAddress: acceptedAddress,
		jar:             jar,
		svpnCookie:      svpnCookie,
	}, nil
}

func parseFortinetTopLocation(content []byte) (string, bool, error) {
	text := string(content)
	marker := "top.location=\""
	start := strings.Index(text, marker)
	if start < 0 {
		return "", false, nil
	}
	start += len(marker)
	var escaped bool
	for position := start; position < len(text); position++ {
		value := text[position]
		if escaped {
			escaped = false
			continue
		}
		if value == '\\' {
			escaped = true
			continue
		}
		if value == '"' {
			quoted := "\"" + text[start:position] + "\""
			location, unquoteErr := strconv.Unquote(quoted)
			if unquoteErr != nil {
				return "", false, E.Cause(unquoteErr, "decode Fortinet JavaScript redirect")
			}
			if location == "" {
				return "", false, E.New("Fortinet JavaScript redirect is empty")
			}
			return location, true, nil
		}
	}
	return "", false, E.New("unterminated Fortinet JavaScript redirect")
}

func isFortinetRedirectStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func cloneFortinetURL(serverURL *url.URL) *url.URL {
	if serverURL == nil {
		return nil
	}
	cloned := *serverURL
	return &cloned
}

func equalFortinetEndpoint(left *url.URL, right *url.URL) bool {
	if left == nil || right == nil || !strings.EqualFold(left.Scheme, right.Scheme) || !strings.EqualFold(left.Hostname(), right.Hostname()) {
		return false
	}
	leftPort, leftErr := fortinetURLPort(left)
	rightPort, rightErr := fortinetURLPort(right)
	return leftErr == nil && rightErr == nil && leftPort == rightPort
}

func fortinetURLPort(serverURL *url.URL) (uint16, error) {
	if serverURL == nil {
		return 0, E.New("Fortinet endpoint URL is empty")
	}
	portText := serverURL.Port()
	if portText == "" {
		if strings.EqualFold(serverURL.Scheme, "https") {
			return 443, nil
		}
		return 0, E.New("Fortinet endpoint has no port")
	}
	port, parseErr := strconv.ParseUint(portText, 10, 16)
	if parseErr != nil || port == 0 {
		return 0, E.New("Fortinet endpoint has an invalid port: ", portText)
	}
	return uint16(port), nil
}

func parseFortinetRemoteAddress(address net.Addr) netip.Addr {
	if address == nil {
		return netip.Addr{}
	}
	switch typedAddress := address.(type) {
	case *net.TCPAddr:
		parsed, _ := netip.AddrFromSlice(typedAddress.IP)
		return parsed.Unmap()
	case *net.UDPAddr:
		parsed, _ := netip.AddrFromSlice(typedAddress.IP)
		return parsed.Unmap()
	}
	host, _, splitErr := net.SplitHostPort(address.String())
	if splitErr != nil {
		return netip.Addr{}
	}
	parsed, parseErr := netip.ParseAddr(host)
	if parseErr != nil {
		return netip.Addr{}
	}
	return parsed.Unmap()
}

func (s *fortinetSessionState) snapshot() fortinetSessionSnapshot {
	s.access.RLock()
	defer s.access.RUnlock()
	return fortinetSessionSnapshot{
		serverURL:            cloneFortinetURL(s.serverURL),
		acceptedAddress:      s.acceptedAddress,
		jar:                  s.jar,
		svpnCookie:           s.svpnCookie,
		previousIPv4:         s.previousIPv4,
		previousIPv6:         s.previousIPv6,
		hasPreviousAddresses: s.hasPreviousAddresses,
		connectedOnce:        s.connectedOnce,
		initialSourceAddress: s.initialSourceAddress,
		droppedAt:            s.droppedAt,
		skipInitialDTLS:      s.skipInitialDTLS,
	}
}

func (s *fortinetSessionState) attachSession(session *pppSession) error {
	s.access.Lock()
	defer s.access.Unlock()
	if s.svpnCookie == "" || s.jar == nil {
		return ErrSessionRejected
	}
	if s.activeSession != nil && s.activeSession != session {
		return E.New("Fortinet obtained session already owns an active tunnel")
	}
	s.activeSession = session
	return nil
}

func (s *fortinetSessionState) detachSession(session *pppSession) {
	s.access.Lock()
	if s.activeSession == session {
		s.activeSession = nil
	}
	s.access.Unlock()
}

func (s *fortinetSessionState) Close() error {
	s.closeOnce.Do(func() {
		s.access.RLock()
		activeSession := s.activeSession
		s.access.RUnlock()
		if activeSession != nil {
			s.closeErr = activeSession.Close()
		}
		snapshot := s.snapshot()
		if snapshot.serverURL != nil && snapshot.acceptedAddress.IsValid() && snapshot.jar != nil && snapshot.svpnCookie != "" {
			logoutContext, cancelLogout := context.WithTimeout(context.Background(), fortinetLogoutTimeout)
			logoutErr := s.frontend.logout(logoutContext, snapshot)
			cancelLogout()
			s.closeErr = E.Append(s.closeErr, logoutErr, func(cause error) error {
				return E.Cause(cause, "logout Fortinet session")
			})
		}
		s.access.Lock()
		if s.configuration != nil {
			for byteIndex := range s.configuration.tlsConnectRequest {
				s.configuration.tlsConnectRequest[byteIndex] = 0
			}
			for byteIndex := range s.configuration.dtlsConnectRequest {
				s.configuration.dtlsConnectRequest[byteIndex] = 0
			}
			s.configuration.tlsConnectRequest = nil
			s.configuration.dtlsConnectRequest = nil
		}
		s.jar = nil
		s.svpnCookie = ""
		s.configuration = nil
		s.access.Unlock()
	})
	return s.closeErr
}

func (f *fortinetFrontend) logout(ctx context.Context, snapshot fortinetSessionSnapshot) error {
	logoutURL := cloneFortinetURL(snapshot.serverURL)
	logoutURL.Path = "/remote/logout"
	logoutURL.RawPath = ""
	logoutURL.RawQuery = ""
	logoutClient, transport, clientErr := f.newPinnedHTTPClient(snapshot)
	if clientErr != nil {
		return clientErr
	}
	defer transport.CloseIdleConnections()
	request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, logoutURL.String(), nil)
	if requestErr != nil {
		return E.Cause(requestErr, "create Fortinet logout request")
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", fortinetProtocolUserAgent)
	response, responseErr := logoutClient.Do(request)
	if responseErr != nil {
		return E.Cause(responseErr, "send Fortinet logout request")
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, fortinetMaximumAuthenticationBody+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		return E.Errors(E.Cause(readErr, "read Fortinet logout response"), closeErr)
	}
	if closeErr != nil {
		return E.Cause(closeErr, "close Fortinet logout response")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return E.New("Fortinet logout returned HTTP ", response.StatusCode)
	}
	return nil
}

func (f *fortinetFrontend) newPinnedHTTPClient(
	snapshot fortinetSessionSnapshot,
) (*http.Client, *http.Transport, error) {
	if snapshot.serverURL == nil || !snapshot.acceptedAddress.IsValid() || snapshot.jar == nil {
		return nil, nil, E.New("Fortinet accepted endpoint is incomplete")
	}
	expectedPort, portErr := fortinetURLPort(snapshot.serverURL)
	if portErr != nil {
		return nil, nil, portErr
	}
	f.client.httpTransport.CloseIdleConnections()
	return newPinnedHTTPClient(f.client, snapshot.serverURL, snapshot.acceptedAddress, snapshot.jar, expectedPort, "Fortinet")
}

package openconnect

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"sync/atomic"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	AuthFormFieldText     = "text"
	AuthFormFieldPassword = "password"
	AuthFormFieldSelect   = "select"

	authFormFieldHidden = "hidden"
	authFormFieldToken  = "token"
)

const (
	authCacheUsername  = "username"
	authCachePassword  = "password"
	authCacheAuthGroup = "auth-group"
)

type AuthChallenge struct {
	ID      string
	Banner  string
	Message string
	Error   string
	Form    *AuthForm
	Browser *BrowserRequest
}

type AuthForm struct {
	Fields []AuthFormField
}

type AuthFormField struct {
	SubmissionKey string
	Name          string
	Label         string
	Kind          string
	Value         string
	Options       []AuthFormChoice
}

type AuthFormChoice struct {
	Value string
	Label string
}

type BrowserRequest struct {
	URL         string
	FinalURL    string
	CookieNames []string
	HeaderNames []string
}

type BrowserCookie struct {
	Name  string
	Value string
}

type BrowserResult struct {
	FinalURL string
	Cookies  []BrowserCookie
	Header   http.Header
}

type AuthResponse struct {
	Form    *AuthFormResponse
	Browser *BrowserResult
}

type AuthFormResponse struct {
	Values map[string]string
}

type authenticationRequest struct {
	FormID         string
	Banner         string
	Message        string
	Error          string
	Browser        *BrowserRequest
	Fields         []authenticationRequestField
	ClearCacheKeys []string
}

type authenticationRequestField struct {
	SubmissionKey string
	Name          string
	Label         string
	Kind          string
	Value         string
	Options       []AuthFormChoice
	CacheKey      string
	Automatic     func(ctx context.Context) (string, error)
}

type authenticationResponse struct {
	Values        map[string]string
	BrowserResult *BrowserResult
}

type pendingAuthChallengeState struct {
	challenge AuthChallenge
	validate  func(response AuthResponse) error
	complete  func(response AuthResponse)
	cancel    func() error
	canceled  atomic.Bool
}

var authChallengeIdentifier atomic.Uint64

func newAuthChallengeID() string {
	return strconv.FormatUint(authChallengeIdentifier.Add(1), 10)
}

func (c *Client) PendingAuthChallenge() *AuthChallenge {
	c.authChallengeAccess.Lock()
	defer c.authChallengeAccess.Unlock()
	if c.pendingAuthChallenge == nil {
		return nil
	}
	challenge := cloneAuthChallenge(c.pendingAuthChallenge.challenge)
	return &challenge
}

func (c *Client) AuthChallengeUpdated() <-chan struct{} {
	c.authChallengeAccess.Lock()
	defer c.authChallengeAccess.Unlock()
	return c.authChallengeUpdated
}

func (c *Client) CompleteAuthChallenge(id string, response AuthResponse) error {
	response = cloneAuthResponse(response)
	c.authChallengeAccess.Lock()
	pending := c.pendingAuthChallenge
	if pending == nil || pending.challenge.ID != id {
		c.authChallengeAccess.Unlock()
		return ErrNoPendingAuthChallenge
	}
	if pending.complete == nil {
		c.authChallengeAccess.Unlock()
		return ErrAuthChallengeNotAnswerable
	}
	validate := pending.validate
	c.authChallengeAccess.Unlock()
	if validate != nil {
		err := validate(response)
		if err != nil {
			return err
		}
	}
	c.authChallengeAccess.Lock()
	if c.pendingAuthChallenge != pending || pending.challenge.ID != id {
		c.authChallengeAccess.Unlock()
		return ErrNoPendingAuthChallenge
	}
	c.pendingAuthChallenge = nil
	c.signalAuthChallengeUpdatedLocked()
	c.authChallengeAccess.Unlock()
	pending.complete(response)
	return nil
}

func (c *Client) CancelAuthChallenge(id string) error {
	c.authChallengeAccess.Lock()
	pending := c.pendingAuthChallenge
	if pending == nil || pending.challenge.ID != id {
		c.authChallengeAccess.Unlock()
		return ErrNoPendingAuthChallenge
	}
	c.pendingAuthChallenge = nil
	c.signalAuthChallengeUpdatedLocked()
	c.authChallengeAccess.Unlock()
	c.setTerminalError(ErrAuthChallengeCanceled)
	if pending.cancel != nil {
		err := pending.cancel()
		if err != nil {
			return E.Cause(err, "cancel openconnect authentication continuation")
		}
	}
	return nil
}

func (c *Client) awaitAuthChallenge(ctx context.Context, request authenticationRequest, continuation authContinuation) (authenticationResponse, error) {
	if c.options.Flavor == FlavorAnyConnect && c.options.PasswordAuthenticationDisabled {
		return authenticationResponse{}, markTerminal(E.Errors(ErrAuthenticationFailed, E.New("server requested an authentication form while password authentication is disabled")))
	}
	c.clearStableCredentials(request.ClearCacheKeys...)
	values := make(map[string]string, len(request.Fields))
	visibleFields := make([]AuthFormField, 0, len(request.Fields))
	seenKeys := make(map[string]struct{}, len(request.Fields))
	allVisibleFieldsAutomatic := true
	for i := range request.Fields {
		field := &request.Fields[i]
		if field.SubmissionKey == "" {
			field.SubmissionKey = request.FormID + ":" + field.Name + ":" + strconv.Itoa(i)
		}
		_, exists := seenKeys[field.SubmissionKey]
		if exists {
			return authenticationResponse{}, markTerminal(E.New("duplicate openconnect authentication submission key: ", field.SubmissionKey))
		}
		seenKeys[field.SubmissionKey] = struct{}{}
		fieldValue, automatic := c.prefillAuthField(request.FormID, *field)
		if field.Automatic != nil {
			automatic = true
		}
		promote := false
		entry, loaded := c.formEntry(request.FormID, field.SubmissionKey, field.Name)
		if loaded {
			if entry.Promote {
				promote = true
			} else {
				fieldValue = entry.Value
				automatic = true
			}
		}
		if field.Kind == authFormFieldToken && field.Automatic == nil && fieldValue == "" {
			return authenticationResponse{}, markTerminal(E.New("token field has no automatic token generator: ", field.Name))
		}
		if (field.Kind == authFormFieldHidden && !promote) || field.Kind == authFormFieldToken {
			if field.Automatic == nil {
				values[field.SubmissionKey] = fieldValue
			}
			continue
		}
		kind := field.Kind
		if kind == authFormFieldHidden {
			kind = AuthFormFieldText
		}
		if kind != AuthFormFieldText && kind != AuthFormFieldPassword && kind != AuthFormFieldSelect {
			return authenticationResponse{}, markTerminal(E.New("unsupported openconnect authentication field kind: ", kind))
		}
		if kind == AuthFormFieldSelect && automatic && !authFormChoiceContains(field.Options, fieldValue) {
			automatic = false
		}
		if automatic && field.Automatic == nil {
			values[field.SubmissionKey] = fieldValue
		} else {
			allVisibleFieldsAutomatic = false
		}
		visibleFields = append(visibleFields, AuthFormField{
			SubmissionKey: field.SubmissionKey,
			Name:          field.Name,
			Label:         field.Label,
			Kind:          kind,
			Value:         fieldValue,
			Options:       append([]AuthFormChoice(nil), field.Options...),
		})
	}
	evaluateAutomaticFields := func() error {
		for i := range request.Fields {
			field := &request.Fields[i]
			if field.Automatic == nil {
				continue
			}
			value, err := field.Automatic(ctx)
			if err != nil {
				return err
			}
			values[field.SubmissionKey] = value
		}
		return nil
	}
	if request.Browser != nil {
		responseChannel := make(chan AuthResponse, 1)
		cancelChannel := make(chan struct{})
		state := &pendingAuthChallengeState{
			challenge: AuthChallenge{
				ID:      newAuthChallengeID(),
				Banner:  request.Banner,
				Message: request.Message,
				Error:   request.Error,
				Browser: cloneBrowserRequest(request.Browser),
			},
			validate: func(response AuthResponse) error {
				if response.Form != nil || response.Browser == nil {
					return ErrInvalidAuthResponse
				}
				if response.Browser.FinalURL == "" && len(response.Browser.Cookies) == 0 && len(response.Browser.Header) == 0 {
					return ErrInvalidBrowserAuthentication
				}
				return nil
			},
			complete: func(response AuthResponse) {
				responseChannel <- response
			},
		}
		state.cancel = func() error {
			state.canceled.Store(true)
			close(cancelChannel)
			return continuation.Close()
		}
		c.publishAuthChallenge(state)
		select {
		case <-ctx.Done():
			c.clearAuthChallenge(state)
			return authenticationResponse{}, ctx.Err()
		case <-cancelChannel:
			return authenticationResponse{}, ErrAuthChallengeCanceled
		case continuationErr, open := <-continuation.Done():
			c.clearAuthChallenge(state)
			if state.canceled.Load() {
				return authenticationResponse{}, ErrAuthChallengeCanceled
			}
			if open && continuationErr != nil {
				return authenticationResponse{}, continuationErr
			}
			return authenticationResponse{}, markTerminal(E.New("authentication continuation closed while a browser challenge was pending"))
		case response := <-responseChannel:
			err := evaluateAutomaticFields()
			if err != nil {
				return authenticationResponse{}, err
			}
			return authenticationResponse{Values: values, BrowserResult: response.Browser}, nil
		}
	}
	if len(request.Fields) > 0 && (len(visibleFields) == 0 || allVisibleFieldsAutomatic) {
		err := evaluateAutomaticFields()
		if err != nil {
			return authenticationResponse{}, err
		}
		return authenticationResponse{Values: values}, nil
	}
	responseChannel := make(chan map[string]string, 1)
	cancelChannel := make(chan struct{})
	challenge := AuthChallenge{
		ID:      newAuthChallengeID(),
		Banner:  request.Banner,
		Message: request.Message,
		Error:   request.Error,
		Form:    &AuthForm{Fields: visibleFields},
	}
	state := &pendingAuthChallengeState{
		challenge: challenge,
		validate: func(response AuthResponse) error {
			if response.Form == nil || response.Browser != nil {
				return ErrInvalidAuthResponse
			}
			return validateAuthFormValues(visibleFields, response.Form.Values)
		},
		complete: func(response AuthResponse) {
			responseChannel <- response.Form.Values
		},
	}
	state.cancel = func() error {
		state.canceled.Store(true)
		close(cancelChannel)
		return continuation.Close()
	}
	c.publishAuthChallenge(state)
	select {
	case <-ctx.Done():
		c.clearAuthChallenge(state)
		return authenticationResponse{}, ctx.Err()
	case <-cancelChannel:
		return authenticationResponse{}, ErrAuthChallengeCanceled
	case continuationErr, open := <-continuation.Done():
		c.clearAuthChallenge(state)
		if state.canceled.Load() {
			return authenticationResponse{}, ErrAuthChallengeCanceled
		}
		if open && continuationErr != nil {
			return authenticationResponse{}, continuationErr
		}
		return authenticationResponse{}, markTerminal(E.New("authentication continuation closed while a form was pending"))
	case responseValues := <-responseChannel:
		for _, field := range request.Fields {
			value, exists := responseValues[field.SubmissionKey]
			if !exists {
				continue
			}
			values[field.SubmissionKey] = value
			if field.CacheKey != "" {
				c.storeStableCredential(field.CacheKey, value)
			}
		}
		err := evaluateAutomaticFields()
		if err != nil {
			return authenticationResponse{}, err
		}
		return authenticationResponse{Values: values}, nil
	}
}

func (c *Client) prefillAuthField(formID string, field authenticationRequestField) (string, bool) {
	entry, loaded := c.formEntry(formID, field.SubmissionKey, field.Name)
	if loaded && !entry.Promote {
		return entry.Value, true
	}
	if field.CacheKey != "" {
		c.authChallengeAccess.Lock()
		value, exists := c.stableCredentials[field.CacheKey]
		c.authChallengeAccess.Unlock()
		if exists {
			return value, true
		}
	}
	return field.Value, false
}

func (c *Client) formEntry(formID string, submissionKey string, name string) (FormEntry, bool) {
	for _, entry := range slices.Backward(c.options.FormEntries) {
		if entry.SubmissionKey != "" && entry.SubmissionKey == submissionKey {
			return entry, true
		}
	}
	for _, entry := range slices.Backward(c.options.FormEntries) {
		if entry.SubmissionKey == "" && entry.FormID == formID && entry.Name == name {
			return entry, true
		}
	}
	return FormEntry{}, false
}

func (c *Client) storeStableCredential(key string, value string) {
	c.authChallengeAccess.Lock()
	c.stableCredentials[key] = value
	c.authChallengeAccess.Unlock()
}

func (c *Client) clearStableCredentials(keys ...string) {
	if len(keys) == 0 {
		return
	}
	c.authChallengeAccess.Lock()
	for _, key := range keys {
		delete(c.stableCredentials, key)
	}
	c.authChallengeAccess.Unlock()
}

func (c *Client) publishAuthChallenge(state *pendingAuthChallengeState) {
	c.authChallengeAccess.Lock()
	c.pendingAuthChallenge = state
	c.signalAuthChallengeUpdatedLocked()
	c.authChallengeAccess.Unlock()
}

func (c *Client) clearAuthChallenge(state *pendingAuthChallengeState) {
	c.authChallengeAccess.Lock()
	if c.pendingAuthChallenge == state {
		c.pendingAuthChallenge = nil
		c.signalAuthChallengeUpdatedLocked()
	}
	c.authChallengeAccess.Unlock()
}

func (c *Client) signalAuthChallengeUpdatedLocked() {
	close(c.authChallengeUpdated)
	c.authChallengeUpdated = make(chan struct{})
}

func cloneAuthChallenge(challenge AuthChallenge) AuthChallenge {
	if challenge.Form != nil {
		form := *challenge.Form
		form.Fields = append([]AuthFormField(nil), form.Fields...)
		for i := range form.Fields {
			form.Fields[i].Options = append([]AuthFormChoice(nil), form.Fields[i].Options...)
		}
		challenge.Form = &form
	}
	challenge.Browser = cloneBrowserRequest(challenge.Browser)
	return challenge
}

func cloneBrowserRequest(request *BrowserRequest) *BrowserRequest {
	if request == nil {
		return nil
	}
	cloned := *request
	cloned.CookieNames = append([]string(nil), request.CookieNames...)
	cloned.HeaderNames = append([]string(nil), request.HeaderNames...)
	return &cloned
}

func cloneAuthResponse(response AuthResponse) AuthResponse {
	if response.Form != nil {
		form := *response.Form
		form.Values = cloneStringMap(form.Values)
		response.Form = &form
	}
	if response.Browser != nil {
		browser := *response.Browser
		browser.Cookies = append([]BrowserCookie(nil), browser.Cookies...)
		browser.Header = browser.Header.Clone()
		response.Browser = &browser
	}
	return response
}

func validateAuthFormValues(fields []AuthFormField, values map[string]string) error {
	expected := make(map[string]AuthFormField, len(fields))
	for _, field := range fields {
		expected[field.SubmissionKey] = field
	}
	for submissionKey := range values {
		_, exists := expected[submissionKey]
		if !exists {
			return E.New("unknown openconnect authentication submission key: ", submissionKey)
		}
	}
	for submissionKey, field := range expected {
		value, exists := values[submissionKey]
		if !exists {
			return E.New("missing openconnect authentication submission key: ", submissionKey)
		}
		if field.Kind == AuthFormFieldSelect && !authFormChoiceContains(field.Options, value) {
			return E.New("invalid openconnect authentication selection for submission key: ", submissionKey)
		}
	}
	return nil
}

func authFormChoiceContains(choices []AuthFormChoice, value string) bool {
	for _, choice := range choices {
		if choice.Value == value {
			return true
		}
	}
	return false
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	maps.Copy(cloned, values)
	return cloned
}

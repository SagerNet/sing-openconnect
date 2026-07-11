package openconnect

import (
	"context"
	"maps"
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

type AuthForm struct {
	ID      string
	Banner  string
	Message string
	Error   string
	URL     string
	Fields  []AuthFormField
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

type authFormRequest struct {
	FormID         string
	Banner         string
	Message        string
	Error          string
	URL            string
	Browser        BrowserRequest
	Fields         []authFormRequestField
	ClearCacheKeys []string
}

type authFormRequestField struct {
	SubmissionKey string
	Name          string
	Label         string
	Kind          string
	Value         string
	Options       []AuthFormChoice
	CacheKey      string
	Automatic     func(ctx context.Context) (string, error)
}

type authFormResponse struct {
	Values        map[string]string
	BrowserResult *BrowserResult
}

type browserAuthenticationResponse struct {
	result BrowserResult
	err    error
}

type pendingAuthFormState struct {
	form     AuthForm
	validate func(values map[string]string) error
	complete func(values map[string]string)
	cancel   func() error
	canceled atomic.Bool
}

var authFormIdentifier atomic.Uint64

func newAuthFormID() string {
	return strconv.FormatUint(authFormIdentifier.Add(1), 10)
}

func (c *Client) PendingAuthForm() *AuthForm {
	c.authFormAccess.Lock()
	defer c.authFormAccess.Unlock()
	if c.pendingAuthForm == nil {
		return nil
	}
	form := cloneAuthForm(c.pendingAuthForm.form)
	return &form
}

func (c *Client) AuthFormUpdated() <-chan struct{} {
	c.authFormAccess.Lock()
	defer c.authFormAccess.Unlock()
	return c.authFormUpdated
}

func (c *Client) CompleteAuthForm(id string, values map[string]string) error {
	responseValues := cloneStringMap(values)
	c.authFormAccess.Lock()
	pending := c.pendingAuthForm
	if pending == nil || pending.form.ID != id {
		c.authFormAccess.Unlock()
		return ErrNoPendingAuthForm
	}
	if pending.complete == nil {
		c.authFormAccess.Unlock()
		return ErrAuthFormNotAnswerable
	}
	validate := pending.validate
	c.authFormAccess.Unlock()
	if validate != nil {
		err := validate(responseValues)
		if err != nil {
			return err
		}
	}
	c.authFormAccess.Lock()
	if c.pendingAuthForm != pending || pending.form.ID != id {
		c.authFormAccess.Unlock()
		return ErrNoPendingAuthForm
	}
	c.pendingAuthForm = nil
	c.signalAuthFormUpdatedLocked()
	c.authFormAccess.Unlock()
	pending.complete(responseValues)
	return nil
}

func (c *Client) CancelAuthForm(id string) error {
	c.authFormAccess.Lock()
	pending := c.pendingAuthForm
	if pending == nil || pending.form.ID != id {
		c.authFormAccess.Unlock()
		return ErrNoPendingAuthForm
	}
	c.pendingAuthForm = nil
	c.signalAuthFormUpdatedLocked()
	c.authFormAccess.Unlock()
	c.setTerminalError(ErrAuthFormCanceled)
	if pending.cancel != nil {
		err := pending.cancel()
		if err != nil {
			return E.Cause(err, "cancel openconnect authentication continuation")
		}
	}
	return nil
}

func (c *Client) awaitAuthForm(ctx context.Context, request authFormRequest, continuation authContinuation) (authFormResponse, error) {
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
			return authFormResponse{}, markTerminal(E.New("duplicate openconnect authentication submission key: ", field.SubmissionKey))
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
			return authFormResponse{}, markTerminal(E.New("openconnect token field has no automatic token generator: ", field.Name))
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
			return authFormResponse{}, markTerminal(E.New("unsupported openconnect authentication field kind: ", kind))
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
	if request.URL != "" {
		if c.options.Browser == nil {
			return authFormResponse{}, ErrBrowserAuthenticationUnsupported
		}
		browserContext, cancelBrowser := context.WithCancel(ctx)
		state := &pendingAuthFormState{
			form: AuthForm{
				ID:      newAuthFormID(),
				Banner:  request.Banner,
				Message: request.Message,
				Error:   request.Error,
				URL:     request.URL,
			},
		}
		state.cancel = func() error {
			state.canceled.Store(true)
			cancelBrowser()
			return continuation.Close()
		}
		c.publishAuthForm(state)
		browserRequest := request.Browser
		if browserRequest.URL == "" {
			browserRequest.URL = request.URL
		}
		browserRequest.CookieNames = append([]string(nil), browserRequest.CookieNames...)
		browserRequest.HeaderNames = append([]string(nil), browserRequest.HeaderNames...)
		resultChannel := make(chan browserAuthenticationResponse, 1)
		go func() {
			result, authenticateErr := c.options.Browser.Authenticate(browserContext, browserRequest)
			resultChannel <- browserAuthenticationResponse{result: result, err: authenticateErr}
		}()
		var result BrowserResult
		var err error
		select {
		case response := <-resultChannel:
			result = response.result
			err = response.err
		case <-browserContext.Done():
			err = browserContext.Err()
		}
		browserContextErr := browserContext.Err()
		c.clearAuthForm(state)
		cancelBrowser()
		if state.canceled.Load() {
			return authFormResponse{}, ErrAuthFormCanceled
		}
		if err != nil {
			if browserContextErr != nil && ctx.Err() == nil {
				return authFormResponse{}, ErrAuthFormCanceled
			}
			return authFormResponse{}, err
		}
		if result.FinalURL == "" && len(result.Cookies) == 0 && len(result.Header) == 0 {
			return authFormResponse{}, ErrInvalidBrowserAuthentication
		}
		result.Header = result.Header.Clone()
		result.Cookies = append([]BrowserCookie(nil), result.Cookies...)
		err = evaluateAutomaticFields()
		if err != nil {
			return authFormResponse{}, err
		}
		return authFormResponse{Values: values, BrowserResult: &result}, nil
	}
	if len(request.Fields) > 0 && (len(visibleFields) == 0 || allVisibleFieldsAutomatic) {
		err := evaluateAutomaticFields()
		if err != nil {
			return authFormResponse{}, err
		}
		return authFormResponse{Values: values}, nil
	}
	responseChannel := make(chan map[string]string, 1)
	cancelChannel := make(chan struct{})
	form := AuthForm{
		ID:      newAuthFormID(),
		Banner:  request.Banner,
		Message: request.Message,
		Error:   request.Error,
		Fields:  visibleFields,
	}
	state := &pendingAuthFormState{
		form: form,
		validate: func(responseValues map[string]string) error {
			return validateAuthFormValues(visibleFields, responseValues)
		},
		complete: func(responseValues map[string]string) {
			responseChannel <- responseValues
		},
	}
	state.cancel = func() error {
		state.canceled.Store(true)
		close(cancelChannel)
		return continuation.Close()
	}
	c.publishAuthForm(state)
	select {
	case <-ctx.Done():
		c.clearAuthForm(state)
		return authFormResponse{}, ctx.Err()
	case <-cancelChannel:
		return authFormResponse{}, ErrAuthFormCanceled
	case continuationErr, open := <-continuation.Done():
		c.clearAuthForm(state)
		if state.canceled.Load() {
			return authFormResponse{}, ErrAuthFormCanceled
		}
		if open && continuationErr != nil {
			return authFormResponse{}, continuationErr
		}
		return authFormResponse{}, markTerminal(E.New("openconnect authentication continuation closed while a form was pending"))
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
			return authFormResponse{}, err
		}
		return authFormResponse{Values: values}, nil
	}
}

func (c *Client) prefillAuthField(formID string, field authFormRequestField) (string, bool) {
	entry, loaded := c.formEntry(formID, field.SubmissionKey, field.Name)
	if loaded && !entry.Promote {
		return entry.Value, true
	}
	if field.CacheKey != "" {
		c.authFormAccess.Lock()
		value, exists := c.stableCredentials[field.CacheKey]
		c.authFormAccess.Unlock()
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
	c.authFormAccess.Lock()
	c.stableCredentials[key] = value
	c.authFormAccess.Unlock()
}

func (c *Client) clearStableCredentials(keys ...string) {
	if len(keys) == 0 {
		return
	}
	c.authFormAccess.Lock()
	for _, key := range keys {
		delete(c.stableCredentials, key)
	}
	c.authFormAccess.Unlock()
}

func (c *Client) publishAuthForm(state *pendingAuthFormState) {
	c.authFormAccess.Lock()
	c.pendingAuthForm = state
	c.signalAuthFormUpdatedLocked()
	c.authFormAccess.Unlock()
}

func (c *Client) clearAuthForm(state *pendingAuthFormState) {
	c.authFormAccess.Lock()
	if c.pendingAuthForm == state {
		c.pendingAuthForm = nil
		c.signalAuthFormUpdatedLocked()
	}
	c.authFormAccess.Unlock()
}

func (c *Client) signalAuthFormUpdatedLocked() {
	close(c.authFormUpdated)
	c.authFormUpdated = make(chan struct{})
}

func cloneAuthForm(form AuthForm) AuthForm {
	form.Fields = append([]AuthFormField(nil), form.Fields...)
	for i := range form.Fields {
		form.Fields[i].Options = append([]AuthFormChoice(nil), form.Fields[i].Options...)
	}
	return form
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

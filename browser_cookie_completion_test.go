package openconnect

import (
	"errors"
	"testing"
)

func TestCookieBrowserRequestWithoutFinalURL(t *testing.T) {
	t.Parallel()
	request := &BrowserRequest{
		URL:              "https://vpn.example.com/",
		CookieNames:      []string{"session", "ticket"},
		EarlyCookieNames: []string{"error"},
	}
	mode, err := validateBrowserRequest(request)
	if err != nil || mode != browserAuthenticationModeCookies {
		t.Fatalf("validateBrowserRequest = %v, %v", mode, err)
	}
	for _, testCase := range []struct {
		name   string
		result BrowserResult
		valid  bool
	}{
		{
			name:   "every cookie",
			result: BrowserResult{Cookies: []BrowserCookie{{Name: "ticket", Value: "t"}, {Name: "session", Value: "s"}}},
			valid:  true,
		},
		{
			name:   "early cookie",
			result: BrowserResult{Cookies: []BrowserCookie{{Name: "error", Value: "denied"}}},
			valid:  true,
		},
		{
			name:   "missing cookie",
			result: BrowserResult{Cookies: []BrowserCookie{{Name: "session", Value: "s"}}},
		},
		{
			name:   "unrequested final URL",
			result: BrowserResult{FinalURL: "https://vpn.example.com/done", Cookies: []BrowserCookie{{Name: "ticket", Value: "t"}, {Name: "session", Value: "s"}}},
		},
		{
			name:   "unrequested cookie",
			result: BrowserResult{Cookies: []BrowserCookie{{Name: "ticket", Value: "t"}, {Name: "session", Value: "s"}, {Name: "other", Value: "o"}}},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			result := testCase.result
			err := validateBrowserResponse(request, mode, AuthResponse{Browser: &result})
			if testCase.valid && err != nil {
				t.Fatalf("expected the result to be accepted, got %v", err)
			}
			if !testCase.valid && !errors.Is(err, ErrInvalidBrowserAuthentication) {
				t.Fatalf("expected the result to be rejected, got %v", err)
			}
		})
	}
}

func TestCookieBrowserRequestWithFinalURLUnchanged(t *testing.T) {
	t.Parallel()
	request := &BrowserRequest{
		URL:         "https://vpn.example.com/login",
		FinalURL:    "https://vpn.example.com/done",
		CookieNames: []string{"session", "ticket"},
	}
	mode, err := validateBrowserRequest(request)
	if err != nil || mode != browserAuthenticationModeCookies {
		t.Fatalf("validateBrowserRequest = %v, %v", mode, err)
	}
	err = validateBrowserResponse(request, mode, AuthResponse{Browser: &BrowserResult{
		FinalURL: request.FinalURL,
		Cookies:  []BrowserCookie{{Name: "session", Value: "s"}},
	}})
	if err != nil {
		t.Fatalf("a final URL with some of the cookies is still accepted, got %v", err)
	}
	err = validateBrowserResponse(request, mode, AuthResponse{Browser: &BrowserResult{
		Cookies: []BrowserCookie{{Name: "session", Value: "s"}, {Name: "ticket", Value: "t"}},
	}})
	if !errors.Is(err, ErrInvalidBrowserAuthentication) {
		t.Fatalf("a result without the requested final URL is still rejected, got %v", err)
	}
}

func TestCookieBrowserRequestNeedsCookieNames(t *testing.T) {
	t.Parallel()
	_, err := validateBrowserRequest(&BrowserRequest{URL: "https://vpn.example.com/", EarlyCookieNames: []string{"error"}})
	if err == nil {
		t.Fatal("expected a cookie request without cookie names to be rejected")
	}
}

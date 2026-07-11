package openconnect

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

const (
	TokenModeTOTP   = "totp"
	TokenModeHOTP   = "hotp"
	TokenModeSToken = "stoken"
)

type TokenOptions struct {
	Mode          string
	Secret        string
	PIN           string
	Password      string
	DeviceID      string
	Counter       uint64
	UpdateCounter func(ctx context.Context, counter uint64) error
}

type CSDOptions struct {
	WrapperPath string
}

type HIPOptions struct {
	WrapperPath string
}

type TNCCOptions struct {
	WrapperPath                  string
	DeviceID                     string
	UserAgent                    string
	MachineIdentificationEnabled bool
	Certificates                 []Material
}

type FormEntry struct {
	FormID        string
	SubmissionKey string
	Name          string
	Value         string
	Promote       bool
}

type ClientTLSOptions struct {
	Config               *tls.Config
	CertificateAuthority Material
	Certificate          Material
	Key                  Material
	KeyPassword          string
	MCACertificate       Material
	MCAKey               Material
	MCAKeyPassword       string
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

type Browser interface {
	Authenticate(ctx context.Context, request BrowserRequest) (BrowserResult, error)
}

type ClientOptions struct {
	Context               context.Context
	Server                string
	Flavor                string
	Username              string
	Password              string
	AuthGroup             string
	Token                 *TokenOptions
	ReportedOS            string
	UserAgent             string
	CSD                   *CSDOptions
	HIP                   *HIPOptions
	TNCC                  *TNCCOptions
	NoUDP                 bool
	AllowInsecureCrypto   bool
	TLSConfig             ClientTLSOptions
	FormEntries           []FormEntry
	Browser               Browser
	Dialer                N.Dialer
	Logger                logger.ContextLogger
	OnTunnelConfiguration func(event TunnelConfigurationEvent) error
}

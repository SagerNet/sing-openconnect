package openconnect

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

func newPinnedHTTPClient(
	client *Client,
	serverURL *url.URL,
	acceptedAddress netip.Addr,
	jar http.CookieJar,
	expectedPort uint16,
	protocolName string,
) (*http.Client, *http.Transport, error) {
	transport := client.httpTransport.Clone()
	expectedHostname := serverURL.Hostname()
	transport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		destinationHostname, destinationPortText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, E.Cause(err, "parse ", protocolName, " accepted endpoint destination")
		}
		destinationPort, err := strconv.ParseUint(destinationPortText, 10, 16)
		if err != nil || destinationPort == 0 {
			return nil, E.New(protocolName, " accepted endpoint destination has an invalid port")
		}
		if !strings.EqualFold(destinationHostname, expectedHostname) || uint16(destinationPort) != expectedPort {
			return nil, E.New(protocolName, " request attempted to dial outside the accepted endpoint")
		}
		destination := M.ParseSocksaddrHostPort(acceptedAddress.String(), expectedPort)
		return client.options.Dialer.DialContext(ctx, network, destination)
	}
	return &http.Client{
		Transport: transport,
		Jar:       jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, transport, nil
}

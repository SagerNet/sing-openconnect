package openconnect

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

type pinnedHTTPPeer struct {
	access  sync.Mutex
	address netip.Addr
}

func (p *pinnedHTTPPeer) record(address netip.Addr) {
	p.access.Lock()
	defer p.access.Unlock()
	if !p.address.IsValid() {
		p.address = address
	}
}

func (p *pinnedHTTPPeer) load() netip.Addr {
	p.access.Lock()
	defer p.access.Unlock()
	return p.address
}

func (c *Client) connectionPeerAddress(connection net.Conn) netip.Addr {
	if c.options.ProxiedDialer {
		return netip.Addr{}
	}
	return parseConnectionAddress(connection.RemoteAddr())
}

func (c *Client) connectionLocalAddress(connection net.Conn) netip.Addr {
	if c.options.ProxiedDialer {
		return netip.Addr{}
	}
	return parseConnectionAddress(connection.LocalAddr())
}

func parseConnectionAddress(address net.Addr) netip.Addr {
	if address == nil {
		return netip.Addr{}
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return netip.Addr{}
	}
	parsed, parseErr := netip.ParseAddr(strings.Trim(host, "[]"))
	if parseErr != nil {
		return netip.Addr{}
	}
	return parsed.Unmap()
}

func peerDestinationHost(address netip.Addr, hostname string) string {
	if address.IsValid() {
		return address.String()
	}
	return hostname
}

func newPinnedHTTPClient(
	client *Client,
	serverURL *url.URL,
	acceptedAddress netip.Addr,
	jar http.CookieJar,
	expectedPort uint16,
	protocolName string,
) (*http.Client, *http.Transport, *pinnedHTTPPeer, error) {
	transport := client.httpTransport.Clone()
	expectedHostname := serverURL.Hostname()
	peer := &pinnedHTTPPeer{address: acceptedAddress}
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
		destinationHost := expectedHostname
		acceptedPeerAddress := peer.load()
		if acceptedPeerAddress.IsValid() {
			destinationHost = acceptedPeerAddress.String()
		}
		destination := M.ParseSocksaddrHostPort(destinationHost, expectedPort)
		connection, dialErr := client.options.Dialer.DialContext(ctx, network, destination)
		if dialErr != nil {
			return nil, E.Cause(dialErr, "dial ", protocolName, " accepted endpoint")
		}
		peer.record(client.connectionPeerAddress(connection))
		return connection, nil
	}
	return &http.Client{
		Transport: client.wrapHTTPTransport(transport),
		Jar:       jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, transport, peer, nil
}

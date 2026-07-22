package test

import (
	"context"
	"net"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type m1DTLSDialer struct {
	udpDestination M.Socksaddr
}

func TestM1AnyConnectProductionDTLSInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	container := startM1OcservContainer(t, ctx, m1OcservOptions{
		authentication: `auth = "plain[passwd=/fixture/ocpasswd]"`,
		keepalive:      60,
		dpd:            30,
		rekeyMethod:    "new-tunnel",
		files:          map[string][]byte{"ocpasswd": []byte(m1OcservPasswordFile)},
	})
	client := newM1AnyConnectClient(t, ctx, container.tcpAddress, openconnect.ClientOptions{
		Username: ocservUsername,
		Password: ocservPassword,
		Dialer: &m1DTLSDialer{
			udpDestination: M.ParseSocksaddr(container.udpAddress),
		},
	})
	activeTransportUpdated := client.ActiveTransportUpdated()
	startM1Client(t, client)
	waitForM1Ready(t, ctx, client)
	if client.ActiveTransport() != openconnect.TransportDTLS {
		waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportDTLS)
	}
	exchangeM1TunnelEcho(t, ctx, client, 0x4d34, 1, "sing-openconnect-m1-production-dtls")
}

func (d *m1DTLSDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network == N.NetworkUDP {
		destination = d.udpDestination
	}
	return N.SystemDialer.DialContext(ctx, network, destination)
}

func (d *m1DTLSDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

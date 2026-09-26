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

type dTLSDialer struct {
	udpDestination M.Socksaddr
}

func TestAnyConnectProductionDTLSInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	container := startOcservContainer(t, ctx, ocservOptions{
		authentication: `auth = "plain[passwd=/fixture/ocpasswd]"`,
		keepalive:      60,
		dpd:            30,
		rekeyMethod:    "new-tunnel",
		files:          map[string][]byte{"ocpasswd": []byte(ocservPasswordFile)},
	})
	client := newAnyConnectClient(t, ctx, container.tcpAddress, openconnect.ClientOptions{
		Username: ocservUsername,
		Password: ocservPassword,
		Dialer: &dTLSDialer{
			udpDestination: M.ParseSocksaddr(container.udpAddress),
		},
	})
	activeTransportUpdated := client.ActiveTransportUpdated()
	startClient(t, client)
	waitForReady(t, ctx, client)
	if client.ActiveTransport() != openconnect.TransportDTLS {
		waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportDTLS)
	}
	exchangeTunnelEcho(t, ctx, client, 0x4d34, 1, "sing-openconnect-production-dtls")
}

func (d *dTLSDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network == N.NetworkUDP {
		destination = d.udpDestination
	}
	return N.SystemDialer.DialContext(ctx, network, destination)
}

func (d *dTLSDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

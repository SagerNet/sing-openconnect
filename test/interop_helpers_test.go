package test

import (
	"net/netip"
	"testing"
)

func firstIPv4Address(t *testing.T, addresses []netip.Prefix) netip.Addr {
	t.Helper()
	for _, prefix := range addresses {
		if prefix.Addr().Is4() {
			return prefix.Addr()
		}
	}
	t.Fatal("ocserv tunnel has no IPv4 address")
	return netip.Addr{}
}

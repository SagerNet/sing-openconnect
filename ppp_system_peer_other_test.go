//go:build !darwin

package openconnect

import (
	"testing"

	E "github.com/sagernet/sing/common/exceptions"
)

func localSystemPPPDEnabled() bool {
	return false
}

func startLocalSystemPPPDPeer(t *testing.T, framing string, datagram bool, dualCarrier bool, environment map[string]string) (*localPPPDPeer, error) {
	t.Helper()
	return nil, E.New("local system pppd fallback is unavailable")
}

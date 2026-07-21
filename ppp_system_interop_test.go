package openconnect

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	pppdInteropImage   = "sing-openconnect-pppd-m3:2.5.2-1"
	pppdInteropVersion = "2.5.2-1+1"
)

var (
	pppdImageOnce sync.Once
	pppdImageErr  error
)

type pppdPeerContainer struct {
	name            string
	address         string
	datagramAddress string
	local           *localPPPDPeer
}

type localPPPDPeer struct {
	address         string
	datagramAddress string
	logs            func() string
}

//nolint:paralleltest
func TestM3PPPSystemPPPDInterop(t *testing.T) {
	if testing.Short() || os.Getenv("OPENCONNECT_IT") == "" {
		t.Skip("OPENCONNECT_IT is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	buildPPPDInteropImage(t, ctx)

	t.Run("F5StreamDualStack", func(t *testing.T) {
		peer := startPPPDPeerContainer(t, ctx, "f5", false, false, map[string]string{
			"MUTATE_CONTROL":  "1",
			"SPLIT_STREAM":    "1",
			"COALESCE_STREAM": "1",
		})

		connection := dialPPPDPeer(t, ctx, peer, false)
		incoming := make(chan []byte, 512)
		link := startPPPDLink(t, ctx, peer, connection, false, pppEncapsulationF5, true, true, incoming, nil)
		assertPPPDConfiguration(t, link.TunnelConfiguration())
		exercisePPPDIPv4(t, link, incoming, 1)
		exercisePPPDIPv6(t, link, incoming, 1)
		time.Sleep(1500 * time.Millisecond)
		logs := pppdPeerLogs(t, ctx, peer)
		for _, marker := range []string{
			"PPPD_CONTROL_PADDING_AND_EARLY_ACFC",
			"PPPD_DATA_EARLY_PFC_ACFC",
			"PPPD_LCP_ECHO_REQUEST",
			"CLIENT_LCP_ECHO_REPLY",
			"PPPD_STREAM_FRAME_SPLIT",
			"PPPD_STREAM_FRAMES_COALESCED",
		} {
			if !strings.Contains(logs, marker) {
				t.Fatalf("real pppd peer did not report %s:\n%s", marker, logs)
			}
		}
		err := link.Close()
		if err != nil {
			t.Fatal(E.Cause(err, "close F5 stream PPP link"))
		}
		logs = pppdPeerLogs(t, ctx, peer)
		if strings.Count(logs, "CLIENT_TERM_REQUEST_") != 1 || !strings.Contains(logs, "CLIENT_TERM_REQUEST_1") {
			t.Fatalf("stream PPP did not send exactly one Terminate-Request:\n%s", logs)
		}
	})

	t.Run("VJAndCCPReject", func(t *testing.T) {
		peer := startPPPDPeerContainer(t, ctx, "f5", false, false, map[string]string{
			"ENABLE_VJ":  "1",
			"INJECT_CCP": "1",
		})

		connection := dialPPPDPeer(t, ctx, peer, false)
		incoming := make(chan []byte, 512)
		link := startPPPDLink(t, ctx, peer, connection, false, pppEncapsulationF5, true, true, incoming, nil)
		waitPPPDPeerMarker(t, ctx, peer, "CLIENT_IPCP_CONFIG_REJECT")
		waitPPPDPeerMarker(t, ctx, peer, "PPPD_SHIM_CCP_CONFIG_REQUEST")
		waitPPPDPeerMarker(t, ctx, peer, "CLIENT_CCP_PROTOCOL_REJECT")
		err := link.Close()
		if err != nil {
			t.Fatal(E.Cause(err, "close VJ/CCP rejection PPP link"))
		}
	})

	t.Run("F5HDLCWireTolerance", func(t *testing.T) {
		peer := startPPPDPeerContainer(t, ctx, "f5-hdlc", false, false, map[string]string{
			"CORRUPT_FIRST_HDLC": "1",
			"OMIT_INITIAL_HDLC":  "1",
			"SPLIT_HDLC_ESCAPE":  "1",
		})

		connection := dialPPPDPeer(t, ctx, peer, false)
		incoming := make(chan []byte, 512)
		link := startPPPDLink(t, ctx, peer, connection, false, pppEncapsulationF5HDLC, true, true, incoming, nil)
		assertPPPDConfiguration(t, link.TunnelConfiguration())
		exercisePPPDIPv4(t, link, incoming, 2)
		logs := pppdPeerLogs(t, ctx, peer)
		for _, marker := range []string{"PPPD_HDLC_FCS_CORRUPTED", "PPPD_HDLC_INITIAL_FLAG_OMITTED", "PPPD_HDLC_ESCAPE_SPLIT"} {
			if !strings.Contains(logs, marker) {
				t.Fatalf("real pppd HDLC peer did not report %s:\n%s", marker, logs)
			}
		}
		err := link.Close()
		if err != nil {
			t.Fatal(E.Cause(err, "close F5 HDLC PPP link"))
		}
	})

	t.Run("IPv4Only", func(t *testing.T) {
		peer := startPPPDPeerContainer(t, ctx, "f5", false, false, nil)
		connection := dialPPPDPeer(t, ctx, peer, false)
		incoming := make(chan []byte, 512)
		link := startPPPDLink(t, ctx, peer, connection, false, pppEncapsulationF5, true, false, incoming, nil)
		configuration := link.TunnelConfiguration()
		if configuration.MTU != 1320 || !slices.Equal(configuration.Addresses, []netip.Prefix{netip.MustParsePrefix("192.0.2.2/32")}) ||
			len(configuration.DNS) != 2 || len(configuration.NBNS) != 2 {
			t.Fatalf("unexpected IPv4-only pppd configuration: %+v", configuration)
		}
		waitPPPDPeerMarker(t, ctx, peer, "CLIENT_IP6CP_PROTOCOL_REJECT")
		err := link.Close()
		if err != nil {
			t.Fatal(E.Cause(err, "close IPv4-only PPP link"))
		}
	})

	t.Run("IPv6Only", func(t *testing.T) {
		peer := startPPPDPeerContainer(t, ctx, "f5", false, false, nil)
		connection := dialPPPDPeer(t, ctx, peer, false)
		incoming := make(chan []byte, 512)
		link := startPPPDLink(t, ctx, peer, connection, false, pppEncapsulationF5, false, true, incoming, nil)
		configuration := link.TunnelConfiguration()
		if configuration.MTU != 1320 || !slices.Equal(configuration.Addresses, []netip.Prefix{netip.MustParsePrefix("fe80::2/64")}) ||
			len(configuration.DNS) != 0 || len(configuration.NBNS) != 0 {
			t.Fatalf("unexpected IPv6-only pppd configuration: %+v", configuration)
		}
		waitPPPDPeerMarker(t, ctx, peer, "CLIENT_IPCP_PROTOCOL_REJECT")
		err := link.Close()
		if err != nil {
			t.Fatal(E.Cause(err, "close IPv6-only PPP link"))
		}
	})

	t.Run("DualStackPeerRejectsIPv6", func(t *testing.T) {
		peer := startPPPDPeerContainer(t, ctx, "f5", false, false, map[string]string{"REJECT_CLIENT_IP6CP": "1"})
		connection := dialPPPDPeer(t, ctx, peer, false)
		incoming := make(chan []byte, 512)
		link := startPPPDLink(t, ctx, peer, connection, false, pppEncapsulationF5, true, true, incoming, nil)
		configuration := link.TunnelConfiguration()
		if !slices.Equal(configuration.Addresses, []netip.Prefix{netip.MustParsePrefix("192.0.2.2/32")}) {
			t.Fatalf("IPv6 rejection did not preserve IPv4 PPP: %+v", configuration)
		}
		waitPPPDPeerMarker(t, ctx, peer, "PPPD_SHIM_IP6CP_CONFIG_REJECT")
		err := link.Close()
		if err != nil {
			t.Fatal(E.Cause(err, "close IPv6-rejected dual-stack PPP link"))
		}
	})

	t.Run("DualStackPeerZeroNaksIPv6", func(t *testing.T) {
		peer := startPPPDPeerContainer(t, ctx, "f5", false, false, map[string]string{"ZERO_NAK_CLIENT_IP6CP": "1"})
		connection := dialPPPDPeer(t, ctx, peer, false)
		incoming := make(chan []byte, 512)
		link := startPPPDLink(t, ctx, peer, connection, false, pppEncapsulationF5, true, true, incoming, nil)
		configuration := link.TunnelConfiguration()
		if !slices.Equal(configuration.Addresses, []netip.Prefix{netip.MustParsePrefix("192.0.2.2/32")}) {
			t.Fatalf("zero IPv6 Nak did not preserve IPv4 PPP: %+v", configuration)
		}
		waitPPPDPeerMarker(t, ctx, peer, "PPPD_SHIM_IP6CP_ZERO_NAK")
		err := link.Close()
		if err != nil {
			t.Fatal(E.Cause(err, "close zero-IPv6-Nak dual-stack PPP link"))
		}
	})

	t.Run("IPv6OnlyPeerRejectsIPv6", func(t *testing.T) {
		peer := startPPPDPeerContainer(t, ctx, "f5", false, false, map[string]string{"REJECT_CLIENT_IP6CP": "1"})
		connection := dialPPPDPeer(t, ctx, peer, false)
		link, err := newPPPLink(ctx, pppLinkConfig{
			Carrier:             pppCarrierConfig{Connection: connection},
			Encapsulation:       pppEncapsulationF5,
			WantIPv6:            true,
			MTU:                 1400,
			NegotiationPeriod:   500 * time.Millisecond,
			NegotiationAttempts: 20,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = link.Close()
		})
		err = link.Start()
		if !E.IsMulti(err, ErrProtocolNotSupported) {
			t.Fatalf("IPv6-only PPP unexpectedly survived peer IPv6 rejection: %v", err)
		}
		waitPPPDPeerMarker(t, ctx, peer, "PPPD_SHIM_IP6CP_CONFIG_REJECT")
	})

	t.Run("ContextCancellationCleanup", func(t *testing.T) {
		peer := startPPPDPeerContainer(t, ctx, "f5", false, false, nil)
		linkContext, cancelLink := context.WithCancel(ctx)
		connection := dialPPPDPeer(t, linkContext, peer, false)
		incoming := make(chan []byte, 512)
		link := startPPPDLink(t, linkContext, peer, connection, false, pppEncapsulationF5, true, true, incoming, nil)
		cancelLink()
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		select {
		case <-link.Done():
		case <-timer.C:
			t.Fatal("PPP link did not terminate after context cancellation")
		}
		waitPPPDPeerMarker(t, context.Background(), peer, "PPPD_PEER_EXIT")
	})

	t.Run("FortinetDatagramTerminateRetry", func(t *testing.T) {
		peer := startPPPDPeerContainer(t, ctx, "fortinet", true, false, map[string]string{
			"DROP_TERM_REQUESTS": "2",
		})

		connection := dialPPPDPeer(t, ctx, peer, true)
		incoming := make(chan []byte, 512)
		link := startPPPDLink(t, ctx, peer, connection, true, pppEncapsulationFortinet, true, true, incoming, nil)
		assertPPPDConfiguration(t, link.TunnelConfiguration())
		exercisePPPDIPv4(t, link, incoming, 3)
		exercisePPPDIPv6(t, link, incoming, 3)
		started := time.Now()
		err := link.Close()
		elapsed := time.Since(started)
		if err != nil {
			t.Fatal(E.Cause(err, "close Fortinet datagram PPP link"))
		}
		if elapsed < 1800*time.Millisecond || elapsed > 4*time.Second {
			t.Fatalf("datagram PPP terminate retry window was %v", elapsed)
		}
		logs := pppdPeerLogs(t, ctx, peer)
		for _, marker := range []string{"CLIENT_TERM_REQUEST_1", "CLIENT_TERM_REQUEST_2", "CLIENT_TERM_REQUEST_3"} {
			if !strings.Contains(logs, marker) {
				t.Fatalf("real pppd datagram peer did not report %s:\n%s", marker, logs)
			}
		}
	})

	t.Run("F5LateDatagramTakeover", func(t *testing.T) {
		peer := startPPPDPeerContainer(t, ctx, "f5", false, true, nil)
		streamConnection := dialPPPDPeer(t, ctx, peer, false)
		incoming := make(chan []byte, 512)
		deliveryStarted := make(chan struct{}, 1)
		releaseDelivery := make(chan struct{})
		oldCarrierClient := netip.MustParseAddr("192.0.2.2")
		oldCarrierPeer := netip.MustParseAddr("192.0.2.1")
		oldCarrierPayload := []byte("sing-openconnect-m3-pppd-old-carrier-delivery")
		var releaseDeliveryOnce sync.Once
		var blockOldDeliveryOnce sync.Once
		releaseOldDelivery := func() {
			releaseDeliveryOnce.Do(func() {
				close(releaseDelivery)
			})
		}
		link := startPPPDLink(t, ctx, peer, streamConnection, false, pppEncapsulationF5, true, true, incoming, func(packet []byte) {
			if validatePPPDIPv4EchoReply(packet, oldCarrierClient, oldCarrierPeer, 0x4d33, 5, oldCarrierPayload) != nil {
				return
			}
			blockDelivery := false
			blockOldDeliveryOnce.Do(func() {
				blockDelivery = true
			})
			if !blockDelivery {
				return
			}
			deliveryStarted <- struct{}{}
			<-releaseDelivery
		})

		t.Cleanup(releaseOldDelivery)
		before := link.TunnelConfiguration()
		exercisePPPDIPv4(t, link, incoming, 4)
		drainPPPDIncoming(incoming)
		oldCarrierRequest := buildPPPDIPv4EchoRequest(
			oldCarrierClient,
			oldCarrierPeer,
			0x4d33,
			5,
			oldCarrierPayload,
		)
		writeOldCarrierProbe := func() {
			err := link.WriteDataPacket(oldCarrierRequest)
			if err != nil {
				t.Fatal(E.Cause(err, "write old-carrier IPv4 packet before PPP takeover"))
			}
		}
		writeOldCarrierProbe()
		retryOldCarrier := time.NewTicker(250 * time.Millisecond)
		oldCarrierDeadline := time.NewTimer(10 * time.Second)
	waitOldCarrierDelivery:
		for {
			select {
			case <-deliveryStarted:
				break waitOldCarrierDelivery
			case <-retryOldCarrier.C:
				writeOldCarrierProbe()
			case <-oldCarrierDeadline.C:
				t.Fatal("real pppd exact old-carrier delivery did not reach the generation gate")
			}
		}
		retryOldCarrier.Stop()
		if !oldCarrierDeadline.Stop() {
			select {
			case <-oldCarrierDeadline.C:
			default:
			}
		}
		datagramConnection := dialPPPDPeer(t, ctx, peer, true)
		var err error
		switchDone := make(chan error, 1)
		go func() {
			switchDone <- link.SwitchCarrier(pppCarrierConfig{Connection: datagramConnection, Datagram: true, MTU: 1280})
		}()
		select {
		case err = <-switchDone:
			t.Fatalf("PPP takeover published while an old-generation delivery was still in flight: %v", err)
		case <-time.After(250 * time.Millisecond):
		}
		releaseOldDelivery()
		waitPPPDDataPacket(t, incoming, 4, func(packet []byte) error {
			return validatePPPDIPv4EchoReply(
				packet,
				oldCarrierClient,
				oldCarrierPeer,
				0x4d33,
				5,
				oldCarrierPayload,
			)
		})
		select {
		case err = <-switchDone:
			if err != nil {
				t.Fatal(E.Cause(err, "switch PPP link to datagram carrier"))
			}
		case <-time.After(10 * time.Second):
			t.Fatal("PPP takeover did not complete after old-generation delivery finished")
		}
		waitPPPDPeerMarker(t, ctx, peer, "PPPD_DUAL_UDP_CLIENT_CONNECTED")
		waitPPPDPeerMarker(t, ctx, peer, "PPPD_DUAL_TCP_CARRIER_CLOSED")
		after := link.TunnelConfiguration()
		if before.MTU != 1320 || after.MTU != 1280 || !slices.Equal(before.Addresses, after.Addresses) ||
			!slices.Equal(before.DNS, after.DNS) || !slices.Equal(before.NBNS, after.NBNS) {
			t.Fatalf("PPP carrier takeover did not preserve identity and adopt its MTU: before=%+v after=%+v", before, after)
		}
		exercisePPPDTakeoverData(t, ctx, peer, link, incoming)
		exercisePPPDMaximumIPv4(t, link, incoming, netip.MustParseAddr("192.0.2.1"), 1280, 9)
		assertPPPDDualCarrierMarkers(t, ctx, peer,
			"CLIENT_DUAL_TCP_IPV4_DATA",
			"CLIENT_DUAL_UDP_LCP_CONFIG_REQUEST",
			"CLIENT_DUAL_UDP_IPV4_DATA",
			"CLIENT_DUAL_UDP_IPV6_DATA",
			"PPPD_DUAL_UDP_IPV4_DATA",
			"PPPD_DUAL_UDP_IPV6_DATA",
		)
		err = link.Close()
		if err != nil {
			t.Fatal(E.Cause(err, "close taken-over PPP link"))
		}
	})

	t.Run("F5BlockedWriterTakeover", func(t *testing.T) {
		peer := startPPPDPeerContainer(t, ctx, "f5", false, true, map[string]string{
			"PAUSE_CLIENT_READS_AFTER_IPV4": "64",
		})

		streamConnection := dialPPPDPeer(t, ctx, peer, false)
		tcpConnection, loaded := streamConnection.(*net.TCPConn)
		if !loaded {
			t.Fatalf("real pppd stream carrier is not TCP: %T", streamConnection)
		}
		err := tcpConnection.SetWriteBuffer(4096)
		if err != nil {
			t.Fatal(E.Cause(err, "reduce real pppd carrier write buffer"))
		}
		incoming := make(chan []byte, 512)
		link := startPPPDLink(t, ctx, peer, streamConnection, false, pppEncapsulationF5, true, false, incoming, nil)
		before := link.TunnelConfiguration()
		exercisePPPDIPv4(t, link, incoming, 9)
		blockedWrite := blockPPPDCarrierWrite(t, link)
		waitPPPDPeerMarker(t, ctx, peer, "PPPD_CLIENT_READS_PAUSED")
		datagramConnection := dialPPPDPeer(t, ctx, peer, true)
		switchDone := make(chan error, 1)
		go func() {
			switchDone <- link.SwitchCarrier(pppCarrierConfig{Connection: datagramConnection, Datagram: true})
		}()
		timer := time.NewTimer(5 * time.Second)
		select {
		case err = <-switchDone:
			if err != nil {
				t.Fatal(E.Cause(err, "switch PPP carrier while its writer is blocked"))
			}
		case <-timer.C:
			t.Fatal("PPP carrier takeover remained blocked behind the old carrier writer")
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		select {
		case err = <-blockedWrite:
			if !E.IsMulti(err, ErrDataChannelNotReady) {
				t.Fatalf("old PPP carrier writer did not become transiently unavailable: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("old PPP carrier writer survived carrier takeover")
		}
		waitPPPDPeerMarker(t, ctx, peer, "PPPD_DUAL_UDP_CLIENT_CONNECTED")
		waitPPPDPeerMarker(t, ctx, peer, "PPPD_DUAL_TCP_CARRIER_CLOSED")
		after := link.TunnelConfiguration()
		if before.MTU != after.MTU || !slices.Equal(before.Addresses, after.Addresses) ||
			!slices.Equal(before.DNS, after.DNS) || !slices.Equal(before.NBNS, after.NBNS) {
			t.Fatalf("blocked-writer takeover changed PPP configuration: before=%+v after=%+v", before, after)
		}
		drainPPPDIncoming(incoming)
		clientAddress := netip.MustParseAddr("192.0.2.2")
		peerAddress := netip.MustParseAddr("192.0.2.1")
		payload := []byte("sing-openconnect-m3-pppd-blocked-takeover")
		request := buildPPPDIPv4EchoRequest(
			clientAddress,
			peerAddress,
			0x4d33,
			10,
			payload,
		)
		exercisePPPDDataProbe(t, link, incoming, 4, request, func(packet []byte) error {
			return validatePPPDIPv4EchoReply(packet, clientAddress, peerAddress, 0x4d33, 10, payload)
		})
		waitPPPDPeerMarker(t, ctx, peer, "CLIENT_DUAL_UDP_IPV4_DATA")
		assertPPPDDualCarrierMarkers(t, ctx, peer,
			"CLIENT_DUAL_TCP_IPV4_DATA",
			"CLIENT_DUAL_UDP_LCP_CONFIG_REQUEST",
			"PPPD_DUAL_UDP_IPV4_DATA",
		)
	})

	t.Run("F5BlockedWriterClose", func(t *testing.T) {
		peer := startPPPDPeerContainer(t, ctx, "f5", false, false, map[string]string{
			"PAUSE_CLIENT_READS_AFTER_IPV4": "64",
		})

		connection := dialPPPDPeer(t, ctx, peer, false)
		tcpConnection, loaded := connection.(*net.TCPConn)
		if !loaded {
			t.Fatalf("real pppd stream carrier is not TCP: %T", connection)
		}
		err := tcpConnection.SetWriteBuffer(4096)
		if err != nil {
			t.Fatal(E.Cause(err, "reduce real pppd carrier write buffer"))
		}
		incoming := make(chan []byte, 512)
		link := startPPPDLink(t, ctx, peer, connection, false, pppEncapsulationF5, true, false, incoming, nil)
		exercisePPPDIPv4(t, link, incoming, 11)
		blockedWrite := blockPPPDCarrierWrite(t, link)
		waitPPPDPeerMarker(t, ctx, peer, "PPPD_CLIENT_READS_PAUSED")
		closeDone := make(chan error, 1)
		go func() {
			closeDone <- link.Close()
		}()
		select {
		case err = <-closeDone:
			if err != nil {
				t.Fatal(E.Cause(err, "close PPP link with blocked carrier writer"))
			}
		case <-time.After(2 * time.Second):
			t.Fatal("PPP close remained blocked behind the carrier writer")
		}
		select {
		case err = <-blockedWrite:
			if !E.IsMulti(err, ErrDataChannelNotReady) {
				t.Fatalf("closing PPP carrier writer did not become transiently unavailable: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("PPP carrier writer survived link close")
		}
		select {
		case <-link.Done():
		default:
			t.Fatal("PPP link survived close with a blocked carrier writer")
		}
	})
}

func buildPPPDInteropImage(t *testing.T, ctx context.Context) {
	t.Helper()
	pppdImageOnce.Do(func() {
		_, pppdImageErr = runPPPDInteropDocker(ctx,
			"build", "--pull=false", "--tag", pppdInteropImage,
			filepath.Join("test", "testdata", "pppd-peer"),
		)
	})
	if pppdImageErr != nil {
		t.Fatal(pppdImageErr)
	}
}

func startPPPDPeerContainer(t *testing.T, ctx context.Context, framing string, datagram bool, dualCarrier bool, environment map[string]string) pppdPeerContainer {
	t.Helper()
	name := "sing-openconnect-pppd-m3-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	protocol := "tcp"
	if datagram {
		protocol = "udp"
	}
	arguments := []string{
		"run", "--detach", "--name", name, "--privileged",
		"--publish", "127.0.0.1::4433/" + protocol,
	}
	if dualCarrier {
		arguments = append(arguments, "--publish", "127.0.0.1::4434/udp")
	}
	for key, value := range environment {
		arguments = append(arguments, "--env", key+"="+value)
	}
	arguments = append(arguments, pppdInteropImage, framing)
	if dualCarrier {
		arguments = append(arguments, "dual")
	} else if datagram {
		arguments = append(arguments, "udp")
	}
	_, err := runPPPDInteropDocker(ctx, arguments...)
	if err != nil {
		t.Fatal(err)
	}
	peer := pppdPeerContainer{name: name}
	t.Cleanup(func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = runPPPDInteropDocker(cleanupContext, "rm", "--force", name)
	})
	time.Sleep(250 * time.Millisecond)
	running, err := runPPPDInteropDocker(ctx, "inspect", "--format", "{{.State.Running}}", name)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(running) != "true" {
		logs := pppdPeerLogs(t, ctx, peer)
		if strings.Contains(logs, "PPPD_UNAVAILABLE") {
			if localSystemPPPDEnabled() {
				localPeer, localErr := startLocalSystemPPPDPeer(t, framing, datagram, dualCarrier, environment)
				if localErr != nil {
					t.Fatal(localErr)
				}
				peer = pppdPeerContainer{
					address:         localPeer.address,
					datagramAddress: localPeer.datagramAddress,
					local:           localPeer,
				}
				t.Cleanup(func() {
					if t.Failed() {
						t.Log(peer.local.logs())
					}
				})
				return peer
			}
			t.Fatal("Docker host does not provide the real pppd kernel device and no local system pppd fallback is available: " + strings.TrimSpace(logs))
		}
		t.Fatalf("real pppd peer exited before connection:\n%s", logs)
	}
	version, err := runPPPDInteropDocker(ctx, "exec", name, "dpkg-query", "-W", "-f=${Version}", "ppp")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(version) != pppdInteropVersion {
		t.Fatalf("unexpected pppd package version: %q", strings.TrimSpace(version))
	}
	published, err := runPPPDInteropDocker(ctx, "port", name, "4433/"+protocol)
	if err != nil {
		t.Fatal(err)
	}
	peer.address = strings.TrimSpace(strings.SplitN(published, "\n", 2)[0])
	if _, _, err = net.SplitHostPort(peer.address); err != nil {
		t.Fatal(E.Cause(err, "parse real pppd published address"))
	}
	if dualCarrier {
		published, err = runPPPDInteropDocker(ctx, "port", name, "4434/udp")
		if err != nil {
			t.Fatal(err)
		}
		peer.datagramAddress = strings.TrimSpace(strings.SplitN(published, "\n", 2)[0])
		if _, _, err = net.SplitHostPort(peer.datagramAddress); err != nil {
			t.Fatal(E.Cause(err, "parse real pppd dual-carrier datagram address"))
		}
	}
	t.Cleanup(func() {
		if t.Failed() {
			logsContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			logs, logsErr := runPPPDInteropDocker(logsContext, "logs", peer.name)
			if logsErr == nil {
				t.Log(logs)
			}
		}
	})
	return peer
}

func dialPPPDPeer(t *testing.T, ctx context.Context, peer pppdPeerContainer, datagram bool) net.Conn {
	t.Helper()
	network := "tcp"
	address := peer.address
	if datagram {
		network = "udp"
		if peer.datagramAddress != "" {
			address = peer.datagramAddress
		}
	}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		t.Fatal(E.Cause(err, "dial real pppd peer"))
	}
	return connection
}

func startPPPDLink(t *testing.T, ctx context.Context, peer pppdPeerContainer, connection net.Conn, datagram bool, encapsulation pppEncapsulation, wantIPv4 bool, wantIPv6 bool, incoming chan<- []byte, beforeDeliver func([]byte)) *pppLink {
	t.Helper()
	link, err := newPPPLink(ctx, pppLinkConfig{
		Carrier:                pppCarrierConfig{Connection: connection, Datagram: datagram},
		Encapsulation:          encapsulation,
		WantIPv4:               wantIPv4,
		WantIPv6:               wantIPv6,
		MTU:                    1400,
		RequestIPv4NameServers: wantIPv4,
		NegotiationPeriod:      500 * time.Millisecond,
		NegotiationAttempts:    20,
		EchoInterval:           500 * time.Millisecond,
		EchoFailures:           6,
		Deliver: func(packetBuffer *buf.Buffer) {
			defer packetBuffer.Release()
			payload := packetBuffer.Bytes()
			if beforeDeliver != nil {
				beforeDeliver(payload)
			}
			select {
			case incoming <- append([]byte(nil), payload...):
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = link.Start()
	if err != nil {
		logs := pppdPeerLogs(t, context.Background(), peer)
		t.Fatalf("start PPP link with real pppd: %v\n%s", err, logs)
	}
	t.Cleanup(func() {
		_ = link.Close()
	})
	return link
}

func assertPPPDConfiguration(t *testing.T, configuration TunnelConfiguration) {
	t.Helper()
	expectedAddresses := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.2/32"),
		netip.MustParsePrefix("fe80::2/64"),
	}
	expectedDNS := []netip.Addr{netip.MustParseAddr("203.0.113.53"), netip.MustParseAddr("203.0.113.54")}
	expectedNBNS := []netip.Addr{netip.MustParseAddr("203.0.113.137"), netip.MustParseAddr("203.0.113.138")}
	if configuration.MTU != 1320 || !slices.Equal(configuration.Addresses, expectedAddresses) ||
		!slices.Equal(configuration.DNS, expectedDNS) || !slices.Equal(configuration.NBNS, expectedNBNS) {
		t.Fatalf("unexpected real pppd configuration: %+v", configuration)
	}
}

func exercisePPPDIPv4(t *testing.T, link *pppLink, incoming <-chan []byte, sequence uint16) {
	t.Helper()
	clientAddress := netip.MustParseAddr("192.0.2.2")
	peerAddress := netip.MustParseAddr("192.0.2.1")
	payload := []byte("sing-openconnect-m3-pppd-ipv4")
	request := buildPPPDIPv4EchoRequest(clientAddress, peerAddress, 0x4d33, sequence, payload)
	exercisePPPDDataProbe(t, link, incoming, 4, request, func(packet []byte) error {
		return validatePPPDIPv4EchoReply(packet, clientAddress, peerAddress, 0x4d33, sequence, payload)
	})
}

func exercisePPPDIPv6(t *testing.T, link *pppLink, incoming <-chan []byte, sequence uint16) {
	t.Helper()
	clientAddress := netip.MustParseAddr("fe80::2")
	peerAddress := netip.MustParseAddr("fe80::1")
	payload := []byte("sing-openconnect-m3-pppd-ipv6")
	request := buildPPPDIPv6EchoRequest(clientAddress, peerAddress, 0x4d36, sequence, payload)
	exercisePPPDDataProbe(t, link, incoming, 6, request, func(packet []byte) error {
		return validatePPPDIPv6EchoReply(packet, clientAddress, peerAddress, 0x4d36, sequence, payload)
	})
}

func exercisePPPDTakeoverData(t *testing.T, ctx context.Context, peer pppdPeerContainer, link *pppLink, incoming <-chan []byte) {
	t.Helper()
	drainPPPDIncoming(incoming)
	ipv4Client := netip.MustParseAddr("192.0.2.2")
	ipv4Peer := netip.MustParseAddr("192.0.2.1")
	ipv4Payload := []byte("sing-openconnect-m3-pppd-takeover-ipv4")
	ipv4Request := buildPPPDIPv4EchoRequest(
		ipv4Client,
		ipv4Peer,
		0x4d33,
		8,
		ipv4Payload,
	)
	exercisePPPDDataProbe(t, link, incoming, 4, ipv4Request, func(packet []byte) error {
		return validatePPPDIPv4EchoReply(packet, ipv4Client, ipv4Peer, 0x4d33, 8, ipv4Payload)
	})
	waitPPPDPeerMarker(t, ctx, peer, "CLIENT_DUAL_UDP_IPV4_DATA")
	ipv6Client := netip.MustParseAddr("fe80::2")
	ipv6Peer := netip.MustParseAddr("fe80::1")
	ipv6Payload := []byte("sing-openconnect-m3-pppd-takeover-ipv6")
	ipv6Request := buildPPPDIPv6EchoRequest(
		ipv6Client,
		ipv6Peer,
		0x4d36,
		8,
		ipv6Payload,
	)
	exercisePPPDDataProbe(t, link, incoming, 6, ipv6Request, func(packet []byte) error {
		return validatePPPDIPv6EchoReply(packet, ipv6Client, ipv6Peer, 0x4d36, 8, ipv6Payload)
	})
	waitPPPDPeerMarker(t, ctx, peer, "CLIENT_DUAL_UDP_IPV6_DATA")
}

func exercisePPPDMaximumIPv4(t *testing.T, link *pppLink, incoming <-chan []byte, peerAddress netip.Addr, mtu int, sequence uint16) {
	t.Helper()
	payload := bytes.Repeat([]byte{0x5a}, mtu-28)
	request := buildPPPDIPv4EchoRequest(
		netip.MustParseAddr("192.0.2.2"),
		peerAddress,
		0x4d39,
		sequence,
		payload,
	)
	exercisePPPDDataProbe(t, link, incoming, 4, request, func(packet []byte) error {
		return validatePPPDIPv4EchoReply(
			packet,
			netip.MustParseAddr("192.0.2.2"),
			peerAddress,
			0x4d39,
			sequence,
			payload,
		)
	})
}

func exercisePPPDDataProbe(
	t *testing.T,
	link *pppLink,
	incoming <-chan []byte,
	version byte,
	request []byte,
	validate func([]byte) error,
) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	retry := time.NewTicker(250 * time.Millisecond)
	defer retry.Stop()
	writeProbe := func() {
		err := link.WriteDataPacket(request)
		if err != nil {
			t.Fatal(E.Cause(err, "write IPv", version, " probe to real pppd"))
		}
	}
	writeProbe()
	var lastErr error
	for {
		select {
		case packet := <-incoming:
			if len(packet) > 0 && packet[0]>>4 == version {
				lastErr = validate(packet)
				if lastErr == nil {
					return
				}
			}
		case <-retry.C:
			writeProbe()
		case <-deadline.C:
			t.Fatalf("timed out waiting for exact IPv%d probe reply from real pppd: %v", version, lastErr)
		}
	}
}

func drainPPPDIncoming(incoming <-chan []byte) {
	for {
		select {
		case <-incoming:
		default:
			return
		}
	}
}

func blockPPPDCarrierWrite(t *testing.T, link *pppLink) <-chan error {
	t.Helper()
	payload := bytes.Repeat([]byte{0xa5}, 1292)
	packet := buildPPPDIPv4EchoRequest(
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.1"),
		0x4d33,
		12,
		payload,
	)
	started := make(chan struct{}, 1)
	result := make(chan error, 1)
	go func() {
		for {
			select {
			case started <- struct{}{}:
			default:
			}
			err := link.WriteDataPacket(packet)
			if err != nil {
				result <- err
				return
			}
		}
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	select {
	case <-started:
	case err := <-result:
		t.Fatalf("real PPP carrier writer stopped before saturation: %v", err)
	case <-deadline.C:
		t.Fatal("real PPP carrier writer did not begin")
	}
	for {
		stalled := time.NewTimer(250 * time.Millisecond)
		select {
		case <-started:
			if !stalled.Stop() {
				select {
				case <-stalled.C:
				default:
				}
			}
		case err := <-result:
			if !stalled.Stop() {
				select {
				case <-stalled.C:
				default:
				}
			}
			t.Fatalf("real PPP carrier writer stopped before blocking: %v", err)
		case <-stalled.C:
			return result
		case <-deadline.C:
			if !stalled.Stop() {
				select {
				case <-stalled.C:
				default:
				}
			}
			t.Fatal("real PPP carrier send buffer did not saturate")
		}
	}
}

func waitPPPDDataPacket(t *testing.T, incoming <-chan []byte, version byte, validate func([]byte) error) {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	var lastErr error
	for {
		select {
		case packet := <-incoming:
			if len(packet) > 0 && packet[0]>>4 == version {
				lastErr = validate(packet)
				if lastErr == nil {
					return
				}
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for IPv%d packet from real pppd: %v", version, lastErr)
		}
	}
}

func buildPPPDIPv4EchoRequest(source netip.Addr, destination netip.Addr, identifier uint16, sequence uint16, payload []byte) []byte {
	packet := make([]byte, 28+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 1
	sourceBytes := source.As4()
	destinationBytes := destination.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	binary.BigEndian.PutUint16(packet[10:12], pppdChecksum(packet[:20]))
	packet[20] = 8
	binary.BigEndian.PutUint16(packet[24:26], identifier)
	binary.BigEndian.PutUint16(packet[26:28], sequence)
	copy(packet[28:], payload)
	binary.BigEndian.PutUint16(packet[22:24], pppdChecksum(packet[20:]))
	return packet
}

func validatePPPDIPv4EchoReply(packet []byte, client netip.Addr, peer netip.Addr, identifier uint16, sequence uint16, payload []byte) error {
	if len(packet) != 28+len(payload) || packet[0]>>4 != 4 || packet[9] != 1 || packet[20] != 0 {
		return E.New("invalid IPv4 ICMP echo reply from real pppd: length=", len(packet), " protocol=", packet[9], " type=", packet[20])
	}
	if pppdChecksum(packet[:20]) != 0 || pppdChecksum(packet[20:]) != 0 {
		return E.New("invalid IPv4 ICMP checksum from real pppd")
	}
	clientBytes := client.As4()
	peerBytes := peer.As4()
	if !bytes.Equal(packet[12:16], peerBytes[:]) || !bytes.Equal(packet[16:20], clientBytes[:]) ||
		binary.BigEndian.Uint16(packet[24:26]) != identifier || binary.BigEndian.Uint16(packet[26:28]) != sequence ||
		!bytes.Equal(packet[28:], payload) {
		return E.New("unexpected IPv4 ICMP echo reply fields from real pppd")
	}
	return nil
}

func buildPPPDIPv6EchoRequest(source netip.Addr, destination netip.Addr, identifier uint16, sequence uint16, payload []byte) []byte {
	packet := make([]byte, 48+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(payload)))
	packet[6] = 58
	packet[7] = 64
	sourceBytes := source.As16()
	destinationBytes := destination.As16()
	copy(packet[8:24], sourceBytes[:])
	copy(packet[24:40], destinationBytes[:])
	packet[40] = 128
	binary.BigEndian.PutUint16(packet[44:46], identifier)
	binary.BigEndian.PutUint16(packet[46:48], sequence)
	copy(packet[48:], payload)
	binary.BigEndian.PutUint16(packet[42:44], pppdIPv6Checksum(packet[8:24], packet[24:40], packet[40:]))
	return packet
}

func validatePPPDIPv6EchoReply(packet []byte, client netip.Addr, peer netip.Addr, identifier uint16, sequence uint16, payload []byte) error {
	if len(packet) != 48+len(payload) || packet[0]>>4 != 6 || packet[6] != 58 || packet[40] != 129 {
		return E.New("invalid IPv6 ICMP echo reply from real pppd")
	}
	if pppdIPv6Checksum(packet[8:24], packet[24:40], packet[40:]) != 0 {
		return E.New("invalid IPv6 ICMP checksum from real pppd")
	}
	clientBytes := client.As16()
	peerBytes := peer.As16()
	if !bytes.Equal(packet[8:24], peerBytes[:]) || !bytes.Equal(packet[24:40], clientBytes[:]) ||
		binary.BigEndian.Uint16(packet[44:46]) != identifier || binary.BigEndian.Uint16(packet[46:48]) != sequence ||
		!bytes.Equal(packet[48:], payload) {
		return E.New("unexpected IPv6 ICMP echo reply fields from real pppd")
	}
	return nil
}

func pppdIPv6Checksum(source []byte, destination []byte, payload []byte) uint16 {
	pseudoHeader := make([]byte, 40+len(payload))
	copy(pseudoHeader[:16], source)
	copy(pseudoHeader[16:32], destination)
	binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(len(payload)))
	pseudoHeader[39] = 58
	copy(pseudoHeader[40:], payload)
	return pppdChecksum(pseudoHeader)
}

func pppdChecksum(content []byte) uint16 {
	var sum uint32
	for len(content) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(content[:2]))
		content = content[2:]
	}
	if len(content) == 1 {
		sum += uint32(content[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func pppdPeerLogs(t *testing.T, ctx context.Context, peer pppdPeerContainer) string {
	t.Helper()
	if peer.local != nil {
		return peer.local.logs()
	}
	logs, err := runPPPDInteropDocker(ctx, "logs", peer.name)
	if err != nil {
		t.Fatal(err)
	}
	return logs
}

func assertPPPDDualCarrierMarkers(t *testing.T, ctx context.Context, peer pppdPeerContainer, markers ...string) {
	t.Helper()
	for _, marker := range markers {
		waitPPPDPeerMarker(t, ctx, peer, marker)
	}
	logs := pppdPeerLogs(t, ctx, peer)
	if strings.Count(logs, "PPPD_PROCESS_SPAWNED ") != 1 {
		t.Fatalf("dual-carrier oracle did not keep exactly one real pppd process:\n%s", logs)
	}
}

func waitPPPDPeerMarker(t *testing.T, ctx context.Context, peer pppdPeerContainer, marker string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		logs := pppdPeerLogs(t, ctx, peer)
		if strings.Contains(logs, marker) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("real pppd peer did not report %s:\n%s", marker, logs)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context ended while waiting for real pppd marker %s: %v", marker, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func runPPPDInteropDocker(ctx context.Context, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", E.Cause(err, "docker ", strings.Join(arguments, " "), ": ", strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

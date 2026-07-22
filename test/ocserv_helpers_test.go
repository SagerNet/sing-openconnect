package test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	ocservInteropVersion = "1.3.0-2"
	ocservInteropImage   = "sing-openconnect-ocserv:" + ocservInteropVersion
	ocservUsername       = "test"
	ocservPassword       = "test"
	ocservTunnelAddress  = "192.168.77.1"
)

type ocservContainer struct {
	tcpAddress string
	udpAddress string
}

func dockerPublishedAddress(t *testing.T, ctx context.Context, containerName string, port string) string {
	t.Helper()
	output, err := dockerOutput(ctx, "port", containerName, port)
	if err != nil {
		t.Fatal(err)
	}
	address := strings.TrimSpace(output)
	_, _, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		t.Fatal(E.Cause(splitErr, "parse Docker published address: ", address))
	}
	return address
}

func dockerOutput(ctx context.Context, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", E.Cause(err, "docker ", strings.Join(arguments, " "), ": ", strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func waitForTCP(t *testing.T, ctx context.Context, address string) {
	t.Helper()
	for {
		conn, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for ocserv TCP listener"))
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func buildIPv4ICMPEchoRequest(
	t *testing.T,
	sourceAddress netip.Addr,
	destinationAddress netip.Addr,
	identifier uint16,
	sequence uint16,
	payload []byte,
) []byte {
	t.Helper()
	if !sourceAddress.Is4() || !destinationAddress.Is4() {
		t.Fatalf("ICMP echo requires IPv4 addresses: source=%s destination=%s", sourceAddress, destinationAddress)
	}
	icmpMessage := make([]byte, 8+len(payload))
	icmpMessage[0] = 8
	binary.BigEndian.PutUint16(icmpMessage[4:6], identifier)
	binary.BigEndian.PutUint16(icmpMessage[6:8], sequence)
	copy(icmpMessage[8:], payload)
	binary.BigEndian.PutUint16(icmpMessage[2:4], internetChecksum(icmpMessage))
	packet := make([]byte, 20+len(icmpMessage))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], identifier)
	packet[8] = 64
	packet[9] = 1
	sourceBytes := sourceAddress.As4()
	destinationBytes := destinationAddress.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:20]))
	copy(packet[20:], icmpMessage)
	return packet
}

func validateIPv4ICMPEchoReply(
	packet []byte,
	clientAddress netip.Addr,
	serverAddress netip.Addr,
	identifier uint16,
	sequence uint16,
	payload []byte,
) error {
	if len(packet) < 28 {
		return E.New("IPv4 ICMP echo reply is too short: ", len(packet))
	}
	if packet[0]>>4 != 4 {
		return E.New("ICMP echo reply has unexpected IP version: ", packet[0]>>4)
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(packet) {
		return E.New("ICMP echo reply has invalid IPv4 header length: ", headerLength)
	}
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLength != len(packet) {
		return E.New("ICMP echo reply length mismatch: header=", totalLength, " packet=", len(packet))
	}
	if packet[9] != 1 {
		return E.New("IPv4 echo reply has unexpected protocol: ", packet[9])
	}
	if internetChecksum(packet[:headerLength]) != 0 {
		return E.New("IPv4 echo reply has invalid header checksum")
	}
	sourceBytes := [4]byte{packet[12], packet[13], packet[14], packet[15]}
	destinationBytes := [4]byte{packet[16], packet[17], packet[18], packet[19]}
	sourceAddress := netip.AddrFrom4(sourceBytes)
	destinationAddress := netip.AddrFrom4(destinationBytes)
	if sourceAddress != serverAddress || destinationAddress != clientAddress {
		return E.New("IPv4 echo reply has unexpected addresses: source=", sourceAddress, " destination=", destinationAddress)
	}
	icmpMessage := packet[headerLength:]
	if len(icmpMessage) != 8+len(payload) {
		return E.New("ICMP echo reply has unexpected length: ", len(icmpMessage))
	}
	if internetChecksum(icmpMessage) != 0 {
		return E.New("ICMP echo reply has invalid checksum")
	}
	if icmpMessage[0] != 0 || icmpMessage[1] != 0 {
		return E.New("unexpected ICMP echo reply type/code: ", icmpMessage[0], "/", icmpMessage[1])
	}
	replyIdentifier := binary.BigEndian.Uint16(icmpMessage[4:6])
	replySequence := binary.BigEndian.Uint16(icmpMessage[6:8])
	if replyIdentifier != identifier || replySequence != sequence {
		return E.New("ICMP echo reply identifier/sequence mismatch: ", replyIdentifier, "/", replySequence)
	}
	if !bytes.Equal(icmpMessage[8:], payload) {
		return E.New("ICMP echo reply payload mismatch: ", hex.EncodeToString(icmpMessage[8:]))
	}
	return nil
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

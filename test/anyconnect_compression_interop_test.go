package test

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type compressionDialer struct {
	udpDestination M.Socksaddr
}

func TestAnyConnectCompressionInterop(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	t.Cleanup(cancel)
	payload := strings.Repeat("sing-openconnect-compression-", 24)
	packetSize := 28 + len(payload)
	for _, algorithm := range []string{"oc-lz4", "lzs"} {
		t.Run(algorithm, func(t *testing.T) {
			t.Parallel()
			container := startOcservContainer(t, ctx, ocservOptions{
				authentication: `auth = "plain[passwd=/fixture/ocpasswd]"`,
				extra: "compression = true\n" +
					"compression-algo-priority = " + algorithm + ":1000\n" +
					"no-compress-limit = 64",
				logLevel:    5,
				keepalive:   60,
				dpd:         30,
				rekeyMethod: "new-tunnel",
				files:       map[string][]byte{"ocpasswd": []byte(ocservPasswordFile)},
			})

			//nolint:paralleltest // These consumers intentionally take turns using the same real ocserv account.
			t.Run("cstp", func(t *testing.T) {
				client := newAnyConnectClient(t, ctx, container.tcpAddress, openconnect.ClientOptions{
					Username: ocservUsername,
					Password: ocservPassword,
					NoUDP:    true,
				})
				startClient(t, client)
				waitForReady(t, ctx, client)
				assertActiveTransport(t, client, openconnect.TransportCSTP)
				logsBefore, err := dockerOutput(ctx, "logs", "--tail", "5000", container.name)
				if err != nil {
					t.Fatal(E.Cause(err, "read ocserv logs before CSTP compression exchange"))
				}
				exchangeTunnelEcho(t, ctx, client, 0x4d35, 1, payload)
				waitForCompressionActivity(t, ctx, container, logsBefore, packetSize)
				closeCompressionClient(t, ctx, container, client)
			})

			//nolint:paralleltest // These consumers intentionally take turns using the same real ocserv account.
			t.Run("dtls", func(t *testing.T) {
				dialer := &compressionDialer{udpDestination: M.ParseSocksaddr(container.udpAddress)}
				client := newAnyConnectClient(t, ctx, container.tcpAddress, openconnect.ClientOptions{
					Username: ocservUsername,
					Password: ocservPassword,
					Dialer:   dialer,
				})
				activeTransportUpdated := client.ActiveTransportUpdated()
				startClient(t, client)
				waitForReady(t, ctx, client)
				if client.ActiveTransport() != openconnect.TransportDTLS {
					waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportDTLS)
				}
				assertCompressionNegotiation(t, ctx, container, algorithm)
				logsBefore, err := dockerOutput(ctx, "logs", "--tail", "5000", container.name)
				if err != nil {
					t.Fatal(E.Cause(err, "read ocserv logs before DTLS compression exchange"))
				}
				exchangeTunnelEcho(t, ctx, client, 0x4d35, 2, payload)
				waitForCompressionActivity(t, ctx, container, logsBefore, packetSize)
				closeCompressionClient(t, ctx, container, client)
			})
		})
	}

	t.Run("disabled", func(t *testing.T) {
		t.Parallel()
		container := startOcservContainer(t, ctx, ocservOptions{
			authentication: `auth = "plain[passwd=/fixture/ocpasswd]"`,
			extra:          "compression = true\ncompression-algo-priority = oc-lz4:1000\nno-compress-limit = 64",
			logLevel:       5,
			keepalive:      60,
			dpd:            30,
			rekeyMethod:    "new-tunnel",
			files:          map[string][]byte{"ocpasswd": []byte(ocservPasswordFile)},
		})
		dialer := &compressionDialer{udpDestination: M.ParseSocksaddr(container.udpAddress)}
		client := newAnyConnectClient(t, ctx, container.tcpAddress, openconnect.ClientOptions{
			Username:            ocservUsername,
			Password:            ocservPassword,
			CompressionDisabled: true,
			Dialer:              dialer,
		})
		activeTransportUpdated := client.ActiveTransportUpdated()
		startClient(t, client)
		waitForReady(t, ctx, client)
		if client.ActiveTransport() != openconnect.TransportDTLS {
			waitForActiveTransportUpdate(t, ctx, client, activeTransportUpdated, openconnect.TransportDTLS)
		}
		occtlOutput := runOcctl(t, ctx, container, "show", "user", ocservUsername)
		if strings.Contains(occtlOutput, "CSTP compression:") || strings.Contains(occtlOutput, "DTLS compression:") {
			t.Fatalf("ocserv negotiated compression with CompressionDisabled:\n%s", occtlOutput)
		}
		exchangeTunnelEcho(t, ctx, client, 0x4d35, 3, payload)
		closeCompressionClient(t, ctx, container, client)
	})
}

func assertCompressionNegotiation(
	t *testing.T,
	ctx context.Context,
	container fixtureOcservContainer,
	algorithm string,
) {
	t.Helper()
	waitContext, cancelWait := context.WithTimeout(ctx, 5*time.Second)
	defer cancelWait()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var latestOutput string
	for {
		dockerArguments := []string{"exec", container.name, "occtl", "-s", "/run/occtl.socket", "show", "user", ocservUsername}
		output, occtlErr := dockerOutput(waitContext, dockerArguments...)
		if occtlErr != nil {
			latestOutput = occtlErr.Error()
		} else {
			latestOutput = output
			cstpNegotiated := strings.Contains(output, "CSTP compression: "+algorithm)
			dtlsNegotiated := strings.Contains(output, "DTLS compression: "+algorithm)
			if cstpNegotiated && dtlsNegotiated {
				return
			}
		}
		select {
		case <-waitContext.Done():
			t.Fatalf("ocserv did not publish expected %s CSTP and DTLS compression state:\n%s", algorithm, latestOutput)
		case <-ticker.C:
		}
	}
}

func waitForCompressionActivity(
	t *testing.T,
	ctx context.Context,
	container fixtureOcservContainer,
	logsBefore string,
	packetSize int,
) {
	t.Helper()
	decompressedBefore, compressedBefore := countCompressionActivity(logsBefore, packetSize)
	waitContext, cancelWait := context.WithTimeout(ctx, 5*time.Second)
	defer cancelWait()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var latestLogs string
	for {
		select {
		case <-waitContext.Done():
			t.Fatal(E.Cause(waitContext.Err(), "wait for bidirectional ocserv compression activity: ", latestLogs))
		case <-ticker.C:
			logs, err := dockerOutput(waitContext, "logs", "--tail", "5000", container.name)
			if err != nil {
				if waitContext.Err() != nil {
					continue
				}
				t.Fatal(E.Cause(err, "read ocserv compression logs"))
			}
			latestLogs = logs
			decompressedAfter, compressedAfter := countCompressionActivity(logs, packetSize)
			if decompressedAfter > decompressedBefore && compressedAfter > compressedBefore {
				return
			}
		}
	}
}

func countCompressionActivity(logs string, packetSize int) (int, int) {
	decompressed := 0
	compressed := 0
	packetSizeText := strconv.Itoa(packetSize)
	compressedPrefix := "compressed " + packetSizeText + " to "
	for line := range strings.SplitSeq(logs, "\n") {
		if strings.Contains(line, "decompressed ") && strings.Contains(line, " to "+packetSizeText) {
			decompressed++
		}
		if strings.Contains(line, "decompressed ") {
			continue
		}
		_, compressedFieldsText, found := strings.Cut(line, compressedPrefix)
		if !found {
			continue
		}
		compressedFields := strings.Fields(compressedFieldsText)
		if len(compressedFields) == 0 {
			continue
		}
		compressedSize, parseErr := strconv.Atoi(compressedFields[0])
		if parseErr == nil && compressedSize > 0 && compressedSize < packetSize {
			compressed++
		}
	}
	return decompressed, compressed
}

func closeCompressionClient(t *testing.T, ctx context.Context, container fixtureOcservContainer, client *openconnect.Client) {
	t.Helper()
	closeErr := client.Close()
	if closeErr != nil && !E.IsClosed(closeErr) {
		t.Fatal(E.Cause(closeErr, "close compression client"))
	}
	waitForOcservUserAbsent(t, ctx, container, ocservUsername)
}

func (d *compressionDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network == N.NetworkUDP {
		destination = d.udpDestination
	}
	return N.SystemDialer.DialContext(ctx, network, destination)
}

func (d *compressionDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return N.SystemDialer.ListenPacket(ctx, destination)
}

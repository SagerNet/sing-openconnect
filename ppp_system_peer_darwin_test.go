//go:build darwin

package openconnect

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const localPPPDPeerPath = "/tmp/sing-openconnect-pppd-peer-m3"

var (
	localPPPDCompileOnce   sync.Once
	localPPPDCompileErr    error
	localPPPDOptionsAccess sync.Mutex
	localPPPDOptionsMade   bool
	localPPPDOptionsInode  uint64
)

type synchronizedPPPDLogs struct {
	access sync.Mutex
	buffer bytes.Buffer
}

func (l *synchronizedPPPDLogs) Write(content []byte) (int, error) {
	l.access.Lock()
	defer l.access.Unlock()
	return l.buffer.Write(content)
}

func (l *synchronizedPPPDLogs) String() string {
	l.access.Lock()
	defer l.access.Unlock()
	return l.buffer.String()
}

func localSystemPPPDEnabled() bool {
	return true
}

func startLocalSystemPPPDPeer(t *testing.T, framing string, datagram bool, dualCarrier bool, environment map[string]string) (*localPPPDPeer, error) {
	t.Helper()
	err := prepareLocalPPPDOptions(t)
	if err != nil {
		return nil, err
	}
	localPPPDCompileOnce.Do(func() {
		command := exec.Command(
			"cc", "-O2", "-Wall", "-Wextra", "-Werror",
			"-o", localPPPDPeerPath,
			filepath.Join("test", "testdata", "pppd-peer", "peer.c"),
		)
		output, compileErr := command.CombinedOutput()
		if compileErr != nil {
			localPPPDCompileErr = E.Cause(compileErr, "compile macOS pppd framing peer: ", strings.TrimSpace(string(output)))
		}
	})
	if localPPPDCompileErr != nil {
		return nil, localPPPDCompileErr
	}
	versionCommand := exec.Command("sudo", "-n", "/usr/sbin/pppd", "--version")
	versionOutput, err := versionCommand.CombinedOutput()
	if err != nil {
		return nil, E.Cause(err, "query macOS system pppd version: ", strings.TrimSpace(string(versionOutput)))
	}
	version := strings.TrimSpace(string(versionOutput))
	if !strings.Contains(strings.ToLower(version), "ppp") {
		return nil, E.New("unexpected macOS system pppd version output: ", version)
	}
	port, err := reserveLocalPPPDPort(datagram)
	if err != nil {
		return nil, err
	}
	secondaryPort := 0
	if dualCarrier {
		secondaryPort, err = reserveLocalPPPDPort(true)
		if err != nil {
			return nil, err
		}
	}
	arguments := []string{"-n", "env", "PORT=" + strconv.Itoa(port)}
	if dualCarrier {
		arguments = append(arguments, "SECONDARY_PORT="+strconv.Itoa(secondaryPort))
	}
	for key, value := range environment {
		arguments = append(arguments, key+"="+value)
	}
	arguments = append(arguments, localPPPDPeerPath, framing)
	if dualCarrier {
		arguments = append(arguments, "dual")
	} else if datagram {
		arguments = append(arguments, "udp")
	}
	logs := &synchronizedPPPDLogs{}
	command := exec.Command("sudo", arguments...)
	command.Stdout = logs
	command.Stderr = logs
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	err = command.Start()
	if err != nil {
		return nil, E.Cause(err, "start macOS system pppd peer")
	}
	done := make(chan error, 1)
	go func() {
		done <- command.Wait()
		close(done)
	}()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			select {
			case <-done:
				return
			default:
			}
			processGroup := "-" + strconv.Itoa(command.Process.Pid)
			stopCommand := exec.Command("sudo", "-n", "/bin/kill", "-TERM", processGroup)
			_, _ = stopCommand.CombinedOutput()
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-done:
			case <-timer.C:
				killCommand := exec.Command("sudo", "-n", "/bin/kill", "-KILL", processGroup)
				_, _ = killCommand.CombinedOutput()
				<-done
			}
		})
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(logs.String(), "PPPD_PEER_LISTENING") {
		select {
		case startErr := <-done:
			if startErr == nil {
				return nil, E.New("macOS system pppd peer exited during startup: ", logs.String())
			}
			return nil, E.Cause(startErr, "macOS system pppd peer exited during startup: ", logs.String())
		default:
		}
		if time.Now().After(deadline) {
			return nil, E.New("macOS system pppd peer did not begin listening: ", logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	datagramAddress := ""
	if dualCarrier {
		datagramAddress = net.JoinHostPort("127.0.0.1", strconv.Itoa(secondaryPort))
	}
	return &localPPPDPeer{
		address:         net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		datagramAddress: datagramAddress,
		logs: func() string {
			return "PPPD_SYSTEM_VERSION " + version + "\n" + logs.String()
		},
	}, nil
}

func prepareLocalPPPDOptions(t *testing.T) error {
	t.Helper()
	localPPPDOptionsAccess.Lock()
	defer localPPPDOptionsAccess.Unlock()
	if localPPPDOptionsMade {
		return nil
	}
	_, err := os.Stat("/etc/ppp/options")
	if err == nil {
		return E.New("refusing to modify an existing /etc/ppp/options for the macOS pppd integration test")
	}
	if !os.IsNotExist(err) {
		return E.Cause(err, "inspect macOS system pppd options")
	}
	temporary, err := os.CreateTemp("/tmp", "sing-openconnect-pppd-options-")
	if err != nil {
		return E.Cause(err, "create temporary macOS pppd options")
	}
	temporaryPath := temporary.Name()
	closeErr := temporary.Close()
	if closeErr != nil {
		_ = os.Remove(temporaryPath)
		return E.Cause(closeErr, "close temporary macOS pppd options")
	}
	defer os.Remove(temporaryPath)
	moveCommand := exec.Command("sudo", "-n", "/bin/mv", "-n", temporaryPath, "/etc/ppp/options")
	moveOutput, err := moveCommand.CombinedOutput()
	if err != nil {
		return E.Cause(err, "atomically install temporary macOS pppd options: ", strings.TrimSpace(string(moveOutput)))
	}
	info, err := os.Stat("/etc/ppp/options")
	if err != nil {
		return E.Cause(err, "verify temporary macOS pppd options")
	}
	stat, loaded := info.Sys().(*syscall.Stat_t)
	if !loaded {
		return E.New("macOS pppd options did not expose an inode")
	}
	localPPPDOptionsInode = stat.Ino
	localPPPDOptionsMade = true
	t.Cleanup(func() {
		localPPPDOptionsAccess.Lock()
		defer localPPPDOptionsAccess.Unlock()
		currentInfo, statErr := os.Stat("/etc/ppp/options")
		if statErr != nil {
			t.Errorf("temporary macOS pppd options disappeared before cleanup: %v", statErr)
			localPPPDOptionsMade = false
			return
		}
		currentStat, currentLoaded := currentInfo.Sys().(*syscall.Stat_t)
		if !currentLoaded || currentStat.Ino != localPPPDOptionsInode || currentInfo.Size() != 0 {
			t.Error("temporary macOS pppd options changed during the integration test; refusing to remove it")
			localPPPDOptionsMade = false
			return
		}
		removeCommand := exec.Command("sudo", "-n", "/bin/rm", "/etc/ppp/options")
		removeOutput, removeErr := removeCommand.CombinedOutput()
		if removeErr != nil {
			t.Errorf("remove temporary macOS pppd options: %v: %s", removeErr, strings.TrimSpace(string(removeOutput)))
		}
		localPPPDOptionsMade = false
		localPPPDOptionsInode = 0
	})
	return nil
}

func reserveLocalPPPDPort(datagram bool) (int, error) {
	if datagram {
		packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return 0, E.Cause(err, "reserve macOS pppd UDP port")
		}
		address := packetConn.LocalAddr().(*net.UDPAddr)
		closeErr := packetConn.Close()
		if closeErr != nil {
			return 0, E.Cause(closeErr, "release macOS pppd UDP port")
		}
		return address.Port, nil
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, E.Cause(err, "reserve macOS pppd TCP port")
	}
	address := listener.Addr().(*net.TCPAddr)
	closeErr := listener.Close()
	if closeErr != nil {
		return 0, E.Cause(closeErr, "release macOS pppd TCP port")
	}
	return address.Port, nil
}

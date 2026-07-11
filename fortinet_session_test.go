package openconnect

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

type fortinetTrackingConn struct {
	net.Conn
	access sync.Mutex
	writes int
}

func (c *fortinetTrackingConn) Write(content []byte) (int, error) {
	c.access.Lock()
	c.writes++
	c.access.Unlock()
	return c.Conn.Write(content)
}

func (c *fortinetTrackingConn) writeCount() int {
	c.access.Lock()
	defer c.access.Unlock()
	return c.writes
}

func TestFortinetTLSRejectionPrecedesInitialPPPWrite(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	trackedConn := &fortinetTrackingConn{Conn: clientConn}
	connection := &fortinetTLSConn{
		Conn:                trackedConn,
		classificationReady: make(chan struct{}),
	}
	link, err := newPPPLink(context.Background(), pppLinkConfig{
		Carrier: pppCarrierConfig{
			Connection: connection,
		},
		Encapsulation: pppEncapsulationFortinet,
		WantIPv4:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = link.Close()
		_ = serverConn.Close()
	})
	go func() {
		defer serverConn.Close()
		_, _ = serverConn.Write([]byte("HT"))
		time.Sleep(20 * time.Millisecond)
		_, _ = serverConn.Write([]byte("TP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
	}()
	startErr := link.Start()
	if !E.IsMulti(startErr, ErrSessionRejected) {
		t.Fatalf("Fortinet TLS rejection was not classified before PPP start: %v", startErr)
	}
	if writes := trackedConn.writeCount(); writes != 0 {
		t.Fatalf("Fortinet client wrote %d PPP frames before classifying TLS rejection", writes)
	}
}

type fortinetSecondWriteFailureConn struct {
	net.Conn
	access sync.Mutex
	writes int
}

func (c *fortinetSecondWriteFailureConn) Write(content []byte) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	c.writes++
	if c.writes == 1 {
		return len(content), nil
	}
	return 0, io.ErrClosedPipe
}

func TestFortinetTLSLaterWriteFailureWaitsForHTTPClassification(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	connection := &fortinetTLSConn{
		Conn:                &fortinetSecondWriteFailureConn{Conn: clientConn},
		classificationReady: make(chan struct{}),
	}
	readDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1024)
		_, readErr := connection.Read(buffer)
		readDone <- readErr
	}()
	go func() {
		timer := time.NewTimer(500 * time.Millisecond)
		defer timer.Stop()
		<-timer.C
		_, _ = serverConn.Write([]byte("HT"))
		time.Sleep(20 * time.Millisecond)
		_, _ = serverConn.Write([]byte("TP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
	}()
	_, writeErr := connection.Write([]byte("first PPP request"))
	if writeErr != nil {
		t.Fatalf("first Fortinet PPP write failed: %v", writeErr)
	}
	_, writeErr = connection.Write([]byte("PPP retry"))
	if !E.IsMulti(writeErr, ErrSessionRejected) {
		t.Fatalf("Fortinet write failure lost delayed HTTP classification: %v", writeErr)
	}
	select {
	case readErr := <-readDone:
		if !E.IsMulti(readErr, ErrSessionRejected) {
			t.Fatalf("Fortinet read returned unexpected classification: %v", readErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Fortinet HTTP classification read did not finish")
	}
}

package openconnect

import (
	"context"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

const cstpDisconnectWriteTimeout = 5 * time.Second

type anyConnectSessionState struct {
	access               sync.Mutex
	ServerURL            *url.URL
	AuthenticatedAddress netip.Addr
	Cookie               string
	PreviousAddresses    []netip.Prefix
	DynamicDNS           bool
}

func (s *anyConnectSessionState) Close() error {
	s.access.Lock()
	s.Cookie = ""
	s.PreviousAddresses = nil
	s.access.Unlock()
	return nil
}

type anyConnectCSTPSession struct {
	ctx                 context.Context
	cancel              context.CancelFunc
	client              *Client
	state               *anyConnectSessionState
	transport           *cstpConnectedTransport
	configurationAccess sync.RWMutex
	configuration       TunnelConfiguration
	keepalive           *cstpKeepaliveState
	done                chan error
	doneOnce            sync.Once
	closeOnce           sync.Once
	lifecycleAccess     sync.Mutex
	writeAccess         sync.Mutex
	dtlsAccess          sync.RWMutex
	dtlsNegotiation     *cstpDTLSNegotiation
	dtls                *anyConnectDTLSChannel
	waitGroup           sync.WaitGroup
	started             bool
	closed              bool
	closeErr            error
	ready               atomic.Bool
	active              atomic.Bool
}

func newAnyConnectCSTPSession(
	ctx context.Context,
	client *Client,
	state *anyConnectSessionState,
	transport *cstpConnectedTransport,
) *anyConnectCSTPSession {
	sessionContext, cancel := context.WithCancel(ctx)
	negotiated := transport.negotiated
	session := &anyConnectCSTPSession{
		ctx:           sessionContext,
		cancel:        cancel,
		client:        client,
		state:         state,
		transport:     transport,
		configuration: cloneTunnelConfiguration(negotiated.Configuration),
		keepalive:     newCSTPKeepaliveState(negotiated.DPD, negotiated.Keepalive, negotiated.Rekey, negotiated.RekeyMethod),
		done:          make(chan error, 1),
	}
	state.access.Lock()
	state.PreviousAddresses = append([]netip.Prefix(nil), negotiated.Configuration.Addresses...)
	state.DynamicDNS = negotiated.DynamicDNS
	state.access.Unlock()
	if negotiated.DTLS != nil {
		dtlsNegotiation := *negotiated.DTLS
		dtlsNegotiation.SessionID = append([]byte(nil), negotiated.DTLS.SessionID...)
		dtlsNegotiation.AppID = append([]byte(nil), negotiated.DTLS.AppID...)
		dtlsNegotiation.MasterSecret = append([]byte(nil), negotiated.DTLS.MasterSecret...)
		dtlsNegotiation.TLSConnection = transport.connection
		dtlsNegotiation.RequestRekey = session.requestDTLSRekey
		dtlsNegotiation.MinimumMTU = 576
		for _, address := range negotiated.Configuration.Addresses {
			if address.Addr().Is6() {
				dtlsNegotiation.MinimumMTU = 1280
				break
			}
		}
		session.dtlsNegotiation = &dtlsNegotiation
	}
	return session
}

func (s *anyConnectCSTPSession) Start() error {
	s.lifecycleAccess.Lock()
	if s.started {
		s.lifecycleAccess.Unlock()
		return nil
	}
	if s.closed {
		s.lifecycleAccess.Unlock()
		return ErrClientClosed
	}
	s.started = true
	s.active.Store(true)
	workerCount := 2
	if s.dtlsNegotiation != nil {
		workerCount++
	}
	s.waitGroup.Add(workerCount)
	s.lifecycleAccess.Unlock()
	s.client.setActiveTransport(s, TransportCSTP)
	go s.readLoop()
	go s.timerLoop()
	if s.dtlsNegotiation != nil {
		initialResult := make(chan error, 1)
		go s.dtlsLoop(initialResult)
		dtlsErr := <-initialResult
		if E.IsMulti(dtlsErr, ErrProtocolNotSupported, ErrDeprecatedCryptoDisabled) {
			return dtlsErr
		}
	}
	s.lifecycleAccess.Lock()
	if s.closed || !s.active.Load() {
		s.lifecycleAccess.Unlock()
		return E.New("AnyConnect CSTP session closed during startup")
	}
	s.ready.Store(true)
	s.lifecycleAccess.Unlock()
	return nil
}

func (s *anyConnectCSTPSession) Done() <-chan error {
	return s.done
}

func (s *anyConnectCSTPSession) Ready() bool {
	return s.ready.Load()
}

func (s *anyConnectCSTPSession) TunnelConfiguration() TunnelConfiguration {
	s.configurationAccess.RLock()
	defer s.configurationAccess.RUnlock()
	return cloneTunnelConfiguration(s.configuration)
}

func (s *anyConnectCSTPSession) WriteDataPacket(payload []byte) error {
	return s.WriteDataPackets([][]byte{payload})
}

func (s *anyConnectCSTPSession) WriteDataPackets(payloads [][]byte) error {
	if len(payloads) == 0 {
		return nil
	}
	return s.WriteDataPacketBuffers(newPacketBuffersFrom(payloads))
}

func (s *anyConnectCSTPSession) WriteDataPacketBuffers(packetBuffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(packetBuffers)
	if !s.ready.Load() {
		return ErrDataChannelNotReady
	}
	for index, packetBuffer := range packetBuffers {
		mtu := s.currentMTU()
		if packetBuffer.Len() > mtu {
			return E.New("AnyConnect data packet exceeds negotiated MTU: ", packetBuffer.Len(), " > ", mtu)
		}
		s.dtlsAccess.RLock()
		dtlsChannel := s.dtls
		s.dtlsAccess.RUnlock()
		if dtlsChannel != nil && dtlsChannel.Ready() {
			err := dtlsChannel.WriteDataPacketBuffer(&packetBuffers[index])
			if err == nil {
				continue
			}
		}
		return s.writeDataPacketBuffers(packetBuffers[index:])
	}
	return nil
}

func (s *anyConnectCSTPSession) writeDataPacketBuffers(packetBuffers []*buf.Buffer) error {
	s.writeAccess.Lock()
	if !s.active.Load() {
		s.writeAccess.Unlock()
		return ErrDataChannelNotReady
	}
	for index, packetBuffer := range packetBuffers {
		mtu := s.currentMTU()
		if packetBuffer.Len() > mtu {
			s.writeAccess.Unlock()
			return E.New("AnyConnect data packet exceeds negotiated MTU: ", packetBuffer.Len(), " > ", mtu)
		}
		err := writeCSTPPacketBuffer(s.transport.connection, cstpPacketData, &packetBuffers[index])
		if err != nil {
			s.writeAccess.Unlock()
			s.terminate(err)
			return err
		}
		s.keepalive.markTransmitted()
	}
	s.writeAccess.Unlock()
	return nil
}

func (s *anyConnectCSTPSession) Fail(err error) {
	if err == nil {
		err = E.New("AnyConnect CSTP session failed")
	}
	s.terminate(err)
}

func (s *anyConnectCSTPSession) Close() error {
	s.closeOnce.Do(func() {
		var disconnectErr error
		s.lifecycleAccess.Lock()
		alreadyClosed := s.closed
		s.lifecycleAccess.Unlock()
		if !alreadyClosed && s.ready.Load() {
			deadlineErr := s.transport.connection.SetWriteDeadline(time.Now().Add(cstpDisconnectWriteTimeout))
			s.writeAccess.Lock()
			if deadlineErr == nil && s.active.Load() {
				disconnectErr = writeCSTPDisconnect(s.transport.connection, "Client disconnect")
			} else if deadlineErr != nil {
				disconnectErr = E.Cause(deadlineErr, "set CSTP disconnect write deadline")
			}
			s.writeAccess.Unlock()
		}
		s.terminate(nil)
		s.waitGroup.Wait()
		if disconnectErr != nil && E.IsClosed(disconnectErr) {
			disconnectErr = nil
		}
		if disconnectErr != nil {
			s.lifecycleAccess.Lock()
			s.closeErr = E.Errors(disconnectErr, s.closeErr)
			s.lifecycleAccess.Unlock()
		}
	})
	s.lifecycleAccess.Lock()
	closeErr := s.closeErr
	s.lifecycleAccess.Unlock()
	return closeErr
}

func (s *anyConnectCSTPSession) writePacket(packetType byte, payload []byte) error {
	s.writeAccess.Lock()
	defer s.writeAccess.Unlock()
	if !s.active.Load() {
		return ErrDataChannelNotReady
	}
	err := writeCSTPPacket(s.transport.connection, packetType, payload)
	if err != nil {
		s.terminate(err)
		return err
	}
	s.keepalive.markTransmitted()
	return nil
}

// Upstream cstp_mainloop answers DPD requests, consumes keepalives, queues DATA, and treats disconnect, terminate, malformed, or unnegotiated compressed records as failures.
func (s *anyConnectCSTPSession) readLoop() {
	defer s.waitGroup.Done()
	maximumPayloadSize := max(s.currentMTU(), 16384)
	for {
		packetType, packetBuffer, err := readCSTPPacket(s.transport.reader, maximumPayloadSize)
		if err != nil {
			if s.ctx.Err() == nil && !E.IsClosed(err) && err != io.EOF {
				s.terminate(err)
			} else {
				s.terminate(nil)
			}
			return
		}
		s.keepalive.markReceived()
		switch packetType {
		case cstpPacketDPDRequest:
			packetBuffer.Release()
			err = s.writePacket(cstpPacketDPDResponse, nil)
			if err != nil {
				return
			}
		case cstpPacketDPDResponse, cstpPacketKeepalive:
			packetBuffer.Release()
		case cstpPacketData:
			s.client.pushIncomingDataPacket(packetBuffer)
		case cstpPacketDisconnect, cstpPacketTerminate:
			reason := renderCSTPDisconnectReason(packetBuffer.Bytes())
			packetBuffer.Release()
			s.terminate(markTerminal(E.New("AnyConnect server disconnected CSTP session: ", reason)))
			return
		case cstpPacketCompressed:
			packetBuffer.Release()
			s.terminate(E.Extend(ErrProtocolNotSupported, "received compressed CSTP packet without negotiated compression"))
			return
		default:
			packetBuffer.Release()
			s.terminate(E.Extend(ErrProtocolNotSupported, "received unknown CSTP packet type: ", packetType))
			return
		}
	}
}

func (s *anyConnectCSTPSession) timerLoop() {
	defer s.waitGroup.Done()
	timer := time.NewTimer(s.keepalive.nextDelay(time.Now()))
	defer timer.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-timer.C:
			switch s.keepalive.action(now) {
			case cstpTimerDPD:
				err := s.writePacket(cstpPacketDPDRequest, nil)
				if err != nil {
					return
				}
			case cstpTimerDeadPeer:
				s.terminate(E.New("CSTP dead peer detection expired"))
				return
			case cstpTimerKeepalive:
				err := s.writePacket(cstpPacketKeepalive, nil)
				if err != nil {
					return
				}
			case cstpTimerRekey:
				// Upstream cstp_mainloop falls back to establishing a new tunnel when an SSL rehandshake fails; Go crypto/tls cannot initiate the proprietary post-handshake rehandshake.
				s.terminate(&sessionRekeyError{method: s.keepalive.rekeyMethod})
				return
			}
			timer.Reset(s.keepalive.nextDelay(time.Now()))
		}
	}
}

func (s *anyConnectCSTPSession) dtlsLoop(initialResult chan<- error) {
	defer s.waitGroup.Done()
	initialResultPending := true
	retryDelay := clientReconnectInitialBackoff
	for s.ctx.Err() == nil && s.active.Load() {
		negotiation := *s.dtlsNegotiation
		negotiation.MTU = s.currentMTU()
		channel := newAnyConnectDTLS(s.ctx, negotiation, s.client.pushIncomingDataPacket)
		s.dtlsAccess.Lock()
		if !s.active.Load() {
			s.dtlsAccess.Unlock()
			if initialResultPending {
				initialResult <- s.ctx.Err()
			}
			return
		}
		s.dtls = channel
		s.dtlsAccess.Unlock()
		dtlsErr := channel.Start()
		if dtlsErr == nil {
			s.applyDTLSMTU(channel.DetectedMTU())
			s.client.setActiveTransport(s, TransportDTLS)
		}
		if initialResultPending {
			initialResult <- dtlsErr
			initialResultPending = false
		}
		if dtlsErr == nil {
			retryDelay = clientReconnectInitialBackoff
			doneErr, open := <-channel.Done()
			if open {
				dtlsErr = doneErr
			} else {
				dtlsErr = nil
			}
		}
		s.dtlsAccess.Lock()
		fallbackToCSTP := false
		if s.dtls == channel {
			s.dtls = nil
			fallbackToCSTP = s.active.Load()
		}
		s.dtlsAccess.Unlock()
		if fallbackToCSTP {
			s.client.setActiveTransport(s, TransportCSTP)
		}
		if s.ctx.Err() != nil || !s.active.Load() {
			return
		}
		if E.IsMulti(dtlsErr, ErrProtocolNotSupported, ErrDeprecatedCryptoDisabled) {
			s.terminate(dtlsErr)
			return
		}
		if E.IsMulti(dtlsErr, errAnyConnectDTLSRekey) {
			retryDelay = clientReconnectInitialBackoff
			continue
		}
		if s.client.options.Logger != nil {
			if dtlsErr == nil {
				s.client.options.Logger.WarnContext(s.ctx, "AnyConnect DTLS stopped; retrying while CSTP remains active")
			} else {
				s.client.options.Logger.WarnContext(s.ctx, "AnyConnect DTLS unavailable; retrying while CSTP remains active: ", dtlsErr)
			}
		}
		retryTimer := time.NewTimer(retryDelay)
		select {
		case <-s.ctx.Done():
			if !retryTimer.Stop() {
				<-retryTimer.C
			}
			return
		case <-retryTimer.C:
		}
		retryDelay = nextClientReconnectBackoff(retryDelay)
	}
	if initialResultPending {
		initialResult <- s.ctx.Err()
	}
}

func (s *anyConnectCSTPSession) requestDTLSRekey(method string) error {
	parsedMethod, err := parseCSTPRekeyMethod(method)
	if err != nil {
		return err
	}
	if parsedMethod == cstpRekeyTLS {
		return errAnyConnectDTLSRekey
	}
	return nil
}

func (s *anyConnectCSTPSession) currentMTU() int {
	s.configurationAccess.RLock()
	mtu := int(s.configuration.MTU)
	s.configurationAccess.RUnlock()
	return mtu
}

func (s *anyConnectCSTPSession) applyDTLSMTU(mtu int) {
	if mtu <= 0 {
		return
	}
	s.configurationAccess.Lock()
	if mtu >= int(s.configuration.MTU) {
		s.configurationAccess.Unlock()
		return
	}
	s.configuration.MTU = uint32(mtu)
	configuration := cloneTunnelConfiguration(s.configuration)
	s.configurationAccess.Unlock()
	if s.ready.Load() {
		configuration = s.client.setTunnelConfiguration(configuration)
		s.client.publishTunnelConfigurationEvent(TunnelConfigurationEventPathMTU, configuration)
	}
}

func (s *anyConnectCSTPSession) terminate(err error) {
	s.doneOnce.Do(func() {
		s.lifecycleAccess.Lock()
		s.ready.Store(false)
		s.active.Store(false)
		s.closed = true
		s.lifecycleAccess.Unlock()
		s.client.stopActiveTransport(s)
		s.cancel()
		s.dtlsAccess.Lock()
		dtlsChannel := s.dtls
		s.dtls = nil
		s.dtlsAccess.Unlock()
		var closeErr error
		if dtlsChannel != nil {
			closeErr = dtlsChannel.Close()
		}
		connectionCloseErr := s.transport.connection.Close()
		if connectionCloseErr != nil && !E.IsClosed(connectionCloseErr) {
			closeErr = E.Append(closeErr, connectionCloseErr, func(cause error) error {
				return E.Cause(cause, "close CSTP connection")
			})
		}
		if closeErr != nil {
			s.lifecycleAccess.Lock()
			s.closeErr = closeErr
			s.lifecycleAccess.Unlock()
			if err != nil {
				err = E.Errors(err, closeErr)
			}
		}
		if err != nil {
			s.done <- err
		}
		close(s.done)
	})
}

func renderCSTPDisconnectReason(payload []byte) string {
	if len(payload) == 0 {
		return "unspecified"
	}
	reasonCode := payload[0]
	reason := make([]rune, 0, len(payload)-1)
	for _, value := range payload[1:] {
		character := rune(value)
		if !unicode.IsPrint(character) {
			character = '.'
		}
		reason = append(reason, character)
	}
	if len(reason) == 0 {
		return "code 0x" + strconv.FormatUint(uint64(reasonCode), 16)
	}
	return "code 0x" + strconv.FormatUint(uint64(reasonCode), 16) + " " + string(reason)
}

var _ clientSession = (*anyConnectCSTPSession)(nil)

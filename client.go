package openconnect

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type Client struct {
	options                   ClientOptions
	serverURL                 *url.URL
	tlsConfig                 *tls.Config
	mcaIdentity               *mcaIdentity
	clientCertificateAccess   sync.RWMutex
	clientCertificateSet      bool
	selectedClientCertificate []byte
	httpClient                *http.Client
	httpTransport             *http.Transport
	frontend                  flavorFrontend
	authChallengeAccess       sync.Mutex
	authChallengeUpdated      chan struct{}
	pendingAuthChallenge      *pendingAuthChallengeState
	stableCredentials         map[string]string
	configurationAccess       sync.RWMutex
	tunnelConfiguration       TunnelConfiguration
	configurationEventAccess  sync.Mutex
	configurationEvents       []TunnelConfigurationEvent
	configurationEventWake    chan struct{}
	configurationEventStopped bool
	activeTransportAccess     sync.Mutex
	activeTransport           string
	activeTransportUpdated    chan struct{}
	incomingDataPackets       *dataPacketQueue[*buf.Buffer]
	droppedIncomingPackets    atomic.Uint64
	lifecycleAccess           sync.Mutex
	started                   bool
	closed                    bool
	terminalError             error
	currentSession            clientSession
	publishedSession          clientSession
	activeTransportSession    clientSession
	stateChanged              chan struct{}
	supervisorCancel          context.CancelFunc
	supervisorDone            chan struct{}
	closeOnce                 sync.Once
	closeErr                  error
}

func NewClient(options ClientOptions) (*Client, error) {
	options = cloneClientOptions(options)
	if options.Context == nil {
		options.Context = context.Background()
	}
	if options.Server == "" {
		return nil, ErrMissingServer
	}
	if options.Flavor == "" {
		options.Flavor = FlavorAnyConnect
	}
	err := validateClientOptions(options)
	if err != nil {
		return nil, err
	}
	if options.Dialer == nil {
		options.Dialer = N.SystemDialer
	}
	serverURL, err := parseServerURL(options.Server)
	if err != nil {
		return nil, err
	}
	tlsConfig, mcaIdentity, err := buildClientTLS(options)
	if err != nil {
		return nil, err
	}
	client := &Client{
		options:                options,
		serverURL:              serverURL,
		tlsConfig:              tlsConfig,
		mcaIdentity:            mcaIdentity,
		clientCertificateSet:   len(tlsConfig.Certificates) > 0 || tlsConfig.GetClientCertificate != nil,
		authChallengeUpdated:   make(chan struct{}),
		stableCredentials:      make(map[string]string),
		configurationEventWake: make(chan struct{}, 1),
		activeTransportUpdated: make(chan struct{}),
		incomingDataPackets:    newDataPacketQueueWithCapacity[*buf.Buffer](dataPacketQueueCapacity),
		stateChanged:           make(chan struct{}),
	}
	wrapTLSClientCertificateSelection(tlsConfig, client.recordTLSClientCertificate)
	if options.Username != "" {
		client.stableCredentials[authCacheUsername] = options.Username
	}
	if options.Password != "" {
		client.stableCredentials[authCachePassword] = options.Password
	}
	if options.AuthGroup != "" {
		client.stableCredentials[authCacheAuthGroup] = options.AuthGroup
	}
	client.httpClient, client.httpTransport, err = newHTTPClient(client, tlsConfig)
	if err != nil {
		return nil, err
	}
	client.frontend, err = newFlavorFrontend(options.Flavor, client)
	if err != nil {
		client.httpTransport.CloseIdleConnections()
		return nil, err
	}
	return client, nil
}

func (c *Client) configuredTLSClientCertificate() bool {
	return c.clientCertificateSet
}

func (c *Client) resetTLSClientCertificate() {
	c.clientCertificateAccess.Lock()
	c.selectedClientCertificate = nil
	c.clientCertificateAccess.Unlock()
}

func (c *Client) recordTLSClientCertificate(certificate *tls.Certificate) {
	var leafCertificate []byte
	if certificate != nil && len(certificate.Certificate) > 0 {
		leafCertificate = append([]byte(nil), certificate.Certificate[0]...)
	}
	c.clientCertificateAccess.Lock()
	c.selectedClientCertificate = leafCertificate
	c.clientCertificateAccess.Unlock()
}

func (c *Client) selectedTLSClientCertificateDER() []byte {
	c.clientCertificateAccess.RLock()
	defer c.clientCertificateAccess.RUnlock()
	return append([]byte(nil), c.selectedClientCertificate...)
}

func validateClientOptions(options ClientOptions) error {
	for _, entry := range options.FormEntries {
		if entry.SubmissionKey == "" && (entry.FormID == "" || entry.Name == "") {
			return E.New("openconnect form entry requires a submission key or a form ID and field name")
		}
		if entry.Promote && entry.Value != "" {
			return E.New("openconnect promoted form entry cannot also provide a value")
		}
	}
	if options.Token == nil {
		return nil
	}
	if options.Token.Secret == "" {
		return E.New("openconnect software token requires a secret")
	}
	switch options.Token.Mode {
	case TokenModeTOTP, TokenModeSToken:
	case TokenModeHOTP:
		if options.Token.UpdateCounter == nil {
			return E.New("openconnect HOTP token requires an update counter callback")
		}
	default:
		return E.New("unsupported openconnect software token mode: ", options.Token.Mode)
	}
	return nil
}

func cloneClientOptions(options ClientOptions) ClientOptions {
	options.FormEntries = append([]FormEntry(nil), options.FormEntries...)
	options.TLSConfig.CertificateAuthority.Content = append([]byte(nil), options.TLSConfig.CertificateAuthority.Content...)
	options.TLSConfig.Certificate.Content = append([]byte(nil), options.TLSConfig.Certificate.Content...)
	options.TLSConfig.Key.Content = append([]byte(nil), options.TLSConfig.Key.Content...)
	options.TLSConfig.MCACertificate.Content = append([]byte(nil), options.TLSConfig.MCACertificate.Content...)
	options.TLSConfig.MCAKey.Content = append([]byte(nil), options.TLSConfig.MCAKey.Content...)
	if options.TLSConfig.Config != nil {
		options.TLSConfig.Config = cloneTLSConfig(options.TLSConfig.Config)
	}
	if options.Token != nil {
		token := *options.Token
		options.Token = &token
	}
	if options.CSD != nil {
		csd := *options.CSD
		options.CSD = &csd
	}
	if options.HIP != nil {
		hip := *options.HIP
		options.HIP = &hip
	}
	if options.TNCC != nil {
		tncc := *options.TNCC
		tncc.Certificates = append([]Material(nil), options.TNCC.Certificates...)
		for certificateIndex := range tncc.Certificates {
			tncc.Certificates[certificateIndex].Content = append([]byte(nil), tncc.Certificates[certificateIndex].Content...)
		}
		options.TNCC = &tncc
	}
	return options
}

func (c *Client) Start() error {
	c.lifecycleAccess.Lock()
	if c.started {
		c.lifecycleAccess.Unlock()
		return nil
	}
	if c.closed {
		c.lifecycleAccess.Unlock()
		return ErrClientClosed
	}
	supervisorContext, cancelSupervisor := context.WithCancel(c.options.Context)
	c.supervisorCancel = cancelSupervisor
	c.supervisorDone = make(chan struct{})
	c.started = true
	c.lifecycleAccess.Unlock()
	if c.options.OnTunnelConfiguration != nil {
		go c.runTunnelConfigurationDispatcher()
	}
	go c.runSupervisor(supervisorContext)
	return nil
}

func (c *Client) RestartSession() {
	c.lifecycleAccess.Lock()
	session := c.currentSession
	c.lifecycleAccess.Unlock()
	c.httpTransport.CloseIdleConnections()
	if session != nil {
		session.Fail(E.New("openconnect: session restart requested"))
	}
}

// ReadDataPacket returns a caller-owned copy of the next packet.
func (c *Client) ReadDataPacket(ctx context.Context) ([]byte, error) {
	packetBuffer, err := c.ReadDataPacketBuffer(ctx)
	if err != nil {
		return nil, err
	}
	payload := append([]byte(nil), packetBuffer.Bytes()...)
	packetBuffer.Release()
	return payload, nil
}

// ReadDataPackets transfers ownership of the returned buffers to the caller, which must release each buffer.
func (c *Client) ReadDataPackets(ctx context.Context) ([]*buf.Buffer, error) {
	return c.readDataPackets(ctx, 0)
}

// ReadDataPacketBuffer transfers ownership of the returned buffer to the caller, which must release it.
func (c *Client) ReadDataPacketBuffer(ctx context.Context) (*buf.Buffer, error) {
	packetBuffers, err := c.readDataPackets(ctx, 1)
	if err != nil {
		return nil, err
	}
	return packetBuffers[0], nil
}

func (c *Client) readDataPackets(ctx context.Context, maximumPackets int) ([]*buf.Buffer, error) {
	for {
		c.lifecycleAccess.Lock()
		stateChanged := c.stateChanged
		terminalError := c.terminalError
		closed := c.closed
		c.lifecycleAccess.Unlock()
		if terminalError != nil {
			return nil, terminalError
		}
		if closed {
			return nil, ErrClientClosed
		}
		packetBuffers := c.incomingDataPackets.Pop(maximumPackets)
		if len(packetBuffers) > 0 {
			return packetBuffers, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-stateChanged:
		case <-c.incomingDataPackets.Wake():
		}
	}
}

// WriteDataPacket copies packet before returning.
func (c *Client) WriteDataPacket(packet []byte) error {
	return c.WriteDataPackets([][]byte{packet})
}

// WriteDataPackets copies every packet before returning.
func (c *Client) WriteDataPackets(packets [][]byte) error {
	if len(packets) == 0 {
		return nil
	}
	return c.WriteDataPacketBuffers(newPacketBuffersFrom(packets))
}

// WriteDataPacketBuffers takes ownership of every buffer and releases them before returning.
func (c *Client) WriteDataPacketBuffers(packetBuffers []*buf.Buffer) error {
	if len(packetBuffers) == 0 {
		return nil
	}
	session := c.readySession()
	if session == nil {
		buf.ReleaseMulti(packetBuffers)
		return ErrDataChannelNotReady
	}
	return session.WriteDataPacketBuffers(packetBuffers)
}

func (c *Client) Ready() bool {
	return c.readySession() != nil
}

func (c *Client) TunnelConfiguration() TunnelConfiguration {
	c.configurationAccess.RLock()
	defer c.configurationAccess.RUnlock()
	return cloneTunnelConfiguration(c.tunnelConfiguration)
}

func (c *Client) setTunnelConfiguration(configuration TunnelConfiguration) TunnelConfiguration {
	configuration = cloneTunnelConfiguration(configuration)
	c.configurationAccess.Lock()
	c.tunnelConfiguration = configuration
	c.configurationAccess.Unlock()
	return configuration
}

func (c *Client) publishTunnelConfigurationEvent(reason TunnelConfigurationEventReason, configuration TunnelConfiguration) {
	if c.options.OnTunnelConfiguration == nil {
		return
	}
	c.configurationEventAccess.Lock()
	if !c.configurationEventStopped {
		c.configurationEvents = append(c.configurationEvents, TunnelConfigurationEvent{
			Reason:        reason,
			Configuration: cloneTunnelConfiguration(configuration),
		})
	}
	c.configurationEventAccess.Unlock()
	select {
	case c.configurationEventWake <- struct{}{}:
	default:
	}
}

func (c *Client) runTunnelConfigurationDispatcher() {
	for {
		c.configurationEventAccess.Lock()
		if c.configurationEventStopped {
			c.configurationEvents = nil
			c.configurationEventAccess.Unlock()
			return
		}
		if len(c.configurationEvents) == 0 {
			c.configurationEventAccess.Unlock()
			<-c.configurationEventWake
			continue
		}
		event := c.configurationEvents[0]
		c.configurationEvents[0] = TunnelConfigurationEvent{}
		c.configurationEvents = c.configurationEvents[1:]
		c.configurationEventAccess.Unlock()
		err := c.options.OnTunnelConfiguration(event)
		if err == nil {
			continue
		}
		failure := E.Errors(errTunnelConfiguration, E.Cause(err, "apply openconnect tunnel configuration"))
		c.configurationEventAccess.Lock()
		c.configurationEventStopped = true
		c.configurationEvents = nil
		c.configurationEventAccess.Unlock()
		c.lifecycleAccess.Lock()
		session := c.currentSession
		c.lifecycleAccess.Unlock()
		c.setTerminalError(failure)
		if session != nil {
			session.Fail(failure)
		}
		return
	}
}

func (c *Client) pushIncomingDataPacket(packetBuffer *buf.Buffer) {
	if packetBuffer == nil {
		return
	}
	if packetBuffer.IsEmpty() {
		packetBuffer.Release()
		return
	}
	dropped := c.incomingDataPackets.PushBatch([]*buf.Buffer{packetBuffer}, (*buf.Buffer).Release)
	c.droppedIncomingPackets.Add(dropped)
}

func (c *Client) DroppedIncomingDataPackets() uint64 {
	return c.droppedIncomingPackets.Load()
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.lifecycleAccess.Lock()
		c.closed = true
		c.activeTransportSession = nil
		c.setActiveTransportWithLifecycleLocked("")
		if c.supervisorCancel != nil {
			c.supervisorCancel()
		}
		session := c.currentSession
		supervisorDone := c.supervisorDone
		c.signalStateChangedLocked()
		c.lifecycleAccess.Unlock()
		c.configurationEventAccess.Lock()
		c.configurationEventStopped = true
		c.configurationEvents = nil
		c.configurationEventAccess.Unlock()
		select {
		case c.configurationEventWake <- struct{}{}:
		default:
		}

		c.authChallengeAccess.Lock()
		pending := c.pendingAuthChallenge
		c.pendingAuthChallenge = nil
		c.signalAuthChallengeUpdatedLocked()
		c.authChallengeAccess.Unlock()
		if pending != nil && pending.cancel != nil {
			cancelErr := pending.cancel()
			if cancelErr != nil {
				c.closeErr = E.Append(c.closeErr, cancelErr, func(cause error) error {
					return E.Cause(cause, "cancel openconnect authentication continuation")
				})
			}
		}
		if session != nil {
			sessionCloseErr := session.Close()
			if sessionCloseErr != nil {
				c.closeErr = E.Append(c.closeErr, sessionCloseErr, func(cause error) error {
					return E.Cause(cause, "close openconnect session")
				})
			}
		}
		if supervisorDone != nil {
			<-supervisorDone
		}
		c.httpTransport.CloseIdleConnections()
		c.incomingDataPackets.Drain((*buf.Buffer).Release)
	})
	return c.closeErr
}

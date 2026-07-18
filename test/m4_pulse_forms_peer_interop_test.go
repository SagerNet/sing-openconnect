package test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

type m4PulseFormPeer struct {
	listener net.Listener
	port     uint16
	failures chan error
	done     chan struct{}
	close    sync.Once
}

func TestM4PulseIndependentAuthenticationForms(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	certificate, roots := createM2GPPeerCertificate(t, m4PulseHostname)
	peer := newM4PulseFormPeer(t, certificate)
	defer peer.Close()
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context:    ctx,
		Server:     net.JoinHostPort(m4PulseHostname, strconv.Itoa(int(peer.port))),
		Flavor:     openconnect.FlavorPulse,
		Username:   m4PulseUsername,
		Password:   m4PulsePassword,
		ReportedOS: "linux-64",
		NoUDP:      true,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
		}},
		Dialer: &m4PulseDialer{
			hostname: m4PulseHostname,
			address:  M.ParseSocksaddrHostPort("127.0.0.1", peer.port),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	answeredForms := make(map[string]bool)
	for !client.Ready() {
		formUpdated := client.AuthChallengeUpdated()
		select {
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for Pulse authentication forms"))
		case peerErr := <-peer.failures:
			t.Fatal(peerErr)
		case <-formUpdated:
			form := client.PendingAuthChallenge()
			if form == nil {
				continue
			}
			formKind, values := answerM4PulseForm(t, form)
			if answeredForms[formKind] {
				t.Fatal("Pulse published a duplicate authentication form: ", formKind)
			}
			answeredForms[formKind] = true
			err = client.CompleteAuthChallenge(form.ID, openconnect.AuthResponse{Form: &openconnect.AuthFormResponse{Values: values}})
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Millisecond):
		}
	}
	wantedForms := []string{"realm-entry", "realm-choice", "region-choice", "session", "password-change", "gtc"}
	for _, wantedForm := range wantedForms {
		if !answeredForms[wantedForm] {
			t.Fatal("Pulse did not publish authentication form: ", wantedForm)
		}
	}
	packet := []byte{
		0x45, 0, 0, 20, 0, 1, 0, 0, 64, 59, 0, 0,
		192, 0, 2, 10, 198, 51, 100, 9,
	}
	err = client.WriteDataPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	received, err := client.ReadDataPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, packet) {
		t.Fatalf("unexpected Pulse form peer TLS echo: %x", received)
	}
	err = client.Close()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case peerErr := <-peer.failures:
		t.Fatal(peerErr)
	case <-peer.done:
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for Pulse form peer close"))
	}
}

func TestM4PulseHostCheckerFailsTowardNC(t *testing.T) {
	t.Parallel()
	if testing.Short() || !interopEnabled() {
		t.Skip(openConnectInteropEnvironment + " is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	certificate, roots := createM2GPPeerCertificate(t, m4PulseHostname)
	peer := newM4PulseHostCheckerPeer(t, certificate)
	defer peer.Close()
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context:    ctx,
		Server:     net.JoinHostPort(m4PulseHostname, strconv.Itoa(int(peer.port))),
		Flavor:     openconnect.FlavorPulse,
		Username:   m4PulseUsername,
		Password:   m4PulsePassword,
		ReportedOS: "linux-64",
		NoUDP:      true,
		TLSConfig: openconnect.ClientTLSOptions{Config: &tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
		}},
		Dialer: &m4PulseDialer{
			hostname: m4PulseHostname,
			address:  M.ParseSocksaddrHostPort("127.0.0.1", peer.port),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	err = client.Start()
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ReadDataPacket(ctx)
	if !E.IsMulti(err, openconnect.ErrProtocolNotSupported) || !bytes.Contains([]byte(err.Error()), []byte("nc flavor")) {
		t.Fatal("Pulse Host Checker did not fail specifically toward the nc flavor: ", err)
	}
	select {
	case peerErr := <-peer.failures:
		t.Fatal(peerErr)
	case <-peer.done:
	case <-ctx.Done():
		t.Fatal(E.Cause(ctx.Err(), "wait for Pulse Host Checker peer close"))
	}
}

func answerM4PulseForm(t *testing.T, form *openconnect.AuthChallenge) (string, map[string]string) {
	t.Helper()
	if form.Browser != nil || form.Form == nil {
		t.Fatalf("Pulse published a non-form authentication challenge: %#v", form)
	}
	values := make(map[string]string, len(form.Form.Fields))
	formKind := ""
	if len(form.Form.Fields) == 3 && form.Form.Fields[0].Name == "oldpass" {
		formKind = "password-change"
		if form.Form.Fields[1].Name != "newpass1" || form.Form.Fields[2].Name != "newpass1" ||
			form.Form.Fields[1].SubmissionKey == form.Form.Fields[2].SubmissionKey {
			t.Fatal("Pulse password-change form did not preserve duplicate wire names with distinct submission keys")
		}
	}
	for index, field := range form.Form.Fields {
		switch field.Name {
		case "realm":
			formKind = "realm-entry"
			values[field.SubmissionKey] = "entered-realm"
		case "realm_choice":
			formKind = "realm-choice"
			values[field.SubmissionKey] = "realm-two"
		case "region_choice":
			formKind = "region-choice"
			values[field.SubmissionKey] = "region-two"
		case "session_choice":
			formKind = "session"
			values[field.SubmissionKey] = "session-one"
		case "oldpass":
			values[field.SubmissionKey] = "old-password"
		case "newpass1":
			if index != 1 && index != 2 {
				t.Fatal("Pulse password-change duplicate field order changed")
			}
			values[field.SubmissionKey] = "new-password"
		case "username":
			values[field.SubmissionKey] = m4PulseUsername
		case "tokencode":
			formKind = "gtc"
			values[field.SubmissionKey] = "654321"
		default:
			t.Fatal("unexpected Pulse authentication form field: ", field.Name)
		}
	}
	if formKind == "" {
		t.Fatal("unknown Pulse authentication form")
	}
	return formKind, values
}

func newM4PulseFormPeer(t *testing.T, certificate tls.Certificate) *m4PulseFormPeer {
	t.Helper()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(E.Cause(err, "listen for independent Pulse form peer"))
	}
	tcpAddress, loaded := listener.Addr().(*net.TCPAddr)
	if !loaded {
		_ = listener.Close()
		t.Fatal("Pulse form listener has no TCP address")
	}
	peer := &m4PulseFormPeer{
		listener: listener,
		port:     uint16(tcpAddress.Port),
		failures: make(chan error, 1),
		done:     make(chan struct{}),
	}
	go peer.serve()
	return peer
}

func newM4PulseHostCheckerPeer(t *testing.T, certificate tls.Certificate) *m4PulseFormPeer {
	t.Helper()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(E.Cause(err, "listen for independent Pulse Host Checker peer"))
	}
	tcpAddress, loaded := listener.Addr().(*net.TCPAddr)
	if !loaded {
		_ = listener.Close()
		t.Fatal("Pulse Host Checker listener has no TCP address")
	}
	peer := &m4PulseFormPeer{
		listener: listener,
		port:     uint16(tcpAddress.Port),
		failures: make(chan error, 1),
		done:     make(chan struct{}),
	}
	go peer.serveHostChecker()
	return peer
}

func (p *m4PulseFormPeer) serve() {
	defer close(p.done)
	conn, err := p.listener.Accept()
	if err != nil {
		if !E.IsClosed(err) {
			p.report(E.Cause(err, "accept independent Pulse form connection"))
		}
		return
	}
	defer conn.Close()
	err = p.exchange(conn)
	if err != nil {
		p.report(err)
	}
}

func (p *m4PulseFormPeer) serveHostChecker() {
	defer close(p.done)
	conn, err := p.listener.Accept()
	if err != nil {
		if !E.IsClosed(err) {
			p.report(E.Cause(err, "accept independent Pulse Host Checker connection"))
		}
		return
	}
	defer conn.Close()
	err = exchangeM4PulseHostChecker(conn)
	if err != nil {
		p.report(err)
	}
}

func (p *m4PulseFormPeer) exchange(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return E.Cause(err, "read independent Pulse form upgrade request")
	}
	if request.Method != http.MethodGet || request.URL.Path != "/" || request.Header.Get("Upgrade") != "IF-T/TLS 1.0" {
		return E.New("independent Pulse form peer received invalid HTTP upgrade")
	}
	err = writeM4PulseBytes(conn, []byte("HTTP/1.1 101 Switching Protocols\r\n\r\n"))
	if err != nil {
		return err
	}
	clientAttributes, err := exchangeM4PulseFormPreamble(conn, reader)
	if err != nil {
		return err
	}
	if string(m4PulseAVPValue(clientAttributes, 0xd5e, m4PulseVendorJuniper2)) != "Linux" {
		return E.New("Pulse form peer received invalid client platform")
	}
	sequence := uint32(3)
	identifier := byte(4)
	realmEntry := appendM4PulseAVP(nil, 0xd4f, m4PulseVendorJuniper2, nil)
	responseAttributes, err := exchangeM4PulseFormChallenge(conn, reader, sequence, identifier, realmEntry)
	if err != nil {
		return err
	}
	if string(m4PulseAVPValue(responseAttributes, 0xd50, m4PulseVendorJuniper2)) != "entered-realm" {
		return E.New("Pulse realm-entry response was incorrect")
	}
	sequence++
	identifier++
	realmChoices := appendM4PulseAVP(nil, 0xd4e, m4PulseVendorJuniper2, []byte("realm-one"))
	realmChoices = appendM4PulseAVP(realmChoices, 0xd4e, m4PulseVendorJuniper2, []byte("realm-two"))
	responseAttributes, err = exchangeM4PulseFormChallenge(conn, reader, sequence, identifier, realmChoices)
	if err != nil {
		return err
	}
	if string(m4PulseAVPValue(responseAttributes, 0xd50, m4PulseVendorJuniper2)) != "realm-two" {
		return E.New("Pulse realm-choice response was incorrect")
	}
	sequence++
	identifier++
	regionChoices := appendM4PulseAVP(nil, 0xd51, m4PulseVendorJuniper2, []byte("region-one"))
	regionChoices = appendM4PulseAVP(regionChoices, 0xd51, m4PulseVendorJuniper2, []byte("region-two"))
	responseAttributes, err = exchangeM4PulseFormChallenge(conn, reader, sequence, identifier, regionChoices)
	if err != nil {
		return err
	}
	if string(m4PulseAVPValue(responseAttributes, 0xd52, m4PulseVendorJuniper2)) != "region-two" {
		return E.New("Pulse region-choice response was incorrect")
	}
	sequence++
	identifier++
	sessionAttributes := appendM4PulseAVP(nil, 0xd66, m4PulseVendorJuniper2, []byte("session-one"))
	sessionAttributes = appendM4PulseAVP(sessionAttributes, 0xd67, m4PulseVendorJuniper2, []byte("198.51.100.10"))
	var sessionTime [8]byte
	binary.BigEndian.PutUint64(sessionTime[:], uint64(time.Now().Unix()))
	sessionAttributes = appendM4PulseAVP(sessionAttributes, 0xd68, m4PulseVendorJuniper2, sessionTime[:])
	sessionChallenge := appendM4PulseAVP(nil, 0xd65, m4PulseVendorJuniper2, sessionAttributes)
	responseAttributes, err = exchangeM4PulseFormChallenge(conn, reader, sequence, identifier, sessionChallenge)
	if err != nil {
		return err
	}
	if string(m4PulseAVPValue(responseAttributes, 0xd69, m4PulseVendorJuniper2)) != "session-one" {
		return E.New("Pulse session-choice response was incorrect")
	}
	sequence++
	identifier++
	err = exchangeM4PulseFormPassword(conn, reader, sequence, identifier)
	if err != nil {
		return err
	}
	sequence++
	identifier++
	err = exchangeM4PulseFormPasswordChange(conn, reader, sequence, identifier)
	if err != nil {
		return err
	}
	sequence++
	identifier++
	err = exchangeM4PulseFormGTC(conn, reader, sequence, identifier)
	if err != nil {
		return err
	}
	sequence++
	identifier++
	cookieAttributes := appendM4PulseAVP(nil, 0xd53, m4PulseVendorJuniper2, []byte("pulse-form-cookie-0123456789"))
	responseAttributes, err = exchangeM4PulseFormChallenge(conn, reader, sequence, identifier, cookieAttributes)
	if err != nil {
		return err
	}
	if len(responseAttributes) != 0 {
		return E.New("Pulse form peer received a non-empty cookie acknowledgement")
	}
	var authType [4]byte
	binary.BigEndian.PutUint32(authType[:], m4PulseAuthJuniper)
	successPayload := append(authType[:0:0], authType[:]...)
	successPayload = append(successPayload, 3, identifier, 0, 4)
	err = writeM4PulseFrame(conn, m4PulseVendorTCG, 7, sequence+1, successPayload, false)
	if err != nil {
		return err
	}
	err = writeM4PulseFrame(conn, m4PulseVendorJuniper, 1, sequence+2, buildM4PulseMainConfiguration(), false)
	if err != nil {
		return err
	}
	err = writeM4PulseFrame(conn, m4PulseVendorJuniper, 0x8f, sequence+3, []byte{0, 0, 0, 0}, false)
	if err != nil {
		return err
	}
	frame, err := readM4PulseFrame(reader)
	if err != nil {
		return err
	}
	if frame.vendor != m4PulseVendorJuniper || frame.frameType != 4 || len(frame.payload) == 0 || frame.payload[0]>>4 != 4 {
		return E.New("Pulse form peer did not receive tunnel data")
	}
	err = writeM4PulseFrame(conn, m4PulseVendorJuniper, 4, sequence+4, frame.payload, false)
	if err != nil {
		return err
	}
	frame, err = readM4PulseFrame(reader)
	if err != nil {
		return err
	}
	if frame.vendor != m4PulseVendorJuniper || frame.frameType != 0x89 || len(frame.payload) != 0 {
		return E.New("Pulse form peer did not receive graceful close")
	}
	return nil
}

func exchangeM4PulseFormPreamble(conn net.Conn, reader *bufio.Reader) ([]m4PulseAVP, error) {
	frame, err := readM4PulseFrame(reader)
	if err != nil {
		return nil, err
	}
	if frame.vendor != m4PulseVendorTCG || frame.frameType != 1 || !bytes.Equal(frame.payload, []byte{0, 1, 2, 2}) {
		return nil, E.New("Pulse form peer received invalid version request")
	}
	err = writeM4PulseFrame(conn, m4PulseVendorTCG, 2, 0, []byte{0, 0, 0, 2}, false)
	if err != nil {
		return nil, err
	}
	frame, err = readM4PulseFrame(reader)
	if err != nil {
		return nil, err
	}
	if frame.vendor != m4PulseVendorJuniper || frame.frameType != 0x88 ||
		!bytes.Contains(frame.payload, []byte("clientCapabilities={}")) {
		return nil, E.New("Pulse form peer received invalid client information")
	}
	var authType [4]byte
	binary.BigEndian.PutUint32(authType[:], m4PulseAuthJuniper)
	err = writeM4PulseFrame(conn, m4PulseVendorTCG, 5, 1, authType[:], false)
	if err != nil {
		return nil, err
	}
	frame, err = readM4PulseFrame(reader)
	if err != nil {
		return nil, err
	}
	identity, err := parseM4PulseAuthenticationEAP(frame, 2)
	if err != nil {
		return nil, err
	}
	if len(identity) != 14 || identity[4] != 1 || string(identity[5:]) != "anonymous" {
		return nil, E.New("Pulse form peer received invalid anonymous identity")
	}
	serverInformation := buildM4PulseEAP(1, 3, 0xfe, 1, nil)
	err = writeM4PulseAuthentication(conn, 2, serverInformation, false)
	if err != nil {
		return nil, err
	}
	frame, err = readM4PulseFrame(reader)
	if err != nil {
		return nil, err
	}
	clientInformation, err := parseM4PulseAuthenticationEAP(frame, 2)
	if err != nil {
		return nil, err
	}
	if len(clientInformation) < 12 {
		return nil, E.New("Pulse form peer received short client information EAP")
	}
	return parseM4PulseAVPs(clientInformation[12:])
}

func exchangeM4PulseHostChecker(conn net.Conn) error {
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return E.Cause(err, "read independent Pulse Host Checker upgrade request")
	}
	if request.Method != http.MethodGet || request.URL.Path != "/" || request.Header.Get("Upgrade") != "IF-T/TLS 1.0" {
		return E.New("independent Pulse Host Checker peer received invalid HTTP upgrade")
	}
	err = writeM4PulseBytes(conn, []byte("HTTP/1.1 101 Switching Protocols\r\n\r\n"))
	if err != nil {
		return err
	}
	_, err = exchangeM4PulseFormPreamble(conn, reader)
	if err != nil {
		return err
	}
	hostCheckerRequest := buildM4PulseEAP(1, 44, 0xfe, 3, nil)
	attributes := appendM4PulseAVP(nil, 79, 0, hostCheckerRequest)
	outerRequest := buildM4PulseEAP(1, 4, 0xfe, 1, attributes)
	err = writeM4PulseAuthentication(conn, 3, outerRequest, false)
	if err != nil {
		return err
	}
	_, err = readM4PulseFrame(reader)
	if err != nil && !E.IsClosed(err) {
		return err
	}
	return nil
}

func exchangeM4PulseFormChallenge(
	conn net.Conn,
	reader *bufio.Reader,
	sequence uint32,
	identifier byte,
	attributes []byte,
) ([]m4PulseAVP, error) {
	request := buildM4PulseEAP(1, identifier, 0xfe, 1, attributes)
	err := writeM4PulseAuthentication(conn, sequence, request, false)
	if err != nil {
		return nil, err
	}
	frame, err := readM4PulseFrame(reader)
	if err != nil {
		return nil, err
	}
	response, err := parseM4PulseAuthenticationEAP(frame, 2)
	if err != nil {
		return nil, err
	}
	if len(response) < 12 || response[1] != identifier || binary.BigEndian.Uint32(response[4:8]) != m4PulseExpanded ||
		binary.BigEndian.Uint32(response[8:12]) != 1 {
		return nil, E.New("Pulse form peer received invalid expanded response")
	}
	return parseM4PulseAVPs(response[12:])
}

func exchangeM4PulseFormPassword(conn net.Conn, reader *bufio.Reader, sequence uint32, identifier byte) error {
	innerIdentifier := identifier + 40
	innerRequest := buildM4PulseEAP(1, innerIdentifier, 0xfe, 2, []byte{1})
	attributes := appendM4PulseAVP(nil, 79, 0, innerRequest)
	responseAttributes, err := exchangeM4PulseFormChallenge(conn, reader, sequence, identifier, attributes)
	if err != nil {
		return err
	}
	if string(m4PulseAVPValue(responseAttributes, 0xd6d, m4PulseVendorJuniper2)) != m4PulseUsername {
		return E.New("Pulse form peer received incorrect username")
	}
	passwordEAP := m4PulseAVPValue(responseAttributes, 79, 0)
	if len(passwordEAP) < 15 || passwordEAP[1] != innerIdentifier || binary.BigEndian.Uint32(passwordEAP[8:12]) != 2 ||
		passwordEAP[12] != 2 || passwordEAP[13] != 2 {
		return E.New("Pulse form peer received malformed password EAP")
	}
	passwordLength := int(passwordEAP[14]) - 2
	if passwordLength < 0 || 15+passwordLength != len(passwordEAP) || string(passwordEAP[15:]) != m4PulsePassword {
		return E.New("Pulse form peer received incorrect password")
	}
	return nil
}

func exchangeM4PulseFormPasswordChange(conn net.Conn, reader *bufio.Reader, sequence uint32, identifier byte) error {
	innerIdentifier := identifier + 40
	innerRequest := buildM4PulseEAP(1, innerIdentifier, 0xfe, 2, []byte{0x43})
	attributes := appendM4PulseAVP(nil, 79, 0, innerRequest)
	responseAttributes, err := exchangeM4PulseFormChallenge(conn, reader, sequence, identifier, attributes)
	if err != nil {
		return err
	}
	passwordEAP := m4PulseAVPValue(responseAttributes, 79, 0)
	if len(passwordEAP) < 17 || passwordEAP[1] != innerIdentifier || binary.BigEndian.Uint32(passwordEAP[8:12]) != 2 ||
		passwordEAP[12] != 2 || passwordEAP[13] != 2 {
		return E.New("Pulse form peer received malformed password-change EAP")
	}
	payload := passwordEAP[12:]
	oldPasswordLength := int(payload[2]) - 2
	if oldPasswordLength < 0 || len(payload) < 3+oldPasswordLength+2 || string(payload[3:3+oldPasswordLength]) != "old-password" {
		return E.New("Pulse form peer received incorrect old password")
	}
	newPasswordOffset := 3 + oldPasswordLength
	if payload[newPasswordOffset] != 3 {
		return E.New("Pulse form peer received malformed new-password field")
	}
	newPasswordLength := int(payload[newPasswordOffset+1]) - 2
	if newPasswordLength < 0 || newPasswordOffset+2+newPasswordLength != len(payload) ||
		string(payload[newPasswordOffset+2:]) != "new-password" {
		return E.New("Pulse form peer received incorrect new password")
	}
	return nil
}

func exchangeM4PulseFormGTC(conn net.Conn, reader *bufio.Reader, sequence uint32, identifier byte) error {
	innerIdentifier := identifier + 40
	innerRequest := buildM4PulseEAP(1, innerIdentifier, 6, 0, []byte("Token code:"))
	attributes := appendM4PulseAVP(nil, 79, 0, innerRequest)
	responseAttributes, err := exchangeM4PulseFormChallenge(conn, reader, sequence, identifier, attributes)
	if err != nil {
		return err
	}
	if string(m4PulseAVPValue(responseAttributes, 0xd6d, m4PulseVendorJuniper2)) != m4PulseUsername {
		return E.New("Pulse GTC response omitted its username")
	}
	tokenEAP := m4PulseAVPValue(responseAttributes, 79, 0)
	if len(tokenEAP) < 5 || tokenEAP[1] != innerIdentifier || tokenEAP[4] != 6 || string(tokenEAP[5:]) != "654321" {
		return E.New("Pulse form peer received incorrect GTC token")
	}
	return nil
}

func (p *m4PulseFormPeer) report(err error) {
	select {
	case p.failures <- err:
	default:
	}
}

func (p *m4PulseFormPeer) Close() {
	p.close.Do(func() {
		_ = p.listener.Close()
	})
}

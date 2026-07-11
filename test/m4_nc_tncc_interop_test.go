package test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	openconnect "github.com/sagernet/sing-openconnect"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const m4NCTNCCHostname = "gateway.m4-nc-tncc.test"

type m4NCTNCCPeer struct {
	access           sync.Mutex
	server           *httptest.Server
	dialer           *m4NCDialer
	errors           chan error
	logout           chan struct{}
	logoutOnce       sync.Once
	mandatoryPolicy  bool
	initialRequests  int
	responseRequests int
	issuedDSID       bool
}

func TestM4NetworkConnectBuiltInTNCCPeerInterop(t *testing.T) {
	t.Parallel()
	peer, client := newM4NCTNCCPeer(t, false)
	runM4NCTNCCClient(t, peer, client, "oNCP endpoint returned HTTP 500")
	peer.access.Lock()
	initialRequests := peer.initialRequests
	responseRequests := peer.responseRequests
	issuedDSID := peer.issuedDSID
	peer.access.Unlock()
	if initialRequests != 2 || responseRequests != 2 || !issuedDSID {
		t.Fatalf("built-in TNCC exchange mismatch: initial=%d response=%d DSID=%v", initialRequests, responseRequests, issuedDSID)
	}
	peer.dialer.access.Lock()
	hostnameDials := peer.dialer.hostnameDialsAfterPoison
	pinnedDials := peer.dialer.pinnedDialsAfterPoison
	peer.dialer.access.Unlock()
	if hostnameDials != 0 || pinnedDials < 2 {
		t.Fatalf("built-in TNCC did not remain on accepted endpoint: hostname=%d pinned=%d", hostnameDials, pinnedDials)
	}
}

func TestM4NetworkConnectBuiltInTNCCRejectsUnknownMandatoryPolicy(t *testing.T) {
	t.Parallel()
	peer, client := newM4NCTNCCPeer(t, true)
	runM4NCTNCCClient(t, peer, client, "unmodeled mandatory policy Required Antivirus")
	peer.access.Lock()
	initialRequests := peer.initialRequests
	responseRequests := peer.responseRequests
	issuedDSID := peer.issuedDSID
	peer.access.Unlock()
	if initialRequests != 1 || responseRequests != 0 || issuedDSID {
		t.Fatalf("mandatory TNCC policy was falsely accepted: initial=%d response=%d DSID=%v", initialRequests, responseRequests, issuedDSID)
	}
}

func newM4NCTNCCPeer(t *testing.T, mandatoryPolicy bool) (*m4NCTNCCPeer, *openconnect.Client) {
	t.Helper()
	rootCertificate, certificates := createM4NCCertificates(t, []string{m4NCTNCCHostname, m4NCTNCCHostname})
	peer := &m4NCTNCCPeer{
		errors:          make(chan error, 16),
		logout:          make(chan struct{}),
		mandatoryPolicy: mandatoryPolicy,
	}
	peer.server = newM2GPTLSServer(t, certificates[0], http.HandlerFunc(peer.serve))
	lure := newM2GPTLSServer(t, certificates[1], http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		peer.fail(writer, E.New("built-in TNCC followed poisoned gateway DNS"))
	}))
	gatewayAddress := M.SocksaddrFromNet(peer.server.Listener.Addr())
	lureAddress := M.SocksaddrFromNet(lure.Listener.Addr())
	peer.dialer = &m4NCDialer{
		routes: map[string]M.Socksaddr{
			m4NCTNCCHostname: gatewayAddress,
		},
		gatewayHostname: m4NCTNCCHostname,
		gatewayAddress:  gatewayAddress,
		lureAddress:     lureAddress,
	}
	serverURL := "https://" + net.JoinHostPort(m4NCTNCCHostname, strconv.Itoa(int(gatewayAddress.Port)))
	client, err := openconnect.NewClient(openconnect.ClientOptions{
		Context: context.Background(),
		Server:  serverURL + "/start",
		Flavor:  openconnect.FlavorNC,
		NoUDP:   true,
		Dialer:  peer.dialer,
		TLSConfig: openconnect.ClientTLSOptions{
			CertificateAuthority: openconnect.Material{Content: rootCertificate},
		},
		TNCC: &openconnect.TNCCOptions{DeviceID: "device-47"},
	})
	if err != nil {
		t.Fatal(E.Cause(err, "create built-in TNCC peer client"))
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	return peer, client
}

func runM4NCTNCCClient(t *testing.T, peer *m4NCTNCCPeer, client *openconnect.Client, expectedError string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := client.Start()
	if err != nil {
		t.Fatal(E.Cause(err, "start built-in TNCC peer client"))
	}
	terminal := make(chan error, 1)
	go func() {
		_, readErr := client.ReadDataPacket(ctx)
		terminal <- readErr
	}()
	for {
		select {
		case peerErr := <-peer.errors:
			t.Fatal(peerErr)
		case terminalErr := <-terminal:
			if terminalErr == nil {
				t.Fatal("built-in TNCC client ended without a terminal error")
			}
			if !strings.Contains(terminalErr.Error(), expectedError) {
				t.Fatal(E.Cause(terminalErr, "unexpected built-in TNCC terminal result"))
			}
			if !peer.mandatoryPolicy {
				select {
				case <-peer.logout:
				case <-ctx.Done():
					t.Fatal(E.Cause(ctx.Err(), "wait for built-in TNCC logout"))
				}
			}
			return
		case <-ctx.Done():
			t.Fatal(E.Cause(ctx.Err(), "wait for built-in TNCC peer"))
		}
	}
}

func (p *m4NCTNCCPeer) serve(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/start":
		p.serveAuthentication(writer, request)
	case "/dana-na/hc/tnchcupdate.cgi":
		p.serveTNCC(writer, request)
	case "/dana-na/auth/logout.cgi":
		cookie, err := request.Cookie("DSID")
		if err != nil || cookie.Value != "tncc-session" {
			p.fail(writer, E.New("built-in TNCC logout omitted DSID"))
			return
		}
		writer.WriteHeader(http.StatusOK)
		p.logoutOnce.Do(func() { close(p.logout) })
	case "/dana/js":
		writer.WriteHeader(http.StatusInternalServerError)
	default:
		p.fail(writer, E.New("unexpected built-in TNCC peer path: ", request.URL.Path))
	}
}

func (p *m4NCTNCCPeer) fail(writer http.ResponseWriter, err error) {
	select {
	case p.errors <- err:
	default:
	}
	http.Error(writer, err.Error(), http.StatusInternalServerError)
}

func (p *m4NCTNCCPeer) serveAuthentication(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		p.fail(writer, E.New("built-in TNCC authentication request was not GET"))
		return
	}
	preauthenticationCookie, err := request.Cookie("DSPREAUTH")
	if err != nil {
		http.SetCookie(writer, &http.Cookie{Name: "DSPREAUTH", Value: "initial-check", Path: "/", Secure: true})
		http.SetCookie(writer, &http.Cookie{Name: "DSSIGNIN", Value: "/start", Path: "/", Secure: true})
		p.dialer.poison()
		writer.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(writer, "<html><body>Host Checker required</body></html>")
		return
	}
	if preauthenticationCookie.Value != "checked-1" {
		p.fail(writer, E.New("unexpected built-in TNCC DSPREAUTH cookie: ", preauthenticationCookie.Value))
		return
	}
	p.access.Lock()
	p.issuedDSID = true
	p.access.Unlock()
	http.SetCookie(writer, &http.Cookie{Name: "DSID", Value: "tncc-session", Path: "/", Secure: true})
	writer.Header().Set("Content-Type", "text/html")
	_, _ = io.WriteString(writer, "<html><body>accepted</body></html>")
}

func (p *m4NCTNCCPeer) serveTNCC(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		p.fail(writer, E.New("built-in TNCC request metadata mismatch"))
		return
	}
	if request.Header.Get("User-Agent") != "Neoteris HC Http" {
		p.fail(writer, E.New("built-in TNCC user agent mismatch: ", request.Header.Get("User-Agent")))
		return
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		p.fail(writer, E.Cause(err, "read built-in TNCC body"))
		return
	}
	values, err := parseM4NCTNCCBody(string(body))
	if err != nil {
		p.fail(writer, err)
		return
	}
	encodedMessage := values["msg"]
	message, err := base64.StdEncoding.DecodeString(encodedMessage)
	if err != nil {
		p.fail(writer, E.Cause(err, "decode built-in TNCC message"))
		return
	}
	err = validateM4NCTNCCPackets(message, 0)
	if err != nil {
		p.fail(writer, err)
		return
	}
	switch values["connID"] {
	case "0":
		if values["timestamp"] != "0" || values["firsttime"] != "1" || values["deviceid"] != "device-47" || !bytes.Contains(message, []byte("policy request")) {
			p.fail(writer, E.New("built-in TNCC initial message mismatch"))
			return
		}
		p.access.Lock()
		p.initialRequests++
		round := p.initialRequests
		p.access.Unlock()
		policy := "policy response"
		if p.mandatoryPolicy {
			policy = `<html><param value="policy=Required Antivirus;"></html>`
		}
		responseMessage := encodeM4NCTNCCPacket(0x0013, encodeM4NCTNCCPacket(0x0ce4, encodeM4NCTNCCString(0x58316, []byte(policy))))
		_, _ = io.WriteString(writer, "interval="+strconv.Itoa(6-round)+"\nmsg="+base64.StdEncoding.EncodeToString(responseMessage)+"\n")
	case "1":
		if values["firsttime"] != "1" || values["timestamp"] != "" || values["deviceid"] != "" || !bytes.Contains(message, []byte("Accept-Language: en")) {
			p.fail(writer, E.New("built-in TNCC response message mismatch"))
			return
		}
		p.access.Lock()
		p.responseRequests++
		round := p.responseRequests
		p.access.Unlock()
		http.SetCookie(writer, &http.Cookie{Name: "DSPREAUTH", Value: "checked-" + strconv.Itoa(round), Path: "/", Secure: true})
		_, _ = io.WriteString(writer, "accepted\n")
	default:
		p.fail(writer, E.New("unexpected built-in TNCC connection ID: ", values["connID"]))
	}
}

func parseM4NCTNCCBody(body string) (map[string]string, error) {
	if !strings.HasSuffix(body, ";") {
		return nil, E.New("built-in TNCC body omitted trailing semicolon")
	}
	values := make(map[string]string)
	for _, field := range strings.Split(strings.TrimSuffix(body, ";"), ";") {
		name, value, found := strings.Cut(field, "=")
		if !found || name == "" {
			return nil, E.New("malformed built-in TNCC field: ", field)
		}
		if _, loaded := values[name]; loaded {
			return nil, E.New("duplicate built-in TNCC field: ", name)
		}
		values[name] = value
	}
	return values, nil
}

func encodeM4NCTNCCString(identifier uint32, content []byte) []byte {
	payload := make([]byte, 4, len(content)+6)
	binary.BigEndian.PutUint32(payload, identifier)
	payload = append(payload, content...)
	payload = append(payload, 0, 0)
	return encodeM4NCTNCCPacket(0x0ce7, payload)
}

func encodeM4NCTNCCPacket(command uint32, payload []byte) []byte {
	packetLength := 12 + len(payload)
	paddedLength := (packetLength + 3) &^ 3
	packet := make([]byte, paddedLength)
	binary.BigEndian.PutUint32(packet, command)
	packet[4] = 0xc0
	binary.BigEndian.PutUint16(packet[6:], uint16(packetLength))
	binary.BigEndian.PutUint32(packet[8:], 0x583)
	copy(packet[12:], payload)
	return packet
}

func validateM4NCTNCCPackets(content []byte, depth int) error {
	if depth > 16 {
		return E.New("built-in TNCC message nesting exceeded peer limit")
	}
	position := 0
	for position < len(content) {
		if len(content)-position < 12 {
			if len(bytes.Trim(content[position:], "\x00")) == 0 {
				return nil
			}
			return E.New("built-in TNCC message has truncated peer packet")
		}
		command := binary.BigEndian.Uint32(content[position:])
		packetLength := int(binary.BigEndian.Uint16(content[position+6:]))
		if content[position+4] != 0xc0 || binary.BigEndian.Uint32(content[position+8:]) != 0x583 || packetLength < 12 || packetLength > len(content)-position {
			return E.New("built-in TNCC packet header mismatch")
		}
		paddedLength := (packetLength + 3) &^ 3
		if paddedLength > len(content)-position {
			return E.New("built-in TNCC packet padding mismatch")
		}
		payload := content[position+12 : position+packetLength]
		if (command == 0x0013 && len(payload) >= 12) || command == 0x0ce4 || command == 0x0cf0 {
			err := validateM4NCTNCCPackets(payload, depth+1)
			if err != nil {
				return err
			}
		}
		position += paddedLength
	}
	return nil
}

# sing-openconnect architecture log

This file records verified protocol facts, adopted architecture decisions,
resolved conflicts with `PROMPT.md`, and milestone evidence. It is not by
itself an implementation-completion report.

## Status and evidence baseline

- Research date: 2026-07-13.
- OpenConnect wire oracle: `/tmp/openconnect`, commit
  `2035601b64a5360a46d18e08937e7f654b3230f2`.
- ocserv is the AnyConnect server oracle. Its source oracle is
  `/tmp/ocserv`, commit `7e8ce7078f6a3044c9fca9a7e8324c5462b6203d`;
  real-peer tests pin the Debian ocserv package to 1.3.0-2.
- M1 selected `github.com/pion/dtls/v3@v3.1.5` for modern standards-compliant
  DTLS 1.2 PSK and as the engine for Cisco DTLS 1.2 injected abbreviated
  resumption. Cisco DTLS 0.9 remains an owned record, crypto, and abbreviated-
  handshake implementation because Pion cannot represent version `0x0100`.
- `../sing-openvpn` is the structural precedent. Its current working tree was
  inspected, not treated as a wire-format oracle.
- M0 is complete: the dependency survey and a minimal real CSTP plus modern
  DTLS data path passed against ocserv 1.3.0-2. M1 implementation, its
  real-peer matrix, and milestone-wide verification are complete. M2
  GlobalProtect implementation and its auth, GPST, ESP, and HIP real-peer
  matrices are complete. M3 Fortinet/F5 implementation and its complete
  authentication, PPP, TLS, DTLS, recovery, and real-peer verification
  matrices are complete. M4 Pulse/Network Connect implementation, shared
  ESP/LZO completion, and its upstream-derived plus independent real-peer
  matrices are complete.

Only facts tied to source below are settled. Text labelled **Adopted decision**
is the implementation contract chosen under the mission's deployed-gateway
compatibility rule. The conflict register now records resolved design
conflicts; none of C-01 through C-11 remains a decision blocker.

## Upstream flavor decomposition

OpenConnect fixes the family boundary in `struct vpn_proto`. `obtain_cookie`
performs complete authentication, `tcp_connect` establishes the primary
connection and obtains configuration, and the UDP channel has separate setup,
wire-handshake/mainloop, close, shutdown, and probe hooks
(`/tmp/openconnect/openconnect-internal.h:830-872`, `struct vpn_proto`). Public
dispatch calls the selected `obtain_cookie` and `tcp_connect` hooks
(`/tmp/openconnect/library.c:513-533`).

| Flavor | Obtain session | Primary TCP channel | Secondary UDP channel | Authentication material |
| --- | --- | --- | --- | --- |
| `anyconnect` | `cstp_obtain_cookie` | `cstp_connect`, `cstp_mainloop` | DTLS | `webvpn` |
| `nc` | `oncp_obtain_cookie` | `oncp_connect`, `oncp_mainloop` | ESP-in-UDP | `DSID` |
| `gp` | `gpst_obtain_cookie` | `gpst_setup`, `gpst_mainloop` | ESP-in-UDP | serialized GP login arguments |
| `pulse` | `pulse_obtain_cookie` | `pulse_connect`, `pulse_mainloop` | ESP-in-UDP | IF-T/TLS cookie AVP |
| `f5` | `f5_obtain_cookie` | `f5_connect`, shared PPP mainloop | DTLS carrying PPP | `MRHSession` plus `F5_ST` |
| `fortinet` | `fortinet_obtain_cookie` | `fortinet_connect`, shared PPP mainloop | DTLS carrying PPP | `SVPNCOOKIE` |

The exact operations and feature flags are in
`/tmp/openconnect/library.c:277-399`, `openconnect_protos`. Relevant differences
are:

- AnyConnect has CSD, certificate, OTP, software-token, and multiple-certificate
  authentication flags and a protocol-specific SSO completion hook
  (`library.c:279-297`).
- NC has CSD and periodic-trojan flags but no `sso_detect_done` hook
  (`library.c:299-318`).
- GP has CSD, periodic-trojan, and protocol-specific SSO completion hooks
  (`library.c:320-339`).
- Pulse has no CSD or periodic-trojan flag (`library.c:341-359`).
- F5 and Fortinet share `ppp_tcp_mainloop` and `ppp_udp_mainloop`, but retain
  protocol-specific authentication, connection, logout, and DTLS probe parsing
  (`library.c:361-399`).

The internal flavor interface should preserve this split, but its obtain result
must be opaque protocol state rather than a bare cookie string. The reasons are
recorded under each flavor and in conflict C-04.

### AnyConnect

- `cstp_obtain_cookie` first probes XMLPOST, falls back to old GET and
  URL-encoded authentication, handles certificate and MCA requests, executes
  CSD when requested, processes repeated forms, and collects the `webvpn`
  cookie (`/tmp/openconnect/auth.c:1386-1732`, `cstp_obtain_cookie`).
- Cisco XML supports select choices with second-auth metadata and name/label
  overrides (`auth.c:96-183`, `parse_auth_choice`), and hidden, text, SSO,
  token, and password controls (`auth.c:185-275`, `parse_form`).
- `cstp_connect` sends `CONNECT /CSCOSSLC/tunnel`, `Cookie: webvpn`, CSTP
  headers, and DTLS offers (`/tmp/openconnect/cstp.c:226-325`). It parses CSTP
  and DTLS configuration including MTU, routes, DNS, DPD, rekey method, DTLS
  session ID, App-ID, port, and cipher (`cstp.c:361-684`).
- CSTP packets use the `STF\x01` header and carry data, DPD, keepalive,
  compressed data, and disconnect records; reconnect and rekey handling remain
  in the same primary loop (`cstp.c:946-1235`, `cstp_mainloop`).
- The DTLS channel performs a DTLS handshake over a connected UDP socket and
  carries a one-byte packet type followed by the payload
  (`/tmp/openconnect/dtls.c:99-200`, `/tmp/openconnect/dtls.c:235-457`).
- CSD is an authentication-stage external contract, not a static report:
  OpenConnect downloads or invokes the wrapper, passes protocol-defined
  arguments and environment, and consumes an `sdesktop` cookie
  (`/tmp/openconnect/auth.c:1112-1360`, `set_csd_user`, `run_csd_script`).
- ocserv plain plus liboath clears the accepted primary-password state, selects
  its hard-coded `pass_msg_otp`, and returns another authentication round with
  password counter zero (`/tmp/ocserv/src/auth/plain.c:341-374`).
  `get_auth_handler2` consequently serializes that round as the same
  `id="main"`, `name="password"` control used by a primary-password retry
  (`/tmp/ocserv/src/worker-auth.c:313-340`). OpenConnect's OATH heuristic only
  recognizes `secondary_password` or `id="challenge"`
  (`/tmp/openconnect/auth.c:1011-1034`), so it misses this real ocserv shape.
  This client extends the heuristic only after a stable primary password was
  submitted and only for the source-verified ocserv OTP prompt spellings. An
  indistinguishable unknown prompt is exposed as one-shot input with stable
  password reuse disabled; guessing an OTP would risk an account lockout.
- Multiple-certificate authentication first proves the machine certificate on
  the TLS connection. `cstp_obtain_cookie` handles an unaccepted CERT1 request
  before considering CERT2, retries once on a fresh TLS connection, and only
  signs the CERT2 challenge after the server returns `cert-authenticated`
  (`/tmp/openconnect/auth.c:1470-1552`).
- The CERT2 signature covers the exact byte sequence of the server's complete
  preceding XML response. The signer chooses the strongest common digest in
  SHA-512, SHA-384, SHA-256 order, using RSA PKCS#1 v1.5 or ECDSA according to
  the user key. The response carries the user certificate and intermediates in
  a degenerate PKCS#7 structure under certificate store `1U`; store `1M`
  records the TLS machine certificate proof (`/tmp/openconnect/auth.c:1750-1983`,
  `/tmp/openconnect/openssl.c:2605-2785`,
  `/tmp/openconnect/gnutls.c:3449-3614`).
- The M1 MCA interop test derives its peer from OpenConnect commit
  `2035601b64a5360a46d18e08937e7f654b3230f2`
  `tests/fake-cisco-server.py`. The peer requires the independent TLS machine
  certificate, validates a user-plus-intermediate PKCS#7 chain against a root,
  requires SHA-512 when all three hashes are offered, and verifies both RSA
  PKCS#1 v1.5 and ECDSA signatures over its exact prior response.

### GlobalProtect

- Prelogin can yield username/password fields or SSO user/token controls
  (`/tmp/openconnect/auth-globalprotect.c:78-227`, `parse_prelogin_xml`).
- A gateway challenge replaces the prompt, clears the prior secret, hides the
  username, and attaches the server-provided `inputStr` to the next request
  (`auth-globalprotect.c:232-274`, `challenge_cb`).
- Portal and gateway authentication are one state machine with portal-to-gateway
  credential or cookie propagation and repeated forms
  (`auth-globalprotect.c:674-805`, `gpst_login`).
- The successful gateway result is not one HTTP cookie. It serializes selected
  JNLP arguments including `authcookie`, `portal`, `user`, `domain`, preferred
  addresses, and `computer` (`auth-globalprotect.c:293-410`,
  `gp_login_args`, `parse_login_xml`).
- Tunnel configuration contains addresses, routes, DNS, `ssl-tunnel-url`,
  timers, and ESP algorithms, keys, ports, SPIs, and magic values
  (`/tmp/openconnect/gpst.c:406-640`, `gpst_parse_config_xml`).
- `gpst_get_config` obtains that configuration (`gpst.c:642-717`).
  `gpst_connect` performs the selected tunnel GET (`gpst.c:719-801`). If ESP
  keys are already present it deliberately does not first open GPST TLS because
  a new TLS connection invalidates those keys (`gpst.c:719-727`).
- GPST TCP framing and its primary loop are documented and implemented at
  `gpst.c:61-69` and `gpst.c:1111-1377`.
- HIP check/report generation and periodic scheduling span
  `gpst.c:803-1109`; GP ESP has protocol-specific probe packets at
  `gpst.c:1435-1602`.

### Fortinet

- `fortinet_obtain_cookie` follows the initial HTTP redirect, recognizes the
  FortiOS 7.4-only `top.location="..."` JavaScript redirect, captures the
  `realm=` query value without double encoding, then posts a static `username`
  plus `credential` form
  to `/remote/logincheck` (`/tmp/openconnect/fortinet.c:98-194`). Normal login,
  comma-delimited `tokeninfo`, blank-code FTM push, HTTP-401 HTML 2FA, HTTP-405
  invalid credentials, and repeated challenge rounds occupy distinct branches
  (`fortinet.c:193-331`). Success requires `SVPNCOOKIE`
  (`fortinet.c:241-251`).
- Configuration parsing covers IPv4/IPv6 addresses, DNS/search domains,
  include/exclude routes, default IPv4 routing, idle/authentication expiry,
  DPD, DTLS, and reconnect restrictions. Split-DNS is present on the wire but
  only warned about by upstream (`fortinet.c:344-390`,
  `fortinet.c:427-643`).
- `fortinet_configure` requests `/remote/fortisslvpn_xml?dual_stack=1`, prepares
  the response-less `GET /remote/sslvpn-tunnel` TLS switch, builds the
  length-prefixed `clthello` containing `SVPNCOOKIE`, and initializes Fortinet
  PPP framing (`fortinet.c:645-773`). The source comment says reconfiguration
  can invalidate the cookie and reconnect must only reset PPP
  (`fortinet.c:652-661`), although the current `fortinet_connect` calls
  `fortinet_configure` unconditionally (`fortinet.c:775-780`); M3 resolves that
  contradiction below.
- A successful TLS switch has no HTTP response and begins directly with PPP;
  only failure yields an HTTP response (`fortinet.c:786-819`). The DTLS probe
  accepts an exact length-prefixed `svrhello` with status `ok` and documents
  that an immediately received PPP frame must also count as success if the
  `ok` datagram was lost (`fortinet.c:837-871`).

### F5

- F5 authentication supports a static first-round username/password fallback,
  recoverable POST-only HTML forms, and strict JSON extracted from
  `appLoader.configure(...)` (`/tmp/openconnect/f5.c:45-81`,
  `f5.c:112-248`, `f5.c:251-385`). The first real HTML form must have
  `id="auth_form"`; a later password control may become a token control, while
  the first password remains the stable primary secret (`f5.c:305-360`).
- Authentication is considered successful only when both `MRHSession` and
  `F5_ST` are present because `MRHSession` may be replaced before authentication
  finishes (`f5.c:84-110`). Every response is checked for the pair before its
  body is parsed, and form actions plus HTTP redirects advance the accepted
  authentication origin (`f5.c:264-284`, `f5.c:366-375`).
- Profile/options parsing selects the first VPN favorite, requires `ur_Z`,
  `Session_ID`, and at least one network family, and covers routes, DNS, NBNS,
  search domains, IPv4/IPv6, idle expiry, HDLC framing, and DTLS
  (`f5.c:405-469`, `f5.c:471-640`). An HDLC profile disables DTLS because
  escaping destroys a predictable datagram MTU (`f5.c:598-613`).
- `f5_configure` builds a cookie-free
  `GET /myvpn?sess=...&hdlc_framing=...&ipv4=...&ipv6=...&Z=...&hostname=...`
  request shared by TLS and DTLS and initializes either four-byte F5 or RFC1662
  HDLC PPP framing (`f5.c:670-777`). TLS accepts HTTP 200/201, consumes
  `X-VPN-client-IP[v6]`, and maps HTTP 504 to session rejection
  (`f5.c:642-668`, `f5.c:779-842`). DTLS sends the same request and requires an
  HTTP 200 probe response (`f5.c:871-913`). Logout closes the tunnel and uses a
  fresh authenticated GET to `/vdesk/hangup.php3?hangup_error=1`
  (`f5.c:844-868`).

### Pulse

- Pulse authentication is not a sequence of ordinary HTTPS form posts.
  `pulse_authenticate` sends HTTP Upgrade for IF-T/TLS, then performs nested
  IF-T/TLS, EAP, and EAP-TTLS exchange on that TLS channel
  (`/tmp/openconnect/pulse.c:1375-2067`).
- Its generated forms include realm entry and selection, active-session kill,
  primary and secondary username/password, expired-password change, and GTC
  or token challenges (`pulse.c:778-1328`).
- `pulse_obtain_cookie` is exactly `pulse_authenticate(vpninfo, 0)`
  (`pulse.c:2316-2319`). `pulse_connect` reuses the already-open authenticated
  channel; only if it is absent does it authenticate again with the cookie
  (`pulse.c:2697-2709`).
- Configuration and optional ESP keys are parsed at `pulse.c:2411-2695`.
  The TCP data channel uses 16-byte IF-T/TLS records and the primary loop at
  `pulse.c:2868-3213`; UDP reuses shared ESP.
- If the server requests Host Checker/TNCC, upstream returns an explicit
  unsupported error and suggests NC mode (`pulse.c:1867-1871`).

### Network Connect

- `oncp_obtain_cookie` handles HTML login, realm and role selection, tokens,
  confirmations, hidden-form SAML, and cross-host redirects
  (`/tmp/openconnect/auth-juniper.c:445-623`).
- Successful authentication gathers `DSID` and supporting cookies and updates
  TNCC state (`auth-juniper.c:122-169`, `check_cookie_success`). TNCC preauth
  starts a wrapper protocol and reads its cookie and periodic interval
  (`auth-juniper.c:171-332`, `tncc_preauth`).
- `oncp_connect` POSTs `/dana/js?prot=1&svc=4`, retains the TLS connection
  despite the required `Connection: close` header, receives KMP configuration,
  and exchanges ESP keys (`/tmp/openconnect/oncp.c:466-795`).
- oNCP TLS records, KMP control, and IP packet processing are implemented at
  `oncp.c:837-1076`; outgoing TCP data uses KMP300 at `oncp.c:1241-1261`.
- NC uses protocol-specific ESP activation and probes
  (`oncp.c:1293-1341`), and runs periodic TNCC from `oncp_mainloop`
  (`oncp.c:890-899`).

## Shared wire infrastructure

The following code can be ported once and parameterized by the flavor:

- HTML input parsing retains hidden values, recognizes password, text,
  username, email, submit, checkbox, and select controls, and maps NC realm and
  F5 domain selects to auth groups
  (`/tmp/openconnect/auth-html.c:56-199`, `parse_input_node`,
  `parse_select_node`). Form parsing is POST-only and retains action and form ID
  (`auth-html.c:201-294`, `parse_form_node`).
- Form submission is an ordered walk over option instances, not a map keyed by
  wire name (`/tmp/openconnect/auth-common.c:143-170`, `append_form_opts`).
- Soft-token dispatch supports stoken, TOTP, HOTP, and YubiOATH upstream
  (`auth-common.c:249-302`, `do_gen_tokencode`, `can_gen_tokencode`). This
  project intentionally excludes YubiOATH.
- Shared ESP supports AES-128/256-CBC and truncated HMAC MD5, SHA1, or SHA256
  (`/tmp/openconnect/esp.c:32-76`), performs SPI/sequence/padding/encryption,
  decryption, probes, DPD, and TCP fallback (`esp.c:79-443`), and uses a
  64-packet replay window (`/tmp/openconnect/esp-seqno.c:27-141`).
- Shared UDP connects to the exact negotiated peer address and port and has a
  reconnect loop which treats cookie rejection as terminal
  (`/tmp/openconnect/ssl.c:1153-1318`).
- Shared PPP implements LCP, IPCP, and IP6CP, then applies F5 four-byte or
  Fortinet six-byte outer framing (`/tmp/openconnect/ppp.c:211-294`,
  `ppp.c:1047-1218`, `ppp.c:1459-1649`). It prefers DTLS and falls back to TLS
  when the secondary channel is unavailable (`ppp.c:1517-1649`).
- Common timer processing covers keepalive, DPD, and rekey; compliance-wrapper
  deadlines are part of the same loop (`/tmp/openconnect/mainloop.c:424-507`).

## Public API architecture

### Settled shape inherited from sing-openvpn

**Adopted decision:** keep one flat root package, a `Client` owning a
reconnecting supervisor, a packet read/write surface, snapshots of negotiated
`TunnelConfiguration`, and closed-channel notification for changing state.

Sibling evidence:

- Packet read/write, ready-state, and copied tunnel-configuration snapshots:
  `../sing-openvpn/client.go:169-216`.
- Initial/update/renegotiation tunnel-configuration events:
  `../sing-openvpn/options.go:37-48` and
  `../sing-openvpn/client.go:218-280`.
- The sibling groups caller input in `ClientOptions` and keeps negotiated
  results in `TunnelConfiguration`
  (`../sing-openvpn/options.go:154-168`, `../sing-openvpn/options.go:282-315`).
- Its supervisor classifies terminal versus retryable failures before applying
  reconnect backoff (`../sing-openvpn/client_supervisor.go:27-98`,
  `client_supervisor.go:222-320`).

For this project, all address, route, DNS, MTU, keepalive, rekey, cipher, and
secondary-channel values stay out of caller options because the six protocols
negotiate them in the flavor functions cited above. Caller-provided server,
flavor, credentials, OS/user agent, compliance settings, UDP policy, TLS
material, dialer, and logger remain inputs. `AllowInsecureCrypto` is a pure
caller security decision which gates deprecated TLS/DTLS algorithms, including
3DES; it never supplies or overrides a negotiated cipher.

### Session handoff

**Adopted decision:** define an internal opaque `obtainedSession` owned by the
flavor. It must carry the authentication material, original DNS name, exact
connected IP, port, accepted certificate identity, full connect URL/path, and
any live protocol continuation. It must not be serialized through a public
cookie-only API.

OpenConnect documents that a two-stage connection must retain both DNS name and
the exact authentication backend IP, and that Pulse requires the full URL
including path (`/tmp/openconnect/openconnect.h:494-565`). GP additionally
serializes several login arguments rather than one cookie
(`/tmp/openconnect/auth-globalprotect.c:293-410`), while Pulse may hand the live
IF-T/TLS channel directly from obtain to connect
(`/tmp/openconnect/pulse.c:2697-2709`).

## Asynchronous authentication state machine

### Required ownership model

**Adopted decision:** model authentication as a resumable machine owned by the
client supervisor:

1. A flavor step performs wire I/O until it either obtains a session, fails, or
   returns a pending form plus a continuation.
2. The supervisor publishes a copied, immutable form view and waits for a
   response. No separately spawned protocol goroutine waits on user input.
3. `CompleteAuthForm` validates the form instance ID, removes the pending view,
   and resumes the matching continuation outside the form-state lock.
4. `CancelAuthForm` removes the pending view and produces a terminal
   authentication error immediately.
5. The notification channel is closed and replaced on every state transition,
   matching `../sing-openvpn/challenge.go:52-82` and
   `challenge.go:149-152`.

The sibling's `pendingChallengeState` stores an owner and completion/cancel
callbacks (`../sing-openvpn/challenge.go:39-44`), returns a copy from
`PendingChallenge` (`challenge.go:52-60`), and invokes completion outside the
lock (`challenge.go:68-82`). Its supervisor, rather than a protocol goroutine,
waits for user response (`challenge.go:154-180`). These are concurrency
precedents, not proof that a destroyed OpenConnect wire continuation can be
reused.

### Form representation

**Adopted decision:** `AuthFormField.SubmissionKey` is a unique field-instance
identifier and `Name` remains the wire name. `AuthForm.Fields` preserves server
order, and `CompleteAuthForm` keys its values by `SubmissionKey`, so duplicate
wire names survive the public map. The internal kind set preserves text,
password, select, hidden, token, SSO token, and SSO user, matching
`OC_FORM_OPT_*` (`/tmp/openconnect/openconnect.h:224-230`). The public view hides
automatic hidden/token controls without discarding their internal instances.

Select choices must retain value and label; Cisco choices also carry auth type,
override name/label, and second-auth metadata
(`/tmp/openconnect/openconnect.h:263-283`, `/tmp/openconnect/auth.c:96-183`).
Auth-group reselection is a distinct form result upstream
(`/tmp/openconnect/openconnect.h:232-296`).

### Credential retention

**Adopted decision:** cache only values explicitly classified as stable caller
input: username, primary password, and selected auth group, plus explicit caller
prefills. Never automatically reuse OTPs, server challenges, hidden server
state, session-kill choices, old/new passwords, or a value bound to a server
nonce. Prefill a new form from stable cache only after the flavor matches its
semantic role, not merely its wire name. A gateway rejection clears the stable
credential implicated by that round before republishing input.

## M0 DTLS risk-retirement spike

### AnyConnect DTLS variants verified upstream

OpenConnect supports three materially different AnyConnect DTLS modes:

1. Cisco's legacy nonexistent-session-resume hack. The client supplies a random
   master secret over CSTP, receives a DTLS Session-ID, and resumes without a
   normal handshake. Cisco's version predates RFC 4347 and differs from the
   historical OpenSSL pre-RFC variant (`/tmp/openconnect/dtls.c:35-58`).
2. Cisco DTLS 1.2 cipher offers, which still use the resume-style exchange.
   OpenConnect's table distinguishes DTLS 0.9 ciphers from Cisco DTLS 1.2
   ciphers (`/tmp/openconnect/gnutls-dtls.c:66-103`).
3. ocserv `PSK-NEGOTIATE`. The client advertises the marker; the server replies
   with the same selection. The `X-DTLS-Session-ID`/App-ID is placed in the
   ClientHello session-ID field as an identifier, but the session is not
   actually resumed (`gnutls-dtls.c:180-193`). ocserv defines the marker at
   `/tmp/ocserv/src/vpn.h:52`.

CSTP parses `X-DTLS-Session-ID`, `X-DTLS-App-ID`, selected cipher, UDP port,
keepalive, DPD, and rekey values at `/tmp/openconnect/cstp.c:443-519`.

For modern PSK negotiation, the 32-byte key is exported from the CSTP TLS
channel with label `EXPORTER-openconnect-psk`
(`/tmp/openconnect/openconnect-internal.h:1064-1067`). The GnuTLS path derives
it and sets PSK credentials at `/tmp/openconnect/gnutls-dtls.c:223-264`; the
OpenSSL path uses `SSL_export_keying_material` at
`/tmp/openconnect/openssl-dtls.c:409-424`. ocserv uses the same label and
32-byte material at `/tmp/ocserv/src/worker-vpn.c:267-273`.

### Pion v3.1.5 expressiveness

Verified capabilities:

- `Config` exposes PSK, PSK identity, cipher selection, custom cipher suites,
  and a session store
  (`$GOMODCACHE/github.com/pion/dtls/v3@v3.1.5/config.go:30-43`,
  `config.go:79-82`, `config.go:153-154`).
- A caller-supplied `SessionStore` returns explicit `Session{ID, Secret}`
  (`.../session.go:6-27`).
- The first client flight copies those values into ClientHello session ID and
  connection master secret (`.../flight1handler.go:137-146`) and emits the
  session ID in a DTLS 1.2 ClientHello (`flight1handler.go:164-171`).
- `State` retains master secret, cipher suite, cipher ID, and session ID
  (`.../state.go:19-37`, `state.go:77-93`).

This makes standard DTLS 1.2 resume-style state injection and modern DTLS 1.2
PSK representable. The M0 spike then proved the modern PSK path against a real
ocserv peer; it did not prove the legacy Cisco path or select a production
dependency.

Verified gap:

- Pion v3.1.5's supported-version check accepts only DTLS 1.2
  (`.../pkg/protocol/version.go:27-37`). Its record parser accepts only standard
  DTLS 1.0 and 1.2 record versions
  (`.../pkg/protocol/recordlayer/header.go:53-80`). It has no representation for
  OpenSSL `DTLS1_BAD_VER`/Cisco DTLS 0.9.
- OpenConnect explicitly selects `GNUTLS_DTLS0_9` for the legacy cipher set
  (`/tmp/openconnect/gnutls-dtls.c:66-76`), and the OpenSSL backend defines
  `DTLS1_BAD_VER` as `0x100` (`/tmp/openconnect/openssl-dtls.c:39-40`).

**M0 result at the milestone boundary:** unmodified Pion v3.1.5 was sufficient
for the test-only modern ocserv PSK and DTLS 1.2 path but could not represent
Cisco DTLS 0.9. M1 subsequently selected Pion for the representable DTLS 1.2
paths and implemented the `0x0100` legacy layer in-tree after packet captures
and upstream behavior were reproduced. `NoUDP` remains a caller-controlled
fallback; an unrecognized negotiated mode returns a specific unsupported-mode
error instead of silently disabling UDP.

### M1 Cisco DTLS 0.9 real-peer evidence

The production legacy implementation is an owned record and abbreviated-
handshake layer because Pion cannot represent version `0x0100`. A real ocserv
1.3.0 legacy-resumption exchange established the following second server path,
in addition to the HelloVerify path exercised by OpenConnect's
`tests/bad_dtls_test.c`:

- ocserv passes the initial no-cookie ClientHello to its GnuTLS worker and
  answers directly with ServerHello. The first datagram was record type 22,
  version `0x0100`, epoch 0, record sequence 0; the contained ServerHello used
  handshake sequence 0 and selected `AES128-SHA` (`0x002f`). The captured
  prefix was
  `160100000000000000000000520200004600000000000000460100`.
- The next datagram was exactly
  `14010000000000000000010003010001`: ChangeCipherSpec, version `0x0100`,
  epoch 0, record sequence 1, payload `01 0001`.
- The following encrypted Finished record used version `0x0100`, epoch 1,
  record sequence 0. Successful authenticated decryption and Finished
  verification established handshake sequence 2. The client's matching final
  flight uses epoch-0 sequence 1 with CCS payload `01 0001`, then epoch-1
  sequence 0 with Finished handshake sequence 2.
- In this direct path the Finished transcript is the body of the initial
  no-cookie ClientHello followed by the ServerHello body; the client Finished
  additionally includes the server Finished verify data. ocserv logged
  `DTLS handshake completed`, then accepted encrypted application data and DPD.

The owned implementation retains the separate HelloVerify behavior from
OpenConnect's manual oracle: HelloVerify sequence 0, cookie-bearing ClientHello,
ServerHello sequence 1, CCS payload `01 0002`, and Finished sequence 3. These
are two strict paths selected by the received server flight, not relaxed
sequence acceptance.

That HelloVerify branch now also has an independent real UDP peer rather than
source inspection alone. `test/testdata/dtls09-helloverify/peer.c` is derived
solely from OpenConnect `tests/bad_dtls_test.c` at commit
`2035601b64a5360a46d18e08937e7f654b3230f2`; its `SOURCE` file records the
LGPL-2.1-or-later provenance. The C process links only libcrypto and shares no
record, parser, PRF, MAC, or cipher code with the production Go implementation.
The accompanying TLS/CSTP peer extracts the client's real 48-byte
`X-DTLS-Master-Secret`, supplies its own 32-byte session ID and `AES128-SHA`,
and routes the resulting connected UDP socket through a published Docker port.
The C oracle then requires record-sequence-zero ClientHello with an empty
cookie, returns a fixed 20-byte HelloVerify cookie, and accepts the
record-sequence-one ClientHello only with that exact cookie. It sends
ServerHello, three-byte CCS, and authenticated encrypted Finished; decrypts
and verifies the client's CCS and Finished verify data; and only then exchanges
bidirectional application DATA plus a type-3/type-4 DPD request/response. The
CSTP observer rejects any DATA fallback. The real path records the client
destination, loopback-published UDP endpoint, and container-visible source;
the test passed with `-count=5` and under the Go race detector.

### M0 real-peer evidence

`test/testdata/ocserv/Dockerfile:1-16` pins the Debian base image by digest and
the ocserv package to `1.3.0-2`, and copies committed test certificate material
instead of generating a new identity during the build. The test runs without
`--privileged`, adding `NET_ADMIN` and `/dev/net/tun` and publishing TCP/UDP
only on loopback; it also verifies the installed package version at runtime
(`test/m0_ocserv_interop_test.go:294-339`). The test has a five-minute overall
deadline and shorter deadlines around CSTP, DTLS, Docker log, and cleanup
operations (`m0_ocserv_interop_test.go:80-98`,
`m0_ocserv_interop_test.go:124-128`, `m0_ocserv_interop_test.go:168-180`,
`m0_ocserv_interop_test.go:206-215`, `m0_ocserv_interop_test.go:250-260`,
`m0_ocserv_interop_test.go:315-327`).

`TestM0OcservCSTPAndModernPSKDTLSInterop` is gated by `OPENCONNECT_IT`
(`test/m0_ocserv_interop_test.go:80-89`) and passed with:

```shell
cd test
OPENCONNECT_IT=1 go test -run '^TestM0OcservCSTPAndModernPSKDTLSInterop$' -count=1 -v ./...
OPENCONNECT_IT=1 go test -run '^TestM0OcservCSTPAndModernPSKDTLSInterop$' -count=3 -v ./...
```

The single run passed. The latest `-count=3` run also passed all three
iterations in 9.88s, 11.82s, and 5.79s. The exercised behavior is:

- initial XML auth form followed by the second password round and `webvpn`
  cookie acquisition (`test/m0_ocserv_interop_test.go:381-434`);
- CSTP CONNECT, DPD request/response, and a raw IPv4 ICMP echo request/reply
  through the tunnel (`m0_ocserv_interop_test.go:89-146`,
  `m0_ocserv_interop_test.go:459-514`);
- negotiation of `PSK-NEGOTIATE`, decoding the 32-byte `X-DTLS-App-ID`, and
  deriving the 32-byte PSK with TLS exporter label
  `EXPORTER-openconnect-psk` (`m0_ocserv_interop_test.go:148-166`);
- a Pion DTLS 1.2 PSK connection whose ClientHello SessionID is set to the
  negotiated App-ID (`m0_ocserv_interop_test.go:168-204`);
- DTLS DPD traffic and a raw IPv4 ICMP echo request/reply, with UDP packet
  counters checked before and after both exchanges so a passing result requires
  post-handshake UDP datagrams (`m0_ocserv_interop_test.go:58-78`,
  `m0_ocserv_interop_test.go:206-292`).

This is exactly the PROMPT M0 exit scope: survey dependency expressiveness and
prove a minimal CSTP plus DTLS channel carrying real data. UDP-unavailable
fallback, reconnect with cookie reuse, and rekey are M1 work, together with the
full AnyConnect supervisor and transport lifecycle.

The upstream executable precedent starts ocserv, obtains a cookie, connects
with `--dtls-ciphers=PSK-NEGOTIATE`, waits for the tunnel, and sends IPv4/IPv6
traffic (`/tmp/openconnect/tests/dtls-psk:71-145`).

## Compliance probes

- CSD's reference script fetches server token/data endpoints and POSTs generated
  scan XML; it is not a constant local report
  (`/tmp/openconnect/trojans/csd-post.sh:88-165`).
- The two CSD tokens have distinct wire roles. `csd-post.sh` fetches a fresh
  token from `+CSCOE+/sdesktop/token.xml` and sends that token as the
  `sdesktop` cookie on `scan.xml` (`csd-post.sh:88-93`, `csd-post.sh:162-165`).
  After the wrapper returns, OpenConnect instead installs the original
  `host-scan-token` as the `sdesktop` cookie used by the wait request and the
  resumed authentication exchange (`/tmp/openconnect/auth.c:1271-1275`). The
  implementation and independent HTTPS peer test deliberately use different
  values for these tokens.
- The built-in CSD endpoints follow the reference wrapper rather than treating
  `host-scan-base-uri` as an endpoint root: token, optional data, and scan use
  the authenticated gateway origin and fixed paths
  (`csd-post.sh:88-98`, `csd-post.sh:164-165`). The base/start URI is passed to
  an external wrapper as `-url` (`/tmp/openconnect/auth.c:1334-1340`). All CSD
  requests and redirects retain normal TLS verification and reject non-HTTPS
  URLs. The built-in implementation never downloads or executes the
  server-provided stub.
- `data.xml` requests File and Process facts. The reference script reports
  file existence, modification time, timestamp, and CRC32, and process
  existence (`csd-post.sh:95-159`). The built-in report keeps those facts,
  derives OS identity from `uname`, reads hostname and MAC addresses from the
  local system, and reports only actually observed listening TCP ports. It
  intentionally omits the reference script's placeholder MAC, fixed open-port
  list, and fabricated protection/firewall version strings.
- CSD wait pages are polled by body type: HTML refresh pages sleep for one
  second, XML completes the wait, and authentication then refreshes the saved
  pre-CSD URL (`/tmp/openconnect/auth.c:1363-1379`,
  `/tmp/openconnect/auth.c:1599-1629`). Completed state suppresses repeated
  host-scan nodes like upstream's `csd_scriptname` gate
  (`auth.c:504-505`, `auth.c:1271-1275`).
- `test/m1_anyconnect_csd_interop_test.go` is an independent HTTPS consumer of
  the complete exchange. It verifies token/data/scan requests, different scan
  and wait/auth cookies, truthful uname/hostname/MAC/listening-port/File/CRC32/
  Process values, a real one-second HTML refresh, bodyless GET requests, the
  final authentication refresh, and suppression of a repeated host-scan node.
- A second consumer redirects authentication to a distinct HTTPS action origin
  before requesting CSD. Token/data/scan/wait and the final authentication
  refresh remain pinned to the backend accepted for that action instead of
  drifting back to the original backend, matching the form-action redirect
  performed by `cstp_obtain_cookie`
  (`/tmp/openconnect/auth.c:1549-1555`, `/tmp/openconnect/auth.c:1655-1661`).
- The external-wrapper peer verifies the exact upstream argument contract
  (`-ticket`, `-stub`, `-group`, combined server/client MD5 `-certhash`, `-url`,
  `-langselen`) and `CSD_SHA256`, `CSD_TOKEN`, and `CSD_HOSTNAME` environment.
  Certificate hashes come from the TLS peer and client identity actually used
  on the accepted authentication origin. A normal nonzero wrapper exit logs a
  warning and continues through wait/auth, while signal termination is a
  terminal error and is never retried. These exit semantics and inputs follow
  `run_csd_script` (`/tmp/openconnect/auth.c:1168-1360`).
- TNCC emulation is an active command protocol with HTTPS requests, device and
  policy data, certificate/MAC inputs, a cookie, and periodic scheduling
  (`/tmp/openconnect/trojans/tncc-emulate.py:450-727`).
- HIP is a large generated report dependent on cookie, address, operating
  system, and local data (`/tmp/openconnect/trojans/hipreport.sh:1-444`), and GP
  schedules it periodically (`/tmp/openconnect/gpst.c:803-1109`).

**Adopted decision:** retain a protocol-neutral compliance lifecycle hook but
separate CSD, TNCC, and HIP caller inputs and protocol state by flavor. A
built-in Go implementation is the default only for facts it can observe and
server exchanges it can represent. Keep an external wrapper escape hatch for
deployment-specific checks. Pulse Host Checker is explicitly unsupported and
must fail with a specific error directing users to NC mode; an empty mission
table cell does not mean that gateways cannot request it.

## Real test assets and their limits

The OpenConnect test manifest enables full netns tests only when their runtime
dependencies exist; auth fake tests are enabled under cwrap/Python conditions
(`/tmp/openconnect/tests/Makefile.am:78-116`). The fake servers do not all
implement a data tunnel.

| Peer | Verified usable coverage | Verified tunnel limit |
| --- | --- | --- |
| ocserv | AnyConnect auth, CSTP, DTLS, traffic | Reference AnyConnect peer |
| fake Cisco | MCA/certificate authentication | No CSTP or DTLS |
| fake GP | portal/gateway prelogin, forms, challenges, login, config | Tunnel always HTTP 502; no GPST/ESP data |
| fake Fortinet | realm, password, push/HTML/tokeninfo 2FA, config | Tunnel always HTTP 403; no PPP/DTLS data |
| fake F5 | fallback/HTML forms, domains, hidden override, 2FA, config | Tunnel always HTTP 504; no PPP/DTLS data |
| fake Juniper | forms, realms, roles, token, confirmation, cookie | Tunnel always HTTP 401; no oNCP/ESP data |
| fake Juniper SSO/TNCC | multi-host SAML form path and wrapper exchange | No oNCP/ESP data |
| fake Pulse | IF-T/TLS auth/config, TCP data, ESP crypto/data | Full existing Pulse peer |

Evidence:

- The Cisco stub rejects every mode except MCA
  (`/tmp/openconnect/tests/fake-cisco-server.py:257-270`); its test only invokes
  `--authenticate` with client and MCA certificates
  (`tests/auth-multicert:35-47`).
- GP's tunnel route asserts user/cookie parameters and aborts with 502
  (`tests/fake-gp-server.py:374-383`); its test treats client exit 2 as expected
  rejection (`tests/gp-auth-and-config:115-125`).
- The Fortinet fake describes itself as authentication-phase emulation
  (`tests/fake-fortinet-server.py:20-35`) and aborts the tunnel with 403
  (`fake-fortinet-server.py:278-284`); the test expects that failure
  (`tests/fortinet-auth-and-config:99-102`).
- The F5 fake describes itself as authentication-phase emulation
  (`tests/fake-f5-server.py:20-32`) and returns 504 from `/myvpn`
  (`fake-f5-server.py:296-307`); the test expects that failure
  (`tests/f5-auth-and-config:90-93`).
- The Juniper fake describes itself as authentication-phase emulation
  (`tests/fake-juniper-server.py:20-23`) and aborts `/dana/js` with 401
  (`fake-juniper-server.py:253-260`); the test expects that failure
  (`tests/juniper-auth:107-110`).
- The Pulse fake answers IF-T/TLS IP packets (`tests/fake-pulse-server.py:385-414`),
  validates/decrypts ESP and answers IP packets (`fake-pulse-server.py:435-479`),
  and runs the complete auth/config/tunnel state machine
  (`fake-pulse-server.py:495-543`). `tests/pulse-ping:73-119` performs real
  namespace pings over both TLS and UDP.
- Full AnyConnect DTLS traffic exists against ocserv in
  `tests/dtls-psk:77-145`. Username/password and certificate auth entry points
  are `tests/auth-username-pass:22-58` and `tests/auth-certificate:22-45`.
- `nullppp` tests prove generic PPP negotiation and synchronous/HDLC framing,
  not F5 or Fortinet outer protocol interop
  (`tests/ppp-over-tls:48-136`, `tests/ppp-over-tls-sync:48-69`).

**Testing direction:** reuse existing fakes for auth/config regression and Pulse
data interop. Build or extend real wire peers for GPST/ESP, F5 PPP/DTLS,
Fortinet PPP/DTLS, and oNCP/ESP before claiming those milestones complete.
Expected HTTP rejection is not tunnel interop.

The local M0 ocserv spike remains a real AnyConnect test asset. M1 promotes the
same Pion version to the root module for modern PSK and Cisco DTLS 1.2 while
retaining the separate test-module pin for independent peers.

### M1 client lifecycle and authentication evidence

The public `Client` API is exercised against the pinned ocserv 1.3.0-2 image,
not only through the lower-level M0 exchange:

- With no prefills, ocserv presents authgroup selection, username, and password
  as separate asynchronous rounds. The test completes each published form and
  uses occtl's detailed user view to confirm that the real server applied the
  selected group. Interactive and prefilled clients use distinct usernames,
  and the first server session is required to disappear before the second
  starts, so each occtl result is uniquely attributable rather than an
  aggregate match. The second client proves that username, password, and
  authgroup prefills complete without a visible form and selects a different
  group.
- An independent TLS/HTTP consumer exercises both XMLPOST fallback triggers
  used by `cstp_obtain_cookie`: HTTP rejection and a same-host redirect
  (`/tmp/openconnect/auth.c:1405-1490`). It then requires the legacy GET,
  resolves a relative form action, and accepts only the exact URL-encoded POST
  containing the hidden value and two ordered instances of the same wire name.
  A form carrying `<authentication-complete/>` plus visible fields is published
  and answered before the consumer accepts CSTP CONNECT; completion is not
  inferred from the marker while fields remain. OpenConnect also jumps directly
  to POST only when that marker has no option instances
  (`/tmp/openconnect/auth.c:477-482`, `/tmp/openconnect/auth.c:708-777`).
- A separate cross-host redirect consumer requires the XMLPOST body to survive
  unchanged while the origin cookie is discarded, the destination cookie is
  retained, stable username/password values are reused on the next round, and
  the one-shot answer is blank. OpenConnect likewise clears cookies when
  `handle_redirect` changes hosts (`/tmp/openconnect/http.c:646-680`).
- The cross-endpoint CSD action consumer also includes inputs with a missing
  type, a missing name, and an unknown vendor type before its real password
  field. They are ignored without discarding the valid field, matching
  `parse_form` (`/tmp/openconnect/auth.c:185-275`).
- Certificate-only authentication uses a test-owned CA and client certificate;
  ocserv requires that CA, extracts the certificate common name, and reports
  the resulting user on the established CSTP session.
- CERT1 consumers reproduce an ASA which omits its TLS CertificateRequest on
  the first connection. The client closes that connection, retries on a fresh
  TLS connection with either configured certificate material or
  `GetClientCertificate`, and proceeds only after the peer observes the machine
  certificate. Missing and configured-but-unaccepted identities each send
  exactly one `<client-cert-fail/>` before legacy fallback, matching
  `cstp_obtain_cookie` (`/tmp/openconnect/auth.c:1470-1521`), and each scenario
  must subsequently establish and explicitly close CSTP.
- A combined real chain proves authentication-stage ordering rather than four
  isolated features: one CERT1 origin request redirects on a fresh TLS
  connection to the fake Cisco peer; that peer validates exactly one CERT2/MCA
  SHA-512 signature and returns one absolute action URL; the action is applied
  exactly once before token, data, scan, and wait CSD phases; and only the
  post-CSD session cookie reaches an active CSTP tunnel which is explicitly
  closed. The dialer also verifies the fresh CERT/MCA TLS connection and the
  CSD counters reject a repeated action.
- Independent TLS material coverage uses a DNS-only server certificate and a
  real CA, observes the exact SNI on both authentication and CSTP handshakes,
  and requires a verified client certificate whose PKCS#8 key is decrypted by
  `KeyPassword`. The same successful flow decrypts a distinct MCA PKCS#8 key
  with `MCAKeyPassword`, verifies its PKCS#7 certificate and exact SHA-512
  challenge signature, then exchanges CSTP DATA in both directions. Separate
  peers prove that the wrong CA and wrong hostname terminate with stable
  `x509.UnknownAuthorityError` and `x509.HostnameError` before any HTTP handler
  request.
- ocserv's plain backend delegates the second authentication factor to its
  linked liboath. Independent TOTP and HOTP runs accept the generated wire
  values, update the liboath users file, and never expose the automatic token
  field. HOTP also proves that the caller counter callback advances to one.
- `NoUDP` makes no UDP dial and exchanges a real ICMP echo over CSTP after
  several negotiated keepalive/DPD intervals. A deliberate UDP dial failure
  emits the fallback warning and exchanges the same real traffic over CSTP.
- ocserv configurations with `new-tunnel` and `ssl` rekey both produce a
  `rekey` configuration event. Replacing the password file before each event
  proves that the new CSTP tunnel reused the accepted cookie. Closing the live
  CSTP socket without a protocol DISCONNECT produces a `reestablishment`
  event; the primary ocserv backend accepts the old cookie and answers another
  ICMP echo even after its password backend is replaced with a rejecting one.
  The dialer then switches to a second ocserv backend and drops the connection:
  that backend returns 401 for the foreign cookie, rejects one cached password,
  and publishes a fresh password form whose value is empty. Exact per-backend
  CONNECT/authentication/log counts prove both cookie rejection and password
  clear-cache behavior through wire-visible backend attribution.
- The independent AnyConnect SSO HTTPS consumer requires a visible companion
  username, hidden server state, an automatic HOTP field, and a browser adapter
  result containing the requested final URL and token cookie. It proves the
  HOTP counter stays unchanged while the browser is blocked, then validates the
  RFC 4226 counter-zero value and all companion fields on the wire. This
  exercises the same final-URI/cookie completion inputs consumed by
  `cstp_sso_detect_done` (`/tmp/openconnect/cstp.c:1310-1335`). Success is
  recorded only after the consumer receives `CONNECT /CSCOSSLC/tunnel` with
  the exact `webvpn` SSO session cookie, exchanges CSTP DATA in both directions,
  and validates the client's disconnect frame.
- The stoken HTTPS consumer validates CTF v2, password/device-locked CTF v3,
  and device-locked CTF v4 wire values with the C CLI built from stoken commit
  `837e843e8850d14a5d49d799b066d61d04fd649a`. The CTF inputs come from that
  commit's `tests/tokencode-v2.pipe`, `tokencode-v3.pipe`, and
  `tokencode-v4.pipe`; `test/testdata/stoken/SOURCE` records their LGPL-2.1-or-
  later provenance. Each fixture then receives a real “next tokencode” second
  challenge. The independent CLI reports the token period and computes both
  the initial code at a bounded candidate time and the code at exactly one
  period later; only that current/next pair is accepted, and neither round may
  publish a user form.
- A TLS consumer which rejects every CSTP cookie records one-, then two-second
  reconnect spacing and proves sixteen concurrent `Client.Close` calls cancel
  backoff promptly. This is real-peer coverage for HTTP 401 session rejection;
  the broader policy is source-backed: 401/403 are session rejection,
  408/425/429 and 5xx are transient, and other non-200 CSTP statuses are
  terminal (`cstp_client.go`, `anyconnect_auth.go:1068-1074`). No independent
  peer claim is made for every status in that policy. Another consumer
  publishes SSO to an adapter which ignores context cancellation;
  `CancelAuthForm` removes the form and makes `ReadDataPacket` return terminal
  `ErrAuthFormCanceled` before `Client.Close`, while the adapter is still
  blocked. Close also completes without waiting for that goroutine. These are
  real wire and lifecycle effects rather than lock-shape assertions.

### M1 CSTP and DTLS evidence

- The CSTP wire peer requires `CONNECT /CSCOSSLC/tunnel`, parses the accepted
  cookie, negotiates MTU/address/banner/tunnel-all-DNS/client-bypass state,
  sends a DPD request with a payload, and accepts only the empty DPD response
  used by OpenConnect's static `dpd_resp_pkt`
  (`/tmp/openconnect/cstp.c:65-78`, `/tmp/openconnect/cstp.c:996-1016`). It then
  delivers a 1000-byte data packet despite a 600-byte negotiated MTU and sends
  a server DISCONNECT record whose reason is returned by `ReadDataPacket` as a
  stable terminal error. Authentication and CONNECT counts remain one after a
  reconnect window, proving that protocol DISCONNECT is not ordinary EOF and
  never triggers reauthentication. Upstream similarly reserves extra receive
  space for packets larger than negotiated MTU and returns a broken-channel
  result with `quit_reason` set for server disconnect; the supervisor supplies
  the terminal classification
  (`/tmp/openconnect/cstp.c:962-1051`).
- The configuration snapshot additionally carries routes, excluded routes,
  IPv4/IPv6 DNS, NBNS, search/split domains, PAC URL, idle timeout, and the
  earliest nonzero lease/session expiration parsed by `start_cstp_connection`
  (`/tmp/openconnect/cstp.c:535-650`). Idle/expiration values are exposed like
  OpenConnect's getters rather than enforced by an invented client timer
  (`/tmp/openconnect/library.c:1140-1148`).
- `X-CSTP-DynDNS: true` is retained in the obtained session so reconnect first
  resolves the gateway name and can fall back to the accepted cached address,
  matching `/tmp/openconnect/cstp.c:580-584` and
  `/tmp/openconnect/ssl.c:335-505`. A real IPv4/IPv6 loopback peer authenticates
  on the original domain target, switches resolution to a replacement address,
  then makes the domain unavailable so the accepted cached address is used.
  Exact authentication/CONNECT counts, distinct cookies and configurations,
  and DATA from each live CSTP endpoint make the three stages uniquely
  attributable. The test skips only when IPv6 loopback is unavailable.
- Real ocserv traffic has passed through all three production DTLS mechanisms:
  standards-compliant `PSK-NEGOTIATE`; Cisco DTLS 1.2 injected abbreviated
  resumption with static-RSA `AES128-GCM-SHA256` and
  `AES256-GCM-SHA384` plus ECDHE-RSA `AES128-GCM-SHA256` and
  `AES256-GCM-SHA384`; and the owned Cisco DTLS 0.9 abbreviated-resumption path
  with `AES128-SHA`, `AES256-SHA`, and opt-in `DES-CBC3-SHA`. Each path carries
  ICMP data; owned AES-CBC and 3DES paths additionally observe post-handshake
  DPD. The cipher names and version split follow OpenConnect's table
  (`/tmp/openconnect/gnutls-dtls.c:66-103`).
- The modern PSK test retries after two injected UDP dial failures while CSTP
  remains ready, then proves subsequent ICMP request and reply counters move on
  UDP rather than CSTP. Recorded dial timestamps require the negotiated retry
  series to follow one- then two-second exponential delays, with explicit
  scheduler-tolerance bounds of 0.8–2.5 times each target. This matches
  OpenConnect's sleeping/retry lifecycle, where a failed DTLS handshake does
  not tear down the primary tunnel
  (`/tmp/openconnect/dtls.c:235-271`,
  `/tmp/openconnect/gnutls-dtls.c:568-583`).
- One path-MTU test imposes a real 1100-byte UDP datagram ceiling. Padded DPD
  probes cross and are dropped by that ceiling, binary search converges near
  the largest accepted datagram instead of collapsing to a fixed value, the
  client publishes a `path-mtu` event, and ICMP succeeds on DTLS. A second peer
  caps IPv4 datagrams at 605 bytes and proves both the event and final tunnel
  MTU stop at the exact IPv4 minimum of 576. The algorithm follows OpenConnect's
  576/1280 minimum, 50 ms padded DPD probes, six retries, exact echoed length,
  and ten-second bound (`/tmp/openconnect/dtls.c:470-659`).
- An independent DTLS-PSK peer omits `X-DTLS-App-ID` while still supplying the
  exporter-backed PSK negotiation and `X-DTLS-Session-ID`. It accepts the real
  handshake and echoes application data only when ClientHello SessionID is
  empty. OpenConnect also installs the application ID only when its length is
  nonzero (`/tmp/openconnect/gnutls-dtls.c:180-250`).
- A TLS header proxy preserves the response's raw `X-DTLS-*`/
  `X-DTLS12-*` order. Real ocserv connections prove the last selected
  `CipherSuite` header wins in both directions: a final DTLS 1.2 GCM selection
  overrides an earlier recognized DTLS 0.9 `AES128-SHA` value, and a final DTLS
  0.9 `AES128-SHA` selection overrides an earlier recognized DTLS 1.2
  `AES128-GCM-SHA256` value. This matches OpenConnect's
  sequential response loop, which overwrites `dtls12` and `dtls_cipher` for
  every selected header (`/tmp/openconnect/cstp.c:419-534`).
- The ECDHE-RSA run rewrites every selected companion header—not only
  `CipherSuite`, but Session-ID, port, MTU, DPD, keepalive, and rekey state—to
  the `X-DTLS12-*` prefix. The real handshake and ICMP exchange prove those
  companion fields remain associated with the selected DTLS 1.2 mode, as in
  OpenConnect's single sequential DTLS-option list
  (`/tmp/openconnect/cstp.c:419-534`).
- The production offer/decoder represents the upstream AES-128/256 CBC,
  AES-128/256 GCM, ECDHE-RSA GCM, DHE-RSA CBC, and modern PSK families from the
  same cipher table. `DES-CBC3-SHA` is advertised and accepted only with the
  explicit `AllowInsecureCrypto` opt-in; its real ocserv run proves application
  data and DPD on version `0x0100`. An independent C/OpenSSL DTLS 1.2 server
  injects the negotiated 32-byte session ID and 48-byte master secret into a
  server-side `SSL_SESSION`, resumes it through OpenSSL's session callback, and
  proves `SSL_session_reused()` for `AES128-SHA`, `AES256-SHA`,
  `DHE-RSA-AES128-SHA`, and `DHE-RSA-AES256-SHA`. All four carry bidirectional
  1000-byte application datagrams and authenticated close-notify. The DHE-RSA
  names are the real resumed-session cipher IDs; an abbreviated resumed
  handshake does not and is not claimed to perform a fresh DHE exchange. This
  closes the former AES-CBC/DHE-RSA-CBC real-peer residual without weakening
  the distinct GCM, modern PSK, or owned DTLS 0.9 evidence above.
- Both negotiated CSTP rekey methods, `new-tunnel` and `ssl`, pass against
  ocserv and publish a `rekey` event. Go cannot initiate Cisco's proprietary
  TLS rehandshake, so `ssl` deliberately establishes a new CSTP tunnel, the
  same fallback OpenConnect takes after rehandshake failure
  (`/tmp/openconnect/cstp.c:1125-1145`). Replacing the password backend before
  each event proves the accepted cookie, rather than cached credentials, is
  reused.
- A separate real ocserv run removes CSTP rekey headers and negotiates only
  `X-DTLS-Rekey-Time: 5` with method `ssl`. It observes a new UDP handshake,
  keeps the CSTP CONNECT count at one, emits no CSTP configuration-rekey event,
  and carries subsequent ICMP on the replacement DTLS channel. UDP timestamps
  reject a replacement opened before the negotiated five-second window, while
  an eight-second observation floor distinguishes the rekey from initial
  handshake activity. OpenConnect's DTLS loop likewise handles SSL rekey inside
  the secondary channel and falls back to reconnect when rehandshake fails
  (`/tmp/openconnect/dtls.c:350-380`).

## M2 GlobalProtect implementation and evidence

### Authentication and accepted endpoint identity

- The `gp` frontend implements the upstream portal/gateway decomposition rather
  than treating GlobalProtect as a single cookie login. Server targets select
  automatic portal discovery, explicit `portal`/`global-protect`, or explicit
  `gateway`/`ssl-vpn`; a final `:field-name` selects the deployment-specific
  alternate secret used by SAML gateways. Prelogin, portal configuration,
  portal-to-gateway blind continuation, gateway prelogin, and repeated login
  forms follow `gpst_obtain_cookie` and `gpst_login`
  (`/tmp/openconnect/auth-globalprotect.c:674-845`).
- Username/password/token controls, XML errors, and the XML, JavaScript, and
  HTML challenge formats are normalized into the asynchronous form model.
  Every challenge is one-shot: it clears the prior password, hides the
  username, and returns the exact new `inputStr`, matching `challenge_cb` and
  `gpst_xml_or_error` (`auth-globalprotect.c:232-274`,
  `/tmp/openconnect/gpst.c:113-357`). Stable username, password, and auth group
  remain supervisor credentials; nonce-bound challenge answers do not become
  reconnect credentials.
- Portal gateway entries retain their wire endpoint and use the lowest numeric
  priority among current-region and `Any` matches, with stable source order for
  ties and unprioritized entries. An explicit `AuthGroup` matches the wire name
  or description; otherwise the client publishes a select field whose values
  remain unique even when a portal
  repeats a label. This is the portal selection performed by
  `parse_portal_xml` (`auth-globalprotect.c:418-672`).
- SAML `REDIRECT` opens the decoded URL and `POST` opens the decoded document as
  a data URL. The `BrowserRequest` names all three completion headers, and the
  result consumes `saml-username`, `prelogin-cookie`, or
  `portal-userauthcookie` case-insensitively, as required by
  `gpst_sso_detect_done` (`/tmp/openconnect/gpst.c:1380-1406`). Browser-returned
  credentials are kept inside the live authentication continuation rather than
  promoted to stable password state.
- GlobalProtect `ReportedOS` defaults from the actual Go runtime, is restricted
  to the protocol's supported names, and is mapped consistently into prelogin,
  login, configuration, HIP, and wrapper fields. The local hostname is required
  once and reused as `computer`; the default `PAN GlobalProtect` user agent can
  be replaced by the caller's explicit `UserAgent`. The independent peers
  validate those identities on the wire.
- A successful gateway JNLP response is parsed by the source-defined required
  argument positions while accepting trailing future arguments. Percent
  decoding preserves malformed `%` bytes seen in deployed opaque cookies, and
  subsequent configuration, HIP, GPST, and logout bodies retain the original
  argument order and lowercase escaping instead of round-tripping through
  `url.Values`. The resulting `gpSessionState` owns the selected URL, accepted
  TCP address, opaque query, client version, HIP interval, and preferred
  addresses (`auth-globalprotect.c:293-410`).
- Authentication cookie jars are shared within one accepted gateway so config,
  HIP, tunnel setup, and logout see gateway cookies, but are replaced whenever
  the portal/gateway endpoint changes so a host or port transition cannot leak
  the prior origin's cookies. After gateway authentication, config, HIP, raw
  GPST, and logout dial the accepted IP. HTTPS config, HIP, and logout retain
  the original URL host for Host and SNI; raw GPST retains it for SNI but its
  headerless request intentionally has no Host header. Logout gets an
  independent five-second context and sends the complete opaque query required
  by `gpst_bye`
  (`auth-globalprotect.c:847-883`). A rejected session clears the cookie before
  state close, so it reauthenticates without logging out an already rejected
  identity.
- `test/m2_gp_auth_peer_interop_test.go` is an independent multi-certificate,
  multi-host and multi-port TLS peer. It proves region ordering plus explicit
  selection, `AuthGroup` selection across ports, portal/gateway jar isolation,
  gateway cookie reuse, REDIRECT and POST SAML with mixed-case response
  headers, future JNLP arguments and malformed percent bytes, raw headerless
  GPST, exact opaque config/HIP/logout fields, selected-host SNI, and accepted-
  address pinning after DNS is poisoned. Its 502 recovery case proves the first
  portal and gateway logins omit preferred addresses, the second pair carry
  both previously assigned addresses, the rejected state is not logged out,
  and only the final valid state performs pinned logout.
- The upstream fake is copied verbatim from
  `/tmp/openconnect/tests/fake-gp-server.py` with provenance in
  `test/testdata/fake-gp/SOURCE`. Its Docker matrix has ten cases: portal and
  gateway password, portal auth group, portal random challenge plus cookie
  continuation, portal and gateway alternate-secret SAML, portal password plus
  gateway challenge, and gateway XML/JavaScript/HTML challenges. Every case
  reaches the fake's real `/ssl-tunnel-connect.sslvpn` handler and observes its
  expected HTTP 502, so an authentication-only partial exchange cannot pass.

### Configuration, GPST, recovery, and rekey

- Gateway configuration is requested with the authenticated opaque query and
  source-compatible ordered options. The parser installs IPv4/IPv6 addresses,
  included and excluded routes, IPv4/IPv6 DNS, NBNS, search domains, MTU, idle
  timeout, authentication expiration, the negotiated tunnel path, rekey time,
  and ESP material. Unknown informational fields are diagnosed; malformed
  negotiated data is a specific terminal error. Missing or unusable ESP
  material falls back to GPST, and a missing `ipsec-mode` remains compatible;
  only an explicitly unsupported mode disables ESP. These fields originate in
  `gpst_parse_config_xml` (`/tmp/openconnect/gpst.c:406-640`).
- A rekey uses the same accepted opaque session and repeats configuration
  without logging in again. Current assigned IPv4/IPv6 values are emitted once
  as `preferred-ip`/`preferred-ipv6`, replacing stale copies in the opaque
  query. The timeout adjustment is `seconds-60` above one minute and the
  bounded short-interval contract below it; the 61-second peer therefore
  produces a one-second real rekey and a `TunnelConfigurationEventRekey`.
- GPST opens a new TLS connection to the accepted address with gateway SNI,
  sends the upstream headerless `GET path?user&authcookie HTTP/1.1`, and
  requires the exact twelve-byte `START_TUNNEL` marker
  (`/tmp/openconnect/gpst.c:719-801`). Frames carry magic `0x1a2b3c4d`, a
  big-endian EtherType and payload length, and the source-compatible
  little-endian data trailer; the magic-only frame is DPD/keepalive. IPv4 and
  IPv6 packets and oversized-but-bounded receive frames are accepted as in
  `gpst_mainloop` (`gpst.c:1111-1377`).
- HTTP 502 from the raw tunnel is a rejected authentication cookie and forces
  a fresh portal/gateway login. HTTP 405 is a specific terminal unsupported-
  GPST error used by the auth peer. Configuration/GPST 401, 403, and 512 reject
  the session; authentication 401/403 reject authentication and 512 clears the
  rejected stable password before retry. HTTP 513 at gateway login or tunnel
  configuration is a terminal authentication failure; two raw TLS peer cases
  prove that each path stops after one wire request. Transient HTTP and network
  failures retain supervisor backoff. An ordinary GPST EOF reuses the obtained
  session for configuration and tunnel reestablishment without a new login,
  while incompatible successful responses are terminal rather than silently
  retried.
- `gpSession` assigns every ESP/GPST ownership transition a generation and
  clears `Ready` before closing or replacing a transport. A late completion
  can publish only when its phase, channel, and generation still match. GPST is
  closed before a periodic HIP check and reopened afterward; ESP remains live
  because that check does not invalidate its keys. Rekey terminates the current
  transport with an internal new-tunnel event while retaining the obtained
  session.
- The independent raw TLS peer in
  `test/m2_gp_transport_interop_test.go` requires the headerless GET, exact
  query, marker and frame layout, echoes real IPv4/IPv6 packets, answers DPD,
  and verifies the full configuration snapshot. A second IP-addressed run with
  explicit TLS `ServerName` proves verification still uses the configured name
  while the data connection uses the accepted address. Recovery peers prove a
  502 performs exactly two logins/configurations/tunnels with the second
  cookie; a peer EOF repeats config, HIP, and GPST with one login and publishes
  a reestablishment event; and a 61-second timeout repeats config and tunnel
  with one login, no logout, replaced preferred addresses, and a rekey event.

### ESP-in-UDP and transport fallback

- The shared userspace ESP layer implements AES-128-CBC and AES-256-CBC with
  truncated HMAC-MD5-96, HMAC-SHA1-96, or HMAC-SHA256-128, separate inbound
  and outbound SPIs, explicit IVs, source-compatible outbound IV chaining,
  padding/next-header validation, sequence exhaustion, and a bounded 64-bit
  replay window. Parsed raw key bytes and owned security associations are
  cleared on parse failure, fallback, replacement, and close. The contracts
  come from `/tmp/openconnect/esp.c:79-290`,
  `/tmp/openconnect/esp-seqno.c:32-96`, and
  `/tmp/openconnect/openssl-esp.c:48-236`.
- GlobalProtect establishes ESP only after an encrypted source-compatible ICMP
  probe to the negotiated magic IPv4 or IPv6 address receives the matching
  echo response. The probe payload, IPv4/IPv6 headers and checksums follow
  `gpst_esp_send_probes`/`gpst_esp_catch_probe`
  (`/tmp/openconnect/gpst.c:1433-1602`). Initial probes use absolute one-second
  deadlines for five seconds; a transient UDP setup/write failure may retry
  inside that window without discarding the negotiated keys.
- `test/testdata/gp-esp-peer/esp_peer.c` is an independent C/OpenSSL UDP test
  implementation derived from the cited OpenConnect source files under
  LGPL-2.1-or-later, with no code shared with the production Go implementation.
  Its six-suite matrix is the Cartesian product of two AES-CBC sizes and three
  HMACs. The oracle requires the first client sequence to be zero, verifies the
  OpenConnect next-IV chain on later datagrams, begins its independent server
  sequence at zero with fresh random explicit IVs, and sends every response
  twice. Each suite carries real IPv4 and IPv6 ICMP echo; delivery of one copy
  proves replay suppression. The AES-128/MD5 case also omits `ipsec-mode` and
  injects one UDP dial failure, proving compatible config parsing and retry at
  the next absolute probe deadline without GPST use. The AES-256/SHA-256 case
  injects a real UDP close error and requires it to propagate through
  `Client.Close` after key and socket cleanup.
- With no ESP keys the client starts GPST immediately. With valid keys but a
  silent UDP path it sends probes for the full five-second window, closes UDP
  before opening GPST, and a deliberately released late ESP reply cannot
  reclaim the active transport. A transparent relay proves periodic encrypted
  DPD keeps ESP ready; forced closure of the live UDP socket then falls back to
  GPST using the same login, configuration, and opaque session. These are real
  socket and packet effects, not phase-only unit tests.
- ESP next-header `0x05` is Juniper LZO-compressed IPv4 as documented by
  `/tmp/openconnect/esp.c:212-280`. M4 completed the bounded shared LZO1X
  decoder and independent liblzo2 oracle used by Pulse and NC. GlobalProtect
  still rejects next-header `0x05` with the same specific terminal
  `ErrProtocolNotSupported`, because its channel does not negotiate
  `AcceptLZO`; compressed bytes are never exposed as plaintext.

### HIP report and periodic lifecycle

- `gpHIPRunner` performs the initial and negotiated periodic
  `hipreportcheck.esp`, submits `hipreport.esp` only when requested, includes
  the complete opaque identity and assigned IPv4/IPv6 fields, and computes the
  MD5 correlation value after removing only authcookie and preferred-address
  segments, as `build_csd_token` and the HIP loop require
  (`/tmp/openconnect/gpst.c:803-1109`). HIP uses the gateway cookie jar and the
  accepted address; redirects are not followed and cannot move the opaque
  cookie or report to another origin.
- The built-in report emits version 4 identity, actual runtime OS/vendor,
  hostname, assigned addresses, and only MAC addresses observed from local
  interfaces. It emits the expected security category structure empty rather
  than fabricating antivirus, firewall, encryption, or product state. This is
  the truthful subset of `/tmp/openconnect/trojans/hipreport.sh`; deployments
  requiring additional facts use the flavor-specific `HIPOptions.WrapperPath`.
- The wrapper receives exactly `--cookie`, available `--client-ip` and
  `--client-ipv6`, `--md5`, and `--client-os`; inherited `APP_VERSION` is
  removed and the negotiated version is supplied. Bounded nonempty stdout is
  submitted verbatim. Start failure, ordinary nonzero exit, abnormal
  termination, empty output, and oversized output are terminal compliance
  errors rather than silently fabricated success, following `run_hip_script`
  (`/tmp/openconnect/gpst.c:913-1057`).
- The periodic real peer poisons DNS after login, validates the truthful report
  and correlation identity, blocks the second check long enough to prove GPST
  has closed and `Client.Ready` is false, then verifies GPST reopens and carries
  data. A parallel ESP run carries data before and after the periodic check
  with one unchanged UDP socket and no GPST. A redirect peer proves no request
  reaches the decoy, client close proves the timer stops, and the wrapper
  matrix proves exact arguments/environment plus successful stdout, nonzero,
  abnormal, and start-error outcomes.

## Resolved locked-conflict register

### C-01: hidden fields cannot be permanently unobservable

**Locked text in conflict:** hidden fields never surface.

OpenConnect retains hidden values (`/tmp/openconnect/auth-html.c:76-82`) and its
CLI permits a caller to override a hidden value or explicitly promote it to a
text prompt (`/tmp/openconnect/main.c:2929-2938`). The F5 fake records that a
real deployment requires this behavior (`tests/fake-f5-server.py:84-93`),
rejects the default hidden value (`fake-f5-server.py:173-178`), and supplies the
actual hidden `choice` field (`fake-f5-server.py:204-210`). The upstream test
passes `--form-entry 'hidden_form:choice=17'`
(`tests/f5-auth-and-config:78-83`).

**Adopted decision:** hidden fields remain hidden by default and auto-submit
their server value. `ClientOptions.FormEntries` can target an exact
`SubmissionKey`, or a `FormID` plus wire `Name`, to override the value or set
`Promote` and publish that instance as interactive text. The internal field is
never discarded. This preserves the safe default while meeting F5's deployed
override requirement.

### C-02: `map[string]string` cannot represent the upstream form

**Locked text in conflict:** `AuthFormField.Name` is the submission key and
`CompleteAuthForm` accepts `map[string]string`.

Pulse's expired-password form has distinct “new password” and “verify new
password” controls with the same wire name `newpass1`
(`/tmp/openconnect/pulse.c:1150-1157`, `pulse_request_pass_change`). Upstream
stores and compares their two values separately (`pulse.c:1164-1176`). Common
form submission also iterates ordered option instances
(`/tmp/openconnect/auth-common.c:158-168`).

**Adopted decision:** `AuthFormField.SubmissionKey` is the unique instance ID,
`Name` is the wire name, and the public field slice preserves wire order.
`CompleteAuthForm` retains its map shape but keys it by `SubmissionKey`; the
flavor emits one ordered wire value per instance, including duplicate names.

### C-03: caching every interactive value is unsafe

**Locked text in conflict:** all interactively submitted values are cached for
the client's lifetime and reconnect must not reprompt.

GP replaces the prior challenge secret, clears its value, and binds the next
submission to a new server `inputStr`
(`/tmp/openconnect/auth-globalprotect.c:232-274`). The fake generates a random
`inputStr` for each challenge (`tests/fake-gp-server.py:205-225`). Fortinet's
real upstream test requires two tokeninfo 2FA rounds
(`tests/fortinet-auth-and-config:87-92`). Pulse password-change and session-kill
answers are also form-instance state (`/tmp/openconnect/pulse.c:903-1225`).

**Adopted decision:** cache only stable semantic username, primary password,
auth group, and explicit caller prefills. OTPs, challenge answers, nonce-bound
values, hidden server state, session choices, and password-change values remain
one-shot. Cache matching is by flavor-assigned semantic role rather than wire
name, and a rejected stable credential is cleared before reauthentication.

### C-04: a pending form cannot always survive wire-session teardown unchanged

**Locked text in conflict:** form state survives session teardown and reconnect.

Pulse processes forms inside a live EAP/EAP-TTLS exchange
(`/tmp/openconnect/pulse.c:1375-2067`) and passes the still-open authenticated
channel into `pulse_connect` (`pulse.c:2697-2709`). GP challenges carry a
server-generated `inputStr` tied to the current exchange
(`/tmp/openconnect/auth-globalprotect.c:232-274`). Destroying those continuations
invalidates submission of the old form.

**Adopted decision:** an `authContinuation` owns the live exchange and its
pending form only while that continuation remains valid. Teardown closes the
continuation; retry starts a new authentication exchange, semantically prefills
only stable inputs, and publishes a new `AuthForm.ID`. An old ID and its dynamic
state are never submitted to a replacement exchange.

### C-05: system-browser-only SSO lacks required completion data

**Locked text in conflict:** all clients use the system browser; library
completion uses localhost redirect or cookie polling; no embedded webview.

AnyConnect completion consumes a browser-provided cookie list and final URI
(`/tmp/openconnect/cstp.c:1310-1335`, `cstp_sso_detect_done`). GP completion
consumes arbitrary response headers `saml-username`, `prelogin-cookie`, and
`portal-userauthcookie` (`/tmp/openconnect/gpst.c:1380-1406`,
`gpst_sso_detect_done`). NC has no SSO completion hook in the ops table and
instead follows HTML forms and cross-host redirects internally
(`/tmp/openconnect/library.c:299-318`,
`/tmp/openconnect/auth-juniper.c:445-623`). A localhost redirect alone does not
provide GP response headers, and ordinary external-browser cookie polling does
not guarantee access to HttpOnly cookies.

**Adopted decision:** `Browser.Authenticate` receives a `BrowserRequest` with
login/final URLs and requested cookie/header names and returns `BrowserResult`
with the final URL, cookie pairs, and response headers. The library embeds no
webview; the caller's system-browser integration is responsible for returning
those artifacts, using a localhost companion/helper or explicit import where
the platform browser cannot expose them. AnyConnect consumes final URL and
cookies, GP consumes headers, and NC keeps its internal HTML redirect flow.

### C-06: the public options omit required certificate inputs

**Locked text in conflict:** the shown `ClientOptions` shape is locked, while M1
requires certificate and MCA coverage.

OpenConnect has separate client certificate/key and MCA certificate/key APIs
(`/tmp/openconnect/openconnect.h:644-654`). The Cisco fake test supplies both
pairs independently (`/tmp/openconnect/tests/auth-multicert:42-47`). A standard
TLS configuration can represent the TLS client certificate but not by itself
the second MCA signing identity and its separate key password.

**Adopted decision:** `ClientTLSOptions` carries a caller `tls.Config`, optional
CA material, TLS client certificate/key material and key password, plus a
separate MCA certificate/key and key password. `Material` accepts caller-owned
content or a path. TLS identity selection, including `GetClientCertificate`,
remains distinct from the MCA signing identity; neither is negotiated tunnel
configuration.

### C-07: HOTP state conflicts with no persistence contract

**Locked text in conflict:** HOTP is built in and nothing is ever persisted to
disk.

HOTP advances a counter. OpenConnect exposes lock/unlock callbacks specifically
so updated token state can be loaded and persisted after code generation
(`/tmp/openconnect/openconnect.h:587-607`). A process-lifetime-only counter will
reuse an old counter after restart unless the caller can receive and store the
updated token state.

**Adopted decision:** `TokenOptions.Counter` supplies the loaded HOTP state and
HOTP configuration requires `UpdateCounter(ctx, nextCounter)`. The callback
must succeed before the generated code is returned, after which the in-memory
counter advances. Persistence remains caller-owned and the library writes no
token state to disk.

### C-08: Pulse Host Checker is a real unsupported behavior

**Locked text in conflict:** the Pulse trojan column is empty while the mission
requires whatever deployed gateways demand.

Pulse servers can request Host Checker. OpenConnect detects request type 3 and
returns “not yet supported; try Juniper mode”
(`/tmp/openconnect/pulse.c:1867-1871`).

**Adopted decision:** Pulse compatibility is scoped to OpenConnect's current
support. A Pulse Host Checker request fails specifically as unsupported and
directs the caller to NC mode; it is never ignored and no success is fabricated.
Implementing Pulse Host Checker would require a separately reviewed milestone.

### C-09: built-in compliance emulation needs more input surface

**Locked text in conflict:** CSD, TNCC, and HIP are built in by default, with
only a generic CSD option shown.

CSD performs server endpoint exchanges (`trojans/csd-post.sh:88-165`); TNCC has
device, policy, certificate, MAC, command, cookie, and periodic state
(`trojans/tncc-emulate.py:450-727`); HIP depends on session and local system
facts (`trojans/hipreport.sh:1-444`). These are distinct contracts.

**Adopted decision:** compliance inputs are flavor-specific and narrowly
scoped: M1 exposes `CSDOptions`, M2 exposes `HIPOptions`, and M4 exposes NC
TNCC through its separate `TNCCOptions` type. Negotiated/session-derived facts
remain internal. Built-ins emit only observed facts, external wrappers remain
an escape hatch, and an unmodeled mandatory check fails specifically.

### C-10: current fake peers cannot satisfy the locked tunnel milestones

**Locked text in conflict:** non-AnyConnect milestones use the existing fake
servers as interop peers and include GPST/ESP, PPP/DTLS, and oNCP/ESP.

The exact auth-only failure endpoints and Pulse exception are recorded in
“Real test assets and their limits.” GP, F5, Fortinet, and Juniper tests
explicitly accept tunnel rejection. Cisco's fake is MCA-only.

**Adopted decision:** existing upstream fakes remain the auth/config oracle, but
data milestones extend them or add independent real wire peers for GPST/ESP,
F5 PPP/DTLS, Fortinet PPP/DTLS, and oNCP/ESP. Expected tunnel rejection cannot
satisfy a milestone. Pulse's existing full peer and AnyConnect against ocserv
remain valid transport evidence.

### C-11: “HTTPS frontend returns cookie” is not universal

**Locked text in conflict:** every flavor frontend is described as an HTTPS
auth phase producing a cookie, followed by cookie-to-tunnel connect.

Pulse upgrades HTTPS to IF-T/TLS and performs EAP forms on that channel
(`/tmp/openconnect/pulse.c:1375-2067`), then normally reuses it in connect
(`pulse.c:2697-2709`). GP's obtained material is a serialized set of login
arguments (`/tmp/openconnect/auth-globalprotect.c:293-410`).

**Adopted decision:** retain `BeginAuthentication`/`ConnectTunnel`, but hand off
an internal opaque `obtainedSession` owned by the flavor. It may contain cookie
material, serialized GP arguments, accepted endpoint identity, or a live Pulse
connection. The public API never assumes or exposes a universal cookie string.

## M1 final verification

The completed tree passed `make fmt`; root and test-module `go mod tidy`;
`make test`; root and test-module `go test -race`; root and test-module
`go vet`; and `make lint`, including every configured root-module GOOS pass and
the test module with zero lint findings. The full real-peer M1 set passed in the
test module as
`OPENCONNECT_IT=1 go test -run '^TestM1' -parallel=2` in 42.443 seconds, and
`OPENCONNECT_IT=1 go test -race -run '^TestM1' -parallel=2` in 46.404 seconds.
The independent injected-session C/OpenSSL oracle subsequently passed Cisco
DTLS 1.2 `AES128-SHA`, `AES256-SHA`, `DHE-RSA-AES128-SHA`, and
`DHE-RSA-AES256-SHA` resumed handshakes, bidirectional application data, and
close-notify. The DHE-RSA labels identify the resumed cipher suites and do not
claim that the abbreviated handshakes perform fresh DHE key exchange.

## M2 final verification

The completed M2 tree passed `make fmt`, `make test`, and `make lint`, including
all configured root-module GOOS lint passes and the test module. Root and test
modules passed ordinary and race-enabled tests. The complete real-peer M2 set,
including the Docker upstream-auth matrix and the independently compiled
C/OpenSSL ESP oracle, passed both ordinary and race-enabled runs as
`OPENCONNECT_IT=1 go test -run '^TestM2GlobalProtect'` and
`OPENCONNECT_IT=1 go test -race -run '^TestM2GlobalProtect'`.

M4 closed M2's explicit shared-transport residual for Juniper LZO-compressed
ESP next-header `0x05`: Pulse and NC now use the bounded shared decoder and the
independent liblzo2 oracle covers valid, malformed, trailing-input, and
oversized output. GlobalProtect deliberately retains its specific terminal
rejection because LZO is not negotiated for that flavor. This does not weaken
the completed GP AES-CBC/HMAC, sequence/IV/replay, GPST, fallback, or HIP
matrices.

## M3 Fortinet/F5 implementation contract

This section is the source-backed implementation and verification contract
completed by M3. The two upstream Python servers remain mandatory
authentication/configuration regressions, but neither is a data-plane peer:
the F5 fake always returns HTTP 504 from `/myvpn` and the Fortinet fake always
returns HTTP 403 from `/remote/sslvpn-tunnel`
(`/tmp/openconnect/tests/fake-f5-server.py:296-307`,
`/tmp/openconnect/tests/fake-fortinet-server.py:278-284`). M3 therefore owns
independent, complete peers in addition to verbatim copies of those fakes.

### Package and ownership shape

**Adopted decision:** follow `../sing-openvpn`'s flat-root decomposition rather
than creating protocol subpackages. Its public client owns lifecycle, packet
queues, stable authentication state, and negotiated configuration, while a
separate supervisor owns retry classification and session replacement
(`../sing-openvpn/client.go:14-75`,
`../sing-openvpn/client_supervisor.go:18-98`,
`client_supervisor.go:221-320`). Its real interop tests separate scenario
selection, Docker/runtime infrastructure, and direction-specific execution
(`../sing-openvpn/test/interop_real_test.go:22-98`,
`../sing-openvpn/test/interop_harness_test.go:66-176`,
`interop_harness_test.go:237-319`). M3 applies the same separation:

- `f5_auth.go` and `f5_form.go` own only F5 authentication, HTML/JSON form
  conversion, cookies, and logout. `f5_config.go` owns profile/options parsing
  and immutable connect parameters. `f5_session.go` owns TLS/DTLS carrier
  selection and the flavor frontend adapter.
- `fortinet_auth.go` and `fortinet_form.go` own the realm/login/challenge state
  machine, cookies, and logout. `fortinet_config.go` owns XML configuration and
  reconnect policy. `fortinet_session.go` owns the response-less TLS switch,
  DTLS application hello, and the flavor frontend adapter.
- `ppp_frame.go`, `ppp_control.go`, `ppp_link.go`, and
  `ppp_negotiation.go` own protocol-neutral PPP framing, control negotiation,
  one active link owner, and carrier replacement. The F5 and Fortinet files
  supply descriptors and connect probes; they do not duplicate PPP.
- `dtls_certificate*.go` owns ordinary certificate-authenticated DTLS 1.2 and
  the independently implemented DTLS 1.0 path. It is separate from Cisco's
  injected-resumption/PSK code because F5 and Fortinet perform a full ordinary
  handshake and validate the peer certificate
  (`/tmp/openconnect/openssl-dtls.c:325-380`,
  `openssl-dtls.c:485-515`, `/tmp/openconnect/gnutls-dtls.c:336-365`).
- A small `acceptedEndpoint` value may be shared by the two frontends. It owns
  the logical URL/SNI host, port, accepted IP, scoped cookie jar, and the
  original user-configured reauthentication URL. It must not turn into a new
  public cookie API.

The protocol operations table independently supports this split: both flavors
use shared PPP TCP/UDP mainloops but distinct authentication, common headers,
connect, logout, and DTLS probe hooks (`/tmp/openconnect/library.c:361-399`).
The upstream interface also separates authentication, TCP establishment,
UDP setup/mainloop, close, and application probe
(`/tmp/openconnect/openconnect-internal.h:830-872`).

### F5 authentication and form contract

- Start with GET at the caller's exact URL. Follow bounded HTTP redirects with
  F5's source-specific redirected-POST-to-GET behavior and resolve each
  POST-only form
  action against the response URL. After every response, check the cookie jar
  before parsing the body; authentication completes only when the same
  accepted origin has both `MRHSession` and `F5_ST`. `MRHSession` alone is an
  intermediate state (`/tmp/openconnect/f5.c:84-110`,
  `f5.c:264-284`, `f5.c:366-375`).
- Parse recoverable HTML with `golang.org/x/net/html`. The first HTML form must
  be POST and `id="auth_form"`; a different first ID is a terminal protocol
  mismatch. Retain form action, ID, banner/message table cells, ordered text,
  password, hidden, checkbox, and select instances. A `select name="domain"`
  is the stable auth-group choice. Hidden values auto-submit but remain
  overrideable through `FormEntries`, as already locked by C-01
  (`/tmp/openconnect/auth-html.c:45-54`, `auth-html.c:56-151`,
  `auth-html.c:154-199`, `auth-html.c:201-294`). Unlike the C parser, the Go
  model preserves duplicate wire names using unique `SubmissionKey` values,
  consistent with C-02.
- If no HTML form exists, locate `appLoader.configure(` in a script and use a
  string/escape-aware balanced-object scanner to extract exactly one JSON
  object. Require `logon.form`; accept its string `id`/`title` and ordered
  `fields`, mapping `text` and `password`, values, names, captions, and the
  `disabled` marker. Unknown field types remain visible text with a warning;
  as upstream does, `disabled` does not discard a named field or its retained
  value. Missing names or malformed structure are terminal rather than
  silently submitting an unaddressable field. This is a more robust delimiter than the
  upstream newline-dependent `\n});` search while retaining its strict JSON
  object contract (`/tmp/openconnect/f5.c:112-168`, `f5.c:171-248`).
- `github.com/sagernet/sing/common/json/badjson` is not the parser for embedded
  JavaScript. At the pinned sing version its `Decode` immediately delegates to
  the ordinary JSON token decoder, and `JSONObject` is an ordered map used for
  merge/marshal behavior; it does not accept JavaScript syntax
  (`github.com/sagernet/sing@v0.8.12-0.20260702081104-2ded2af32d3d/common/json/badjson/json.go:11-54`,
  `common/json/badjson/object.go:15-17`, `object.go:69-106`). The balanced
  extractor plus the standard/sing strict JSON decoder is sufficient, and the
  field array already preserves submission order.
- Only the first round may synthesize the static `username`/`password` form
  when neither HTML nor appLoader JSON yields a form. A later absent/malformed
  challenge is terminal. The first password is the stable primary credential;
  only password controls on later forms may be classified as OTP/token
  (`/tmp/openconnect/f5.c:45-81`, `f5.c:305-344`, `f5.c:349-360`).
- The obtained session owns both secure cookies, their scoped jar, accepted
  endpoint, and parsed `F5_ST` expiry. `F5_ST` follows the observed
  `...z<start>z<duration>` form and yields an absolute authentication expiry
  (`/tmp/openconnect/f5.c:687-697`). Closing the obtained session is idempotent,
  first closes any tunnel, then performs a bounded best-effort authenticated
  GET to `/vdesk/hangup.php3?hangup_error=1` on the accepted endpoint
  (`f5.c:844-868`).

### F5 configuration, carriers, and versions

- Configuration is fetched exactly once per obtained cookie: GET
  `/vdesk/vpn/index.php3?outform=xml&client_version=2.0`, require a
  `<favorites type="VPN">`, choose the first `<favorite>` with `<params>`, then
  GET `/vdesk/vpn/connect.php3?<params>&outform=xml&client_version=2.0`
  (`/tmp/openconnect/f5.c:388-469`, `f5.c:700-728`). The options document must
  be `<favorite><object>`, contain `ur_Z`, `Session_ID`, and enable IPv4 or
  IPv6. Parse idle timeout; default/include/exclude routes; up to three DNS and
  NBNS addresses; search domains; `hdlc_framing`; `tunnel_dtls`, its port, and
  `dtls_v1_2_supported` (`f5.c:471-640`). WINS values populate public `NBNS`,
  not DNS; the assignment to `new_ip_info.dns` at `f5.c:546-552` is treated as
  an upstream implementation typo, not a wire contract.
- Construct the exact cookie-free `/myvpn` GET from opaque `sess`, `Z`, family
  booleans, HDLC mode, and base64 local hostname. It is immutable session state
  and can be sent over either carrier; unbounded cookies must never enter this
  single-DTLS-datagram request (`f5.c:738-767`). TLS reads one HTTP response,
  accepts 200 or 201, seeds proposed addresses from
  `X-VPN-client-IP`/`X-VPN-client-IPv6`, preserves any bytes buffered after the
  header, and then starts PPP (`f5.c:642-668`, `f5.c:779-842`).
- Plain F5 PPP frames are `0xf500` big-endian, a big-endian PPP payload length,
  then the PPP frame. F5 HDLC is RFC1662 asynchronous HDLC-like framing without
  that outer header: flags `0x7e`, `0x7d` escaping according to the negotiated
  async map, and little-endian complemented FCS-16. A missing initial flag is
  tolerated; a missing final flag/FCS or bad FCS drops the frame
  (`/tmp/openconnect/ppp.c:24-158`, `ppp.c:249-293`,
  `ppp.c:1153-1206`, `ppp.c:1462-1479`).
- HDLC and DTLS are mutually exclusive. RFC1662 escaping can nearly double a
  packet and prevents a stable datagram MTU, so an HDLC profile uses TLS and
  logs the negotiated reason rather than trying UDP
  (`/tmp/openconnect/f5.c:598-613`). The full-peer matrix must exercise HDLC
  over TLS and ordinary F5 framing over both TLS and DTLS; it must not claim an
  unsupported HDLC-over-DTLS combination.
- If `dtls_v1_2_supported` is true, perform a full certificate-authenticated
  DTLS 1.2 handshake with Pion, then send the same `/myvpn` GET and require an
  HTTP 200 application response before PPP takes ownership. HTTP 4xx is session
  rejection; malformed or other responses are protocol failure
  (`/tmp/openconnect/f5.c:522-527`, `f5.c:598-603`, `f5.c:871-913`). Pion
  supplies root CA, SNI, client-certificate, and verification callback hooks
  and modern ECDHE-RSA/ECDHE-ECDSA GCM/CBC suites
  (`github.com/pion/dtls/v3@v3.1.5/options.go:214-237`,
  `options.go:380-422`, `options.go:504-514`,
  `cipher_suite.go:23-42`, `cipher_suite.go:210-222`). Upstream treats this bit
  as permission to negotiate 1.2 or newer, even 1.3; M3 deliberately claims
  1.2 only because the pinned Pion version implements only 1.2
  (`/tmp/openconnect/openconnect-internal.h:684-692`).
- If `dtls_v1_2_supported` is absent or zero, send **only** a DTLS 1.0
  ClientHello. OpenConnect explicitly pins DTLS 1.0 because pre-v16 BIG-IP can
  fail catastrophically merely on seeing a 1.2 offer
  (`/tmp/openconnect/openssl-dtls.c:335-341`,
  `/tmp/openconnect/gnutls-dtls.c:353-357`). Pion v3.1.5 cannot implement this:
  although it names 1.0, its support predicate accepts only 1.2
  (`github.com/pion/dtls/v3@v3.1.5/pkg/protocol/version.go:7-11`,
  `version.go:27-37`; `options.go:569-594`). M3 therefore owns a full standards
  DTLS 1.0 client, not a version-byte patch to Pion and not Cisco's abbreviated
  handshake.
- The owned DTLS 1.0 path is gated by `AllowInsecureCrypto`, performs cookie
  verification, certificate chain/hostname and configured callback checks,
  optional client-certificate authentication, handshake fragmentation and
  reassembly, replay protection, authenticated `close_notify`, and full
  application datagrams. Its locked suites are
  `ECDHE-RSA-AES128-SHA`, `ECDHE-RSA-AES256-SHA`, `AES128-SHA`, and
  `AES256-SHA`, with RSA server certificates and P-256/P-384/P-521 ECDHE. DHE
  and ECDSA-authenticated DTLS 1.0 are not claimed. If the correctly versioned
  handshake or application probe fails, UDP falls back to TLS. With no insecure
  opt-in, the client sends no legacy handshake and uses the secure TLS carrier;
  under no circumstance may either fallback first expose a 1.2 ClientHello to
  that legacy endpoint.

### Fortinet authentication contract

- Preserve the caller's initial path because it can select a realm. Follow
  bounded HTTP redirects and the source-verified FortiOS 7.4
  `top.location="..."` form, resolving root-relative or relative targets
  against the current accepted URL. Capture the resulting `realm` semantic
  value and URL-encode it exactly once on POST. A `fake+Realm` path must reach
  the server as the same realm, never as a space or a double-escaped value
  (`/tmp/openconnect/fortinet.c:113-157`,
  `/tmp/openconnect/tests/fortinet-auth-and-config:48-65`).
- Force Fortinet's protocol user agent `Mozilla/5.0 SV1` on authentication,
  configuration, tunnel, and logout requests; do not add the speculative
  openfortivpn header set (`/tmp/openconnect/fortinet.c:45-68`). Publish a
  static first form whose wire names are `username` and `credential`, then POST
  `/remote/logincheck` with `realm` and
  `ajax=1&just_logged_in=1`. HTTP Basic authentication is disabled because 401
  is a protocol-level HTML challenge, not an origin-auth prompt
  (`fortinet.c:159-239`).
- A success response is defined by `SVPNCOOKIE`, not by the body or HTTP 200
  (`fortinet.c:241-251`). For a comma-delimited `ret=...,tokeninfo=...`
  response, hide the stable username, rename the visible answer to `code`, set
  form ID `_challenge`, and preserve opaque
  `reqid,polid,grp,portal,peer,magic` fields and their values. `magic` is
  serialized last (`fortinet.c:253-295`). The parser must bound field count and
  size but must not parse/re-encode opaque values into a lossy map.
- For `tokeninfo=ftm_push`, a blank `code` means an explicit one-shot push
  action: omit `magic` and append `ftmpush=1`. A nonblank code follows the
  ordinary tokeninfo path (`fortinet.c:215-228`). HTTP 401 with an HTML body is
  parsed as POST-only 2FA; retain hidden `username`, `magic`, `reqid`, and
  `grpid`, publish the password control named `credential`, and use `<b>` text
  as the message (`fortinet.c:296-325`,
  `/tmp/openconnect/auth-html.c:283-291`). Repeated tokeninfo or HTML rounds
  each receive fresh one-shot state.
- HTTP 405 republishes the applicable form with an invalid-credentials message
  and clears the rejected visible secret before it can auto-submit again
  (`fortinet.c:326-330`). Closing the obtained session performs a bounded,
  idempotent authenticated GET to `/remote/logout` on the accepted endpoint
  after closing the active tunnel (`fortinet.c:874-901`).

### Fortinet configuration, carriers, and reconnect

- Fetch `/remote/fortisslvpn_xml?dual_stack=1` once per `SVPNCOOKIE`. A redirect
  to `/remote/login` is session rejection. On HTTP 403, probe the legacy
  `/remote/fortisslvpn` endpoint only to distinguish an ancient pre-v5 HTML
  configuration (specific terminal unsupported error) from an expired/rejected
  session; never parse ancient HTML as modern configuration
  (`/tmp/openconnect/fortinet.c:645-722`). A `Set-Cookie` replacement on the
  XML response updates the session jar; the upstream fake exercises precisely
  that regression (`/tmp/openconnect/tests/fake-fortinet-server.py:233-275`).
- Require `<sslvpn-tunnel>`. Parse DTLS enablement on the TLS port; heartbeat
  DPD; idle/authentication expiry; FOS diagnostic identity; IPv4/IPv6 assigned
  addresses and prefixes; DNS/search domains; include and `negate=1` exclude
  routes; and `auth-ses` reconnect permission, source-IP restriction, and
  cleanup timeout. An assigned IPv4 address with no include routes receives
  `0.0.0.0/0` (`/tmp/openconnect/fortinet.c:344-390`,
  `fortinet.c:392-643`). Invalid addresses, masks, prefixes, or a configuration
  with no usable family are terminal configuration errors.
- Fortinet `<split-dns>` supplies both domains and dedicated servers, while the
  current public `SplitDNS []string` cannot preserve that association.
  **Adopted decision:** M3 adds an additive
  `SplitDNSRules []TunnelSplitDNSRule`, where each rule owns copied
  `Domains []string` and `Servers []netip.Addr`. Existing `SplitDNS` continues
  to mean domains routed to the global `DNS` list, as in Cisco/F5; Fortinet
  domains with dedicated servers are not also flattened into it. Preserve wire
  order, remove only exact duplicates permitted by the source format, and
  deep-copy the rule slice and each nested domain/server slice. A malformed
  nonempty split-DNS rule fails specifically; it is never silently ignored or
  converted to global DNS. This closes the behavior which upstream only warns
  about (`fortinet.c:532-543`, `fortinet.c:577-588`).
- The TLS carrier writes exactly
  `GET /remote/sslvpn-tunnel HTTP/1.1` plus Fortinet common headers and the
  cookie, then treats the first bytes as PPP. There is no successful HTTP
  response. If the first bytes begin `HTTP/`, 4xx means session rejection and
  any other HTTP response is terminal protocol failure; a partial `HTTP/`
  prefix must be buffered before classification
  (`fortinet.c:726-740`, `fortinet.c:775-835`,
  `/tmp/openconnect/ppp.c:1047-1056`, `ppp.c:1123-1135`).
- Fortinet PPP outer framing is big-endian total length, `0x5050`, big-endian
  PPP payload length, then PPP. Both length fields must agree and be within the
  bounded receive size; TLS may split one frame or concatenate several
  (`/tmp/openconnect/ppp.c:269-273`, `ppp.c:1110-1121`,
  `ppp.c:1188-1197`, `ppp.c:1219-1234`, `ppp.c:1480-1485`). Fortinet does not
  request async-map, protocol-field compression, or address/control
  compression because deployed servers reject them (`ppp.c:249-293`). Inbound
  compressed or uncompressed headers remain accepted after negotiation.
- If XML enables DTLS, use the accepted TLS port and full certificate-authenticated
  DTLS 1.2. After the cryptographic handshake, send `be16(total)` followed by
  `GFtype\0clthello\0SVPNCOOKIE\0`, the cookie value, and a final NUL. Accept
  `be16(total)`, `GFtype\0svrhello\0handshake\0`, and a status field containing
  exactly `ok` with an optional final NUL; also accept a structurally valid
  first Fortinet PPP frame as application success when the `ok` datagram was
  lost, and feed that frame into PPP rather than dropping it
  (`/tmp/openconnect/fortinet.c:39-43`, `fortinet.c:458-465`,
  `fortinet.c:743-761`, `fortinet.c:837-871`). A `fail`/malformed hello disables
  that UDP attempt and retains/falls back to TLS unless it proves session
  rejection.
- Resolve the reconnect contradiction in favor of the source's deployment
  warning: configuration is immutable for the lifetime of one cookie and is
  not refetched after a carrier drop because that can invalidate
  `SVPNCOOKIE` (`fortinet.c:652-661`). Reuse it and reset/re-negotiate PPP only
  when `<auth-ses tun-connect-without-reauth="1">` permits reconnection, the
  cleanup deadline has not elapsed, and a `check-src-ip=1` session observes the
  same local source IP. Otherwise return `ErrSessionRejected`, discard the
  obtained session, and authenticate again. This intentionally does not copy
  the unconditional configure call at `fortinet.c:775-780`.

### Shared PPP and carrier lifecycle

- PPP negotiation and phase state are serialized by `access`, carrier writes
  by `writeAccess`, and switch/termination/close lifecycle transitions by
  `lifecycleAccess` (with `carrierAccess` protecting carrier snapshots).
  Reader and timer goroutines operate through those serialized paths rather
  than a single-owner goroutine or bounded event queues. A carrier generation
  number prevents a stale TLS/DTLS reader or write from taking effect after
  takeover. PPP has no inner PAP/CHAP phase because gateway web authentication
  already completed.
- Reset initializes LCP, IPCP, and IP6CP, then negotiates LCP before the enabled
  network-control protocols. LCP covers MRU, async map, magic, PFCOMP, and
  ACCOMP. IPCP negotiates the address and RFC1877 DNS/NBNS; IP6CP negotiates an
  interface identifier. VJ compression and CCP are rejected, unknown options
  receive Configure-Reject, unknown protocols receive Protocol-Reject, and
  configuration requests retry every three seconds
  (`/tmp/openconnect/ppp.c:379-540`, `ppp.c:543-774`,
  `ppp.c:776-869`, `ppp.c:871-1030`).
- Parsing is stream-safe and length-first: retain partial TLS records, consume
  concatenated outer frames, accept address/control and protocol-field
  compression on inbound packets, bound receive storage to at least 16 KiB but
  reject an advertised length before allocation when it exceeds the configured
  maximum, and deliver IPv4/IPv6 only in NETWORK state
  (`ppp.c:1058-1135`, `ppp.c:1137-1339`). HDLC additionally handles multiple
  frames and an escape split across reads.
- On first setup, give configured DTLS the source-verified five-second first
  opportunity; retransmit the application connect probe each second. Only a
  valid flavor probe makes DTLS eligible to own PPP. Then reset PPP, retain the
  previously negotiated address as the next requested address, and negotiate
  again on the new carrier. Close the stale TLS carrier after takeover. If
  DTLS cryptographic handshake, probe, or subsequent carrier fails, preserve
  the obtained web session when policy permits and reconnect PPP over TLS
  (`/tmp/openconnect/ppp.c:1513-1649`, `ppp.c:1651-1799`).
- `Client.Ready` becomes true only at PPP NETWORK and false during every reset
  or carrier switch. The initial configuration event is emitted only then;
  successful carrier recovery emits reestablishment with the same assigned
  addresses. A server NAK that changes an already accepted reconnect address
  rejects that reconnect rather than silently publishing an identity change,
  matching the F5 address rule (`/tmp/openconnect/f5.c:642-668`,
  `/tmp/openconnect/ppp.c:692-710`).
- PPP LCP Discard-Request is keepalive; Echo-Request/Echo-Reply is DPD. A dead
  carrier enters the protocol reconnect policy. Clean close sends one TLS
  Terminate-Request or up to three DTLS requests one second apart and accepts a
  peer Terminate-Request/Terminate-Ack (`/tmp/openconnect/ppp.c:807-834`,
  `ppp.c:963-1010`, `ppp.c:1388-1427`).

### Credential, endpoint, and error policy

Credential retention is semantic, never inferred solely from a wire name:

- F5 username, first-round primary password, and selected domain are stable
  cache candidates. Fortinet username, initial `credential` primary password,
  and caller-selected initial realm path are stable. An authentication
  rejection clears the rejected stable secret before a new exchange. In F5,
  returning another primary username/password form after that password was
  submitted counts as rejection and forces publication instead of automatic
  resubmission; a hidden/OTP successor does not clear the accepted primary
  password. Fortinet has the explicit HTTP-405 signal.
- F5 later password/token controls; Fortinet `code` and HTML-2FA
  `credential`; FTM push; hidden values; `magic`, request/policy/group/portal
  IDs; form actions; and all token-generated codes are one-shot continuation
  state. This distinction is required because Fortinet uses the same
  `credential` wire name for a primary password and HTML OTP and its upstream
  test requires two fresh tokeninfo rounds
  (`/tmp/openconnect/tests/fortinet-auth-and-config:78-92`).
- Stable values may prefill a newly created continuation, but no old form ID,
  hidden field, challenge value, or cookie survives teardown. This is the
  concrete M3 application of C-03 and C-04.

The accepted endpoint is also semantic session state:

- Authentication redirects may change origin. Each request uses normal cookie
  scoping; an origin change clears/leaves behind origin cookies and never leaks
  secure cookies to the next host. On success, record the URL host/port used by
  the successful cookie response, its TLS SNI, and the peer IP accepted by that
  TLS connection.
- Profile/config, TLS tunnel, DTLS, and logout keep the logical accepted host
  and SNI but dial the accepted IP and negotiated port. DNS may be used on a
  later full reauthentication, not to move an existing opaque session. Config,
  tunnel, DTLS probes, and logout do not follow redirects to a new origin.
- F5 DTLS uses its negotiated port; Fortinet DTLS uses the accepted TLS port.
  DTLS validates through the same root/callback policy as HTTPS, but it does
  not require byte-for-byte equality with the HTTPS leaf certificate; upstream
  intentionally reuses the credential store rather than leaf pinning
  (`/tmp/openconnect/gnutls-dtls.c:341-351`).

Errors enter five explicit classes:

| Class | Examples | Supervisor action |
| --- | --- | --- |
| Continue current authentication | F5 next form, Fortinet tokeninfo/HTML 401, FTM push, Fortinet 405 invalid answer | Clear only rejected/one-shot values, publish the next fresh form, no reconnect backoff. |
| Session rejected | F5 TLS 504 or DTLS 4xx; Fortinet config redirect to login, rejected config cookie, TLS-tunnel 4xx; expired auth timer | Close/logout the opaque session, clear the rejected stable credential only when authentication itself was rejected, and start a fresh authentication exchange with reconnect backoff. |
| UDP-local fallback | DTLS version/cipher unavailable by policy, DTLS certificate rejection, cryptographic timeout/error, malformed/non-rejection application hello | Disable or sleep that UDP attempt and establish/retain the authenticated TLS carrier; never weaken verification and never discard a usable web session. |
| Retryable primary-carrier failure | TLS EOF/timeout, DPD failure, ordinary established-carrier I/O | Keep the opaque session only when F5/Fortinet reconnect policy permits; reset PPP and reconnect, otherwise reauthenticate. |
| Terminal | HTTPS/TLS trust or hostname failure, caller cancellation, unsupported mandatory legacy config/crypto with no safe carrier fallback, malformed required form/config/frame, invalid length, no usable network family, impossible PPP negotiation, malformed split DNS | Stop the supervisor with a specific wrapped error; never retry an account-lockout-risk input or fabricate success. |

### Independent peer and oracle matrix

The test matrix has three independent sources and must keep their claims
separate:

1. Copy the fixed upstream F5 and Fortinet Python fakes verbatim with a `SOURCE`
   file naming OpenConnect commit `2035601b64a5360a46d18e08937e7f654b3230f2`.
   The F5 matrix covers JSON/no-HTML fallback, normal HTML, three-domain
   authgroup, hidden then OTP, required hidden override, cookies/config, and the
   expected 504 (`/tmp/openconnect/tests/f5-auth-and-config:42-93`). The
   Fortinet matrix covers default/nondefault/`fake+Realm`, normal login,
   tokeninfo, blank FTM push, HTML 2FA, two tokeninfo rounds, cookie replacement,
   config, and expected 403 (`/tmp/openconnect/tests/fortinet-auth-and-config:42-102`).
   The final HTTP rejection proves classification only, never PPP/DTLS.
2. Build independent complete F5 and Fortinet peers which implement auth,
   config, logout, exact TLS switch, exact outer framing, and the DTLS
   application probe, then bridge the decoded PPP byte stream to a real
   `pppd` process instead of copying the production negotiation state machine.
   They must carry bidirectional IPv4/IPv6 data and validate cookie
   non-leakage, forced Fortinet UA, exact query/realm and hello bytes, accepted
   IP/SNI pinning after DNS poisoning, real stream splitting/coalescing, DPD,
   clean termination, session rejection/re-authentication, TLS recovery,
   DTLS-first timing, late DTLS takeover, and no goroutine or socket survival
   after close. Auth-only upstream code cannot be extended with a trivial
   success response and called independent.
3. Triangulate shared machinery against real implementations. Run system
   `pppd` through an independent C framing shim: the `pppd`-facing side uses
   RFC1662, while the shim separately implements and verifies the
   production-visible RFC1661-like length-delimited raw PPP framing, RFC1662
   HDLC escaping/FCS framing, and Fortinet length/magic framing. Cover
   IPv4+IPv6, IPv4-only, IPv6-only, DNS, NBNS, MRU, rejected VJ/CCP,
   compressed/uncompressed PPP headers, Echo, Terminate, and deliberate stream
   split/coalesce (including an HDLC escape split across reads). Do not claim
   that `pppd` itself runs in synchronous mode or through a PTY: real `pppd`
   proves negotiation, while the C peer, which shares no production Go code,
   proves all three production wire framings and their streaming boundaries.
   OpenConnect's own `nullppp` tests remain supporting research evidence
   (`/tmp/openconnect/tests/common.sh:75-107`,
   `tests/ppp-over-tls:48-134`, `tests/ppp-over-tls-sync:48-69`). Run each
   certificate DTLS version/cipher against a separately compiled C/OpenSSL
   peer with a real CA and DNS SAN, optional mTLS, two-way full datagrams,
   close-notify, MTU/fragmentation, retransmission, and race coverage. The
   legacy F5 sentinel must observe and complete an actual DTLS 1.0 ClientHello,
   while its 1.2 listener must receive no packet; modern F5/Fortinet must
   complete DTLS 1.2. This is independent crypto evidence, not a Pion-to-Pion
   mirror.

M3 completion required every full-peer TLS mode, DTLS 1.0/1.2 mode, and
real-`pppd` scenario to carry packets in both directions. The completed
matrices satisfy that requirement. Expected HTTP rejection, a parser-only
test, a production-code mirror, or a skipped interop dependency was not
accepted as a substitute.

### Executable agent division and gate

Work is divided by non-overlapping file ownership, in this order:

1. **Certificate-DTLS agent:** owns `dtls_certificate*.go`,
   `dtls_certificate_interop_test.go`, and
   `test/testdata/certificate-dtls-peer/**`. It implements the
   shared Pion 1.2 wrapper and owned full DTLS 1.0 client, reports negotiated
   version/cipher/data MTU on the carrier, and completes the C/OpenSSL matrix.
2. **PPP agent:** owns `ppp_frame.go`, `ppp_control.go`, `ppp_link.go`,
   `ppp_negotiation.go`, `ppp_system_interop_test.go`, and
   `test/testdata/pppd-peer/**`. It completes real-`pppd` negotiation before
   flavor sessions depend on its carrier API.
3. **F5 agent:** after the two shared APIs compile, owns only `f5_*.go`,
   `test/m3_f5_*_interop_test.go`, and F5 fixtures. It first lands the verbatim
   upstream matrix, then the complete TLS plain/HDLC and DTLS 1.0/1.2 peer,
   accepted-endpoint, fallback, reconnect, data, and logout matrix.
4. **Fortinet agent:** after the shared APIs compile, owns only
   `fortinet_*.go`, `test/m3_fortinet_*_interop_test.go`, and Fortinet fixtures.
   It lands the upstream realm/2FA matrix, then the complete response-less TLS,
   DTLS hello, lost-hello PPP-first, reconnect-policy, data, and logout matrix.
5. **Integrator:** alone owns any necessary edits to `client_supervisor.go`,
   `errors.go`, `tunnel_config.go`, `options.go`, shared accepted-endpoint code,
   dependency files, and this ledger. It reviews every source contradiction,
   runs the cross-flavor matrix, and prevents one flavor agent from weakening
   shared behavior for the other.

The completed final gate used `make fmt`; root and test-module `go mod tidy`;
`make test`; root and test-module `go test -race ./...`; root and test-module
`go vet ./...`; `make lint`; then, at the recorded counts, the root module ran
both ordinary and `-race` forms of
`OPENCONNECT_IT=1 go test -run '^TestM3PPPSystemPPPDInterop$'` and
`OPENCONNECT_IT=1 go test -run '^TestCertificateDTLS'`, while the test module
ran both ordinary and `-race` forms of
`OPENCONNECT_IT=1 go test -run '^TestM3'`. The root certificate pattern is
intentionally separate because those test names do not begin with `TestM3`.
The results and complete scenario evidence are recorded below.

## M3 final verification

M3 Fortinet/F5 is complete. The completed tree passed `make fmt`; root and
test-module `go mod tidy`; `make test`; root and test-module
`go test -race ./...`; root and test-module `go vet ./...`; and `make lint`.
The separately gated real peers passed these exact commands:

- The test-module full flavor matrix passed ordinary
  `OPENCONNECT_IT=1 go test -run '^TestM3' -v -count=1 -timeout=10m` in
  251.742 seconds and race-enabled
  `OPENCONNECT_IT=1 go test -run '^TestM3' -v -race -count=3 -timeout=20m`
  in 751.777 seconds.
- The root real-`pppd` matrix passed ordinary
  `OPENCONNECT_IT=1 go test -run '^TestM3PPPSystemPPPDInterop$' -v -count=1 -timeout=10m`
  in 24.803 seconds and race-enabled `-count=3` in 73.969 seconds.
- The root certificate-DTLS matrix passed ordinary
  `OPENCONNECT_IT=1 go test -run '^TestCertificateDTLS' -v -count=1 -timeout=5m`
  in 1.566 seconds and race-enabled `-count=3` in 4.326 seconds.
- The independent injected-session CBC residual passed ordinary
  `OPENCONNECT_IT=1 go test -run '^TestAnyConnectDTLS12CBCOpenSSLInjectedResumeInterop$' -v -count=1 -timeout=5m`
  in 0.988 seconds and race-enabled `-count=3` in 2.048 seconds.

The F5 full peer passed twelve complete TLS/DTLS data-plane cases, its terminal
authentication case, and the five-case upstream authentication/configuration
matrix. The Fortinet full peer passed eighteen complete TLS/DTLS, reconnect,
recovery, and terminal-input cases plus the seven-case upstream matrix. The
late-DTLS PPP-failure-to-TLS recovery regression passed a dedicated
race-enabled `-count=10` run in 194.615 seconds; the F5 DTLS 1.0 cleanup
regression passed its own race-enabled `-count=10` run in 67.472 seconds.

The standalone real-`pppd` matrix passed thirteen framing, family,
negotiation, takeover, blocked-writer, termination, and cleanup cases. The
independent C/OpenSSL certificate matrix passed nine DTLS 1.0/1.2 suites,
negative trust/cipher/curve cases, the legacy-version sentinel, and four
injected-resumption DTLS 1.2 CBC cipher identifiers. The RSA/DHE-RSA labels on
the abbreviated injected sessions identify the resumed cipher suites and do
not claim fresh DHE key exchange.

The production PPP carrier close path now interrupts pending carrier I/O
before entering the synchronous close required by carrier replacement or link
termination. The independent F5 and Fortinet peers bound accepted TLS
handshakes and child shutdown, recheck shutdown after registering OpenSSL, and
print their reaping marker only after both server threads stop and the child
map is empty. Every final full-peer run observed that marker and asserted no
peer, real-`pppd`, or OpenSSL process group survived. The real-`pppd` and peer
cleanup assertions also verified removal of owned temporary `/etc/ppp/options`
and loopback aliases.

## M4 Pulse/Network Connect implementation contract

M4 completes both Juniper-family flavors and the shared ESP work that M2 left
flavor-gated. The source oracle remains OpenConnect commit
`2035601b64a5360a46d18e08937e7f654b3230f2`: Pulse behavior is anchored in
`pulse.c`, NC authentication and Host Checker behavior in `auth-juniper.c` and
`trojans/tncc-emulate.py`, oNCP in `oncp.c`, and shared ESP CBC, replay, and LZO
behavior in `openssl-esp.c`, `esp-seqno.c`, `esp.c`, and `lzo.c`. The production
implementation is pure Go. System OpenSSL and liblzo2 are test-oracle
dependencies only.

### Public API, publication, and ownership

- `FlavorPulse = "pulse"` and `FlavorNC = "nc"` use the common `Client`,
  authentication-form, packet-I/O, readiness, configuration, reconnect, and
  close APIs. Neither flavor introduces a parallel client type. `NoUDP`
  disables ESP for both while preserving the authenticated TLS data channel.
- `ClientOptions.TNCC *TNCCOptions` is the one new flavor-specific public
  surface. `WrapperPath` selects the OpenConnect-compatible external wrapper;
  `DeviceID`, `UserAgent`, `MachineIdentificationEnabled`, and
  `Certificates []Material` configure the bounded built-in runner. Wrapper and
  built-in identity inputs are mutually exclusive, certificate identities
  require machine identification, line-protocol inputs reject delimiter or
  newline injection, and `NewClient` deep-clones the material slice and bytes.
- A session returned by `ConnectTunnel` is first recorded as current but not
  publicly usable. After `Start` succeeds, the supervisor stores a cloned
  `TunnelConfiguration`, publishes that exact still-ready session under the
  lifecycle lock, and only then enqueues the `initial`, `reestablishment`, or
  `rekey` callback event. `Ready` and `WriteDataPacket` require
  `publishedSession == currentSession` in addition to the session's own
  readiness. This closes the observed Pulse race in which `Start` set its
  internal ready bit before the client configuration snapshot existed, and it
  also guarantees that receipt of a configuration callback cannot precede
  public readiness.
- A `Start` error is never published. Every replacement session resets the
  publication gate, including same-obtained-session reconnect and explicit
  `sessionRekeyError`. `Close`, terminal callback failure, context
  cancellation, and supervisor teardown all make the published pointer
  unusable before or while closing the session. Every production session
  clears its own ready state before completing `Done`, and publication checks
  that state, so an immediate post-`Start` failure cannot expose a dead
  session. Session methods are not called while holding a configuration-event
  lock; the serial callback dispatcher can fail or call `Close` without a lock
  cycle.
- Pulse and NC retain the accepted authentication backend IP while TLS
  verification continues to use the configured hostname. Tunnel reconnect,
  ESP, TNCC, and logout therefore cannot leak authenticated state through a
  later DNS answer. Configuration and event snapshots remain deep copies.

### Shared ESP, replay, LZO, and retry ownership

The M4 shared data plane is implemented by `esp_packet.go`, `esp_replay.go`,
`esp_channel.go`, and `esp_lzo.go` and is used by GlobalProtect, Pulse, and NC
with flavor-owned probes and fallback policy.

- ESP-in-UDP framing is SPI plus 32-bit sequence, a 16-byte explicit IV,
  AES-128/256-CBC ciphertext, and truncated HMAC-MD5-96, HMAC-SHA1-96, or
  HMAC-SHA256-128. Padding is the increasing byte sequence followed by pad
  length and next-header. Accepted inner types are IPv4 `4`, Juniper LZO `5`
  when enabled, and IPv6 `41` when the flavor permits it. New outbound SAs
  begin at sequence zero and use OpenConnect's stateful next-IV chain; sequence
  exhaustion terminates the association. Owned keys, authentication material,
  and IV state are cleared on replacement and destruction.
- Authentication succeeds before replay state or plaintext parsing. The
  64-position replay window accepts in-window out-of-order packets and rejects
  duplicates and packets older than the window. When the server disables
  replay rejection, the cursor and missing bitmap still advance exactly as
  `verify_packet_seqno` does; only the rejection decision changes.
- `espKeySet.install` builds the replacement associations first, then swaps
  outbound and current inbound state under one lock. It retains only the
  immediately previous inbound SA and bounds that transition at the prior
  replay cursor plus 32 packets; an older previous SA and the replaced
  outbound SA are destroyed. This is the common atomic rekey primitive used by
  Pulse and NC.
- The shared LZO1X decoder is enabled explicitly with `AcceptLZO`. Its output
  is bounded by the negotiated MTU and it requires complete input
  consumption. Malformed input, trailing input, or oversized output drops only
  that authenticated datagram and leaves the healthy ESP channel alive.
  Pulse and NC enable it; GlobalProtect continues to return its specific
  terminal unsupported error for next-header `5`. No flavor emits compressed
  outbound data.
- A channel becomes ready only after its flavor probe is authenticated. Ready
  channels run encrypted DPD and fail after two idle DPD periods. UDP setup,
  write, read, or DPD failure closes the socket and returns ownership to the
  flavor's TLS fallback/retry loop. `PreserveKeysOnStartupFailure` supports a
  bounded initial retry and Pulse additionally uses
  `PreserveKeysOnFailure` so a transport replacement can retain the current
  SA without confusing transport failure with cryptographic association
  failure. Association-terminal failures always destroy the keys.

### Pulse authentication, TTLS, configuration, and TLS data

- Pulse sends an HTTPS `Upgrade: IF-T/TLS 1.0` request with `Content-Type:
  EAP`, `Content-Length: 0`, ALPN `http/1.1`, the original path/query, and the
  authenticated cookie. Only HTTP 101 succeeds. IF-T uses its fixed 16-byte
  header and bounded frames, then implements TCG client-auth, EAP Identity,
  Expanded Juniper/1, AVP alignment, and either direct outer authentication or
  inner EAP carried by EAP-TTLS, matching `/tmp/openconnect/pulse.c:1375-2067`.
- Realm entry/choice, region, active-session choice, primary and secondary
  credentials, password change, GTC/token, sign-in, and final cookie all map
  to ordered common auth forms with unique submission keys. Wire-size limits
  and the fixed Juniper-2021 password field are checked. Expanded Juniper Host
  Checker subtype 3 returns terminal `ErrProtocolNotSupported` with guidance
  to select `nc`, matching upstream rather than inventing a Pulse checker.
- `pulseTTLSConn` fragments an outbound TLS message at exactly 8192 bytes.
  The first non-final fragment carries `L|M` and the four-byte total length;
  every continuation carries `M` without `L`, consumes an empty TTLS ACK, and
  updates the EAP identifier before the final flag-zero fragment. Inbound
  reassembly rejects a missing or repeated length flag, inconsistent totals,
  invalid continuation boundaries, unsupported flags, and messages above 1
  MiB. Cancellation closes the outer transport and interrupts a blocked inner
  handshake. The independent Python peer requires a client certificate and
  hard-fails wrong flags, total, identifier, ACK, or 8192-byte boundaries in
  both fragmentation directions.
- Configuration frames supply IPv4/IPv6 addresses, DNS, NBNS, include/exclude
  routes, search domains, MTU, idle/authentication expiration, and optional
  ESP parameters. IPv4 masks must be contiguous; the configuration must
  contain a usable family and an MTU of at least 576, or 1280 when IPv6 is
  assigned. IF-T type 4 carries raw IPv4/IPv6 only for assigned families. TLS
  remains live while ESP is sleeping and is the immediate per-packet fallback
  if ESP is unavailable or disallowed for that family.

### Pulse ESP lifecycle and type-1 rekey

- ESP uses the accepted TLS endpoint plus the negotiated UDP port, random
  nonzero client SPI and keys, the negotiated AES/HMAC/replay/cross-family
  policy, and a one-zero-byte probe. An IPv4 outer endpoint authenticates that
  probe as next-header 4; an IPv6 outer endpoint uses next-header 41. With
  `crossFamily=false`, only inner packets matching the outer endpoint family
  may use ESP; the other assigned family remains on IF-T/TLS. Cross-family
  negotiation permits both.
- A type-1 rekey first classifies the fixed Juniper configuration envelope.
  An invalid envelope, identifier, length tuple, key-block marker, or fixed
  64-byte key length is an outer-invalid notification and is ignored without
  touching the live SA. Once that fixed header is valid, unusable algorithms,
  a zero SPI, malformed key material, or key-install failure is an inner
  rekey failure: the old ESP channel and keyset are suppressed and traffic
  continues over the still-live IF-T/TLS session. The two cases deliberately
  do not share cleanup semantics.
- A valid type-1 rekey installs into the existing shared keyset without a new
  UDP dial or probe. The established socket and channel generation remain
  unchanged, the new outbound/current-inbound SAs take effect atomically, and
  one old inbound SA remains accepted for the bounded 32-packet overlap. The
  C oracle's `zero-established` mode requires the first new-SA business packet
  to be sequence zero, independently proving that an unnecessary probe did
  not consume the sequence.
- License/wakeup frame `0x96` sends an immediate probe only when an existing
  channel is sleeping/not ready. It may launch a missing channel, but an
  established channel returns without an extra datagram. Fatal frame `0x93`
  terminates the session. Ordinary transport failure retries with preserved
  SA state; stale generation tokens prevent a replaced channel from
  delivering data.
- A clean close sends Juniper frame `0x89` and records the graceful bye. EOF,
  fatal error, or cookie rejection follows the accepted-IP-pinned reconnect or
  HTTPS logout path. Rejected reconnect cookies return to full authentication
  and publish `reestablishment`; abnormal loss logs out once and never emits a
  false graceful close.

### Network Connect authentication and TNCC

- NC authentication uses a private cookie jar, refuses automatic redirects,
  requires HTTPS at every origin, and bounds requests, redirects, and bodies.
  It parses `frmLogin`, `loginForm`, Defender, NextToken, confirmation, role,
  TOTP, hidden SAML, and related source-known forms while retaining input order
  and duplicate names. POST encoding adds the source-compatible `X-Pad` to a
  64-byte boundary. Realm/role use the common auth-group input; primary,
  second-factor, token, and retry semantics use the shared stable-credential
  rules. A response that sets `DSID` is successful even when its status is the
  source-observed HTTP 403.
- A `DSPREAUTH` response without a usable login form enters TNCC and retains
  `DSSIGNIN`. The built-in runner performs the two semicolon-delimited
  `/dana-na/hc/tnchcupdate.cgi` exchanges, decodes bounded nested,
  zlib-compressed command packets, reports optional device, platform,
  hostname, nonzero MAC, and issuer-selected machine certificate identity,
  and schedules the shortest nonzero server interval. Unknown mandatory
  policy fails specifically and recommends the external wrapper; it is never
  reported as satisfied.
- On supported Unix-like systems the wrapper receives a socket as fd 0,
  OpenConnect-compatible `start` and `setcookie` lines, and
  `TNCC_SHA256`, `TNCC_HOSTNAME`, and `TNCC_INTERVAL=0`. Each operation is
  bounded to 30 seconds and process shutdown to two seconds before kill.
  Unsupported platforms return terminal `ErrProtocolNotSupported`; the
  built-in runner remains portable. Periodic TNCC, oNCP, and logout all reuse
  the authenticated origin and accepted address.

### Network Connect oNCP, ESP, IPv6 outer, and close

- NC POSTs `/dana/js?prot=1&svc=4` with `NCP-Version: 3`, a 256-byte declared
  body, and the DSID jar, then retains the upgraded TLS byte stream despite
  `Connection: close`. Hostname authentication and oNCP records use
  little-endian 16-bit lengths. The 20-byte KMP header supports data `300`,
  configuration `301`, ESP/rekey `302`, and MTU/ESP control `303`, matching
  `/tmp/openconnect/oncp.c:466-1076`.
- Initial KMP 301 may span records and may be preceded by bounded data records.
  It publishes IPv4 address/netmask, up to three DNS and NBNS addresses,
  search domains, include/exclude IPv4 routes, and MTU. KMP 300 can concatenate
  multiple IPv4 packets; every header and exact total length is validated.
  NC's inner data contract is IPv4-only.
- An IPv4 outer endpoint may negotiate compression 0/1, the shared AES/HMAC
  suites, replay policy, UDP port, DPD/fallback, SPI, and 64-byte secret. The
  client returns random nonzero key material in KMP 302, probes once per second
  for at most five attempts, and sends KMP 303 enable only after an
  authenticated response. Failure or server disable sends/observes KMP 303
  disable and immediately resumes KMP 300/TLS. A usable same-port KMP 302
  rekey atomically installs into the shared keyset; changed port, malformed
  parameters, invalid keys, or install failure disables ESP rather than the
  authenticated oNCP session.
- An IPv6 outer gateway deliberately does not negotiate ESP. It still returns
  the KMP 303 MTU response and transports IPv4 inner packets over KMP 300/TLS.
  This is an explicit, independently tested scope boundary, not an accidental
  inability to establish IPv6 TLS.
- Session close sends a bounded KMP 303 disable before closing an enabled ESP
  tunnel, then closes oNCP/TLS, waits its read/control loops, performs the
  accepted-IP-pinned HTTPS logout, and finally closes TNCC and clears DSID,
  keys, and configuration. Independent peers assert disable, TLS close, and
  logout order and prove that a poisoned later DNS result is never used.

### M4 independent peer and oracle matrix

| Test | Independent evidence | Contract proved |
| --- | --- | --- |
| `TestM4PulseUpstreamAuthenticationConfigurationAndTLSTunnel` | Byte-identical copy of `/tmp/openconnect/tests/fake-pulse-server.py` | Upstream direct and Juniper-2021 authentication, configuration, TLS packet echo. |
| `TestM4PulseIndependentTLSFullPeer` | Independent Go IF-T peer | HTTP 101 upgrade, Expanded auth, dual-stack configuration/data, ready/config visibility, clean close. |
| `TestM4PulseIndependentEAPTTLSFullPeer` | Independent Python TLS/EAP-TTLS peer | Client-certificate TLS, inner EAP, strict bidirectional `L|M`, total, identifier, ACK, and 8192-byte fragmentation, TLS data/family gate. |
| `TestM4PulseIndependentAuthenticationForms`, `TestM4PulseHostCheckerFailsTowardNC` | Independent Go auth peers | Ordered duplicate fields, realm/region/session/password/password-change/GTC paths, and specific Pulse Host Checker rejection. |
| `TestM4PulseIndependentESPLifecycle` | Independent Go IF-T/control peer, UDP relay, and C OpenSSL/liblzo2 oracle | CBC/HMAC/IV/sequence, IPv4/IPv6 and cross-family gates, replay on/off, valid/invalid LZO, retry/key preservation, sleeping-only `0x96`, NH 4/41, outer-invalid versus inner-failed rekey, same-socket atomic rekey and old-SA overlap, fatal/graceful cleanup. |
| `TestM4PulseCookieRejectionFallsBackToFullAuthentication`, `TestM4PulseAbnormalEOFUsesHTTPSLogout`, `TestM4PulseStalledTTLSAuthenticationCancellation` | Independent Go lifecycle peers | Initial/reestablishment event visibility, cookie rejection/full authentication, accepted-IP logout, and bounded cancellation. |
| `TestM4NetworkConnectAuthenticationPeerInterop` | Independent multi-origin HTTPS peer | Redirect/form/TOTP/role/SAML/DSID-on-403, ordered duplicate fields, X-Pad, DNS poison, pinned logout. |
| `TestM4NetworkConnectBuiltInTNCCPeerInterop`, `TestM4NetworkConnectBuiltInTNCCRejectsUnknownMandatoryPolicy` | Independent TNCC command/HTTPS peers | Two-stage and periodic built-in checks, identity inputs and backend pinning, bounded rejection of unknown mandatory policy. |
| `TestM4NetworkConnectExternalTNCCWrapperPeerInterop` | Test executable re-entered only as an fd-0 wrapper process | `start`/`setcookie`, environment, interval, process shutdown, oNCP handoff and logout. |
| `TestM4NetworkConnectONCPTLSPeerInterop` | Independent Go raw oNCP peer | Upgrade/framing, split KMP 301, KMP 303 MTU, concatenated KMP 300 IPv4 data, configuration-event readiness, close/logout. |
| `TestM4NetworkConnectONCPESPPeerInterop` | Independent Go oNCP/ESP peer | KMP 302 keys, 303 enable/disable, encrypted echo and close ordering. |
| `TestM4NetworkConnectONCPESPOracleInterop` | Independent Go oNCP control peer plus the C OpenSSL/liblzo2 oracle | AES-CBC/HMAC wire compatibility, replay rejection, valid LZO and three invalid LZO drop-only cases, fallback and cleanup. |
| `TestM4NetworkConnectONCPDisablesESPOverIPv6Peer` | Independent IPv6-loopback Go peer | IPv6 outer TLS with no ESP negotiation and IPv4 inner KMP 300 data. |

`test/testdata/pulse-esp-peer/SOURCE` pins the C oracle to the source commit
above. It shares no production crypto or compression code: OpenSSL performs
AES/HMAC and liblzo2 performs compression. Its `zero`, `continuation`, and
`zero-established` modes distinguish new SA sequence zero, a transport retry
with an existing SA, and same-socket rekey; `probe4`/`probe41`, `PROBE`, and
`DATA <next-header> <sequence>` outputs make probe family and hidden sequence
consumption hard assertions.

The other imported/independent Pulse assets carry the same explicit
provenance boundary. `test/testdata/fake-pulse/SOURCE` records that the
upstream fake is copied verbatim from that OpenConnect commit with its original
LGPL-2.1-or-later header. `test/testdata/pulse-peer/SOURCE` records that the
Python IF-T/EAP/EAP-TTLS peer is an independent wire implementation derived
from `pulse.c`, reuses no production parser or crypto, and uses Python's system
OpenSSL-backed `ssl` implementation for the peer side of TLS.

## M4 final verification

M4 Pulse/Network Connect is complete. The completed tree passed `make fmt`;
`go mod tidy` in both modules; `make test`; `go test -race ./...` and
`go vet ./...` in both modules; and `make lint`. The lint gate covered the five
configured root GOOS targets plus the test module with zero findings.

The final complete M4 real-peer set passed in the test module as
`OPENCONNECT_IT=1 go test -run '^TestM4' -v -count=1 -timeout=10m` in 10.345
seconds. Its race-enabled three-run gate passed as
`OPENCONNECT_IT=1 go test -run '^TestM4' -v -race -count=3 -timeout=10m` in
31.167 seconds. All three race iterations were green. The internal
`TestM4NetworkConnectExternalTNCCWrapperProcess` helper intentionally skips
when invoked by the Go test runner; every parent external-wrapper peer case
started that executable mode and passed.

In addition to those milestone-wide commands, the high-risk independent peers
passed these repeated targeted gates in the test module:

- `TestM4NetworkConnectONCPESPOracleInterop` passed ordinary `-count=5` and
  race-enabled `-count=5`; the complete `^TestM4NetworkConnect` group passed
  ordinary and race-enabled `-count=1`.
- `TestM4PulseIndependentESPLifecycle` passed ordinary `-count=3` and
  race-enabled `-count=5`.
- The strengthened `TestM4PulseIndependentEAPTTLSFullPeer` passed ordinary
  `-count=3`, race-enabled `-count=5`, and the later final race `-count=3`
  gate.
- The complete `^TestM4Pulse` group passed ordinary and race-enabled
  `-count=1`.
- Pulse initial ready/config visibility passed its dedicated race-enabled
  `-count=50`; the NC configuration-event visibility regression passed
  race-enabled `-count=50`; and the Pulse initial/reestablishment event
  regression passed race-enabled `-count=10`.

## Milestone ledger

| Milestone | State | Verified prerequisite or blocker |
| --- | --- | --- |
| M0 DTLS risk retirement | **Complete** | Dependency survey complete. Real ocserv 1.3.0-2 XML auth, CSTP DPD/data, exporter/App-ID, and Pion v3.1.5 DTLS DPD/data passed once and with `-count=3`. M1 later selected Pion for representable DTLS 1.2 paths and added the owned DTLS 0.9 layer. |
| M1 AnyConnect complete | **Complete** | C-01 through C-11 are adopted. Authentication/forms, XMLPOST/legacy/CERT1, SSO/cancellation, OATH/stoken current-plus-next, TLS/MCA material, combined CERT→MCA→action→CSD, CSD backend pin/wrapper, CSTP lifecycle/rekey/dynamic DNS, supervisor, modern PSK, injected DTLS 1.2 GCM, owned DTLS 0.9 AES/3DES/HelloVerify, path MTU, and DTLS-only SSL rekey have the real-peer coverage above. Milestone-wide format, tidy, test, race, vet, lint, and complete ordinary/race interop runs are green. An independent injected-session C/OpenSSL oracle additionally passes the four DTLS 1.2 RSA/DHE-RSA AES-CBC resumed cipher IDs with bidirectional data and close-notify; the abbreviated DHE-labelled runs do not claim a fresh DHE exchange. |
| M2 GlobalProtect | **Complete** | Portal/gateway auth, dynamic XML/JS/HTML challenge, auth group/region choice, browser-header SSO, opaque JNLP session and accepted-address pinning pass an independent auth peer plus the verbatim upstream fake's ten-case matrix. Config/GPST data/DPD, 502 reauth, EOF reestablishment, same-cookie rekey and preferred addresses pass a raw peer. Six AES-CBC/HMAC suites, IPv4/IPv6, sequence zero, IV chain, replay, DPD, five-second/late/socket fallback, and transient UDP retry pass the independent C/OpenSSL ESP oracle. Built-in/wrapper periodic HIP and GPST/ESP lifecycle pass. M4 closed the shared Juniper LZO residual for Pulse/NC; GP still rejects unnegotiated next-header `0x05` with its specific terminal error. Milestone-wide format, test, race, lint, and ordinary/race interop runs are green. |
| M3 Fortinet and F5 | **Complete** | F5/Fortinet auth, configuration, accepted-endpoint pinning, credential semantics, reconnect policy, shared PPP, TLS, certificate-authenticated DTLS 1.2, owned DTLS 1.0, carrier takeover/fallback, and cleanup pass the upstream-fake and complete independent-peer matrices. Twelve F5 and eighteen Fortinet full-peer cases carry real PPP data; thirteen standalone real-`pppd` cases prove framing/negotiation/lifecycle; the C/OpenSSL DTLS matrix and injected CBC residual pass ordinary and race count-three gates. The late-DTLS recovery and F5 DTLS 1.0 cleanup regressions additionally pass race count-ten. Milestone-wide format, tidy, test, race, vet, lint, and resource-cleanup gates are green. |
| M4 Pulse and NC | **Complete** | Pulse IF-T/EAP/EAP-TTLS authentication, strict fragmentation, forms, dual-stack configuration/data, cookie reconnect/logout, sleeping probe, IPv4/IPv6 family policy, shared ESP/LZO/replay, and same-socket rekey pass the upstream-derived fake, independent Python/Go peers, UDP relay, and C OpenSSL/liblzo2 oracle. NC HTTPS forms/SAML, built-in and external TNCC, oNCP/TLS, IPv4 ESP/replay/LZO/fallback, IPv6-outer TLS policy, accepted-address pinning, and ordered cleanup pass independent peers and the same C oracle. `TNCCOptions`, the ready/config/event publication gate, key preservation, and bounded previous-SA overlap have repeated ordinary/race evidence. Milestone-wide format, tidy, test, race, vet, lint, and combined ordinary/race M4 gates are recorded above. |

No milestone may be marked complete from parser-only, mirror, expected-failure,
or mocked transport tests. Completion requires the real-peer behavior named in
the milestone and a green `make fmt`, `make lint`, and `make test` run.

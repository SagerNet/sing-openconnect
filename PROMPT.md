# sing-openconnect — Mission Brief

You are the architect of `github.com/sagernet/sing-openconnect`, a new sing-box subproject.
This document fixes the mission, the large-scale structure, and the taste. Everything below
the "locked" line is binding; everything else is yours to decide. When a locked decision
proves impossible or wrong against verified upstream reality, STOP and report to the user —
never deviate silently.

## Mission

A pure-Go **client-only** implementation of the OpenConnect protocol family — the proprietary
corporate SSL VPN protocols that the `openconnect` C client speaks:

| flavor | compatible with | TCP tunnel | UDP channel | trojan (compliance probe) |
|---|---|---|---|---|
| `anyconnect` | Cisco AnyConnect / ocserv | CSTP over TLS | DTLS | CSD/hostscan |
| `gp` | Palo Alto GlobalProtect | gpst | ESP-in-UDP | HIP report (periodic) |
| `fortinet` | FortiGate | PPP over TLS | DTLS (PPP) | — |
| `f5` | F5 BIG-IP | PPP over TLS | DTLS (PPP) | — |
| `pulse` | Pulse/Ivanti Connect Secure | pulse | ESP-in-UDP | — |
| `nc` | Juniper Network Connect | oNCP | ESP-in-UDP | TNCC (periodic) |

The audience is people who CANNOT control the gateway they must connect to. Therefore the
compatibility criterion is: **support whatever deployed gateways in the wild require**,
including deprecated and legacy behavior (3DES-era crypto behind an explicit opt-in, XML-POST
fallback for old ASA, legacy DTLS session resumption, ...). Anything we do not support must
fail with a clear, specific error — never silent acceptance, never silent ignore.

## Non-goals (locked)

- **No server implementation.** ocserv already serves the "captive AnyConnect client" case;
  our server would compete with a reference implementation instead of filling a gap. The
  library's control-channel codecs should not preclude a future server, but do not design for it.
- No `array` flavor (negligible user base).
- No sing-box endpoint wiring in this repo (that is a later effort in sing-box itself), but
  the public API must make that wiring mechanical — see "Public API".
- No GUI work. No CLI beyond what tests need.
- No embedded-webview SSO plumbing: ALL our clients open auth URLs in the system browser.

## Ground truth (do not trust memory — read these)

- `openconnect` C source: clone `https://gitlab.com/openconnect/openconnect.git` to
  `/tmp/openconnect` (may already exist). This is the wire-format oracle for every flavor.
  Key entry points: `library.c` (the `vpn_proto` ops table fixes each flavor's decomposition),
  `openconnect.h` (the public model, incl. `oc_auth_form`/`oc_form_opt`), `auth*.c`, `cstp.c`,
  `dtls.c`, `esp*.c`, `ppp.c`, `gpst.c`, `oncp.c`, `pulse.c`, `f5.c`, `fortinet.c`, `csd.c`.
- `ocserv` (server oracle for anyconnect): clone `https://gitlab.com/openconnect/ocserv.git`.
- `/tmp/openconnect/tests/fake-*-server.py`: protocol emulators used by openconnect's own CI
  (cisco, gp, f5, fortinet, juniper, juniper-sso, pulse, tncc). These are our interop
  servers for flavors that have no open-source server.
- `../sing-openvpn`: the sibling project and the **structural precedent**. Read it before
  writing any code: flat package layout, `client_supervisor.go` reconnect/error-classification
  pattern, `Challenge`/`PendingChallenge()`/`ChallengeUpdated()`/`CompleteChallenge()` async
  auth surface, `TunnelConfiguration`, upstream-citing comment style, `test/` as a separate
  module with real Docker interop. Where a shape question has an answer in sing-openvpn,
  that answer wins by default.
- Wire-format claims in code comments must cite the upstream function you verified
  (e.g. `// Upstream cstp_connect sends ...`), same style as sing-openvpn.

## Locked design

### Public API (shape locked; refine names against sing-openvpn conventions)

The consumer is the future sing-box endpoint, which mirrors this API 1:1 into
adapter/daemon-gRPC/dashboard layers. It needs:

```go
type ClientOptions struct {
    Server     string // host[:port][/usergroup]
    Flavor     string // anyconnect | gp | fortinet | f5 | pulse | nc
    Username   string
    Password   string
    AuthGroup  string
    Token      *TokenOptions // built-in soft token: totp | hotp | stoken (RSA SecurID)
    ReportedOS string
    UserAgent  string
    CSD        *CSDOptions   // built-in emulation by default; external wrapper path as escape hatch
    NoUDP      bool          // disable DTLS/ESP secondary channel
    TLSConfig  ...           // caller-provided TLS material/verification, same pattern as sing-openvpn
    Dialer     N.Dialer
    Logger     logger.ContextLogger
    // NO fields for anything the protocol negotiates (addresses, routes, DNS, MTU, ciphers,
    // keepalive, rekey). Judgment rule for every future field: it exists only if it is pure
    // user input with no negotiated source.
}

// Interactive authentication is a first-class citizen: in this family, auth IS interactive
// (multi-round forms), not an error path. Generic form model:
type AuthForm struct {
    ID      string          // unique per instance; idempotent re-delivery
    Banner  string
    Message string
    Error   string          // why the previous round was rejected, when it was
    URL     string          // non-empty = SSO: open in system browser; completion detection
                            // (localhost redirect / cookie polling) is the LIBRARY's job
    Fields  []AuthFormField // empty = informational
}
type AuthFormField struct {
    Name    string          // submission key
    Label   string
    Kind    string          // text | password | select
    Value   string          // prefill
    Options []AuthFormChoice // select only (auth groups etc.)
}

func (c *Client) PendingAuthForm() *AuthForm
func (c *Client) AuthFormUpdated() <-chan struct{}     // closed-channel notify, re-arm per signal
func (c *Client) CompleteAuthForm(id string, values map[string]string) error
func (c *Client) CancelAuthForm(id string) error       // fail the session NOW, terminal auth error
```

Async discipline (locked): a protocol goroutine is NEVER parked on user input; form state
lives at the client/supervisor layer and survives session teardown and reconnects; pending
form is idempotently readable at any time; `TOKEN` fields (upstream `OC_FORM_OPT_TOKEN`) are
auto-filled from `TokenOptions` without surfacing a form; `HIDDEN` fields never surface.
Interactively submitted values are cached in Client memory for the client's lifetime —
reconnects and rekeys must not re-prompt. Session cookies are reused across reconnects until
the gateway rejects them. Nothing is ever persisted to disk.

Tunnel output mirrors sing-openvpn: a packet Read/Write surface plus a
`TunnelConfiguration` (addresses, routes, DNS, MTU, ...) delivered on establishment.

### Large-scale structure

Flat root package (family convention — no subpackages), files prefixed by area:

- **Flavor frontends** (auth phase, HTTPS): `anyconnect_auth.go`, `gp_auth.go`, ... Each
  flavor implements the two-phase decomposition upstream proved out in its `vpn_proto` ops:
  *obtain session* (forms → session cookie) and *connect tunnel* (cookie → established
  tunnel). Fix a small internal flavor interface on exactly that split.
- **Tunnel transports**: `cstp_*.go`, `gpst_*.go`, `oncp_*.go`, `pulse_*.go`, and a shared
  `ppp_*.go` (f5 + fortinet are PPP-over-TLS with different HTTP dressing).
- **Secondary channels**: `dtls_*.go`, and a userspace `esp_*.go` (encap, negotiated keys,
  replay window — sing-openvpn's `replay_window.go` is the precedent).
- **Common infra**: one HTTP client wrapper (cookie jar, per-flavor headers, proxy via
  Dialer), one form-parsing layer that normalizes XML (anyconnect) / HTML (f5, nc) / flavor
  JSON into the single `AuthForm` model, keepalive/DPD/rekey timer machinery, `client.go` +
  `client_supervisor.go` (reconnect, backoff, terminal-vs-retryable classification).
- **Trojans**: `csd_*.go`, `tncc_*.go`, `hip_*.go`. Built-in Go emulation as the default
  (port the behavior of upstream's `csd-post.sh` / `tncc.py` / `hipreport.sh` — that is what
  real users run anyway, and mobile has no shell); external script path as desktop escape
  hatch. gp/nc trojans are periodic — they hang off the session lifecycle.
- **Soft tokens**: `token_*.go` — TOTP/HOTP (RFC 6238/4226) and stoken (RSA SecurID). No
  yubioath (hardware), no OIDC.
- `test/`: separate Go module, real interop only.

### Testing policy (locked)

The sing-box `code-test` rule applies verbatim: only tests that exercise the real protocol
against a real peer; if the implementation is subtly wrong and the test still passes, the
test is worthless. Concretely:
- `anyconnect`: Docker ocserv (the reference server) — full matrix: password auth,
  multi-round + authgroup forms, cert auth, CSD, CSTP data, DTLS data, rekey, reconnect
  with cookie reuse. Plus `fake-cisco-server.py` where ocserv cannot express a Cisco quirk.
- Other flavors: the `fake-*-server.py` emulators from `/tmp/openconnect/tests/`.
- Cross-check trick: our client vs ocserv can be triangulated against the C `openconnect`
  client vs ocserv (same server config, compare negotiated results).
- No parse round-trips, no mirror tests, no form-model unit theater.

### Milestones (commit to `main` at each; no feature branches, no pushes)

- **M0 — risk retirement first**: the single highest technical risk is DTLS interop
  (legacy session-resumption DTLS and the modern PSK negotiation both live in
  `dtls.c` / ocserv; survey what a Go DTLS dependency can express BEFORE building on one).
  Spike: minimal CSTP connect + DTLS channel against ocserv. Report findings before M1.
- **M1 — `anyconnect` complete** (auth forms incl. multi-round/authgroup/token autofill/SSO,
  CSTP + keepalive/DPD/rekey, DTLS, CSD, supervisor, full ocserv suite). This milestone
  defines every shared surface; get it reviewed before starting M2.
- **M2 — `gp`** (auth + gpst + ESP + periodic HIP) vs fake-gp-server.
- **M3 — `fortinet` + `f5`** (shared PPP infra) vs fakes.
- **M4 — `pulse` + `nc`** (oNCP, TNCC) vs fakes.

## Taste

- `.claude/rules/*.md` in this repo are law: errors via `E` only, naming without
  abbreviations beyond the allowed list, comments ONLY for verified external contracts
  (cite the upstream function), `badjson`/`badoption` if any JSON surface appears here
  (it should not — options are plain Go; JSON lives in sing-box).
- `make fmt` / `make lint` / `make test` green at every milestone commit.
- Config-surface parsimony is a feature: every knob you avoid adding is support burden the
  user never pays. When upstream has a flag, ask whether it is user input or negotiable —
  only user input earns a field.
- Prefer boring, verifiable code over cleverness; this library will be read against a C
  codebase by people debugging gateway quirks at 2 a.m.
- Study library source instead of web-searching; clone anything you need to `/tmp`.
- Do not pipe expensive command output through grep/head/tail; read it whole.

## Execution model

You do not write code yourself: assign focused agents (one responsibility per agent — e.g.
infra, a flavor frontend, a transport, trojans, interop tests), give each the relevant slice
of this brief plus the upstream files to verify against, review their upstream-verification
reports, and integrate. Sequence agents so shared infra stabilizes before flavors fan out.
Keep a running architecture log in the repo (`SPEC.md`, committed) recording every locked
decision and every verified upstream fact, so later sessions inherit the context.

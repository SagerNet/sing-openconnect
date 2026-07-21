#!/usr/bin/env python3

import base64
import errno
import os
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse


MAXIMUM_FRAME = 131072
PPP_LCP = 0xC021
PPP_IPV4 = 0x0021
PPP_IPV6 = 0x0057
PPP_TERMINATE_REQUEST = 5
PPP_ECHO_REQUEST = 9

PORT = int(os.environ.get("PORT", "4433"))
CERTIFICATE = os.environ.get("CERTIFICATE", "/certs/server-cert.pem")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY", "/certs/server-key.pem")
DTLS_CERTIFICATE = os.environ.get("DTLS_CERTIFICATE", CERTIFICATE)
DTLS_PRIVATE_KEY = os.environ.get("DTLS_PRIVATE_KEY", PRIVATE_KEY)
OPENSSL = os.environ.get("OPENSSL", "openssl")
PPPD = os.environ.get("PPPD", "/usr/sbin/pppd")
PPPD_USE_SUDO = os.environ.get("PPPD_USE_SUDO", "0") == "1"
HDLC = os.environ.get("HDLC", "0") == "1"
DTLS = os.environ.get("DTLS", "0") == "1"
DTLS12 = os.environ.get("DTLS12", "1") == "1"
DTLS_DELAY = float(os.environ.get("DTLS_DELAY", "0"))
SPLIT_STREAM = os.environ.get("SPLIT_STREAM", "1") == "1"
FAIL_FIRST_TLS = os.environ.get("FAIL_FIRST_TLS", "0") == "1"
FAIL_FIRST_DTLS = os.environ.get("FAIL_FIRST_DTLS", "0") == "1"
REJECT_FIRST_TLS = os.environ.get("REJECT_FIRST_TLS", "0") == "1"
REJECT_FIRST_DTLS = os.environ.get("REJECT_FIRST_DTLS", "0") == "1"
MALFORMED_DTLS = os.environ.get("MALFORMED_DTLS", "0") == "1"
DEFER_PASSWORD = os.environ.get("DEFER_PASSWORD", "0") == "1"
NO_ROUTES = os.environ.get("NO_ROUTES", "0") == "1"
EXPECT_IPV6 = os.environ.get("EXPECT_IPV6", "1") == "1"
AUTH_FAILURE_STATUS = int(os.environ.get("AUTH_FAILURE_STATUS", "0"))
ADDRESS_INDEX = int(os.environ.get("ADDRESS_INDEX", "1"))
if ADDRESS_INDEX < 1 or ADDRESS_INDEX > 127:
    raise ValueError("ADDRESS_INDEX is outside the supported range")
SERVER_ADDRESS_ID = ADDRESS_INDEX * 2 - 1
CLIENT_ADDRESS_ID = ADDRESS_INDEX * 2
SERVER_IPV4 = "192.0.2.{}".format(SERVER_ADDRESS_ID)
CLIENT_IPV4 = "192.0.2.{}".format(CLIENT_ADDRESS_ID)
SERVER_IPV6 = "fe80::{:x}".format(SERVER_ADDRESS_ID)
CLIENT_IPV6 = "fe80::{:x}".format(CLIENT_ADDRESS_ID)

stop_event = threading.Event()
tunnel_access = threading.Lock()
tunnel_count = 0
configuration_count = 0
authentication_count = 0
pre_password_count = 0
dtls_session_rejected = False
child_process_access = threading.Lock()
child_process_condition = threading.Condition(child_process_access)
child_processes = {}
child_process_reapers = set()
privileged_child_processes = set()


def log(message):
    print(message, file=sys.stderr, flush=True)


def stop_peer(_signal_number, _frame):
    stop_event.set()
    signal_child_processes(signal.SIGTERM)


def signal_child_process_group(process, signal_number):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal_number)
    except (PermissionError, ProcessLookupError):
        pass


def signal_child_processes(signal_number):
    with child_process_condition:
        processes = [
            process for process_id, process in child_processes.items()
            if process_id not in privileged_child_processes
        ]
    for process in processes:
        signal_child_process_group(process, signal_number)


def register_child_process(process, privileged=False):
    with child_process_condition:
        child_processes[process.pid] = process
        if privileged:
            privileged_child_processes.add(process.pid)
        child_process_condition.notify_all()


def signal_privileged_child_process_group(process, signal_name):
    try:
        subprocess.run(
            ["sudo", "-n", "/bin/kill", "-" + signal_name, "-" + str(process.pid)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
    except subprocess.TimeoutExpired:
        log("F5_PEER_PRIVILEGED_KILL_TIMEOUT " + str(process.pid))


def terminate_child_process(process):
    with child_process_condition:
        if process.pid not in child_processes:
            return
        while process.pid in child_process_reapers:
            child_process_condition.wait()
        if process.pid not in child_processes:
            return
        child_process_reapers.add(process.pid)
        privileged = process.pid in privileged_child_processes
    try:
        if privileged:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                signal_privileged_child_process_group(process, "TERM")
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    signal_privileged_child_process_group(process, "KILL")
                    process.wait(timeout=2)
        else:
            signal_child_process_group(process, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                signal_child_process_group(process, signal.SIGKILL)
                process.wait(timeout=2)
    finally:
        with child_process_condition:
            if process.poll() is not None:
                child_processes.pop(process.pid, None)
                privileged_child_processes.discard(process.pid)
            child_process_reapers.discard(process.pid)
            child_process_condition.notify_all()


def terminate_all_child_processes(deadline):
    while True:
        with child_process_condition:
            processes = list(child_processes.values())
        if not processes:
            return True
        if time.monotonic() >= deadline:
            return False
        for process in processes:
            terminate_child_process(process)


signal.signal(signal.SIGTERM, stop_peer)
signal.signal(signal.SIGINT, stop_peer)
signal.signal(signal.SIGHUP, stop_peer)


def update_fcs(fcs, value):
    fcs ^= value
    for _ in range(8):
        if fcs & 1:
            fcs = (fcs >> 1) ^ 0x8408
        else:
            fcs >>= 1
    return fcs


def append_hdlc_byte(output, value):
    if value < 0x20 or value in (0x7D, 0x7E):
        output.extend((0x7D, value ^ 0x20))
    else:
        output.append(value)


def encode_hdlc(frame):
    fcs = 0xFFFF
    output = bytearray((0x7E,))
    for value in frame:
        fcs = update_fcs(fcs, value)
        append_hdlc_byte(output, value)
    fcs ^= 0xFFFF
    append_hdlc_byte(output, fcs & 0xFF)
    append_hdlc_byte(output, fcs >> 8)
    output.append(0x7E)
    return bytes(output)


class HDLCDecoder:
    def __init__(self):
        self.frame = bytearray()
        self.escaped = False

    def push(self, content):
        frames = []
        for value in content:
            if value == 0x7E:
                if self.frame:
                    frame = self.finish()
                    if frame is not None:
                        frames.append(frame)
                continue
            if self.escaped:
                value ^= 0x20
                self.escaped = False
            elif value == 0x7D:
                self.escaped = True
                continue
            if len(self.frame) >= MAXIMUM_FRAME:
                raise ValueError("HDLC frame exceeds bound")
            self.frame.append(value)
        return frames

    def finish(self):
        content = bytes(self.frame)
        self.frame.clear()
        self.escaped = False
        if len(content) < 3:
            return None
        fcs = 0xFFFF
        for value in content:
            fcs = update_fcs(fcs, value)
        if fcs != 0xF0B8:
            log("F5_PEER_BAD_HDLC_FCS")
            return None
        return content[:-2]


class F5FrameDecoder:
    def __init__(self, hdlc):
        self.hdlc = hdlc
        self.hdlc_decoder = HDLCDecoder()
        self.pending = bytearray()

    def push(self, content):
        if self.hdlc:
            return self.hdlc_decoder.push(content)
        if len(self.pending) + len(content) > MAXIMUM_FRAME:
            raise ValueError("F5 frame buffer exceeds bound")
        self.pending.extend(content)
        frames = []
        while len(self.pending) >= 4:
            if self.pending[:2] != b"\xf5\x00":
                raise ValueError("invalid F5 frame magic")
            length = int.from_bytes(self.pending[2:4], "big")
            if length == 0 or length > 65535:
                raise ValueError("invalid F5 frame length")
            if len(self.pending) < length + 4:
                break
            frames.append(bytes(self.pending[4:length + 4]))
            del self.pending[:length + 4]
        return frames


def encode_f5_frame(frame, hdlc):
    if hdlc:
        return encode_hdlc(frame)
    return b"\xf5\x00" + len(frame).to_bytes(2, "big") + frame


def ppp_protocol(frame):
    position = 0
    if len(frame) >= 2 and frame[:2] == b"\xff\x03":
        position = 2
    if position >= len(frame):
        return -1, position
    protocol = frame[position]
    position += 1
    if not protocol & 1:
        if position >= len(frame):
            return -1, position
        protocol = (protocol << 8) | frame[position]
        position += 1
    return protocol, position


def ensure_ppp_device():
    if sys.platform == "darwin":
        return
    if os.path.exists("/dev/ppp"):
        return
    try:
        os.mknod("/dev/ppp", 0o600 | 0o20000, os.makedev(108, 0))
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise


def spawn_pppd():
    ensure_ppp_device()
    parent_socket, child_socket = socket.socketpair()
    arguments = [
        PPPD, "nodetach", "notty", "noauth", "local", "debug",
        SERVER_IPV4 + ":" + CLIENT_IPV4, "mru", "1320", "mtu", "1320",
        "noipdefault", "nodefaultroute", "ipcp-accept-local", "ipcp-accept-remote", "novj",
        "ms-dns", "203.0.113.53", "ms-dns", "203.0.113.54",
        "ms-wins", "203.0.113.137", "ms-wins", "203.0.113.138",
        "+ipv6", "ipv6", "::{:x},::{:x}".format(SERVER_ADDRESS_ID, CLIENT_ADDRESS_ID),
    ]
    if sys.platform != "darwin":
        arguments.extend(("nodefaultroute6", "ipv6cp-accept-local", "ipv6cp-accept-remote"))
    else:
        arguments.append("ipv6cp-accept-local")
    arguments.extend((
        "lcp-echo-interval", "1", "lcp-echo-failure", "8",
        "nopcomp", "noaccomp",
    ))
    if PPPD_USE_SUDO:
        arguments = ["sudo", "-n"] + arguments
    process = subprocess.Popen(
        arguments,
        stdin=child_socket,
        stdout=child_socket,
        stderr=None,
        close_fds=True,
        start_new_session=True,
    )
    register_child_process(process, PPPD_USE_SUDO)
    child_socket.close()
    return process, parent_socket


class TLSTransport:
    def __init__(self, connection):
        self.connection = connection

    def recv(self, size):
        return self.connection.recv(size)

    def sendall(self, content):
        self.connection.sendall(content)

    def close(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.connection.close()


class OpenSSLTransport:
    def __init__(self, process):
        self.process = process

    def recv(self, size):
        return self.process.stdout.read(size)

    def sendall(self, content):
        self.process.stdin.write(content)
        self.process.stdin.flush()

    def close(self):
        signal_child_process_group(self.process, signal.SIGTERM)


def send_network_frames(transport, frames, kind, stream_state):
    if not frames:
        return
    if kind == "tls":
        content = b"".join(frames)
        if len(frames) > 1 and not stream_state["coalesced_logged"]:
            log("F5_PEER_STREAM_COALESCED")
            stream_state["coalesced_logged"] = True
        if SPLIT_STREAM and not stream_state["split_sent"] and len(content) > 4:
            transport.sendall(content[:1])
            transport.sendall(content[1:3])
            transport.sendall(content[3:])
            stream_state["split_sent"] = True
            log("F5_PEER_STREAM_SPLIT")
        else:
            transport.sendall(content)
        return
    for frame in frames:
        transport.sendall(frame)


def bridge_ppp(transport, kind, index):
    try:
        pppd_process, pppd_socket = spawn_pppd()
    except OSError as error:
        log("F5_PEER_PPPD_UNAVAILABLE " + str(error))
        transport.close()
        return
    done = threading.Event()
    client_decoder = F5FrameDecoder(HDLC if kind == "tls" else False)
    pppd_decoder = HDLCDecoder()
    stream_state = {"split_sent": False, "coalesced_logged": False}
    client_data_protocols = set()
    pppd_data_protocols = set()

    def from_pppd():
        coalesced = False
        try:
            while not done.is_set():
                content = pppd_socket.recv(65536)
                if not content:
                    return
                ppp_frames = pppd_decoder.push(content)
                network_frames = []
                for frame in ppp_frames:
                    protocol, payload_position = ppp_protocol(frame)
                    if protocol in (PPP_IPV4, PPP_IPV6) and protocol not in pppd_data_protocols:
                        pppd_data_protocols.add(protocol)
                        log("F5_PEER_PPPD_{} {}".format(
                            "IPV4" if protocol == PPP_IPV4 else "IPV6",
                            frame.hex(),
                        ))
                    if protocol == PPP_LCP and payload_position < len(frame) and frame[payload_position] == PPP_ECHO_REQUEST:
                        log("F5_PEER_PPPD_ECHO_REQUEST")
                    network_frames.append(encode_f5_frame(frame, HDLC if kind == "tls" else False))
                    if kind == "tls" and not coalesced and protocol in (PPP_IPV4, PPP_IPV6):
                        pppd_socket.settimeout(2.0)
                        try:
                            while len(network_frames) < 2:
                                additional = pppd_socket.recv(65536)
                                if not additional:
                                    break
                                for additional_frame in pppd_decoder.push(additional):
                                    additional_protocol, additional_position = ppp_protocol(additional_frame)
                                    if (additional_protocol in (PPP_IPV4, PPP_IPV6)
                                            and additional_protocol not in pppd_data_protocols):
                                        pppd_data_protocols.add(additional_protocol)
                                        log("F5_PEER_PPPD_{} {}".format(
                                            "IPV4" if additional_protocol == PPP_IPV4 else "IPV6",
                                            additional_frame.hex(),
                                        ))
                                    if (additional_protocol == PPP_LCP and additional_position < len(additional_frame)
                                            and additional_frame[additional_position] == PPP_ECHO_REQUEST):
                                        log("F5_PEER_PPPD_ECHO_REQUEST")
                                    network_frames.append(encode_f5_frame(
                                        additional_frame,
                                        HDLC if kind == "tls" else False,
                                    ))
                        except socket.timeout:
                            pass
                        finally:
                            pppd_socket.settimeout(None)
                        if len(network_frames) >= 2:
                            coalesced = True
                send_network_frames(transport, network_frames, kind, stream_state)
        except (BrokenPipeError, OSError, ValueError) as error:
            if not done.is_set():
                log("F5_PEER_PPPD_TO_NETWORK_ERROR " + str(error))
        finally:
            done.set()

    sender = threading.Thread(target=from_pppd, daemon=True)
    sender.start()
    try:
        while not done.is_set():
            content = transport.recv(65536)
            if not content:
                break
            for frame in client_decoder.push(content):
                protocol, payload_position = ppp_protocol(frame)
                if protocol in (PPP_IPV4, PPP_IPV6) and protocol not in client_data_protocols:
                    client_data_protocols.add(protocol)
                    log("F5_PEER_CLIENT_{} {}".format(
                        "IPV4" if protocol == PPP_IPV4 else "IPV6",
                        frame.hex(),
                    ))
                if protocol == PPP_LCP and payload_position < len(frame):
                    code = frame[payload_position]
                    if code == PPP_ECHO_REQUEST:
                        log("F5_PEER_CLIENT_ECHO_REQUEST")
                    elif code == PPP_TERMINATE_REQUEST:
                        log("F5_PEER_CLIENT_TERMINATE_REQUEST")
                if FAIL_FIRST_TLS and kind == "tls" and index == 1 and protocol in (PPP_IPV4, PPP_IPV6):
                    log("F5_PEER_FORCED_TLS_FAILURE")
                    return
                if FAIL_FIRST_DTLS and kind == "dtls" and index == 1 and protocol in (PPP_IPV4, PPP_IPV6):
                    log("F5_PEER_FORCED_DTLS_FAILURE")
                    transport.sendall(encode_f5_frame(b"\xff\x03\xc0\x21\x05\x7f\x00\x04", False))
                    time.sleep(0.1)
                    return
                pppd_socket.sendall(encode_hdlc(frame))
    except (BrokenPipeError, OSError, ValueError) as error:
        if not done.is_set():
            log("F5_PEER_NETWORK_TO_PPPD_ERROR " + str(error))
    finally:
        done.set()
        transport.close()
        try:
            pppd_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        pppd_socket.close()
        terminate_child_process(pppd_process)
        sender.join(timeout=5)
        time.sleep(0.25)
        log("F5_PEER_PPP_BRIDGE_CLOSED")


def read_http_request(connection):
    content = bytearray()
    while b"\r\n\r\n" not in content:
        chunk = connection.recv(4096)
        if not chunk:
            return None
        content.extend(chunk)
        if len(content) > 1024 * 1024:
            raise ValueError("HTTP header exceeds bound")
    header_content, body = bytes(content).split(b"\r\n\r\n", 1)
    lines = header_content.decode("iso-8859-1").split("\r\n")
    method, target, version = lines[0].split(" ", 2)
    headers = {}
    for line in lines[1:]:
        name, value = line.split(":", 1)
        headers[name.lower()] = value.strip()
    content_length = int(headers.get("content-length", "0"))
    while len(body) < content_length:
        chunk = connection.recv(content_length - len(body))
        if not chunk:
            raise ValueError("HTTP body ended early")
        body += chunk
    return method, target, version, headers, body[:content_length]


def send_http_response(connection, status, headers=None, body=b""):
    reason = {
        200: "OK",
        302: "Found",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        504: "Gateway Timeout",
    }[status]
    response_headers = {
        "Content-Length": str(len(body)),
        "Connection": "close",
    }
    if headers:
        response_headers.update(headers)
    encoded = "HTTP/1.1 {} {}\r\n".format(status, reason)
    for name, value in response_headers.items():
        if isinstance(value, list):
            for item in value:
                encoded += "{}: {}\r\n".format(name, item)
        else:
            encoded += "{}: {}\r\n".format(name, value)
    connection.sendall(encoded.encode("ascii") + b"\r\n" + body)


def authenticated(headers):
    cookie = headers.get("cookie", "")
    return "MRHSession=f5-full-session" in cookie and "F5_ST=" in cookie


def options_document():
    configured_dtls = DTLS and not (REJECT_FIRST_DTLS and dtls_session_rejected)
    dtls_port = PORT if configured_dtls and not HDLC else 0
    routes = "" if NO_ROUTES else """<LAN0>192.0.2.0/24 198.51.100.0/24</LAN0>
<LAN6_0>2001:db8::/32</LAN6_0>"""
    return """<?xml version="1.0" encoding="UTF-8"?>
<favorite><object>
<ur_Z>/Common/full-peer-Z</ur_Z>
<Session_ID>f5-full-session-id</Session_ID>
<idle_session_timeout>900</idle_session_timeout>
<IPV4_0>1</IPV4_0><IPV6_0>1</IPV6_0>
<tunnel_dtls>{dtls}</tunnel_dtls><tunnel_port_dtls>{port}</tunnel_port_dtls>
<dtls_v1_2_supported>{dtls12}</dtls_v1_2_supported>
<DNS0>203.0.113.53</DNS0><DNS1>203.0.113.54</DNS1>
<WINS0>203.0.113.137</WINS0><WINS1>203.0.113.138</WINS1>
<DNSSuffix0>f5.test</DNSSuffix0><DNS_SPLIT0>internal.f5.test</DNS_SPLIT0>
<SplitTunneling0>1</SplitTunneling0>
{routes}
<ExcludeSubnets0>198.51.100.128/25</ExcludeSubnets0>
<hdlc_framing>{hdlc}</hdlc_framing>
</object></favorite>""".format(
        dtls=1 if configured_dtls else 0,
        port=dtls_port,
        dtls12=1 if DTLS12 else 0,
        hdlc="yes" if HDLC else "no",
        routes=routes,
    ).encode()


def validate_tunnel_request(target, headers):
    parsed = urllib.parse.urlsplit(target)
    if parsed.path != "/myvpn":
        raise ValueError("unexpected tunnel path")
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    expected = {
        "sess": ["f5-full-session-id"],
        "hdlc_framing": ["yes" if HDLC else "no"],
        "ipv4": ["yes"],
        "ipv6": ["yes" if EXPECT_IPV6 else "no"],
        "Z": ["/Common/full-peer-Z"],
    }
    for name, value in expected.items():
        if query.get(name) != value:
            raise ValueError("unexpected tunnel query " + name)
    hostname = query.get("hostname", [""])[0]
    decoded_hostname = base64.b64decode(hostname, validate=True).decode()
    if not decoded_hostname:
        raise ValueError("empty tunnel hostname")
    if "cookie" in headers:
        raise ValueError("cookie leaked into F5 tunnel request")
    if "host" not in headers or "user-agent" not in headers:
        raise ValueError("missing F5 common header")
    log("F5_PEER_TUNNEL_REQUEST_EXACT")
    log("F5_PEER_TUNNEL_COOKIE_FREE")


def next_tunnel_index():
    global tunnel_count
    with tunnel_access:
        tunnel_count += 1
        return tunnel_count


def handle_tls_connection(connection):
    global authentication_count, configuration_count, pre_password_count
    try:
        request = read_http_request(connection)
        if request is None:
            return
        method, target, _version, headers, body = request
        parsed = urllib.parse.urlsplit(target)
        if method == "GET" and parsed.path == "/":
            send_http_response(connection, 302, {"Location": "/my.policy"})
            return
        if parsed.path == "/my.policy" and method == "GET":
            if DEFER_PASSWORD:
                form = b"""<html><body><form id="auth_form" method="post" action="/my.policy?step=password">
<input type="hidden" name="continue" value="yes">
</form></body></html>"""
            else:
                form = b"""<html><body><form id="auth_form" method="post" action="/my.policy">
<input type="text" name="username"><input type="password" name="password">
</form></body></html>"""
            send_http_response(connection, 200, {"Content-Type": "text/html"}, form)
            return
        if parsed.path == "/my.policy" and method == "POST":
            if DEFER_PASSWORD and parsed.query == "step=password":
                values = urllib.parse.parse_qs(body.decode(), keep_blank_values=True)
                if values.get("continue") != ["yes"]:
                    send_http_response(connection, 400)
                    return
                pre_password_count += 1
                form = b"""<html><body><form id="auth_form" method="post" action="/my.policy?step=authenticate">
<input type="text" name="username"><input type="password" name="password">
</form></body></html>"""
                send_http_response(connection, 200, {"Content-Type": "text/html"}, form)
                log("F5_PEER_PRE_PASSWORD_FORM_{}".format(pre_password_count))
                return
            values = urllib.parse.parse_qs(body.decode(), keep_blank_values=True)
            if values.get("username") != ["test"] or values.get("password") != ["test"]:
                send_http_response(connection, 403)
                return
            authentication_count += 1
            if AUTH_FAILURE_STATUS:
                form = b"""<html><body><form id="auth_form" method="post" action="/my.policy">
<input type="text" name="username"><input type="password" name="password">
</form></body></html>"""
                send_http_response(connection, AUTH_FAILURE_STATUS, {"Content-Type": "text/html"}, form)
                log("F5_PEER_AUTH_REJECTED_{}_{}".format(AUTH_FAILURE_STATUS, authentication_count))
                return
            expiration = "1z1z1z{}z3600".format(int(time.time()))
            send_http_response(connection, 302, {
                "Location": "/vdesk/webtop.eui",
                "Set-Cookie": [
                    "MRHSession=f5-full-session; Path=/; Secure; HttpOnly",
                    "F5_ST={}; Path=/; Secure; HttpOnly".format(expiration),
                ],
            })
            log("F5_PEER_AUTHENTICATED")
            log("F5_PEER_PRIMARY_PASSWORD_{}".format(authentication_count))
            return
        if parsed.path == "/vdesk/vpn/index.php3":
            if not authenticated(headers):
                send_http_response(connection, 403)
                return
            configuration_count += 1
            body = b"""<?xml version="1.0"?><favorites type="VPN">
<favorite><params>resourcename=/Common/full-peer</params></favorite></favorites>"""
            send_http_response(connection, 200, {"Content-Type": "application/xml"}, body)
            log("F5_PEER_PROFILE_{}".format(configuration_count))
            return
        if parsed.path == "/vdesk/vpn/connect.php3":
            if not authenticated(headers):
                send_http_response(connection, 403)
                return
            query = urllib.parse.parse_qs(parsed.query)
            if query.get("resourcename") != ["/Common/full-peer"]:
                send_http_response(connection, 400)
                return
            send_http_response(connection, 200, {"Content-Type": "application/xml"}, options_document())
            log("F5_PEER_OPTIONS")
            return
        if parsed.path == "/vdesk/hangup.php3":
            if not authenticated(headers):
                send_http_response(connection, 403)
                return
            send_http_response(connection, 200, body=b"logout")
            log("F5_PEER_LOGOUT")
            return
        if parsed.path == "/myvpn":
            validate_tunnel_request(target, headers)
            index = next_tunnel_index()
            if REJECT_FIRST_TLS and index == 1:
                send_http_response(connection, 504)
                log("F5_PEER_TLS_SESSION_REJECTED")
                return
            response = (
                "HTTP/1.1 200 OK\r\n"
                "X-VPN-client-IP: {}\r\n"
                "X-VPN-client-IPv6: {}\r\n\r\n"
            ).format(CLIENT_IPV4, CLIENT_IPV6).encode()
            connection.sendall(response)
            log("F5_PEER_TLS_TUNNEL_{}".format(index))
            bridge_ppp(TLSTransport(connection), "tls", index)
            return
        send_http_response(connection, 404)
    except (OSError, ValueError, UnicodeError) as error:
        log("F5_PEER_TLS_ERROR " + str(error))
    finally:
        try:
            connection.close()
        except OSError:
            pass


def tls_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(CERTIFICATE, PRIVATE_KEY)

    def record_sni(_connection, server_name, _context):
        log("F5_PEER_SNI_" + str(server_name))

    context.set_servername_callback(record_sni)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", PORT))
    listener.listen(16)
    listener.settimeout(0.5)
    handler_access = threading.Lock()
    handler_threads = []
    active_connections = set()

    def run_handler(connection):
        try:
            handle_tls_connection(connection)
        finally:
            with handler_access:
                active_connections.discard(connection)

    log("F5_PEER_TLS_LISTENING")
    try:
        while not stop_event.is_set():
            try:
                raw_connection, _address = listener.accept()
            except socket.timeout:
                continue
            raw_connection.settimeout(5)
            try:
                connection = context.wrap_socket(raw_connection, server_side=True)
            except (socket.timeout, ssl.SSLError) as error:
                log("F5_PEER_TLS_HANDSHAKE_ERROR " + str(error))
                raw_connection.close()
                continue
            connection.settimeout(None)
            with handler_access:
                active_connections.add(connection)
            handler = threading.Thread(target=run_handler, args=(connection,))
            handler.start()
            handler_threads.append(handler)
    finally:
        listener.close()
        with handler_access:
            connections = list(active_connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass
        for handler in handler_threads:
            handler.join()


def forward_openssl_stderr(process):
    for line in iter(process.stderr.readline, b""):
        text = line.decode(errors="replace").strip()
        if text:
            log("F5_PEER_OPENSSL " + text)


def read_openssl_request(process):
    content = bytearray()
    while b"\r\n\r\n" not in content:
        chunk = process.stdout.read(4096)
        if not chunk:
            return None
        content.extend(chunk)
        if len(content) > 1024 * 1024:
            raise ValueError("DTLS request exceeds bound")
    return bytes(content)


def dtls_server():
    global dtls_session_rejected
    if DTLS_DELAY > 0:
        stop_event.wait(DTLS_DELAY)
    while not stop_event.is_set():
        process = None
        stderr_thread = None
        try:
            arguments = [
                OPENSSL, "s_server", "-accept", str(PORT), "-cert", DTLS_CERTIFICATE,
                "-key", DTLS_PRIVATE_KEY, "-quiet", "-naccept", "1",
            ]
            if DTLS12:
                arguments.extend(("-dtls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256"))
            else:
                arguments.extend(("-dtls1", "-cipher", "ECDHE-RSA-AES128-SHA:@SECLEVEL=0"))
            process = subprocess.Popen(
                arguments,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                start_new_session=True,
            )
            register_child_process(process)
            stderr_thread = threading.Thread(target=forward_openssl_stderr, args=(process,), daemon=True)
            stderr_thread.start()
            stop_event.wait(0.2)
            if stop_event.is_set():
                return
            if process.poll() is not None:
                raise OSError("OpenSSL DTLS listener exited before accepting connections")
            log("F5_PEER_DTLS_LISTENING_{}".format("12" if DTLS12 else "10"))
            request = read_openssl_request(process)
            if request is None:
                continue
            header = request.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
            lines = header.split("\r\n")
            _method, target, _version = lines[0].split(" ", 2)
            headers = {}
            for line in lines[1:]:
                name, value = line.split(":", 1)
                headers[name.lower()] = value.strip()
            validate_tunnel_request(target, headers)
            index = next_tunnel_index()
            if REJECT_FIRST_DTLS and index == 1:
                process.stdin.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                process.stdin.flush()
                log("F5_PEER_DTLS_SESSION_REJECTED")
                dtls_session_rejected = True
                time.sleep(0.5)
                continue
            if MALFORMED_DTLS:
                process.stdin.write(b"not-an-http-response\r\n\r\n")
                process.stdin.flush()
                log("F5_PEER_DTLS_MALFORMED_RESPONSE")
                time.sleep(0.5)
                continue
            response = (
                "HTTP/1.1 200 OK\r\n"
                "X-VPN-client-IP: {}\r\n"
                "X-VPN-client-IPv6: {}\r\n\r\n"
            ).format(CLIENT_IPV4, CLIENT_IPV6).encode()
            process.stdin.write(response)
            process.stdin.flush()
            log("F5_PEER_DTLS_TUNNEL_{}".format(index))
            bridge_ppp(OpenSSLTransport(process), "dtls", index)
        except (BrokenPipeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
            log("F5_PEER_DTLS_ERROR " + str(error))
        finally:
            if process is not None:
                terminate_child_process(process)
            if stderr_thread is not None:
                stderr_thread.join(timeout=2)


def main():
    tls_thread = threading.Thread(target=tls_server, daemon=True)
    tls_thread.start()
    if DTLS and not HDLC:
        dtls_thread = threading.Thread(target=dtls_server, daemon=True)
        dtls_thread.start()
    else:
        dtls_thread = None
    try:
        while not stop_event.wait(0.5):
            pass
    finally:
        stop_event.set()
        signal_child_processes(signal.SIGTERM)
        shutdown_deadline = time.monotonic() + 12
        children_reaped = terminate_all_child_processes(shutdown_deadline)
        tls_thread.join(timeout=max(0, shutdown_deadline - time.monotonic()))
        if dtls_thread is not None:
            dtls_thread.join(timeout=max(0, shutdown_deadline - time.monotonic()))
        remaining_children_reaped = terminate_all_child_processes(shutdown_deadline)
        children_reaped = children_reaped and remaining_children_reaped
        if not tls_thread.is_alive() and (dtls_thread is None or not dtls_thread.is_alive()) and children_reaped:
            log("F5_PEER_CHILDREN_REAPED")
        else:
            log("F5_PEER_CLEANUP_INCOMPLETE")


if __name__ == "__main__":
    main()

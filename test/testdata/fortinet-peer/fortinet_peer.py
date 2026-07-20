#!/usr/bin/env python3

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
PPP_TERMINATE_ACKNOWLEDGEMENT = 6
PPP_ECHO_REQUEST = 9
PPP_CONFIGURE_ACK = 2

PORT = int(os.environ.get("PORT", "4433"))
CERTIFICATE = os.environ.get("CERTIFICATE", "/certs/server-cert.pem")
PRIVATE_KEY = os.environ.get("PRIVATE_KEY", "/certs/server-key.pem")
DTLS_CERTIFICATE = os.environ.get("DTLS_CERTIFICATE", CERTIFICATE)
DTLS_PRIVATE_KEY = os.environ.get("DTLS_PRIVATE_KEY", PRIVATE_KEY)
OPENSSL = os.environ.get("OPENSSL", "openssl")
PPPD = os.environ.get("PPPD", "/usr/sbin/pppd")
PPPD_USE_SUDO = os.environ.get("PPPD_USE_SUDO", "0") == "1"
DTLS = os.environ.get("DTLS", "0") == "1"
DTLS_DELAY = float(os.environ.get("DTLS_DELAY", "0"))
SPLIT_STREAM = os.environ.get("SPLIT_STREAM", "1") == "1"
FAIL_FIRST_TLS = os.environ.get("FAIL_FIRST_TLS", "0") == "1"
FAIL_FIRST_DTLS = os.environ.get("FAIL_FIRST_DTLS", "0") == "1"
REJECT_FIRST_TLS = os.environ.get("REJECT_FIRST_TLS", "0") == "1"
MALFORMED_DTLS = os.environ.get("MALFORMED_DTLS", "0") == "1"
LOST_DTLS_OK = os.environ.get("LOST_DTLS_OK", "0") == "1"
RECONNECT_ALLOWED = os.environ.get("RECONNECT_ALLOWED", "1") == "1"
CHECK_SOURCE_IP = os.environ.get("CHECK_SOURCE_IP", "1") == "1"
RECONNECT_TIMEOUT = int(os.environ.get("RECONNECT_TIMEOUT", "240"))
MALFORMED_SPLIT_DNS = os.environ.get("MALFORMED_SPLIT_DNS", "0") == "1"
MALFORMED_TRAILING_XML = os.environ.get("MALFORMED_TRAILING_XML", "0") == "1"
MAPPED_IPV6 = os.environ.get("MAPPED_IPV6", "0") == "1"
HTML_2FA = os.environ.get("HTML_2FA", "0") == "1"
REJECT_FIRST_LOGIN = os.environ.get("REJECT_FIRST_LOGIN", "0") == "1"
SAML = os.environ.get("SAML", "0") == "1"
FAIL_DTLS_PPP = os.environ.get("FAIL_DTLS_PPP", "0") == "1"
PPPD_MTU = int(os.environ.get("PPPD_MTU", "1320"))

stop_event = threading.Event()
tunnel_access = threading.Lock()
tunnel_count = 0
configuration_count = 0
authentication_count = 0
valid_cookies = set()
latest_cookie = None
login_rejected = False
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
        log("FORTINET_PEER_PRIVILEGED_KILL_TIMEOUT " + str(process.pid))


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
            log("FORTINET_PEER_BAD_HDLC_FCS")
            return None
        return content[:-2]


class FortinetFrameDecoder:
    def __init__(self):
        self.pending = bytearray()

    def push(self, content):
        if len(self.pending) + len(content) > MAXIMUM_FRAME:
            raise ValueError("Fortinet frame buffer exceeds bound")
        self.pending.extend(content)
        frames = []
        while len(self.pending) >= 6:
            total_length = int.from_bytes(self.pending[:2], "big")
            if self.pending[2:4] != b"PP":
                raise ValueError("invalid Fortinet frame magic")
            payload_length = int.from_bytes(self.pending[4:6], "big")
            if payload_length == 0 or total_length != payload_length + 6:
                raise ValueError("invalid Fortinet frame length")
            if len(self.pending) < total_length:
                break
            frames.append(bytes(self.pending[6:total_length]))
            del self.pending[:total_length]
        return frames


def encode_fortinet_frame(frame):
    total_length = len(frame) + 6
    return total_length.to_bytes(2, "big") + b"PP" + len(frame).to_bytes(2, "big") + frame


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
        "192.0.2.1:192.0.2.2", "mru", str(PPPD_MTU), "mtu", str(PPPD_MTU),
        "noipdefault", "nodefaultroute", "ipcp-accept-local", "ipcp-accept-remote", "novj",
        "ms-dns", "203.0.113.53", "ms-dns", "203.0.113.54",
        "ms-wins", "203.0.113.137", "ms-wins", "203.0.113.138",
        "+ipv6", "ipv6", "::1,::2",
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
    def __init__(self, connection, initial=b""):
        self.connection = connection
        self.initial = initial

    def recv(self, size):
        if self.initial:
            content = self.initial[:size]
            self.initial = self.initial[size:]
            return content
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


def send_network_frames(transport, frames, kind):
    if not frames:
        return
    if kind == "tls":
        content = b"".join(frames)
        if len(frames) > 1:
            log("FORTINET_PEER_STREAM_COALESCED")
        if SPLIT_STREAM and len(content) > 4:
            transport.sendall(content[:1])
            transport.sendall(content[1:3])
            transport.sendall(content[3:])
            log("FORTINET_PEER_STREAM_SPLIT")
        else:
            transport.sendall(content)
        return
    for frame in frames:
        transport.sendall(frame)


def bridge_ppp(transport, kind, index):
    try:
        pppd_process, pppd_socket = spawn_pppd()
    except OSError as error:
        log("FORTINET_PEER_PPPD_UNAVAILABLE " + str(error))
        transport.close()
        return
    done = threading.Event()
    client_decoder = FortinetFrameDecoder()
    pppd_decoder = HDLCDecoder()
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
                        log("FORTINET_PEER_PPPD_{} {}".format(
                            "IPV4" if protocol == PPP_IPV4 else "IPV6",
                            frame.hex(),
                        ))
                    if protocol == PPP_LCP and payload_position < len(frame) and frame[payload_position] == PPP_ECHO_REQUEST:
                        log("FORTINET_PEER_PPPD_ECHO_REQUEST")
                    network_frames.append(encode_fortinet_frame(frame))
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
                                        log("FORTINET_PEER_PPPD_{} {}".format(
                                            "IPV4" if additional_protocol == PPP_IPV4 else "IPV6",
                                            additional_frame.hex(),
                                        ))
                                    if (additional_protocol == PPP_LCP and additional_position < len(additional_frame)
                                            and additional_frame[additional_position] == PPP_ECHO_REQUEST):
                                        log("FORTINET_PEER_PPPD_ECHO_REQUEST")
                                    network_frames.append(encode_fortinet_frame(additional_frame))
                        except socket.timeout:
                            pass
                        finally:
                            pppd_socket.settimeout(None)
                        if len(network_frames) >= 2:
                            coalesced = True
                send_network_frames(transport, network_frames, kind)
        except (BrokenPipeError, OSError, ValueError) as error:
            if not done.is_set():
                log("FORTINET_PEER_PPPD_TO_NETWORK_ERROR " + str(error))
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
                    log("FORTINET_PEER_CLIENT_{} {}".format(
                        "IPV4" if protocol == PPP_IPV4 else "IPV6",
                        frame.hex(),
                    ))
                if protocol == PPP_LCP and payload_position < len(frame):
                    code = frame[payload_position]
                    if code == PPP_ECHO_REQUEST:
                        log("FORTINET_PEER_CLIENT_ECHO_REQUEST")
                    elif code == PPP_TERMINATE_REQUEST:
                        log("FORTINET_PEER_CLIENT_TERMINATE_REQUEST")
                    elif (code == PPP_CONFIGURE_ACK and len(frame) >= payload_position + 2
                          and frame[payload_position + 1] == 0x42):
                        log("FORTINET_PEER_CLIENT_ACKED_PPP_FIRST")
                if FAIL_FIRST_TLS and kind == "tls" and index == 1 and protocol in (PPP_IPV4, PPP_IPV6):
                    log("FORTINET_PEER_FORCED_TLS_FAILURE")
                    return
                if FAIL_FIRST_DTLS and kind == "dtls" and index == 1 and protocol in (PPP_IPV4, PPP_IPV6):
                    log("FORTINET_PEER_FORCED_DTLS_FAILURE")
                    transport.sendall(encode_fortinet_frame(b"\xff\x03\xc0\x21\x05\x7f\x00\x04"))
                    time.sleep(0.1)
                    return
                pppd_socket.sendall(encode_hdlc(frame))
    except (BrokenPipeError, OSError, ValueError) as error:
        if not done.is_set():
            log("FORTINET_PEER_NETWORK_TO_PPPD_ERROR " + str(error))
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
        log("FORTINET_PEER_PPP_BRIDGE_CLOSED")


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
    return method, target, version, headers, body[:content_length], body[content_length:]


def send_http_response(connection, status, headers=None, body=b""):
    reason = {
        200: "OK",
        302: "Found",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
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
    with tunnel_access:
        for value in valid_cookies:
            if "SVPNCOOKIE=" + value in cookie:
                return True
    return False


def replace_configuration_cookie(headers):
    global latest_cookie
    cookie_header = headers.get("cookie", "")
    with tunnel_access:
        old_cookie = latest_cookie
        if old_cookie is None or "SVPNCOOKIE=" + old_cookie not in cookie_header:
            raise ValueError("configuration did not use the latest Fortinet cookie")
        replacement = old_cookie + "-configured"
        valid_cookies.discard(old_cookie)
        valid_cookies.add(replacement)
        latest_cookie = replacement
        return replacement


def configuration_document():
    document = """<?xml version="1.0" encoding="UTF-8"?>
<sslvpn-tunnel ver="2" dtls="{dtls}" patch="1">
<dtls-config heartbeat-interval="1" heartbeat-fail-count="8"/>
<fos platform="IndependentFortigate" major="7" minor="4" patch="1" build="2463"/>
<auth-ses tun-connect-without-reauth="{reconnect}" check-src-ip="{check_ip}" tun-user-ses-timeout="{timeout}"/>
<ipv4>
<dns ip="203.0.113.53" domain="fortinet.test"/><dns ip="203.0.113.54"/>
<split-dns domains="internal.fortinet.test,corp.fortinet.test" dnsserver1="198.51.100.53" dnsserver2="{split_dns_2}"/>
<assigned-addr ipv4="192.0.2.2"/>
<split-tunnel-info><addr ip="192.0.2.0" mask="255.255.255.0"/><addr ip="198.51.100.0" mask="255.255.255.0"/></split-tunnel-info>
<split-tunnel-info negate="1"><addr ip="198.51.100.128" mask="255.255.255.128"/></split-tunnel-info>
</ipv4>
<ipv6>
<assigned-addr ipv6="{assigned_ipv6}" prefix-len="64"/>
<split-tunnel-info><addr ipv6="2001:db8::" prefix-len="32"/></split-tunnel-info>
<split-tunnel-info negate="1"><addr ipv6="2001:db8:ffff::" prefix-len="48"/></split-tunnel-info>
</ipv6>
<idle-timeout val="900"/><auth-timeout val="3600"/>
</sslvpn-tunnel>""".format(
        dtls=1 if DTLS else 0,
        reconnect=1 if RECONNECT_ALLOWED else 0,
        check_ip=1 if CHECK_SOURCE_IP else 0,
        timeout=RECONNECT_TIMEOUT,
        split_dns_2="not-an-address" if MALFORMED_SPLIT_DNS else "198.51.100.54",
        assigned_ipv6="::ffff:192.0.2.2" if MAPPED_IPV6 else "fe80::2",
    ).encode()
    if MAPPED_IPV6:
        log("FORTINET_PEER_MAPPED_IPV6_CONFIGURATION")
    if MALFORMED_TRAILING_XML:
        log("FORTINET_PEER_TRAILING_XML_CONFIGURATION")
        document += b"<unexpected/>"
    return document


def validate_tunnel_request(target, headers):
    parsed = urllib.parse.urlsplit(target)
    if parsed.path != "/remote/sslvpn-tunnel" or parsed.query:
        raise ValueError("unexpected tunnel path")
    if set(headers) != {"host", "user-agent", "cookie"}:
        raise ValueError("unexpected Fortinet tunnel headers " + repr(headers))
    if (headers.get("user-agent") != "Mozilla/5.0 SV1"
            or headers.get("cookie") != "SVPNCOOKIE=" + current_cookie()):
        raise ValueError("invalid Fortinet tunnel user agent or cookie")
    log("FORTINET_PEER_TLS_REQUEST_EXACT")


def validate_common_headers(headers):
    if headers.get("user-agent") != "Mozilla/5.0 SV1":
        raise ValueError("Fortinet protocol user agent was not forced")


def current_cookie():
    with tunnel_access:
        if latest_cookie is None:
            raise ValueError("no authenticated Fortinet cookie")
        return latest_cookie


def next_tunnel_index():
    global tunnel_count
    with tunnel_access:
        tunnel_count += 1
        return tunnel_count


def handle_tls_connection(connection):
    global authentication_count, configuration_count, latest_cookie, login_rejected
    try:
        request = read_http_request(connection)
        if request is None:
            return
        method, target, _version, headers, body, buffered = request
        parsed = urllib.parse.urlsplit(target)
        validate_common_headers(headers)
        if method == "GET" and not parsed.path.startswith("/remote/"):
            realm = parsed.path.removeprefix("/")
            location = "/remote/login"
            if realm:
                location += "?realm=" + urllib.parse.quote(realm, safe="")
            javascript = ('<html><script>top.location="{}";</script></html>'.format(location)).encode()
            send_http_response(connection, 200, {"Content-Type": "text/html"}, javascript)
            log("FORTINET_PEER_JAVASCRIPT_REDIRECT")
            return
        if parsed.path == "/remote/login" and method == "GET":
            send_http_response(connection, 200, body=b"Fortinet login page")
            return
        if parsed.path == "/remote/logincheck" and method == "POST":
            values = urllib.parse.parse_qs(body.decode(), keep_blank_values=True)
            if REJECT_FIRST_LOGIN and not login_rejected:
                login_rejected = True
                send_http_response(connection, 405)
                log("FORTINET_PEER_LOGIN_405")
                return
            if HTML_2FA and values.get("magic") != ["style-hidden-magic"]:
                if (values.get("username") != ["test"] or values.get("credential") != ["test"]
                        or values.get("realm") != ["fake+Realm"]):
                    send_http_response(connection, 403)
                    return
                challenge = b"""<html><body><form action="/remote/logincheck" method="POST">
<b>Enter the style-hidden Fortinet code</b>
<input type="text" style="display: none;" name="username" value="test">
<input type="text" style="display: none;" name="magic" value="style-hidden-magic">
<input type="password" name="credential"></form></body></html>"""
                send_http_response(connection, 401, {"Content-Type": "text/html"}, challenge)
                log("FORTINET_PEER_HTML_STYLE_CHALLENGE")
                return
            if HTML_2FA:
                if (values.get("username") != ["test"] or values.get("magic") != ["style-hidden-magic"]
                        or not values.get("credential") or values.get("credential") == ["test"]
                        or values.get("realm") != ["fake+Realm"]):
                    send_http_response(connection, 403)
                    return
                log("FORTINET_PEER_HTML_STYLE_RESPONSE")
            else:
                if (values.get("username") != ["test"] or values.get("credential") != ["test"]
                        or values.get("realm") != ["fake+Realm"]
                        or values.get("ajax") != ["1"] or values.get("just_logged_in") != ["1"]):
                    log("FORTINET_PEER_LOGIN_REJECTED " + repr(body))
                    send_http_response(connection, 403)
                    return
                expected_body = b"username=test&credential=test&realm=fake%2BRealm&ajax=1&just_logged_in=1"
                if body != expected_body:
                    raise ValueError("Fortinet login query was not exact: " + repr(body))
            if SAML:
                send_http_response(connection, 200, {"Content-Type": "text/html"},
                                   b"<html><body>Continue at /remote/saml/start</body></html>")
                log("FORTINET_PEER_SAML_CHALLENGE")
                log("FORTINET_PEER_LOGIN_QUERY_EXACT")
                return
            with tunnel_access:
                authentication_count += 1
                cookie = "fortinet-full-session-{}".format(authentication_count)
                valid_cookies.add(cookie)
                latest_cookie = cookie
            send_http_response(connection, 200, {
                "Set-Cookie": "SVPNCOOKIE={}; Path=/; Secure; HttpOnly".format(cookie),
            }, b"ret=1,redir=/remote/fortisslvpn_xml")
            log("FORTINET_PEER_AUTHENTICATED")
            log("FORTINET_PEER_LOGIN_QUERY_EXACT")
            return
        if parsed.path == "/remote/saml/start" and method == "GET":
            if not SAML or urllib.parse.parse_qs(parsed.query).get("realm") != ["fake+Realm"]:
                send_http_response(connection, 403)
                return
            with tunnel_access:
                authentication_count += 1
                cookie = "fortinet-saml-session-{}".format(authentication_count)
                valid_cookies.add(cookie)
                latest_cookie = cookie
            send_http_response(connection, 302, {
                "Location": "/sslvpn/portal/",
                "Set-Cookie": "SVPNCOOKIE={}; Path=/; Secure; HttpOnly".format(cookie),
            })
            log("FORTINET_PEER_SAML_BROWSER")
            log("FORTINET_PEER_AUTHENTICATED")
            return
        if parsed.path == "/sslvpn/portal/" and method == "GET":
            if not SAML or not authenticated(headers):
                send_http_response(connection, 403)
                return
            send_http_response(connection, 200, {"Content-Type": "text/html"}, b"<html>SAML complete</html>")
            return
        if parsed.path == "/remote/fortisslvpn_xml":
            if not authenticated(headers):
                send_http_response(connection, 403)
                return
            if parsed.query != "dual_stack=1":
                send_http_response(connection, 400)
                return
            configuration_count += 1
            replacement_cookie = replace_configuration_cookie(headers)
            send_http_response(connection, 200, {
                "Content-Type": "application/xml",
                "Set-Cookie": "SVPNCOOKIE={}; Path=/; Secure; HttpOnly".format(replacement_cookie),
            }, configuration_document())
            log("FORTINET_PEER_CONFIGURATION_{}".format(configuration_count))
            log("FORTINET_PEER_COOKIE_REPLACED")
            return
        if parsed.path == "/remote/logout":
            if not authenticated(headers):
                send_http_response(connection, 403)
                return
            send_http_response(connection, 200, body=b"logout")
            log("FORTINET_PEER_LOGOUT")
            return
        if parsed.path == "/remote/sslvpn-tunnel":
            validate_tunnel_request(target, headers)
            index = next_tunnel_index()
            log("FORTINET_PEER_TUNNEL_ATTEMPT_{}".format(index))
            if REJECT_FIRST_TLS and index == 1:
                connection.sendall(b"HT")
                time.sleep(0.02)
                connection.sendall(b"TP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                log("FORTINET_PEER_TLS_SESSION_REJECTED")
                return
            log("FORTINET_PEER_TLS_TUNNEL_{}".format(index))
            bridge_ppp(TLSTransport(connection, buffered), "tls", index)
            return
        send_http_response(connection, 404)
    except (OSError, ValueError, UnicodeError) as error:
        log("FORTINET_PEER_TLS_ERROR " + str(error))
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
        log("FORTINET_PEER_SNI_" + str(server_name))

    context.set_servername_callback(record_sni)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", PORT))
    listener.listen(16)
    listener.settimeout(0.5)
    log("FORTINET_PEER_TLS_LISTENING")
    while not stop_event.is_set():
        try:
            raw_connection, _address = listener.accept()
        except socket.timeout:
            continue
        raw_connection.settimeout(5)
        try:
            connection = context.wrap_socket(raw_connection, server_side=True)
        except (socket.timeout, ssl.SSLError) as error:
            log("FORTINET_PEER_TLS_HANDSHAKE_ERROR " + str(error))
            raw_connection.close()
            continue
        connection.settimeout(None)
        threading.Thread(target=handle_tls_connection, args=(connection,), daemon=True).start()
    listener.close()


def forward_openssl_stderr(process):
    for line in iter(process.stderr.readline, b""):
        text = line.decode(errors="replace").strip()
        if text:
            log("FORTINET_PEER_OPENSSL " + text)


def read_exact(stream, length):
    content = bytearray()
    while len(content) < length:
        chunk = stream.read(length - len(content))
        if not chunk:
            return None
        content.extend(chunk)
    return bytes(content)


def read_openssl_request(process):
    header = read_exact(process.stdout, 2)
    if header is None:
        return None
    total_length = int.from_bytes(header, "big")
    if total_length < 2 or total_length > 65535:
        raise ValueError("DTLS request has invalid length")
    payload = read_exact(process.stdout, total_length - 2)
    if payload is None:
        raise ValueError("DTLS request ended early")
    return header + payload


def validate_dtls_client_hello(request):
    prefix = b"GFtype\0clthello\0SVPNCOOKIE\0"
    if len(request) < len(prefix) + 4 or int.from_bytes(request[:2], "big") != len(request):
        raise ValueError("invalid Fortinet DTLS client hello length")
    payload = request[2:]
    if not payload.startswith(prefix) or not payload.endswith(b"\0"):
        raise ValueError("invalid Fortinet DTLS client hello structure")
    cookie = payload[len(prefix):-1].decode()
    if cookie != current_cookie():
        raise ValueError("Fortinet DTLS client hello used an invalid cookie")
    log("FORTINET_PEER_DTLS_HELLO_EXACT")


def dtls_server_hello():
    payload = b"GFtype\0svrhello\0handshake\0ok\0"
    return (len(payload) + 2).to_bytes(2, "big") + payload


def dtls_server():
    if DTLS_DELAY > 0:
        stop_event.wait(DTLS_DELAY)
    while not stop_event.is_set():
        arguments = [
            OPENSSL, "s_server", "-accept", str(PORT), "-cert", DTLS_CERTIFICATE,
            "-key", DTLS_PRIVATE_KEY, "-quiet", "-naccept", "1",
        ]
        arguments.extend(("-dtls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256"))
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            start_new_session=True,
        )
        register_child_process(process)
        threading.Thread(target=forward_openssl_stderr, args=(process,), daemon=True).start()
        time.sleep(0.2)
        if stop_event.is_set():
            return
        if process.poll() is not None:
            log("FORTINET_PEER_DTLS_ERROR OpenSSL listener exited before accepting connections")
            terminate_child_process(process)
            return
        log("FORTINET_PEER_DTLS_LISTENING_12")
        try:
            request = read_openssl_request(process)
            if request is None:
                process.wait(timeout=5)
                continue
            validate_dtls_client_hello(request)
            index = next_tunnel_index()
            log("FORTINET_PEER_TUNNEL_ATTEMPT_{}".format(index))
            if MALFORMED_DTLS:
                process.stdin.write(b"\x00\x05bad")
                process.stdin.flush()
                log("FORTINET_PEER_DTLS_MALFORMED_RESPONSE")
                return
            if LOST_DTLS_OK:
                synthetic_lcp = b"\xff\x03\xc0\x21\x01\x42\x00\x04"
                process.stdin.write(encode_fortinet_frame(synthetic_lcp))
                log("FORTINET_PEER_DTLS_PPP_FIRST")
            else:
                process.stdin.write(dtls_server_hello())
            process.stdin.flush()
            log("FORTINET_PEER_DTLS_TUNNEL_{}".format(index))
            if FAIL_DTLS_PPP:
                while True:
                    ppp_request = read_openssl_request(process)
                    if ppp_request is None:
                        raise ValueError("Fortinet DTLS peer closed before its first PPP request")
                    if ppp_request[2:].startswith(b"GFtype\0clthello\0"):
                        validate_dtls_client_hello(ppp_request)
                        process.stdin.write(dtls_server_hello())
                        process.stdin.flush()
                        continue
                    frames = FortinetFrameDecoder().push(ppp_request)
                    if len(frames) != 1:
                        raise ValueError("Fortinet DTLS peer sent an invalid initial PPP datagram")
                    protocol, payload_position = ppp_protocol(frames[0])
                    if protocol != PPP_LCP:
                        raise ValueError("Fortinet DTLS peer did not start with LCP")
                    break
                terminate_request = b"\xff\x03\xc0\x21\x05\x7f\x00\x04"
                process.stdin.write(encode_fortinet_frame(terminate_request))
                process.stdin.flush()
                while True:
                    acknowledgement = read_openssl_request(process)
                    if acknowledgement is None:
                        raise ValueError("Fortinet DTLS peer closed before acknowledging termination")
                    frames = FortinetFrameDecoder().push(acknowledgement)
                    if len(frames) != 1:
                        raise ValueError("Fortinet DTLS peer sent an invalid termination datagram")
                    protocol, payload_position = ppp_protocol(frames[0])
                    if (protocol == PPP_LCP and payload_position + 1 < len(frames[0])
                            and frames[0][payload_position] == PPP_TERMINATE_ACKNOWLEDGEMENT
                            and frames[0][payload_position + 1] == 0x7f):
                        log("FORTINET_PEER_DTLS_PPP_NEGOTIATION_FAILED")
                        return
            bridge_ppp(OpenSSLTransport(process), "dtls", index)
        except (BrokenPipeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
            log("FORTINET_PEER_DTLS_ERROR " + str(error))
        finally:
            terminate_child_process(process)


def main():
    tls_thread = threading.Thread(target=tls_server, daemon=True)
    tls_thread.start()
    if DTLS:
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
            log("FORTINET_PEER_CHILDREN_REAPED")
        else:
            log("FORTINET_PEER_CLEANUP_INCOMPLETE")


if __name__ == "__main__":
    main()

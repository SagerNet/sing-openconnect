#!/usr/bin/env python3

import argparse
import socket
import ssl
import struct
import sys


VENDOR_TCG = 0x5597
VENDOR_JUNIPER = 0x0A4C
VENDOR_JUNIPER2 = 0x0583
AUTH_JUNIPER = (VENDOR_JUNIPER << 8) | 1
EXPANDED_JUNIPER = 0xFE000A4C
AVP_EAP_MESSAGE = 79
TTLS_LENGTH = 0x80
TTLS_MORE = 0x40
TTLS_START = 0x20
TTLS_FRAGMENT = 8192


def read_exact(stream, length):
    content = bytearray()
    while len(content) < length:
        fragment = stream.read(length - len(content))
        if not fragment:
            raise RuntimeError("unexpected EOF")
        content.extend(fragment)
    return bytes(content)


def write_all(stream, content):
    view = memoryview(content)
    while view:
        written = stream.write(view)
        if not written:
            raise RuntimeError("short write")
        view = view[written:]
    stream.flush()


def read_http(stream):
    lines = []
    while True:
        line = stream.readline()
        if not line:
            raise RuntimeError("HTTP request ended early")
        if line in (b"\r\n", b"\n"):
            break
        lines.append(line.rstrip(b"\r\n"))
    if not lines or not lines[0].startswith(b"GET / HTTP/1.1"):
        raise RuntimeError("invalid HTTP upgrade request")
    headers = {}
    for line in lines[1:]:
        name, value = line.split(b":", 1)
        headers[name.strip().lower()] = value.strip()
    if headers.get(b"content-type") != b"EAP" or headers.get(b"upgrade") != b"IF-T/TLS 1.0":
        raise RuntimeError("missing IF-T/TLS upgrade headers")


def read_frame(stream):
    header = read_exact(stream, 16)
    vendor, frame_type, length, sequence = struct.unpack(">LLLL", header)
    if length < 16 or length > 1024 * 1024:
        raise RuntimeError("invalid IF-T length")
    return vendor, frame_type, sequence, read_exact(stream, length - 16)


def write_frame(stream, vendor, frame_type, sequence, payload):
    write_all(stream, struct.pack(">LLLL", vendor, frame_type, 16 + len(payload), sequence) + payload)


def build_eap(code, identifier, eap_type, subtype, payload):
    if eap_type == 0xFE:
        content = struct.pack(">BBHLL", code, identifier, 12 + len(payload), EXPANDED_JUNIPER, subtype)
    else:
        content = struct.pack(">BBHB", code, identifier, 5 + len(payload), eap_type)
    return content + payload


def parse_eap(content):
    if len(content) < 4:
        raise RuntimeError("short EAP packet")
    code, identifier, length = struct.unpack(">BBH", content[:4])
    if length != len(content):
        raise RuntimeError("EAP length mismatch")
    if len(content) == 4:
        return code, identifier, 0, 0, b""
    if content[4] == 0xFE:
        if len(content) < 12:
            raise RuntimeError("short expanded EAP packet")
        expanded, subtype = struct.unpack(">LL", content[4:12])
        return code, identifier, expanded, subtype, content[12:]
    return code, identifier, content[4], 0, content[5:]


def build_authentication_eap(code, identifier, eap_type, subtype, payload):
    return struct.pack(">L", AUTH_JUNIPER) + build_eap(code, identifier, eap_type, subtype, payload)


def parse_authentication(payload):
    if len(payload) < 4 or struct.unpack(">L", payload[:4])[0] != AUTH_JUNIPER:
        raise RuntimeError("missing Juniper auth type")
    return parse_eap(payload[4:])


def append_avp(content, code, vendor, data):
    header_length = 8
    flags = 0x40
    if vendor:
        header_length = 12
        flags |= 0x80
    length = header_length + len(data)
    result = struct.pack(">LL", code, (flags << 24) | length)
    if vendor:
        result += struct.pack(">L", vendor)
    result += data
    result += b"\0" * ((4 - (length & 3)) & 3)
    return content + result


def parse_avps(content):
    attributes = []
    while content:
        if len(content) < 8:
            raise RuntimeError("short AVP")
        code, flags_length = struct.unpack(">LL", content[:8])
        flags = flags_length >> 24
        length = flags_length & 0xFFFFFF
        header_length = 12 if flags & 0x80 else 8
        aligned_length = (length + 3) & ~3
        if length < header_length or aligned_length > len(content):
            raise RuntimeError("invalid AVP length")
        vendor = struct.unpack(">L", content[8:12])[0] if header_length == 12 else 0
        attributes.append((code, vendor, content[header_length:length]))
        content = content[aligned_length:]
    return attributes


def avp_value(attributes, code, vendor):
    for attribute_code, attribute_vendor, data in attributes:
        if attribute_code == code and attribute_vendor == vendor:
            return data
    return None


class InnerTLSPeer:
    def __init__(self, stream, context):
        self.stream = stream
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.connection = context.wrap_bio(self.incoming, self.outgoing, server_side=True)
        self.sequence = 20
        self.identifier = 10
        self.expected_client_identifier = 9
        self.client_fragmented_messages = 0
        self.server_fragmented_messages = 0

    def drain(self):
        chunks = []
        while True:
            chunk = self.outgoing.read()
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def send_message(self, content):
        if not content:
            return
        if len(content) > TTLS_FRAGMENT:
            self.server_fragmented_messages += 1
        remaining = content
        first = True
        while len(remaining) > TTLS_FRAGMENT:
            flags = TTLS_MORE
            payload = b""
            if first:
                flags |= TTLS_LENGTH
                payload = struct.pack(">L", len(content))
                first = False
            payload += remaining[:TTLS_FRAGMENT]
            self.identifier += 1
            self.expected_client_identifier = self.identifier
            write_frame(
                self.stream,
                VENDOR_TCG,
                5,
                self.sequence,
                build_authentication_eap(1, self.identifier, 0x15, 0, bytes([flags]) + payload),
            )
            self.sequence += 1
            vendor, frame_type, _, response = read_frame(self.stream)
            code, identifier, eap_type, _, ack = parse_authentication(response)
            if vendor != VENDOR_TCG or frame_type != 6 or code != 2 or identifier != self.identifier or eap_type != 0x15 or ack != b"\0":
                raise RuntimeError("invalid client TTLS acknowledgement")
            remaining = remaining[TTLS_FRAGMENT:]
        self.identifier += 1
        self.expected_client_identifier = self.identifier
        write_frame(
            self.stream,
            VENDOR_TCG,
            5,
            self.sequence,
            build_authentication_eap(1, self.identifier, 0x15, 0, b"\0" + remaining),
        )
        self.sequence += 1

    def receive_message(self):
        assembled = bytearray()
        expected = None
        fragment_count = 0
        while True:
            vendor, frame_type, _, payload = read_frame(self.stream)
            fragment_count += 1
            code, identifier, eap_type, _, ttls = parse_authentication(payload)
            if vendor != VENDOR_TCG or frame_type != 6 or code != 2 or eap_type != 0x15 or not ttls:
                raise RuntimeError("invalid client TTLS frame")
            if identifier != self.expected_client_identifier:
                raise RuntimeError("client TTLS fragment identifier mismatch")
            flags = ttls[0]
            fragment = ttls[1:]
            if not assembled and flags & TTLS_MORE:
                if not flags & TTLS_LENGTH:
                    raise RuntimeError("initial client TTLS fragment omitted its length flag")
                if len(fragment) < 4:
                    raise RuntimeError("missing client TTLS length")
                expected = struct.unpack(">L", fragment[:4])[0]
                fragment = fragment[4:]
                if expected <= TTLS_FRAGMENT or len(fragment) != TTLS_FRAGMENT:
                    raise RuntimeError("invalid initial client TTLS fragment boundary")
            elif flags & TTLS_LENGTH:
                raise RuntimeError("repeated client TTLS length")
            if flags & TTLS_MORE and len(fragment) != TTLS_FRAGMENT:
                raise RuntimeError("invalid continued client TTLS fragment boundary")
            if not flags & TTLS_MORE and len(fragment) > TTLS_FRAGMENT:
                raise RuntimeError("invalid final client TTLS fragment boundary")
            assembled.extend(fragment)
            if not flags & TTLS_MORE:
                break
            self.identifier += 1
            self.expected_client_identifier = self.identifier
            write_frame(
                self.stream,
                VENDOR_TCG,
                5,
                self.sequence,
                build_authentication_eap(1, self.identifier, 0x15, 0, b"\0"),
            )
            self.sequence += 1
        if expected is not None and expected != len(assembled):
            raise RuntimeError("client TTLS total length mismatch")
        if fragment_count > 1:
            self.client_fragmented_messages += 1
        return bytes(assembled)

    def handshake(self):
        while True:
            try:
                self.connection.do_handshake()
                break
            except ssl.SSLWantReadError:
                output = self.drain()
                if output:
                    self.send_message(output)
                self.incoming.write(self.receive_message())
        output = self.drain()
        if output:
            self.send_message(output)
        if not self.connection.getpeercert(binary_form=True):
            raise RuntimeError("inner EAP-TTLS client certificate was not received")
        if self.client_fragmented_messages == 0:
            raise RuntimeError("inner EAP-TTLS client handshake was not fragmented")

    def receive_plaintext(self):
        while True:
            try:
                return self.connection.read(65536)
            except ssl.SSLWantReadError:
                output = self.drain()
                if output:
                    self.send_message(output)
                self.incoming.write(self.receive_message())

    def send_plaintext(self, content):
        view = memoryview(content)
        while view:
            try:
                written = self.connection.write(view)
                view = view[written:]
            except ssl.SSLWantWriteError:
                pass
        self.send_message(self.drain())


def parse_inner_eap_message(content):
    if len(content) < 8:
        raise RuntimeError("short inner EAP AVP")
    code, flags_length = struct.unpack(">LL", content[:8])
    length = flags_length & 0xFFFFFF
    if code != AVP_EAP_MESSAGE or length != len(content):
        raise RuntimeError("inner EAP AVP length mismatch")
    return parse_eap(content[8:])


def build_inner_eap_message(eap):
    return struct.pack(">LL", AVP_EAP_MESSAGE, (0x40 << 24) | (8 + len(eap))) + eap


def append_attribute(content, attribute_type, data):
    return content + struct.pack(">HH", attribute_type, len(data)) + data


def build_main_configuration():
    routing = b"\x2e\0\0\x08\0\0\0\0"
    attributes = b"\0\0\0\0\x03\0\0\0"
    attributes = append_attribute(attributes, 0x0001, socket.inet_aton("192.0.2.20"))
    attributes = append_attribute(attributes, 0x0002, socket.inet_aton("255.255.255.0"))
    attributes = append_attribute(attributes, 0x0003, socket.inet_aton("198.51.100.54"))
    attributes = append_attribute(attributes, 0x4005, struct.pack(">L", 1400))
    attributes = struct.pack(">L", len(attributes)) + attributes[4:]
    section = routing + attributes
    payload = bytearray(28 + len(section))
    struct.pack_into(">L", payload, 16, 0x2C20F000)
    struct.pack_into(">L", payload, 24, len(payload))
    payload[28:] = section
    return bytes(payload)


def exchange(stream, inner_context):
    read_http(stream)
    write_all(stream, b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
    vendor, frame_type, _, payload = read_frame(stream)
    if vendor != VENDOR_TCG or frame_type != 1 or payload != b"\0\x01\x02\x02":
        raise RuntimeError("invalid version request")
    write_frame(stream, VENDOR_TCG, 2, 1, b"\0\0\0\x02")
    vendor, frame_type, _, payload = read_frame(stream)
    if vendor != VENDOR_JUNIPER or frame_type != 0x88 or b"clientCapabilities={}" not in payload:
        raise RuntimeError("invalid client information")
    write_frame(stream, VENDOR_TCG, 5, 2, struct.pack(">L", AUTH_JUNIPER))
    vendor, frame_type, _, payload = read_frame(stream)
    code, _, eap_type, _, identity = parse_authentication(payload)
    if vendor != VENDOR_TCG or frame_type != 6 or code != 2 or eap_type != 1 or identity != b"anonymous":
        raise RuntimeError("invalid outer identity")
    write_frame(
        stream,
        VENDOR_TCG,
        5,
        3,
        build_authentication_eap(1, 9, 0x15, 0, bytes([TTLS_START])),
    )
    inner = InnerTLSPeer(stream, inner_context)
    inner.handshake()
    code, _, eap_type, _, identity = parse_inner_eap_message(inner.receive_plaintext())
    if code != 2 or eap_type != 1 or identity != b"anonymous":
        raise RuntimeError("invalid inner identity")
    server_attributes = append_avp(b"", 0xD56, VENDOR_JUNIPER2, b"L" * 12000)
    server_information = build_eap(1, 40, 0xFE, 1, server_attributes)
    inner.send_plaintext(build_inner_eap_message(server_information))
    if inner.server_fragmented_messages == 0:
        raise RuntimeError("inner EAP-TTLS server message was not fragmented")
    code, _, eap_type, subtype, client_information = parse_inner_eap_message(inner.receive_plaintext())
    if code != 2 or eap_type != EXPANDED_JUNIPER or subtype != 1:
        raise RuntimeError("invalid client platform EAP")
    platform_attributes = parse_avps(client_information)
    if avp_value(platform_attributes, 0xD5E, VENDOR_JUNIPER2) != b"Linux":
        raise RuntimeError("invalid client platform")
    password_inner = build_eap(1, 41, 0xFE, 2, b"\x01")
    password_attributes = append_avp(b"", AVP_EAP_MESSAGE, 0, password_inner)
    inner.send_plaintext(build_inner_eap_message(build_eap(1, 42, 0xFE, 1, password_attributes)))
    code, _, eap_type, subtype, credentials = parse_inner_eap_message(inner.receive_plaintext())
    if code != 2 or eap_type != EXPANDED_JUNIPER or subtype != 1:
        raise RuntimeError("invalid credential EAP")
    credential_attributes = parse_avps(credentials)
    if avp_value(credential_attributes, 0xD6D, VENDOR_JUNIPER2) != b"pulse-user":
        raise RuntimeError("invalid username")
    cookie_attributes = append_avp(b"", 0xD53, VENDOR_JUNIPER2, b"ttls-cookie-0123456789")
    inner.send_plaintext(build_inner_eap_message(build_eap(1, 43, 0xFE, 1, cookie_attributes)))
    code, _, eap_type, subtype, final_payload = parse_inner_eap_message(inner.receive_plaintext())
    if code != 2 or eap_type != EXPANDED_JUNIPER or subtype != 1 or final_payload:
        raise RuntimeError("invalid final inner response")
    write_frame(
        stream,
        VENDOR_TCG,
        7,
        30,
        struct.pack(">L", AUTH_JUNIPER) + struct.pack(">BBH", 3, 43, 4),
    )
    write_frame(stream, VENDOR_JUNIPER, 1, 31, build_main_configuration())
    write_frame(stream, VENDOR_JUNIPER, 0x8F, 32, b"\0\0\0\0")
    # The negotiated tunnel is IPv4-only; the client must reject this unsolicited IPv6 frame.
    write_frame(stream, VENDOR_JUNIPER, 4, 33, b"\x60" + b"\0" * 39)
    vendor, frame_type, _, packet = read_frame(stream)
    if vendor != VENDOR_JUNIPER or frame_type != 4 or not packet or packet[0] >> 4 != 4:
        raise RuntimeError("missing TTLS tunnel packet")
    write_frame(stream, VENDOR_JUNIPER, 4, 34, packet)
    vendor, frame_type, _, payload = read_frame(stream)
    if vendor != VENDOR_JUNIPER or frame_type != 0x89 or payload:
        raise RuntimeError("missing TTLS close frame")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("certificate")
    parser.add_argument("key")
    parser.add_argument("certificate_authority")
    arguments = parser.parse_args()
    outer_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    outer_context.minimum_version = ssl.TLSVersion.TLSv1_2
    outer_context.load_cert_chain(arguments.certificate, arguments.key)
    inner_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    inner_context.minimum_version = ssl.TLSVersion.TLSv1_2
    inner_context.load_cert_chain(arguments.certificate, arguments.key)
    inner_context.load_verify_locations(cafile=arguments.certificate_authority)
    inner_context.verify_mode = ssl.CERT_REQUIRED
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    print(listener.getsockname()[1], flush=True)
    client, _ = listener.accept()
    try:
        with outer_context.wrap_socket(client, server_side=True) as connection:
            with connection.makefile("rwb", buffering=0) as stream:
                exchange(stream, inner_context)
    finally:
        listener.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(str(error), file=sys.stderr, flush=True)
        raise

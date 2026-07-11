#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/sysmacros.h>
#endif
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define FRAME_F5 1
#define FRAME_F5_HDLC 2
#define FRAME_FORTINET 3
#define MAX_FRAME 131072
#define PPP_LCP 0xc021
#define PPP_IPCP 0x8021
#define PPP_IP6CP 0x8057
#define PPP_CCP 0x80fd
#define PPP_IPV4 0x0021
#define PPP_IPV6 0x0057
#define PPP_CONFREQ 1
#define PPP_CONFACK 2
#define PPP_CONFNAK 3
#define PPP_CONFREJ 4
#define PPP_TERMREQ 5
#define PPP_PROTREJ 8
#define PPP_ECHOREQ 9
#define PPP_ECHOREP 10

static int framing;
static int datagram_mode;
static int dual_carrier_mode;
static int dual_datagram_active;
static int network_fd = -1;
static int secondary_fd = -1;
static int pppd_fd = -1;
static pid_t pppd_pid = -1;
static struct sockaddr_storage client_address;
static socklen_t client_address_length;
static int have_client_address;
static int drop_term_requests;
static int term_requests_seen;
static int mutate_control;
static int control_mutated;
static int corrupt_first_hdlc;
static int hdlc_corrupted;
static int omit_initial_hdlc;
static int hdlc_initial_omitted;
static int data_compressed_logged;
static int split_stream;
static int stream_split_done;
static int coalesce_stream;
static int stream_coalesced;
static unsigned char coalesced_bytes[MAX_FRAME * 2];
static size_t coalesced_length;
static int split_hdlc_escape;
static int hdlc_escape_split_done;
static int disable_ipv6;
static int enable_vj;
static int sending_corrupt_hdlc;
static int inject_ccp;
static int ccp_injected;
static int client_ipv4_logged;
static int client_ipv6_logged;
static int dual_tcp_client_ipv4_logged;
static int dual_tcp_client_ipv6_logged;
static int dual_udp_client_ipv4_logged;
static int dual_udp_client_ipv6_logged;
static int dual_tcp_pppd_ipv4_logged;
static int dual_tcp_pppd_ipv6_logged;
static int dual_udp_pppd_ipv4_logged;
static int dual_udp_pppd_ipv6_logged;
static int reject_client_ip6cp;
static int zero_nak_client_ip6cp;
static int ip6cp_response_injected;
static int pause_client_reads_after_ipv4;
static int client_reads_paused;
static int client_ipv4_frames_seen;
static volatile sig_atomic_t stopping;

struct hdlc_decoder {
    unsigned char frame[MAX_FRAME];
    size_t length;
    int escaped;
};

struct stream_decoder {
    unsigned char bytes[MAX_FRAME];
    size_t length;
};

static struct hdlc_decoder from_pppd;
static struct hdlc_decoder from_client_hdlc;
static struct stream_decoder from_client_stream;

static void stop_peer(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

static void fatal(const char *operation)
{
    fprintf(stderr, "PPPD_PEER_FATAL %s: %s\n", operation, strerror(errno));
    exit(1);
}

static int write_full(int fd, const unsigned char *bytes, size_t length)
{
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(fd, bytes + written, length - written);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        written += (size_t)count;
    }
    return 0;
}

static uint16_t update_fcs(uint16_t fcs, unsigned char value)
{
    int index;
    fcs ^= value;
    for (index = 0; index < 8; index++) {
        if (fcs & 1)
            fcs = (fcs >> 1) ^ 0x8408;
        else
            fcs >>= 1;
    }
    return fcs;
}

static size_t append_hdlc_byte(unsigned char *output, size_t position, unsigned char value)
{
    if (value < 0x20 || value == 0x7d || value == 0x7e) {
        output[position++] = 0x7d;
        output[position++] = value ^ 0x20;
    } else {
        output[position++] = value;
    }
    return position;
}

static size_t encode_hdlc(const unsigned char *frame, size_t length, unsigned char *output, int include_initial)
{
    uint16_t fcs = 0xffff;
    size_t position = 0;
    size_t index;
    if (include_initial)
        output[position++] = 0x7e;
    for (index = 0; index < length; index++) {
        fcs = update_fcs(fcs, frame[index]);
        position = append_hdlc_byte(output, position, frame[index]);
    }
    fcs ^= 0xffff;
    position = append_hdlc_byte(output, position, (unsigned char)fcs);
    position = append_hdlc_byte(output, position, (unsigned char)(fcs >> 8));
    output[position++] = 0x7e;
    return position;
}

static int ppp_protocol(const unsigned char *frame, size_t length, size_t *payload_position)
{
    size_t position = 0;
    unsigned int protocol;
    if (length >= 2 && frame[0] == 0xff && frame[1] == 0x03)
        position = 2;
    if (position >= length)
        return -1;
    protocol = frame[position++];
    if (!(protocol & 1)) {
        if (position >= length)
            return -1;
        protocol = (protocol << 8) | frame[position++];
    }
    *payload_position = position;
    return (int)protocol;
}

static int network_send(const unsigned char *bytes, size_t length)
{
    if (datagram_mode || dual_datagram_active) {
        if (!have_client_address)
            return 0;
        int datagram_fd = datagram_mode ? network_fd : secondary_fd;
        ssize_t count = sendto(datagram_fd, bytes, length, 0,
                               (struct sockaddr *)&client_address, client_address_length);
        return count == (ssize_t)length ? 0 : -1;
    }
    if (dual_carrier_mode && network_fd < 0)
        return 0;
    if (coalesce_stream && !stream_coalesced) {
        if (!coalesced_length) {
            if (length > sizeof(coalesced_bytes))
                return -1;
            memcpy(coalesced_bytes, bytes, length);
            coalesced_length = length;
            return 0;
        }
        if (coalesced_length + length > sizeof(coalesced_bytes))
            return -1;
        memcpy(coalesced_bytes + coalesced_length, bytes, length);
        coalesced_length += length;
        bytes = coalesced_bytes;
        length = coalesced_length;
        stream_coalesced = 1;
        fprintf(stderr, "PPPD_STREAM_FRAMES_COALESCED\n");
    }
    if (split_hdlc_escape && !hdlc_escape_split_done && !sending_corrupt_hdlc && framing == FRAME_F5_HDLC) {
        size_t index;
        for (index = 0; index + 1 < length; index++) {
            if (bytes[index] == 0x7d) {
                if (write_full(network_fd, bytes, index + 1) < 0)
                    return -1;
                usleep(20000);
                if (write_full(network_fd, bytes + index + 1, length - index - 1) < 0)
                    return -1;
                hdlc_escape_split_done = 1;
                fprintf(stderr, "PPPD_HDLC_ESCAPE_SPLIT\n");
                return 0;
            }
        }
    }
    if (split_stream && !stream_split_done && length > 1) {
        if (write_full(network_fd, bytes, 1) < 0)
            return -1;
        usleep(20000);
        if (write_full(network_fd, bytes + 1, length - 1) < 0)
            return -1;
        stream_split_done = 1;
        fprintf(stderr, "PPPD_STREAM_FRAME_SPLIT\n");
        return 0;
    }
    return write_full(network_fd, bytes, length);
}

static int send_outer_frame(unsigned char *frame, size_t length)
{
    unsigned char output[MAX_FRAME];
    size_t payload_position;
    int protocol = ppp_protocol(frame, length, &payload_position);
    if (dual_carrier_mode && protocol == PPP_IPV4) {
        if (dual_datagram_active && !dual_udp_pppd_ipv4_logged) {
            dual_udp_pppd_ipv4_logged = 1;
            fprintf(stderr, "PPPD_DUAL_UDP_IPV4_DATA\n");
        } else if (!dual_datagram_active && !dual_tcp_pppd_ipv4_logged) {
            dual_tcp_pppd_ipv4_logged = 1;
            fprintf(stderr, "PPPD_DUAL_TCP_IPV4_DATA\n");
        }
    }
    if (dual_carrier_mode && protocol == PPP_IPV6) {
        if (dual_datagram_active && !dual_udp_pppd_ipv6_logged) {
            dual_udp_pppd_ipv6_logged = 1;
            fprintf(stderr, "PPPD_DUAL_UDP_IPV6_DATA\n");
        } else if (!dual_datagram_active && !dual_tcp_pppd_ipv6_logged) {
            dual_tcp_pppd_ipv6_logged = 1;
            fprintf(stderr, "PPPD_DUAL_TCP_IPV6_DATA\n");
        }
    }
    if (protocol == PPP_LCP && length > payload_position && frame[payload_position] == PPP_ECHOREQ)
        fprintf(stderr, "PPPD_LCP_ECHO_REQUEST\n");
    if (protocol == PPP_LCP && length >= payload_position + 6 && frame[payload_position] == PPP_PROTREJ) {
        unsigned int rejected = ((unsigned int)frame[payload_position + 4] << 8) |
                                frame[payload_position + 5];
        if (rejected == PPP_IP6CP)
            fprintf(stderr, "PPPD_IP6CP_PROTOCOL_REJECT\n");
        if (rejected == PPP_IPCP)
            fprintf(stderr, "PPPD_IPCP_PROTOCOL_REJECT\n");
    }
    if (protocol == PPP_LCP && mutate_control && !control_mutated &&
        length >= payload_position + 4 && frame[payload_position] == PPP_CONFREQ) {
        uint16_t declared = ((uint16_t)frame[payload_position + 2] << 8) | frame[payload_position + 3];
        if (declared >= 4 && payload_position + declared <= length && length + 2 < sizeof(output)) {
            if (payload_position >= 2 && frame[0] == 0xff && frame[1] == 0x03) {
                memmove(frame, frame + 2, length - 2);
                length -= 2;
                payload_position -= 2;
            }
            frame[length++] = 0xa5;
            frame[length++] = 0x5a;
            control_mutated = 1;
            fprintf(stderr, "PPPD_CONTROL_PADDING_AND_EARLY_ACFC\n");
        }
    }
    protocol = ppp_protocol(frame, length, &payload_position);
    if ((protocol == PPP_IPV4 || protocol == PPP_IPV6) &&
        length >= 4 && frame[0] == 0xff && frame[1] == 0x03) {
        memmove(frame, frame + 2, length - 2);
        length -= 2;
        if (frame[0] == 0x00) {
            memmove(frame, frame + 1, length - 1);
            length--;
        }
        if (!data_compressed_logged) {
            fprintf(stderr, "PPPD_DATA_EARLY_PFC_ACFC\n");
            data_compressed_logged = 1;
        }
    }
    if (framing == FRAME_F5) {
        output[0] = 0xf5;
        output[1] = 0x00;
        output[2] = (unsigned char)(length >> 8);
        output[3] = (unsigned char)length;
        memcpy(output + 4, frame, length);
        return network_send(output, length + 4);
    }
    if (framing == FRAME_FORTINET) {
        size_t total = length + 6;
        output[0] = (unsigned char)(total >> 8);
        output[1] = (unsigned char)total;
        output[2] = 0x50;
        output[3] = 0x50;
        output[4] = (unsigned char)(length >> 8);
        output[5] = (unsigned char)length;
        memcpy(output + 6, frame, length);
        return network_send(output, total);
    }
    int corrupt = corrupt_first_hdlc && !hdlc_corrupted;
    int include_initial = !(omit_initial_hdlc && !hdlc_initial_omitted && !corrupt);
    size_t output_length = encode_hdlc(frame, length, output, include_initial);
    if (!include_initial) {
        hdlc_initial_omitted = 1;
        fprintf(stderr, "PPPD_HDLC_INITIAL_FLAG_OMITTED\n");
    }
    if (corrupt && output_length > 4) {
        output[output_length / 2] ^= 0x01;
        hdlc_corrupted = 1;
        fprintf(stderr, "PPPD_HDLC_FCS_CORRUPTED\n");
    }
    sending_corrupt_hdlc = corrupt;
    int result = network_send(output, output_length);
    sending_corrupt_hdlc = 0;
    return result;
}

static int send_to_pppd(unsigned char *frame, size_t length)
{
    unsigned char output[MAX_FRAME];
    size_t payload_position;
    int protocol = ppp_protocol(frame, length, &payload_position);
    if (protocol == PPP_IPV4 && !dual_datagram_active)
        client_ipv4_frames_seen++;
    int pause_after_forward = protocol == PPP_IPV4 && pause_client_reads_after_ipv4 > 0 &&
                              client_ipv4_frames_seen >= pause_client_reads_after_ipv4 &&
                              !client_reads_paused && !dual_datagram_active;
    if (!ip6cp_response_injected && protocol == PPP_IP6CP && length > payload_position &&
        frame[payload_position] == PPP_CONFREQ && (reject_client_ip6cp || zero_nak_client_ip6cp)) {
        unsigned char response[MAX_FRAME];
        if (length > sizeof(response))
            return -1;
        memcpy(response, frame, length);
        response[payload_position] = reject_client_ip6cp ? PPP_CONFREJ : PPP_CONFNAK;
        ip6cp_response_injected = 1;
        fprintf(stderr, reject_client_ip6cp ? "PPPD_SHIM_IP6CP_CONFIG_REJECT\n" :
                                             "PPPD_SHIM_IP6CP_ZERO_NAK\n");
        return send_outer_frame(response, length);
    }
    if (protocol == PPP_LCP && length > payload_position) {
        if (dual_carrier_mode && dual_datagram_active && frame[payload_position] == PPP_CONFREQ)
            fprintf(stderr, "CLIENT_DUAL_UDP_LCP_CONFIG_REQUEST\n");
        if (frame[payload_position] == PPP_ECHOREQ)
            fprintf(stderr, "CLIENT_LCP_ECHO_REQUEST\n");
        if (frame[payload_position] == PPP_ECHOREP)
            fprintf(stderr, "CLIENT_LCP_ECHO_REPLY\n");
        if (frame[payload_position] == PPP_PROTREJ && length >= payload_position + 6) {
            unsigned int rejected = ((unsigned int)frame[payload_position + 4] << 8) |
                                    frame[payload_position + 5];
            if (rejected == PPP_CCP)
                fprintf(stderr, "CLIENT_CCP_PROTOCOL_REJECT\n");
            if (rejected == PPP_IPCP)
                fprintf(stderr, "CLIENT_IPCP_PROTOCOL_REJECT\n");
            if (rejected == PPP_IP6CP)
                fprintf(stderr, "CLIENT_IP6CP_PROTOCOL_REJECT\n");
        }
        if (frame[payload_position] == PPP_TERMREQ) {
            term_requests_seen++;
            fprintf(stderr, "CLIENT_TERM_REQUEST_%d\n", term_requests_seen);
            if (term_requests_seen <= drop_term_requests)
                return 0;
        }
    }
    if (protocol == PPP_IPCP && length > payload_position && frame[payload_position] == PPP_CONFREJ)
        fprintf(stderr, "CLIENT_IPCP_CONFIG_REJECT\n");
    if (protocol == PPP_IPV4 && !client_ipv4_logged) {
        client_ipv4_logged = 1;
        fprintf(stderr, "CLIENT_IPV4_DATA\n");
    }
    if (protocol == PPP_IPV6 && !client_ipv6_logged) {
        client_ipv6_logged = 1;
        fprintf(stderr, "CLIENT_IPV6_DATA\n");
    }
    if (dual_carrier_mode && protocol == PPP_IPV4) {
        if (dual_datagram_active && !dual_udp_client_ipv4_logged) {
            dual_udp_client_ipv4_logged = 1;
            fprintf(stderr, "CLIENT_DUAL_UDP_IPV4_DATA\n");
        } else if (!dual_datagram_active && !dual_tcp_client_ipv4_logged) {
            dual_tcp_client_ipv4_logged = 1;
            fprintf(stderr, "CLIENT_DUAL_TCP_IPV4_DATA\n");
        }
    }
    if (dual_carrier_mode && protocol == PPP_IPV6) {
        if (dual_datagram_active && !dual_udp_client_ipv6_logged) {
            dual_udp_client_ipv6_logged = 1;
            fprintf(stderr, "CLIENT_DUAL_UDP_IPV6_DATA\n");
        } else if (!dual_datagram_active && !dual_tcp_client_ipv6_logged) {
            dual_tcp_client_ipv6_logged = 1;
            fprintf(stderr, "CLIENT_DUAL_TCP_IPV6_DATA\n");
        }
    }
    if (inject_ccp && !ccp_injected && protocol == PPP_IPCP &&
        length > payload_position && frame[payload_position] == PPP_CONFACK) {
        unsigned char ccp_request[] = {
            0xff, 0x03, 0x80, 0xfd,
            0x01, 0x77, 0x00, 0x08,
            0x1a, 0x04, 0x78, 0x00
        };
        ccp_injected = 1;
        fprintf(stderr, "PPPD_SHIM_CCP_CONFIG_REQUEST\n");
        if (send_outer_frame(ccp_request, sizeof(ccp_request)) < 0)
            return -1;
    }
    size_t output_length = encode_hdlc(frame, length, output, 1);
    int result = write_full(pppd_fd, output, output_length);
    if (result == 0 && pause_after_forward) {
        client_reads_paused = 1;
        fprintf(stderr, "PPPD_CLIENT_READS_PAUSED\n");
    }
    return result;
}

static int finish_hdlc_frame(struct hdlc_decoder *decoder, int from_client)
{
    uint16_t fcs = 0xffff;
    size_t index;
    if (decoder->length < 3) {
        decoder->length = 0;
        decoder->escaped = 0;
        return 0;
    }
    for (index = 0; index < decoder->length; index++)
        fcs = update_fcs(fcs, decoder->frame[index]);
    if (fcs != 0xf0b8) {
        decoder->length = 0;
        decoder->escaped = 0;
        return 0;
    }
    decoder->length -= 2;
    int result;
    if (from_client)
        result = send_to_pppd(decoder->frame, decoder->length);
    else
        result = send_outer_frame(decoder->frame, decoder->length);
    decoder->length = 0;
    decoder->escaped = 0;
    return result;
}

static int consume_hdlc(struct hdlc_decoder *decoder, const unsigned char *bytes,
                        size_t length, int from_client)
{
    size_t index;
    for (index = 0; index < length; index++) {
        unsigned char value = bytes[index];
        if (value == 0x7e) {
            if (decoder->length != 0 && finish_hdlc_frame(decoder, from_client) < 0)
                return -1;
            continue;
        }
        if (decoder->escaped) {
            value ^= 0x20;
            decoder->escaped = 0;
        } else if (value == 0x7d) {
            decoder->escaped = 1;
            continue;
        }
        if (decoder->length >= sizeof(decoder->frame))
            return -1;
        decoder->frame[decoder->length++] = value;
    }
    return 0;
}

static int consume_outer_stream(const unsigned char *bytes, size_t length)
{
    if (framing == FRAME_F5_HDLC)
        return consume_hdlc(&from_client_hdlc, bytes, length, 1);
    if (from_client_stream.length + length > sizeof(from_client_stream.bytes))
        return -1;
    memcpy(from_client_stream.bytes + from_client_stream.length, bytes, length);
    from_client_stream.length += length;
    for (;;) {
        size_t header_length;
        size_t payload_length;
        if (framing == FRAME_F5) {
            if (from_client_stream.length < 4)
                return 0;
            if (from_client_stream.bytes[0] != 0xf5 || from_client_stream.bytes[1] != 0x00)
                return -1;
            header_length = 4;
            payload_length = ((size_t)from_client_stream.bytes[2] << 8) | from_client_stream.bytes[3];
        } else {
            if (from_client_stream.length < 6)
                return 0;
            size_t total = ((size_t)from_client_stream.bytes[0] << 8) | from_client_stream.bytes[1];
            if (from_client_stream.bytes[2] != 0x50 || from_client_stream.bytes[3] != 0x50)
                return -1;
            header_length = 6;
            payload_length = ((size_t)from_client_stream.bytes[4] << 8) | from_client_stream.bytes[5];
            if (total != payload_length + header_length)
                return -1;
        }
        if (payload_length == 0 || header_length + payload_length > sizeof(from_client_stream.bytes))
            return -1;
        if (from_client_stream.length < header_length + payload_length)
            return 0;
        if (send_to_pppd(from_client_stream.bytes + header_length, payload_length) < 0)
            return -1;
        size_t consumed = header_length + payload_length;
        memmove(from_client_stream.bytes, from_client_stream.bytes + consumed,
                from_client_stream.length - consumed);
        from_client_stream.length -= consumed;
    }
}

static pid_t spawn_pppd(void)
{
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0)
        fatal("socketpair");
    pid_t child = fork();
    if (child < 0)
        fatal("fork");
    if (child == 0) {
        close(sockets[0]);
        if (dup2(sockets[1], STDIN_FILENO) < 0 || dup2(sockets[1], STDOUT_FILENO) < 0)
            fatal("dup2");
        if (sockets[1] > STDERR_FILENO)
            close(sockets[1]);
        char *arguments[] = {
            "/usr/sbin/pppd", "nodetach", "notty", "noauth", "local", "debug",
            "192.0.2.1:192.0.2.2", "mru", "1320", "mtu", "1320",
            "noipdefault", "nodefaultroute", "ipcp-accept-local", "ipcp-accept-remote",
            "ms-dns", "203.0.113.53", "ms-dns", "203.0.113.54",
            "ms-wins", "203.0.113.137", "ms-wins", "203.0.113.138",
            "+ipv6", "ipv6", "::1,::2",
#ifndef __APPLE__
            "nodefaultroute6",
#endif
            "ipv6cp-accept-local",
#ifndef __APPLE__
            "ipv6cp-accept-remote",
#endif
            "lcp-echo-interval", "1", "lcp-echo-failure", "8",
            "nopcomp", "noaccomp", enable_vj ? "debug" : "novj",
            "deflate", "15", "bsdcomp", "15", disable_ipv6 ? "noipv6" : "debug", NULL
        };
        execv(arguments[0], arguments);
        fatal("exec pppd");
    }
    close(sockets[1]);
    pppd_fd = sockets[0];
    fprintf(stderr, "PPPD_PROCESS_SPAWNED %ld\n", (long)child);
    return child;
}

static int parse_environment_int(const char *name)
{
    const char *value = getenv(name);
    if (!value || !*value)
        return 0;
    return atoi(value);
}

static void ensure_ppp_device(void)
{
#ifdef __linux__
    if (access("/dev/ppp", F_OK) < 0 && mknod("/dev/ppp", S_IFCHR | 0600, makedev(108, 0)) < 0) {
        fprintf(stderr, "PPPD_UNAVAILABLE mknod /dev/ppp: %s\n", strerror(errno));
        exit(77);
    }
    int fd = open("/dev/ppp", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "PPPD_UNAVAILABLE open /dev/ppp: %s\n", strerror(errno));
        exit(77);
    }
    close(fd);
#endif
}

static int create_server(int port, int datagram)
{
    int type = datagram ? SOCK_DGRAM : SOCK_STREAM;
    int fd = socket(AF_INET, type, 0);
    if (fd < 0)
        fatal("socket");
    int enabled = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0)
        fatal("bind");
    if (!datagram && listen(fd, 1) < 0)
        fatal("listen");
    return fd;
}

static void close_dual_tcp_carrier(void)
{
    if (network_fd < 0)
        return;
    close(network_fd);
    network_fd = -1;
    client_reads_paused = 0;
    fprintf(stderr, "PPPD_DUAL_TCP_CARRIER_CLOSED\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: pppd-peer f5|f5-hdlc|fortinet [udp|dual]\n");
        return 2;
    }
    if (!strcmp(argv[1], "f5"))
        framing = FRAME_F5;
    else if (!strcmp(argv[1], "f5-hdlc"))
        framing = FRAME_F5_HDLC;
    else if (!strcmp(argv[1], "fortinet"))
        framing = FRAME_FORTINET;
    else
        return 2;
    datagram_mode = argc > 2 && !strcmp(argv[2], "udp");
    dual_carrier_mode = argc > 2 && !strcmp(argv[2], "dual");
    if (argc > 2 && !datagram_mode && !dual_carrier_mode)
        return 2;
    signal(SIGTERM, stop_peer);
    signal(SIGINT, stop_peer);
    signal(SIGPIPE, SIG_IGN);
    drop_term_requests = parse_environment_int("DROP_TERM_REQUESTS");
    mutate_control = parse_environment_int("MUTATE_CONTROL");
    corrupt_first_hdlc = parse_environment_int("CORRUPT_FIRST_HDLC");
    omit_initial_hdlc = parse_environment_int("OMIT_INITIAL_HDLC");
    split_stream = parse_environment_int("SPLIT_STREAM");
    coalesce_stream = parse_environment_int("COALESCE_STREAM");
    split_hdlc_escape = parse_environment_int("SPLIT_HDLC_ESCAPE");
    disable_ipv6 = parse_environment_int("DISABLE_IPV6");
    enable_vj = parse_environment_int("ENABLE_VJ");
    inject_ccp = parse_environment_int("INJECT_CCP");
    reject_client_ip6cp = parse_environment_int("REJECT_CLIENT_IP6CP");
    zero_nak_client_ip6cp = parse_environment_int("ZERO_NAK_CLIENT_IP6CP");
    pause_client_reads_after_ipv4 = parse_environment_int("PAUSE_CLIENT_READS_AFTER_IPV4");
    int port = parse_environment_int("PORT");
    if (!port)
        port = 4433;
    int secondary_port = parse_environment_int("SECONDARY_PORT");
    if (!secondary_port)
        secondary_port = 4434;
    ensure_ppp_device();
    int server_fd = create_server(port, datagram_mode);
    if (dual_carrier_mode)
        secondary_fd = create_server(secondary_port, 1);
    fprintf(stderr, "PPPD_PEER_LISTENING\n");
    if (dual_carrier_mode)
        fprintf(stderr, "PPPD_DUAL_LISTENERS_READY\n");
    unsigned char first_carrier_bytes[MAX_FRAME];
    ssize_t first_length = 0;
    if (datagram_mode) {
        client_address_length = sizeof(client_address);
        first_length = recvfrom(server_fd, first_carrier_bytes, sizeof(first_carrier_bytes), 0,
                                (struct sockaddr *)&client_address, &client_address_length);
        if (first_length <= 0)
            fatal("initial recvfrom");
        have_client_address = 1;
        network_fd = server_fd;
    } else {
        network_fd = accept(server_fd, NULL, NULL);
        if (network_fd < 0)
            fatal("accept");
        close(server_fd);
        if (dual_carrier_mode)
            fprintf(stderr, "PPPD_DUAL_TCP_CLIENT_CONNECTED\n");
        if (pause_client_reads_after_ipv4) {
            int receive_buffer = 4096;
            if (setsockopt(network_fd, SOL_SOCKET, SO_RCVBUF,
                           &receive_buffer, sizeof(receive_buffer)) < 0)
                fatal("set receive buffer");
        }
        do {
            first_length = read(network_fd, first_carrier_bytes, sizeof(first_carrier_bytes));
        } while (first_length < 0 && errno == EINTR);
        if (first_length <= 0)
            fatal("initial network read");
    }
    pppd_pid = spawn_pppd();
    if (consume_outer_stream(first_carrier_bytes, (size_t)first_length) < 0)
        fatal("initial outer frame");
    fprintf(stderr, "PPPD_PEER_READY\n");
    for (;;) {
        struct pollfd descriptors[3];
        descriptors[0].fd = network_fd;
        descriptors[0].events = network_fd < 0 || client_reads_paused ? 0 : POLLIN;
        descriptors[0].revents = 0;
        descriptors[1].fd = pppd_fd;
        descriptors[1].events = POLLIN;
        descriptors[1].revents = 0;
        descriptors[2].fd = dual_carrier_mode ? secondary_fd : -1;
        descriptors[2].events = dual_carrier_mode ? POLLIN : 0;
        descriptors[2].revents = 0;
        int result = poll(descriptors, dual_carrier_mode ? 3 : 2, -1);
        if (stopping)
            break;
        if (result < 0 && errno == EINTR)
            continue;
        if (result < 0)
            fatal("poll");
        if (dual_carrier_mode && descriptors[2].revents & POLLIN) {
            unsigned char bytes[MAX_FRAME];
            struct sockaddr_storage address;
            socklen_t address_length = sizeof(address);
            ssize_t count = recvfrom(secondary_fd, bytes, sizeof(bytes), 0,
                                     (struct sockaddr *)&address, &address_length);
            if (count <= 0)
                fatal("read dual UDP carrier");
            client_address = address;
            client_address_length = address_length;
            have_client_address = 1;
            if (!dual_datagram_active) {
                dual_datagram_active = 1;
                from_client_stream.length = 0;
                from_client_hdlc.length = 0;
                from_client_hdlc.escaped = 0;
                fprintf(stderr, "PPPD_DUAL_UDP_CLIENT_CONNECTED\n");
                close_dual_tcp_carrier();
            }
            if (consume_outer_stream(bytes, (size_t)count) < 0)
                fatal("decode dual UDP client frame");
        }
        if (network_fd >= 0 && !client_reads_paused && descriptors[0].revents & (POLLIN | POLLHUP)) {
            unsigned char bytes[MAX_FRAME];
            ssize_t count;
            if (datagram_mode) {
                struct sockaddr_storage address;
                socklen_t address_length = sizeof(address);
                count = recvfrom(network_fd, bytes, sizeof(bytes), 0,
                                 (struct sockaddr *)&address, &address_length);
                if (count > 0 && !have_client_address) {
                    client_address = address;
                    client_address_length = address_length;
                    have_client_address = 1;
                }
            } else {
                count = read(network_fd, bytes, sizeof(bytes));
            }
            if (count <= 0) {
                if (dual_carrier_mode) {
                    close_dual_tcp_carrier();
                } else {
                    break;
                }
                continue;
            }
            if (consume_outer_stream(bytes, (size_t)count) < 0)
                fatal("decode client frame");
        }
        if (network_fd >= 0 && client_reads_paused && descriptors[0].revents & (POLLHUP | POLLERR | POLLNVAL)) {
            if (dual_carrier_mode)
                close_dual_tcp_carrier();
            else
                break;
        }
        if (descriptors[1].revents & (POLLIN | POLLHUP)) {
            unsigned char bytes[MAX_FRAME];
            ssize_t count = read(pppd_fd, bytes, sizeof(bytes));
            if (count <= 0)
                break;
            if (consume_hdlc(&from_pppd, bytes, (size_t)count, 0) < 0)
                fatal("decode pppd frame");
        }
    }
    if (pppd_pid > 0) {
        kill(pppd_pid, SIGTERM);
        waitpid(pppd_pid, NULL, 0);
    }
    fprintf(stderr, "PPPD_PEER_EXIT\n");
    return 0;
}

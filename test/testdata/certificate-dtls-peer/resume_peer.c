#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static SSL_SESSION *injected_session;
static unsigned char injected_id[32];

static int decode_hex(const char *input, unsigned char *output, size_t length) {
    if (strlen(input) != length * 2) {
        return 0;
    }
    for (size_t i = 0; i < length; i++) {
        unsigned int value;
        if (sscanf(input + i * 2, "%2x", &value) != 1) {
            return 0;
        }
        output[i] = (unsigned char)value;
    }
    return 1;
}

static SSL_SESSION *lookup_session(SSL *ssl, const unsigned char *id, int length, int *copy) {
    (void)ssl;
    if (length != (int)sizeof(injected_id) || memcmp(id, injected_id, sizeof(injected_id)) != 0) {
        return NULL;
    }
    if (!SSL_SESSION_up_ref(injected_session)) {
        return NULL;
    }
    *copy = 0;
    return injected_session;
}

static int fail(const char *operation) {
    fprintf(stderr, "%s failed: errno=%d\n", operation, errno);
    ERR_print_errors_fp(stderr);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: resume-peer port cipher session-id master-secret\n");
        return 2;
    }
    unsigned char master_secret[48];
    if (!decode_hex(argv[3], injected_id, sizeof(injected_id)) ||
        !decode_hex(argv[4], master_secret, sizeof(master_secret))) {
        return 2;
    }

    SSL_CTX *context = SSL_CTX_new(DTLS_server_method());
    if (context == NULL ||
        !SSL_CTX_set_min_proto_version(context, DTLS1_2_VERSION) ||
        !SSL_CTX_set_max_proto_version(context, DTLS1_2_VERSION) ||
        !SSL_CTX_set_cipher_list(context, argv[2])) {
        SSL_CTX_free(context);
        return fail("configure injected session context");
    }
    SSL_CTX_set_security_level(context, 0);
    SSL_CTX_set_options(context, SSL_OP_NO_TICKET | SSL_OP_NO_EXTENDED_MASTER_SECRET);
    static const unsigned char id_context[] = "sing-openconnect-resume";
    if (!SSL_CTX_set_session_id_context(context, id_context, sizeof(id_context) - 1)) {
        SSL_CTX_free(context);
        return fail("set injected session context ID");
    }
    SSL *cipher_lookup = SSL_new(context);
    STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(cipher_lookup);
    const SSL_CIPHER *cipher = NULL;
    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
        const SSL_CIPHER *candidate = sk_SSL_CIPHER_value(ciphers, i);
        if (strcmp(SSL_CIPHER_get_name(candidate), argv[2]) == 0) {
            cipher = candidate;
            break;
        }
    }
    injected_session = SSL_SESSION_new();
    if (cipher == NULL || injected_session == NULL ||
        !SSL_SESSION_set_protocol_version(injected_session, DTLS1_2_VERSION) ||
        !SSL_SESSION_set_cipher(injected_session, cipher) ||
        !SSL_SESSION_set1_id(injected_session, injected_id, sizeof(injected_id)) ||
        !SSL_SESSION_set1_id_context(injected_session, id_context, sizeof(id_context) - 1) ||
        SSL_SESSION_set1_master_key(injected_session, master_secret, sizeof(master_secret)) != 1) {
        SSL_free(cipher_lookup);
        SSL_SESSION_free(injected_session);
        SSL_CTX_free(context);
        return fail("create injected DTLS session");
    }
    SSL_free(cipher_lookup);
    SSL_SESSION_set_time_ex(injected_session, time(NULL));
    SSL_SESSION_set_timeout(injected_session, 300);
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_get_cb(context, lookup_session);

    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct timeval timeout = {.tv_sec = 20, .tv_usec = 0};
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    local.sin_port = htons((unsigned short)atoi(argv[1]));
    if (socket_fd < 0 || bind(socket_fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        close(socket_fd);
        SSL_SESSION_free(injected_session);
        SSL_CTX_free(context);
        return fail("bind injected DTLS peer");
    }
    printf("LISTENING\n");
    fflush(stdout);

    unsigned char first_byte;
    struct sockaddr_in remote = {0};
    socklen_t remote_length = sizeof(remote);
    if (recvfrom(socket_fd, &first_byte, 1, MSG_PEEK, (struct sockaddr *)&remote, &remote_length) < 0 ||
        connect(socket_fd, (struct sockaddr *)&remote, remote_length) != 0) {
        close(socket_fd);
        SSL_SESSION_free(injected_session);
        SSL_CTX_free(context);
        return fail("connect injected DTLS peer");
    }
    BIO *bio = BIO_new_dgram(socket_fd, BIO_NOCLOSE);
    SSL *ssl = SSL_new(context);
    SSL_set_bio(ssl, bio, bio);
    SSL_set_mtu(ssl, 1200);
    if (SSL_accept(ssl) != 1 || !SSL_session_reused(ssl)) {
        SSL_free(ssl);
        close(socket_fd);
        SSL_SESSION_free(injected_session);
        SSL_CTX_free(context);
        return fail("accept injected DTLS session");
    }
    printf("READY version=%s cipher=%s resumed=1\n", SSL_get_version(ssl), SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
    fflush(stdout);

    unsigned char buffer[2048];
    int length = SSL_read(ssl, buffer, sizeof(buffer));
    int payload_valid = length == 1000;
    for (int i = 0; payload_valid && i < length; i++) {
        payload_valid = buffer[i] == (unsigned char)(i % 251);
    }
    if (!payload_valid || SSL_write(ssl, buffer, length) != length) {
        SSL_free(ssl);
        close(socket_fd);
        SSL_SESSION_free(injected_session);
        SSL_CTX_free(context);
        return fail("exchange injected DTLS application data");
    }
    length = SSL_read(ssl, buffer, sizeof(buffer));
    if (length != 0 || SSL_get_error(ssl, length) != SSL_ERROR_ZERO_RETURN) {
        SSL_free(ssl);
        close(socket_fd);
        SSL_SESSION_free(injected_session);
        SSL_CTX_free(context);
        return fail("receive injected DTLS close_notify");
    }
    printf("CLOSED\n");
    fflush(stdout);
    SSL_free(ssl);
    close(socket_fd);
    SSL_SESSION_free(injected_session);
    SSL_CTX_free(context);
    OPENSSL_cleanse(master_secret, sizeof(master_secret));
    return 0;
}

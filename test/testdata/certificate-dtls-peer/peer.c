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
#include <unistd.h>

static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *length) {
    (void)ssl;
    static const unsigned char value[] = "sing-openconnect-dtls-cookie";
    memcpy(cookie, value, sizeof(value) - 1);
    *length = sizeof(value) - 1;
    return 1;
}

static int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int length) {
    (void)ssl;
    static const unsigned char value[] = "sing-openconnect-dtls-cookie";
    return length == sizeof(value) - 1 && memcmp(cookie, value, length) == 0;
}

static int fail(const char *operation) {
    fprintf(stderr, "%s failed: errno=%d\n", operation, errno);
    ERR_print_errors_fp(stderr);
    return 1;
}

static int inject_legacy_untrusted_datagrams(int socket_fd) {
    static const unsigned char short_record[] = {23, 0xfe, 0xff};
    static const unsigned char plaintext_close[] = {
        21, 0xfe, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0,
    };
    unsigned char bad_mac[61] = {0};
    bad_mac[0] = 23;
    bad_mac[1] = 0xfe;
    bad_mac[2] = 0xff;
    bad_mac[4] = 1;
    bad_mac[12] = 48;
    if (send(socket_fd, short_record, sizeof(short_record), 0) != (ssize_t)sizeof(short_record) ||
        send(socket_fd, plaintext_close, sizeof(plaintext_close), 0) != (ssize_t)sizeof(plaintext_close) ||
        send(socket_fd, bad_mac, sizeof(bad_mac), 0) != (ssize_t)sizeof(bad_mac)) {
        return 0;
    }
    printf("INJECTED-UNAUTHENTICATED-DATAGRAMS\n");
    fflush(stdout);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 10) {
        fprintf(stderr, "usage: peer port version cipher cert key ca require-client expected-sni groups\n");
        return 2;
    }

    int port = atoi(argv[1]);
    int legacy = strcmp(argv[2], "1.0") == 0;
    SSL_CTX *context = SSL_CTX_new(DTLS_server_method());
    if (context == NULL) {
        return fail("SSL_CTX_new");
    }
    int version = legacy ? DTLS1_VERSION : DTLS1_2_VERSION;
    if (!SSL_CTX_set_min_proto_version(context, version) ||
        !SSL_CTX_set_max_proto_version(context, version) ||
        !SSL_CTX_set_cipher_list(context, argv[3]) ||
        (strcmp(argv[9], "-") != 0 && !SSL_CTX_set1_groups_list(context, argv[9])) ||
        SSL_CTX_use_certificate_chain_file(context, argv[4]) != 1 ||
        SSL_CTX_use_PrivateKey_file(context, argv[5], SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(context) != 1) {
        SSL_CTX_free(context);
        return fail("configure SSL context");
    }
    if (legacy) {
        SSL_CTX_set_security_level(context, 0);
    }
    SSL_CTX_set_cookie_generate_cb(context, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(context, verify_cookie);
    SSL_CTX_set_options(context, SSL_OP_COOKIE_EXCHANGE | SSL_OP_NO_QUERY_MTU);
    if (atoi(argv[7])) {
        STACK_OF(X509_NAME) *client_ca_list = SSL_load_client_CA_file(argv[6]);
        if (SSL_CTX_load_verify_locations(context, argv[6], NULL) != 1 || client_ca_list == NULL) {
            sk_X509_NAME_pop_free(client_ca_list, X509_NAME_free);
            SSL_CTX_free(context);
            return fail("load client CA");
        }
        SSL_CTX_set_client_CA_list(context, client_ca_list);
        SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    }

    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        SSL_CTX_free(context);
        return fail("socket");
    }
    struct timeval timeout = {.tv_sec = 20, .tv_usec = 0};
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    local.sin_port = htons((unsigned short)port);
    if (bind(socket_fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        close(socket_fd);
        SSL_CTX_free(context);
        return fail("bind");
    }
    printf("LISTENING\n");
    fflush(stdout);

    unsigned char first_byte;
    struct sockaddr_in remote = {0};
    socklen_t remote_length = sizeof(remote);
    if (recvfrom(socket_fd, &first_byte, 1, MSG_PEEK, (struct sockaddr *)&remote, &remote_length) < 0 ||
        connect(socket_fd, (struct sockaddr *)&remote, remote_length) != 0) {
        close(socket_fd);
        SSL_CTX_free(context);
        return fail("connect UDP peer");
    }

    BIO *bio = BIO_new_dgram(socket_fd, BIO_NOCLOSE);
    SSL *ssl = SSL_new(context);
    if (bio == NULL || ssl == NULL) {
        BIO_free(bio);
        SSL_free(ssl);
        close(socket_fd);
        SSL_CTX_free(context);
        return fail("create SSL peer");
    }
    SSL_set_bio(ssl, bio, bio);
    SSL_set_mtu(ssl, 1200);
    if (SSL_accept(ssl) != 1) {
        SSL_free(ssl);
        close(socket_fd);
        SSL_CTX_free(context);
        return fail("SSL_accept");
    }
    const char *server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (server_name == NULL || strcmp(server_name, argv[8]) != 0) {
        fprintf(stderr, "unexpected SNI: %s\n", server_name == NULL ? "<none>" : server_name);
        SSL_free(ssl);
        close(socket_fd);
        SSL_CTX_free(context);
        return 1;
    }
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    X509 *peer_certificate = SSL_get1_peer_certificate(ssl);
    const char *group = SSL_get0_group_name(ssl);
    size_t data_mtu = DTLS_get_data_mtu(ssl);
    printf("READY version=%s cipher=%s group=%s sni=%s peer-cert=%d data-mtu=%zu\n",
           SSL_get_version(ssl), SSL_CIPHER_get_name(cipher),
           group == NULL ? "<none>" : group, server_name,
           peer_certificate != NULL, data_mtu);
    X509_free(peer_certificate);
    fflush(stdout);

    if (legacy && !inject_legacy_untrusted_datagrams(socket_fd)) {
        SSL_free(ssl);
        close(socket_fd);
        SSL_CTX_free(context);
        return fail("inject legacy unauthenticated datagrams");
    }

    unsigned char buffer[2048];
    int length = SSL_read(ssl, buffer, sizeof(buffer));
    int payload_valid = length > 0 && (size_t)length == data_mtu;
    for (int i = 0; payload_valid && i < length; i++) {
        payload_valid = buffer[i] == (unsigned char)(i % 251);
    }
    if (!payload_valid) {
        fprintf(stderr, "unexpected application payload length=%d\n", length);
        SSL_free(ssl);
        close(socket_fd);
        SSL_CTX_free(context);
        return 1;
    }
    if (SSL_write(ssl, buffer, length) != length) {
        SSL_free(ssl);
        close(socket_fd);
        SSL_CTX_free(context);
        return fail("SSL_write");
    }

    if (legacy) {
        int shutdown_result = SSL_shutdown(ssl);
        if (shutdown_result == 0) {
            shutdown_result = SSL_shutdown(ssl);
        }
        if (shutdown_result != 1) {
            SSL_free(ssl);
            close(socket_fd);
            SSL_CTX_free(context);
            return fail("exchange legacy close_notify");
        }
    } else {
        length = SSL_read(ssl, buffer, sizeof(buffer));
        if (length != 0 || SSL_get_error(ssl, length) != SSL_ERROR_ZERO_RETURN) {
            fprintf(stderr, "expected close_notify, read=%d error=%d\n", length, SSL_get_error(ssl, length));
            SSL_free(ssl);
            close(socket_fd);
            SSL_CTX_free(context);
            return 1;
        }
    }
    printf("CLOSED\n");
    fflush(stdout);
    SSL_free(ssl);
    close(socket_fd);
    SSL_CTX_free(context);
    return 0;
}

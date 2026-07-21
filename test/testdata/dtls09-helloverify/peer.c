/*
 * Independent Cisco DTLS1_BAD_VER UDP peer derived solely from OpenConnect
 * tests/bad_dtls_test.c at commit 2035601b64a5360a46d18e08937e7f654b3230f2.
 * Copyright © 2008-2016 Intel Corporation. LGPL-2.1-or-later.
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DTLS09_PORT 4433
#define DTLS09_VERSION_MAJOR 0x01
#define DTLS09_VERSION_MINOR 0x00
#define DTLS09_RECORD_HEADER 13
#define DTLS09_HANDSHAKE_HEADER 12
#define DTLS09_MASTER_SECRET 48
#define DTLS09_SESSION_ID 32
#define DTLS09_RANDOM 32
#define DTLS09_MAC 20
#define DTLS09_MAX_BLOCK 16
#define DTLS09_FINISHED 12
#define DTLS09_MAX_KEY_BLOCK 104

#define CONTENT_CHANGE_CIPHER_SPEC 20
#define CONTENT_HANDSHAKE 22
#define CONTENT_APPLICATION_DATA 23

#define HANDSHAKE_CLIENT_HELLO 1
#define HANDSHAKE_SERVER_HELLO 2
#define HANDSHAKE_HELLO_VERIFY 3
#define HANDSHAKE_FINISHED 20

static const uint8_t hello_verify_cookie[20] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
};

static const EVP_CIPHER *record_cipher;
static size_t record_block_length;
static size_t record_key_length;
static size_t record_key_block_length;
static uint16_t record_cipher_suite;

struct dtls09_record {
    uint8_t type;
    uint16_t epoch;
    uint64_t sequence;
    const uint8_t *payload;
    size_t payload_length;
    size_t consumed;
};

static uint16_t read_u16(const uint8_t *source)
{
    return ((uint16_t)source[0] << 8) | source[1];
}

static uint32_t read_u24(const uint8_t *source)
{
    return ((uint32_t)source[0] << 16) | ((uint32_t)source[1] << 8) | source[2];
}

static uint64_t read_u48(const uint8_t *source)
{
    uint64_t value = 0;
    int i;

    for (i = 0; i < 6; i++)
        value = (value << 8) | source[i];
    return value;
}

static void write_u16(uint8_t *destination, uint16_t value)
{
    destination[0] = (uint8_t)(value >> 8);
    destination[1] = (uint8_t)value;
}

static void write_u24(uint8_t *destination, uint32_t value)
{
    destination[0] = (uint8_t)(value >> 16);
    destination[1] = (uint8_t)(value >> 8);
    destination[2] = (uint8_t)value;
}

static void write_u48(uint8_t *destination, uint64_t value)
{
    int i;

    for (i = 5; i >= 0; i--) {
        destination[i] = (uint8_t)value;
        value >>= 8;
    }
}

static int decode_hex(const char *text, uint8_t *output, size_t output_length)
{
    size_t i;

    if (strlen(text) != output_length * 2)
        return 0;
    for (i = 0; i < output_length; i++) {
        unsigned int value;
        if (sscanf(text + i * 2, "%2x", &value) != 1)
            return 0;
        output[i] = (uint8_t)value;
    }
    return 1;
}

static void encode_hex(const uint8_t *input, size_t input_length, char *output)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < input_length; i++) {
        output[i * 2] = digits[input[i] >> 4];
        output[i * 2 + 1] = digits[input[i] & 0x0f];
    }
    output[input_length * 2] = '\0';
}

static int parse_record(const uint8_t *input, size_t input_length, struct dtls09_record *record)
{
    size_t payload_length;

    if (input_length < DTLS09_RECORD_HEADER ||
        input[1] != DTLS09_VERSION_MAJOR || input[2] != DTLS09_VERSION_MINOR)
        return 0;
    payload_length = read_u16(input + 11);
    if (input_length < DTLS09_RECORD_HEADER + payload_length)
        return 0;
    record->type = input[0];
    record->epoch = read_u16(input + 3);
    record->sequence = read_u48(input + 5);
    record->payload = input + DTLS09_RECORD_HEADER;
    record->payload_length = payload_length;
    record->consumed = DTLS09_RECORD_HEADER + payload_length;
    return 1;
}

static size_t write_record_header(uint8_t *output, uint8_t type, uint16_t epoch,
                                  uint64_t sequence, size_t payload_length)
{
    output[0] = type;
    output[1] = DTLS09_VERSION_MAJOR;
    output[2] = DTLS09_VERSION_MINOR;
    write_u16(output + 3, epoch);
    write_u48(output + 5, sequence);
    write_u16(output + 11, (uint16_t)payload_length);
    return DTLS09_RECORD_HEADER;
}

static size_t write_handshake(uint8_t *output, uint8_t type, uint16_t sequence,
                              const uint8_t *body, size_t body_length)
{
    output[0] = type;
    write_u24(output + 1, (uint32_t)body_length);
    write_u16(output + 4, sequence);
    memset(output + 6, 0, 3);
    write_u24(output + 9, (uint32_t)body_length);
    memcpy(output + DTLS09_HANDSHAKE_HEADER, body, body_length);
    return DTLS09_HANDSHAKE_HEADER + body_length;
}

static int p_hash(const EVP_MD *digest, const uint8_t *secret, size_t secret_length,
                  const uint8_t *seed, size_t seed_length, uint8_t *output,
                  size_t output_length)
{
    uint8_t a[EVP_MAX_MD_SIZE];
    uint8_t chunk[EVP_MAX_MD_SIZE];
    uint8_t *round_input;
    unsigned int a_length = 0;
    unsigned int chunk_length = 0;
    size_t written = 0;

    if (HMAC(digest, secret, (int)secret_length, seed, seed_length, a, &a_length) == NULL)
        return 0;
    round_input = malloc(EVP_MAX_MD_SIZE + seed_length);
    if (round_input == NULL)
        return 0;
    while (written < output_length) {
        size_t copy_length;

        memcpy(round_input, a, a_length);
        memcpy(round_input + a_length, seed, seed_length);
        if (HMAC(digest, secret, (int)secret_length, round_input,
                 a_length + seed_length, chunk, &chunk_length) == NULL) {
            free(round_input);
            return 0;
        }
        copy_length = chunk_length;
        if (copy_length > output_length - written)
            copy_length = output_length - written;
        memcpy(output + written, chunk, copy_length);
        written += copy_length;
        if (HMAC(digest, secret, (int)secret_length, a, a_length, a, &a_length) == NULL) {
            free(round_input);
            return 0;
        }
    }
    free(round_input);
    return 1;
}

static int tls10_prf(const uint8_t *secret, size_t secret_length, const char *label,
                     const uint8_t *seed, size_t seed_length, uint8_t *output,
                     size_t output_length)
{
    uint8_t *labeled_seed;
    uint8_t *md5_output;
    uint8_t *sha1_output;
    size_t label_length = strlen(label);
    size_t half_length = (secret_length + 1) / 2;
    size_t i;
    int result = 0;

    labeled_seed = malloc(label_length + seed_length);
    md5_output = malloc(output_length);
    sha1_output = malloc(output_length);
    if (labeled_seed == NULL || md5_output == NULL || sha1_output == NULL)
        goto done;
    memcpy(labeled_seed, label, label_length);
    memcpy(labeled_seed + label_length, seed, seed_length);
    if (!p_hash(EVP_md5(), secret, half_length, labeled_seed,
                label_length + seed_length, md5_output, output_length) ||
        !p_hash(EVP_sha1(), secret + secret_length - half_length, half_length,
                labeled_seed, label_length + seed_length, sha1_output, output_length))
        goto done;
    for (i = 0; i < output_length; i++)
        output[i] = md5_output[i] ^ sha1_output[i];
    result = 1;

done:
    free(labeled_seed);
    free(md5_output);
    free(sha1_output);
    return result;
}

static int compute_finished(const uint8_t master_secret[DTLS09_MASTER_SECRET],
                            const char *label, const uint8_t *transcript,
                            size_t transcript_length, uint8_t output[DTLS09_FINISHED])
{
    uint8_t handshake_hash[EVP_MAX_MD_SIZE * 2];
    unsigned int md5_length = 0;
    unsigned int sha1_length = 0;

    if (!EVP_Digest(transcript, transcript_length, handshake_hash, &md5_length,
                    EVP_md5(), NULL) ||
        !EVP_Digest(transcript, transcript_length, handshake_hash + md5_length,
                    &sha1_length, EVP_sha1(), NULL))
        return 0;
    return tls10_prf(master_secret, DTLS09_MASTER_SECRET, label, handshake_hash,
                     md5_length + sha1_length, output, DTLS09_FINISHED);
}

static int record_mac(const uint8_t key[DTLS09_MAC], uint8_t type, uint16_t epoch,
                      uint64_t sequence, const uint8_t *content, size_t content_length,
                      uint8_t output[DTLS09_MAC])
{
    uint8_t *input;
    unsigned int mac_length = 0;

    input = malloc(13 + content_length);
    if (input == NULL)
        return 0;
    write_u16(input, epoch);
    write_u48(input + 2, sequence);
    input[8] = type;
    input[9] = DTLS09_VERSION_MAJOR;
    input[10] = DTLS09_VERSION_MINOR;
    write_u16(input + 11, (uint16_t)content_length);
    memcpy(input + 13, content, content_length);
    if (HMAC(EVP_sha1(), key, DTLS09_MAC, input, 13 + content_length,
             output, &mac_length) == NULL || mac_length != DTLS09_MAC) {
        free(input);
        return 0;
    }
    free(input);
    return 1;
}

static int encrypt_record(uint8_t type, uint64_t sequence, const uint8_t *content,
                          size_t content_length, const uint8_t *key,
                          const uint8_t mac_key[20], uint8_t *output,
                          size_t output_capacity, size_t *output_length)
{
    uint8_t mac[DTLS09_MAC];
    uint8_t iv[DTLS09_MAX_BLOCK];
    uint8_t *plaintext;
    uint8_t *ciphertext;
    EVP_CIPHER_CTX *cipher_context;
    size_t padding;
    size_t plaintext_length;
    int encrypted_length = 0;
    int final_length = 0;
    int result = 0;

    if (!record_mac(mac_key, type, 1, sequence, content, content_length, mac))
        return 0;
    padding = record_block_length - 1 - ((content_length + DTLS09_MAC) % record_block_length);
    plaintext_length = content_length + DTLS09_MAC + padding + 1;
    if (output_capacity < DTLS09_RECORD_HEADER + record_block_length + plaintext_length)
        return 0;
    plaintext = malloc(plaintext_length);
    ciphertext = malloc(plaintext_length);
    cipher_context = EVP_CIPHER_CTX_new();
    if (plaintext == NULL || ciphertext == NULL || cipher_context == NULL)
        goto done;
    memcpy(plaintext, content, content_length);
    memcpy(plaintext + content_length, mac, DTLS09_MAC);
    memset(plaintext + content_length + DTLS09_MAC, (int)padding, padding + 1);
    if (RAND_bytes(iv, (int)record_block_length) != 1 ||
        EVP_EncryptInit_ex(cipher_context, record_cipher, NULL, key, iv) != 1 ||
        EVP_CIPHER_CTX_set_padding(cipher_context, 0) != 1 ||
        EVP_EncryptUpdate(cipher_context, ciphertext, &encrypted_length,
                          plaintext, (int)plaintext_length) != 1 ||
        EVP_EncryptFinal_ex(cipher_context, ciphertext + encrypted_length,
                            &final_length) != 1 ||
        (size_t)(encrypted_length + final_length) != plaintext_length)
        goto done;
    write_record_header(output, type, 1, sequence, record_block_length + plaintext_length);
    memcpy(output + DTLS09_RECORD_HEADER, iv, record_block_length);
    memcpy(output + DTLS09_RECORD_HEADER + record_block_length, ciphertext, plaintext_length);
    *output_length = DTLS09_RECORD_HEADER + record_block_length + plaintext_length;
    result = 1;

done:
    EVP_CIPHER_CTX_free(cipher_context);
    free(plaintext);
    free(ciphertext);
    return result;
}

static int decrypt_record(const struct dtls09_record *record, const uint8_t *key,
                          const uint8_t mac_key[20], uint8_t *output,
                          size_t output_capacity, size_t *output_length)
{
    const uint8_t *iv;
    const uint8_t *ciphertext;
    size_t ciphertext_length;
    uint8_t *plaintext;
    uint8_t expected_mac[DTLS09_MAC];
    EVP_CIPHER_CTX *cipher_context;
    int decrypted_length = 0;
    int final_length = 0;
    size_t plaintext_length;
    size_t padding_length;
    size_t content_length;
    size_t i;
    int result = 0;

    if (record->epoch != 1 || record->payload_length <= record_block_length ||
        (record->payload_length - record_block_length) % record_block_length != 0)
        return 0;
    iv = record->payload;
    ciphertext = record->payload + record_block_length;
    ciphertext_length = record->payload_length - record_block_length;
    plaintext = malloc(ciphertext_length);
    cipher_context = EVP_CIPHER_CTX_new();
    if (plaintext == NULL || cipher_context == NULL)
        goto done;
    if (EVP_DecryptInit_ex(cipher_context, record_cipher, NULL, key, iv) != 1 ||
        EVP_CIPHER_CTX_set_padding(cipher_context, 0) != 1 ||
        EVP_DecryptUpdate(cipher_context, plaintext, &decrypted_length,
                          ciphertext, (int)ciphertext_length) != 1 ||
        EVP_DecryptFinal_ex(cipher_context, plaintext + decrypted_length,
                            &final_length) != 1)
        goto done;
    plaintext_length = (size_t)(decrypted_length + final_length);
    if (plaintext_length < DTLS09_MAC + 1)
        goto done;
    padding_length = (size_t)plaintext[plaintext_length - 1] + 1;
    if (padding_length > plaintext_length - DTLS09_MAC)
        goto done;
    for (i = 0; i < padding_length; i++) {
        if (plaintext[plaintext_length - 1 - i] != padding_length - 1)
            goto done;
    }
    content_length = plaintext_length - DTLS09_MAC - padding_length;
    if (content_length > output_capacity ||
        !record_mac(mac_key, record->type, record->epoch, record->sequence,
                    plaintext, content_length, expected_mac) ||
        CRYPTO_memcmp(expected_mac, plaintext + content_length, DTLS09_MAC) != 0)
        goto done;
    memcpy(output, plaintext, content_length);
    *output_length = content_length;
    result = 1;

done:
    EVP_CIPHER_CTX_free(cipher_context);
    free(plaintext);
    return result;
}

static int validate_client_hello(const uint8_t *datagram, size_t datagram_length,
                                 int expect_cookie, const uint8_t session_id[32],
                                 uint8_t client_random[32], uint8_t *body_copy,
                                 size_t *body_length)
{
    struct dtls09_record record;
    const uint8_t *handshake;
    const uint8_t *body;
    size_t handshake_body_length;
    size_t position;
    size_t session_length;
    size_t cookie_length;
    size_t cipher_length;
    size_t compression_length;
    size_t extension_length;

    if (!parse_record(datagram, datagram_length, &record) ||
        record.consumed != datagram_length || record.type != CONTENT_HANDSHAKE ||
        record.epoch != 0 || record.sequence != (uint64_t)expect_cookie ||
        record.payload_length < DTLS09_HANDSHAKE_HEADER)
        return 0;
    handshake = record.payload;
    handshake_body_length = read_u24(handshake + 1);
    if (handshake[0] != HANDSHAKE_CLIENT_HELLO || read_u16(handshake + 4) != 0 ||
        read_u24(handshake + 6) != 0 || read_u24(handshake + 9) != handshake_body_length ||
        record.payload_length != DTLS09_HANDSHAKE_HEADER + handshake_body_length)
        return 0;
    body = handshake + DTLS09_HANDSHAKE_HEADER;
    if (handshake_body_length < 2 + DTLS09_RANDOM + 1 ||
        body[0] != DTLS09_VERSION_MAJOR || body[1] != DTLS09_VERSION_MINOR)
        return 0;
    if (!expect_cookie)
        memcpy(client_random, body + 2, DTLS09_RANDOM);
    else if (CRYPTO_memcmp(client_random, body + 2, DTLS09_RANDOM) != 0)
        return 0;
    position = 2 + DTLS09_RANDOM;
    session_length = body[position++];
    if (session_length != DTLS09_SESSION_ID || position + session_length > handshake_body_length ||
        CRYPTO_memcmp(body + position, session_id, DTLS09_SESSION_ID) != 0)
        return 0;
    position += session_length;
    if (position >= handshake_body_length)
        return 0;
    cookie_length = body[position++];
    if ((!expect_cookie && cookie_length != 0) ||
        (expect_cookie && (cookie_length != sizeof(hello_verify_cookie) ||
                           position + cookie_length > handshake_body_length ||
                           CRYPTO_memcmp(body + position, hello_verify_cookie,
                                         sizeof(hello_verify_cookie)) != 0)))
        return 0;
    position += cookie_length;
    if (position + 2 > handshake_body_length)
        return 0;
    cipher_length = read_u16(body + position);
    position += 2;
    if (cipher_length != 2 || position + cipher_length > handshake_body_length ||
        read_u16(body + position) != record_cipher_suite)
        return 0;
    position += cipher_length;
    if (position >= handshake_body_length)
        return 0;
    compression_length = body[position++];
    if (compression_length != 1 || position + compression_length > handshake_body_length ||
        body[position] != 0)
        return 0;
    position += compression_length;
    if (position + 2 > handshake_body_length)
        return 0;
    extension_length = read_u16(body + position);
    position += 2;
    if (extension_length != 0 || position != handshake_body_length)
        return 0;
    memcpy(body_copy, body, handshake_body_length);
    *body_length = handshake_body_length;
    return 1;
}

static size_t build_hello_verify(uint8_t *output)
{
    uint8_t body[3 + sizeof(hello_verify_cookie)];
    uint8_t handshake[DTLS09_HANDSHAKE_HEADER + sizeof(body)];
    size_t handshake_length;

    body[0] = DTLS09_VERSION_MAJOR;
    body[1] = DTLS09_VERSION_MINOR;
    body[2] = sizeof(hello_verify_cookie);
    memcpy(body + 3, hello_verify_cookie, sizeof(hello_verify_cookie));
    handshake_length = write_handshake(handshake, HANDSHAKE_HELLO_VERIFY, 0,
                                       body, sizeof(body));
    write_record_header(output, CONTENT_HANDSHAKE, 0, 0, handshake_length);
    memcpy(output + DTLS09_RECORD_HEADER, handshake, handshake_length);
    return DTLS09_RECORD_HEADER + handshake_length;
}

static size_t build_server_hello(uint8_t *output, const uint8_t server_random[32],
                                 const uint8_t session_id[32], uint8_t *body_copy,
                                 size_t *body_length)
{
    uint8_t body[70];
    uint8_t handshake[DTLS09_HANDSHAKE_HEADER + sizeof(body)];
    size_t position = 0;
    size_t handshake_length;

    body[position++] = DTLS09_VERSION_MAJOR;
    body[position++] = DTLS09_VERSION_MINOR;
    memcpy(body + position, server_random, DTLS09_RANDOM);
    position += DTLS09_RANDOM;
    body[position++] = DTLS09_SESSION_ID;
    memcpy(body + position, session_id, DTLS09_SESSION_ID);
    position += DTLS09_SESSION_ID;
    write_u16(body + position, record_cipher_suite);
    position += 2;
    body[position++] = 0;
    memcpy(body_copy, body, position);
    *body_length = position;
    handshake_length = write_handshake(handshake, HANDSHAKE_SERVER_HELLO, 1,
                                       body, position);
    write_record_header(output, CONTENT_HANDSHAKE, 0, 1, handshake_length);
    memcpy(output + DTLS09_RECORD_HEADER, handshake, handshake_length);
    return DTLS09_RECORD_HEADER + handshake_length;
}

static size_t build_change_cipher_spec(uint8_t *output)
{
    static const uint8_t payload[] = { 0x01, 0x00, 0x02 };

    write_record_header(output, CONTENT_CHANGE_CIPHER_SPEC, 0, 2, sizeof(payload));
    memcpy(output + DTLS09_RECORD_HEADER, payload, sizeof(payload));
    return DTLS09_RECORD_HEADER + sizeof(payload);
}

static int same_peer(const struct sockaddr_in *left, const struct sockaddr_in *right)
{
    return left->sin_family == right->sin_family &&
           left->sin_port == right->sin_port &&
           left->sin_addr.s_addr == right->sin_addr.s_addr;
}

static ssize_t receive_datagram(int socket_fd, uint8_t *buffer, size_t buffer_length,
                                struct sockaddr_in *peer)
{
    socklen_t peer_length = sizeof(*peer);
    ssize_t received = recvfrom(socket_fd, buffer, buffer_length, 0,
                                (struct sockaddr *)peer, &peer_length);

    if (received < 0)
        fprintf(stderr, "DTLS09_ERROR recvfrom: %s\n", strerror(errno));
    return received;
}

static int send_datagram(int socket_fd, const uint8_t *buffer, size_t buffer_length,
                         const struct sockaddr_in *peer)
{
    ssize_t sent = sendto(socket_fd, buffer, buffer_length, 0,
                          (const struct sockaddr *)peer, sizeof(*peer));

    if (sent != (ssize_t)buffer_length) {
        fprintf(stderr, "DTLS09_ERROR sendto: %s\n", sent < 0 ? strerror(errno) : "short write");
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    uint8_t session_id[DTLS09_SESSION_ID];
    uint8_t master_secret[DTLS09_MASTER_SECRET];
    uint8_t client_random[DTLS09_RANDOM];
    uint8_t server_random[DTLS09_RANDOM];
    uint8_t client_hello_body[512];
    uint8_t server_hello_body[512];
    uint8_t key_seed[DTLS09_RANDOM * 2];
    uint8_t key_block[DTLS09_MAX_KEY_BLOCK];
    const uint8_t *client_mac_key;
    const uint8_t *server_mac_key;
    const uint8_t *client_key;
    const uint8_t *server_key;
    uint8_t transcript[1200];
    size_t transcript_length;
    size_t client_hello_body_length = 0;
    size_t server_hello_body_length = 0;
    uint8_t server_verify[DTLS09_FINISHED];
    uint8_t client_verify[DTLS09_FINISHED];
    uint8_t finished_handshake[DTLS09_HANDSHAKE_HEADER + DTLS09_FINISHED];
    size_t finished_handshake_length;
    uint8_t datagram[4096];
    uint8_t response[4096];
    uint8_t plaintext[2048];
    size_t response_length;
    size_t plaintext_length;
    size_t offset;
    ssize_t received;
    struct dtls09_record record;
    struct dtls09_record second_record;
    struct sockaddr_in bind_address;
    struct sockaddr_in client_address;
    struct sockaddr_in received_address;
    struct timeval timeout;
    int socket_fd = -1;
    char cookie_hex[sizeof(hello_verify_cookie) * 2 + 1];
    char client_ip[INET_ADDRSTRLEN];
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *legacy_provider = NULL;
    int result = 1;

    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc != 4 || !decode_hex(argv[1], session_id, sizeof(session_id)) ||
        !decode_hex(argv[2], master_secret, sizeof(master_secret))) {
        fprintf(stderr, "DTLS09_ERROR usage: dtls09-peer SESSION_ID_HEX MASTER_SECRET_HEX CIPHER\n");
        return 2;
    }
    default_provider = OSSL_PROVIDER_load(NULL, "default");
    legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
    if (default_provider == NULL || legacy_provider == NULL) {
        fprintf(stderr, "DTLS09_ERROR OpenSSL providers unavailable\n");
        goto done;
    }
    if (strcmp(argv[3], "AES128-SHA") == 0) {
        record_cipher = EVP_aes_128_cbc();
        record_block_length = 16;
        record_key_length = 16;
        record_cipher_suite = 0x002f;
    } else if (strcmp(argv[3], "DES-CBC-SHA") == 0) {
        record_cipher = EVP_des_cbc();
        record_block_length = 8;
        record_key_length = 8;
        record_cipher_suite = 0x0009;
    } else {
        fprintf(stderr, "DTLS09_ERROR unsupported cipher: %s\n", argv[3]);
        goto done;
    }
    record_key_block_length = 2 * DTLS09_MAC + 2 * record_key_length + 2 * record_block_length;
    if (record_cipher == NULL || EVP_CIPHER_get_block_size(record_cipher) != (int)record_block_length ||
        EVP_CIPHER_get_key_length(record_cipher) != (int)record_key_length ||
        record_key_block_length > sizeof(key_block)) {
        fprintf(stderr, "DTLS09_ERROR invalid cipher parameters: %s\n", argv[3]);
        goto done;
    }
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        fprintf(stderr, "DTLS09_ERROR socket: %s\n", strerror(errno));
        goto done;
    }
    timeout.tv_sec = 20;
    timeout.tv_usec = 0;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        fprintf(stderr, "DTLS09_ERROR setsockopt: %s\n", strerror(errno));
        goto done;
    }
    memset(&bind_address, 0, sizeof(bind_address));
    bind_address.sin_family = AF_INET;
    bind_address.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_address.sin_port = htons(DTLS09_PORT);
    if (bind(socket_fd, (struct sockaddr *)&bind_address, sizeof(bind_address)) < 0) {
        fprintf(stderr, "DTLS09_ERROR bind: %s\n", strerror(errno));
        goto done;
    }
    encode_hex(hello_verify_cookie, sizeof(hello_verify_cookie), cookie_hex);
    printf("DTLS09_READY port=%d cookie=%s cipher=%s\n", DTLS09_PORT, cookie_hex, argv[3]);

    received = receive_datagram(socket_fd, datagram, sizeof(datagram), &client_address);
    if (received <= 0 || !validate_client_hello(datagram, (size_t)received, 0,
                                                session_id, client_random,
                                                client_hello_body,
                                                &client_hello_body_length)) {
        fprintf(stderr, "DTLS09_ERROR initial ClientHello validation failed\n");
        goto done;
    }
    response_length = build_hello_verify(response);
    if (!send_datagram(socket_fd, response, response_length, &client_address))
        goto done;

    received = receive_datagram(socket_fd, datagram, sizeof(datagram), &received_address);
    if (received <= 0 || !same_peer(&client_address, &received_address) ||
        !validate_client_hello(datagram, (size_t)received, 1, session_id,
                               client_random, client_hello_body,
                               &client_hello_body_length)) {
        fprintf(stderr, "DTLS09_ERROR cookie ClientHello validation failed\n");
        goto done;
    }
    if (RAND_bytes(server_random, sizeof(server_random)) != 1) {
        fprintf(stderr, "DTLS09_ERROR RAND_bytes failed\n");
        goto done;
    }
    memcpy(key_seed, server_random, DTLS09_RANDOM);
    memcpy(key_seed + DTLS09_RANDOM, client_random, DTLS09_RANDOM);
    if (!tls10_prf(master_secret, sizeof(master_secret), "key expansion", key_seed,
                   sizeof(key_seed), key_block, record_key_block_length)) {
        fprintf(stderr, "DTLS09_ERROR key expansion failed\n");
        goto done;
    }
    client_mac_key = key_block;
    server_mac_key = key_block + 20;
    client_key = key_block + 40;
    server_key = client_key + record_key_length;

    offset = build_server_hello(response, server_random, session_id,
                                server_hello_body, &server_hello_body_length);
    offset += build_change_cipher_spec(response + offset);
    memcpy(transcript, client_hello_body, client_hello_body_length);
    memcpy(transcript + client_hello_body_length, server_hello_body,
           server_hello_body_length);
    transcript_length = client_hello_body_length + server_hello_body_length;
    if (!compute_finished(master_secret, "server finished", transcript,
                          transcript_length, server_verify)) {
        fprintf(stderr, "DTLS09_ERROR server Finished calculation failed\n");
        goto done;
    }
    finished_handshake_length = write_handshake(finished_handshake, HANDSHAKE_FINISHED,
                                                3, server_verify, sizeof(server_verify));
    if (!encrypt_record(CONTENT_HANDSHAKE, 0, finished_handshake,
                        finished_handshake_length, server_key, server_mac_key,
                        response + offset, sizeof(response) - offset,
                        &response_length)) {
        fprintf(stderr, "DTLS09_ERROR server Finished encryption failed\n");
        goto done;
    }
    offset += response_length;
    if (!send_datagram(socket_fd, response, offset, &client_address))
        goto done;

    received = receive_datagram(socket_fd, datagram, sizeof(datagram), &received_address);
    if (received <= 0 || !same_peer(&client_address, &received_address) ||
        !parse_record(datagram, (size_t)received, &record) ||
        record.type != CONTENT_CHANGE_CIPHER_SPEC || record.epoch != 0 ||
        record.sequence != 2 || record.payload_length != 3 ||
        CRYPTO_memcmp(record.payload, "\x01\x00\x02", 3) != 0 ||
        !parse_record(datagram + record.consumed,
                      (size_t)received - record.consumed, &second_record) ||
        record.consumed + second_record.consumed != (size_t)received ||
        second_record.type != CONTENT_HANDSHAKE || second_record.epoch != 1 ||
        second_record.sequence != 0 ||
        !decrypt_record(&second_record, client_key, client_mac_key, plaintext,
                        sizeof(plaintext), &plaintext_length) ||
        plaintext_length != DTLS09_HANDSHAKE_HEADER + DTLS09_FINISHED ||
        plaintext[0] != HANDSHAKE_FINISHED || read_u24(plaintext + 1) != DTLS09_FINISHED ||
        read_u16(plaintext + 4) != 3 || read_u24(plaintext + 6) != 0 ||
        read_u24(plaintext + 9) != DTLS09_FINISHED) {
        fprintf(stderr, "DTLS09_ERROR client CCS/Finished validation failed\n");
        goto done;
    }
    memcpy(transcript + transcript_length, server_verify, sizeof(server_verify));
    transcript_length += sizeof(server_verify);
    if (!compute_finished(master_secret, "client finished", transcript,
                          transcript_length, client_verify) ||
        CRYPTO_memcmp(plaintext + DTLS09_HANDSHAKE_HEADER, client_verify,
                      sizeof(client_verify)) != 0) {
        fprintf(stderr, "DTLS09_ERROR client Finished verify_data mismatch\n");
        goto done;
    }
    printf("DTLS09_HANDSHAKE_OK first_cookie=empty retry_cookie=%s client_ccs=verified client_finished=verified\n",
           cookie_hex);

    received = receive_datagram(socket_fd, datagram, sizeof(datagram), &received_address);
    if (received <= 0 || !same_peer(&client_address, &received_address) ||
        !parse_record(datagram, (size_t)received, &record) ||
        record.consumed != (size_t)received || record.type != CONTENT_APPLICATION_DATA ||
        record.epoch != 1 || record.sequence != 1 ||
        !decrypt_record(&record, client_key, client_mac_key, plaintext,
                        sizeof(plaintext), &plaintext_length) ||
        plaintext_length != sizeof("\x00" "dtls09-client-data") - 1 ||
        CRYPTO_memcmp(plaintext, "\x00" "dtls09-client-data",
                      sizeof("\x00" "dtls09-client-data") - 1) != 0) {
        fprintf(stderr, "DTLS09_ERROR client application DATA validation failed\n");
        goto done;
    }
    if (!encrypt_record(CONTENT_APPLICATION_DATA, 1,
                        (const uint8_t *)"\x00" "dtls09-server-data",
                        sizeof("\x00" "dtls09-server-data") - 1,
                        server_key, server_mac_key, response, sizeof(response),
                        &response_length) ||
        !send_datagram(socket_fd, response, response_length, &client_address))
        goto done;
    if (!encrypt_record(CONTENT_APPLICATION_DATA, 2, (const uint8_t *)"\x03", 1,
                        server_key, server_mac_key, response, sizeof(response),
                        &response_length) ||
        !send_datagram(socket_fd, response, response_length, &client_address))
        goto done;

    received = receive_datagram(socket_fd, datagram, sizeof(datagram), &received_address);
    if (received <= 0 || !same_peer(&client_address, &received_address) ||
        !parse_record(datagram, (size_t)received, &record) ||
        record.consumed != (size_t)received || record.type != CONTENT_APPLICATION_DATA ||
        record.epoch != 1 || record.sequence != 2 ||
        !decrypt_record(&record, client_key, client_mac_key, plaintext,
                        sizeof(plaintext), &plaintext_length) ||
        plaintext_length != 1 || plaintext[0] != 4) {
        fprintf(stderr, "DTLS09_ERROR client DPD response validation failed\n");
        goto done;
    }
    if (inet_ntop(AF_INET, &client_address.sin_addr, client_ip, sizeof(client_ip)) == NULL)
        strcpy(client_ip, "unknown");
    printf("DTLS09_COMPLETE client_data=verified server_data=sent dpd_request=sent dpd_response=verified path=%s:%u->0.0.0.0:%d/udp\n",
           client_ip, ntohs(client_address.sin_port), DTLS09_PORT);
    for (;;) {
        received = receive_datagram(socket_fd, datagram, sizeof(datagram), &received_address);
        if (received <= 0)
            goto done;
        if (received == (ssize_t)(sizeof("DTLS09_STOP") - 1) &&
            CRYPTO_memcmp(datagram, "DTLS09_STOP", sizeof("DTLS09_STOP") - 1) == 0)
            break;
        printf("DTLS09_POST_COMPLETE_IGNORED bytes=%zd\n", received);
    }
    printf("DTLS09_STOPPED exit=0\n");
    result = 0;

done:
    if (socket_fd >= 0)
        close(socket_fd);
    if (legacy_provider != NULL)
        OSSL_PROVIDER_unload(legacy_provider);
    if (default_provider != NULL)
        OSSL_PROVIDER_unload(default_provider);
    return result;
}

/*
 * Independent GlobalProtect ESP UDP peer derived solely from OpenConnect
 * esp.c, esp-seqno.c, openssl-esp.c, and gpst.c at commit
 * 2035601b64a5360a46d18e08937e7f654b3230f2.
 * Copyright © 2008-2015 Intel Corporation and © 2016-2017 Daniel Lenski.
 * LGPL-2.1-or-later.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define ESP_BLOCK_SIZE 16
#define ESP_HEADER_SIZE 24
#define MAX_PACKET_SIZE 65536

struct esp_suite {
	const EVP_CIPHER *cbc;
	const EVP_CIPHER *ecb;
	const EVP_MD *digest;
	size_t encryption_key_length;
	size_t authentication_key_length;
	size_t icv_length;
};

struct esp_peer {
	struct esp_suite suite;
	uint32_t client_spi;
	uint32_t server_spi;
	unsigned char client_encryption_key[32];
	unsigned char client_authentication_key[32];
	unsigned char server_encryption_key[32];
	unsigned char server_authentication_key[32];
	uint32_t client_sequence;
	uint32_t server_sequence;
	unsigned char expected_client_iv[ESP_BLOCK_SIZE];
	int have_expected_client_iv;
	int send_lzo_after_echo;
};

static uint16_t load_be16(const unsigned char *data)
{
	return ((uint16_t)data[0] << 8) | data[1];
}

static uint32_t load_be32(const unsigned char *data)
{
	return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
	       ((uint32_t)data[2] << 8) | data[3];
}

static void store_be16(unsigned char *data, uint16_t value)
{
	data[0] = (unsigned char)(value >> 8);
	data[1] = (unsigned char)value;
}

static void store_be32(unsigned char *data, uint32_t value)
{
	data[0] = (unsigned char)(value >> 24);
	data[1] = (unsigned char)(value >> 16);
	data[2] = (unsigned char)(value >> 8);
	data[3] = (unsigned char)value;
}

static uint32_t checksum_add(uint32_t sum, const unsigned char *data, size_t length)
{
	while (length >= 2) {
		sum += ((uint16_t)data[0] << 8) | data[1];
		data += 2;
		length -= 2;
	}
	if (length != 0)
		sum += (uint16_t)data[0] << 8;
	return sum;
}

static uint16_t checksum_finish(uint32_t sum)
{
	while ((sum >> 16) != 0)
		sum = (sum & 0xffffU) + (sum >> 16);
	return (uint16_t)~sum;
}

static int decode_hex(const char *source, unsigned char *destination, size_t expected_length)
{
	size_t source_length = strlen(source);
	if (source_length != expected_length * 2)
		return 0;
	for (size_t i = 0; i < expected_length; i++) {
		char value[3] = {source[i * 2], source[i * 2 + 1], 0};
		char *end = NULL;
		unsigned long decoded = strtoul(value, &end, 16);
		if (end == NULL || *end != 0 || decoded > UCHAR_MAX)
			return 0;
		destination[i] = (unsigned char)decoded;
	}
	return 1;
}

static int parse_u32(const char *source, uint32_t *value)
{
	char *end = NULL;
	errno = 0;
	unsigned long parsed = strtoul(source, &end, 0);
	if (errno != 0 || end == NULL || *end != 0 || parsed == 0 || parsed > UINT32_MAX)
		return 0;
	*value = (uint32_t)parsed;
	return 1;
}

static int encrypt_block(const struct esp_suite *suite, const unsigned char *key,
			 const unsigned char input[ESP_BLOCK_SIZE], unsigned char output[ESP_BLOCK_SIZE])
{
	EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
	if (context == NULL)
		return 0;
	int output_length = 0;
	int final_length = 0;
	int success = EVP_EncryptInit_ex(context, suite->ecb, NULL, key, NULL) == 1 &&
		EVP_CIPHER_CTX_set_padding(context, 0) == 1 &&
		EVP_EncryptUpdate(context, output, &output_length, input, ESP_BLOCK_SIZE) == 1 &&
		EVP_EncryptFinal_ex(context, output + output_length, &final_length) == 1 &&
		output_length + final_length == ESP_BLOCK_SIZE;
	EVP_CIPHER_CTX_free(context);
	return success;
}

static int decrypt_payload(const struct esp_suite *suite, const unsigned char *key,
			   const unsigned char iv[ESP_BLOCK_SIZE], const unsigned char *ciphertext,
			   size_t ciphertext_length, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
	if (context == NULL)
		return 0;
	int output_length = 0;
	int final_length = 0;
	int success = EVP_DecryptInit_ex(context, suite->cbc, NULL, key, iv) == 1 &&
		EVP_CIPHER_CTX_set_padding(context, 0) == 1 &&
		EVP_DecryptUpdate(context, plaintext, &output_length, ciphertext,
				  (int)ciphertext_length) == 1 &&
		EVP_DecryptFinal_ex(context, plaintext + output_length, &final_length) == 1 &&
		(size_t)(output_length + final_length) == ciphertext_length;
	EVP_CIPHER_CTX_free(context);
	return success;
}

static int encrypt_payload(const struct esp_suite *suite, const unsigned char *key,
			   const unsigned char iv[ESP_BLOCK_SIZE], const unsigned char *plaintext,
			   size_t plaintext_length, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
	if (context == NULL)
		return 0;
	int output_length = 0;
	int final_length = 0;
	int success = EVP_EncryptInit_ex(context, suite->cbc, NULL, key, iv) == 1 &&
		EVP_CIPHER_CTX_set_padding(context, 0) == 1 &&
		EVP_EncryptUpdate(context, ciphertext, &output_length, plaintext,
				  (int)plaintext_length) == 1 &&
		EVP_EncryptFinal_ex(context, ciphertext + output_length, &final_length) == 1 &&
		(size_t)(output_length + final_length) == plaintext_length;
	EVP_CIPHER_CTX_free(context);
	return success;
}

static int calculate_hmac(const struct esp_suite *suite, const unsigned char *key,
			  const unsigned char *data, size_t data_length,
			  unsigned char *output, unsigned int *output_length)
{
	return HMAC(suite->digest, key, (int)suite->authentication_key_length,
		    data, data_length, output, output_length) != NULL;
}

static int decrypt_esp(struct esp_peer *peer, const unsigned char *datagram, size_t datagram_length,
		       unsigned char *payload, size_t *payload_length, unsigned char *next_header)
{
	size_t icv_length = peer->suite.icv_length;
	if (datagram_length < ESP_HEADER_SIZE + ESP_BLOCK_SIZE + icv_length)
		return 0;
	if (load_be32(datagram) != peer->client_spi ||
	    load_be32(datagram + 4) != peer->client_sequence)
		return 0;
	if (peer->have_expected_client_iv != 0 &&
	    CRYPTO_memcmp(datagram + 8, peer->expected_client_iv, ESP_BLOCK_SIZE) != 0)
		return 0;
	size_t ciphertext_length = datagram_length - ESP_HEADER_SIZE - icv_length;
	if (ciphertext_length % ESP_BLOCK_SIZE != 0)
		return 0;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_length = 0;
	if (!calculate_hmac(&peer->suite, peer->client_authentication_key,
			    datagram, datagram_length - icv_length, digest, &digest_length) ||
	    digest_length < ESP_BLOCK_SIZE ||
	    CRYPTO_memcmp(digest, datagram + datagram_length - icv_length, icv_length) != 0)
		return 0;
	if (!decrypt_payload(&peer->suite, peer->client_encryption_key, datagram + 8,
			     datagram + ESP_HEADER_SIZE, ciphertext_length, payload))
		return 0;
	unsigned int padding_length = payload[ciphertext_length - 2];
	if (ciphertext_length <= (size_t)padding_length + 2)
		return 0;
	*payload_length = ciphertext_length - padding_length - 2;
	for (unsigned int i = 0; i < padding_length; i++) {
		if (payload[*payload_length + i] != (unsigned char)(i + 1))
			return 0;
	}
	*next_header = payload[ciphertext_length - 1];
	if (*next_header != 4 && *next_header != 41)
		return 0;
	unsigned char chain_input[ESP_BLOCK_SIZE];
	const unsigned char *digest_tail = digest + digest_length - ESP_BLOCK_SIZE;
	const unsigned char *last_ciphertext = datagram + ESP_HEADER_SIZE + ciphertext_length - ESP_BLOCK_SIZE;
	for (size_t i = 0; i < ESP_BLOCK_SIZE; i++)
		chain_input[i] = digest_tail[i] ^ last_ciphertext[i];
	if (!encrypt_block(&peer->suite, peer->client_encryption_key,
			   chain_input, peer->expected_client_iv)) {
		OPENSSL_cleanse(chain_input, sizeof(chain_input));
		return 0;
	}
	OPENSSL_cleanse(chain_input, sizeof(chain_input));
	peer->have_expected_client_iv = 1;
	peer->client_sequence++;
	return 1;
}

static int encrypt_esp(struct esp_peer *peer, const unsigned char *payload, size_t payload_length,
		       unsigned char next_header, unsigned char *datagram, size_t *datagram_length)
{
	size_t padding_length = ESP_BLOCK_SIZE - 1 - ((payload_length + 1) % ESP_BLOCK_SIZE);
	size_t plaintext_length = payload_length + padding_length + 2;
	size_t output_length = ESP_HEADER_SIZE + plaintext_length + peer->suite.icv_length;
	if (output_length > MAX_PACKET_SIZE)
		return 0;
	store_be32(datagram, peer->server_spi);
	store_be32(datagram + 4, peer->server_sequence);
	if (RAND_bytes(datagram + 8, ESP_BLOCK_SIZE) != 1)
		return 0;
	unsigned char plaintext[MAX_PACKET_SIZE];
	memcpy(plaintext, payload, payload_length);
	for (size_t i = 0; i < padding_length; i++)
		plaintext[payload_length + i] = (unsigned char)(i + 1);
	plaintext[plaintext_length - 2] = (unsigned char)padding_length;
	plaintext[plaintext_length - 1] = next_header;
	if (!encrypt_payload(&peer->suite, peer->server_encryption_key, datagram + 8,
			     plaintext, plaintext_length, datagram + ESP_HEADER_SIZE)) {
		OPENSSL_cleanse(plaintext, plaintext_length);
		return 0;
	}
	OPENSSL_cleanse(plaintext, plaintext_length);
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_length = 0;
	if (!calculate_hmac(&peer->suite, peer->server_authentication_key,
			    datagram, ESP_HEADER_SIZE + plaintext_length, digest, &digest_length) ||
	    digest_length < peer->suite.icv_length)
		return 0;
	memcpy(datagram + ESP_HEADER_SIZE + plaintext_length, digest, peer->suite.icv_length);
	peer->server_sequence++;
	*datagram_length = output_length;
	return 1;
}

static int echo_ipv4(unsigned char *packet, size_t *packet_length)
{
	if (*packet_length < 28 || (packet[0] >> 4) != 4)
		return 0;
	size_t header_length = (size_t)(packet[0] & 0x0f) * 4;
	if (header_length < 20 || header_length + 8 > *packet_length || packet[9] != 1)
		return 0;
	size_t total_length = load_be16(packet + 2);
	if (total_length < header_length + 8 || total_length > *packet_length || packet[header_length] != 8)
		return 0;
	if (checksum_finish(checksum_add(0, packet, header_length)) != 0 ||
	    checksum_finish(checksum_add(0, packet + header_length, total_length - header_length)) != 0)
		return 0;
	unsigned char address[4];
	memcpy(address, packet + 12, sizeof(address));
	memcpy(packet + 12, packet + 16, sizeof(address));
	memcpy(packet + 16, address, sizeof(address));
	packet[header_length] = 0;
	packet[header_length + 2] = 0;
	packet[header_length + 3] = 0;
	store_be16(packet + header_length + 2,
		   checksum_finish(checksum_add(0, packet + header_length, total_length - header_length)));
	packet[10] = 0;
	packet[11] = 0;
	store_be16(packet + 10, checksum_finish(checksum_add(0, packet, header_length)));
	*packet_length = total_length;
	return 1;
}

static uint32_t ipv6_icmp_checksum(const unsigned char *packet, size_t payload_length)
{
	uint32_t sum = checksum_add(0, packet + 8, 32);
	sum += (uint16_t)(payload_length >> 16);
	sum += (uint16_t)payload_length;
	sum += 58;
	return checksum_add(sum, packet + 40, payload_length);
}

static int echo_ipv6(unsigned char *packet, size_t *packet_length)
{
	if (*packet_length < 48 || (packet[0] >> 4) != 6 || packet[6] != 58)
		return 0;
	size_t payload_length = load_be16(packet + 4);
	if (payload_length < 8 || 40 + payload_length > *packet_length || packet[40] != 128)
		return 0;
	if (checksum_finish(ipv6_icmp_checksum(packet, payload_length)) != 0)
		return 0;
	unsigned char address[16];
	memcpy(address, packet + 8, sizeof(address));
	memcpy(packet + 8, packet + 24, sizeof(address));
	memcpy(packet + 24, address, sizeof(address));
	packet[40] = 129;
	packet[42] = 0;
	packet[43] = 0;
	store_be16(packet + 42, checksum_finish(ipv6_icmp_checksum(packet, payload_length)));
	*packet_length = 40 + payload_length;
	return 1;
}

static int select_suite(const char *encryption, const char *authentication, struct esp_suite *suite)
{
	if (strcmp(encryption, "aes-128-cbc") == 0) {
		suite->cbc = EVP_aes_128_cbc();
		suite->ecb = EVP_aes_128_ecb();
		suite->encryption_key_length = 16;
	} else if (strcmp(encryption, "aes-256-cbc") == 0) {
		suite->cbc = EVP_aes_256_cbc();
		suite->ecb = EVP_aes_256_ecb();
		suite->encryption_key_length = 32;
	} else {
		return 0;
	}
	if (strcmp(authentication, "md5") == 0) {
		suite->digest = EVP_md5();
		suite->authentication_key_length = 16;
		suite->icv_length = 12;
	} else if (strcmp(authentication, "sha1") == 0) {
		suite->digest = EVP_sha1();
		suite->authentication_key_length = 20;
		suite->icv_length = 12;
	} else if (strcmp(authentication, "sha256") == 0) {
		suite->digest = EVP_sha256();
		suite->authentication_key_length = 32;
		suite->icv_length = 16;
	} else {
		return 0;
	}
	return 1;
}

static int run_peer(uint16_t port, struct esp_peer *peer)
{
	int socket_descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (socket_descriptor < 0) {
		perror("socket");
		return 1;
	}
	int reuse = 1;
	if (setsockopt(socket_descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		perror("setsockopt");
		close(socket_descriptor);
		return 1;
	}
	struct sockaddr_in local_address;
	memset(&local_address, 0, sizeof(local_address));
	local_address.sin_family = AF_INET;
	local_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	local_address.sin_port = htons(port);
	if (bind(socket_descriptor, (struct sockaddr *)&local_address, sizeof(local_address)) < 0) {
		perror("bind");
		close(socket_descriptor);
		return 1;
	}
	socklen_t local_address_length = sizeof(local_address);
	if (getsockname(socket_descriptor, (struct sockaddr *)&local_address, &local_address_length) < 0) {
		perror("getsockname");
		close(socket_descriptor);
		return 1;
	}
	printf("PORT %u\n", ntohs(local_address.sin_port));
	fflush(stdout);
	for (;;) {
		unsigned char datagram[MAX_PACKET_SIZE];
		struct sockaddr_storage remote_address;
		socklen_t remote_address_length = sizeof(remote_address);
		ssize_t received = recvfrom(socket_descriptor, datagram, sizeof(datagram), 0,
					    (struct sockaddr *)&remote_address, &remote_address_length);
		if (received < 0) {
			if (errno == EINTR)
				continue;
			perror("recvfrom");
			close(socket_descriptor);
			return 1;
		}
		unsigned char payload[MAX_PACKET_SIZE];
		size_t payload_length = 0;
		unsigned char next_header = 0;
		if (!decrypt_esp(peer, datagram, (size_t)received,
				 payload, &payload_length, &next_header)) {
			fprintf(stderr, "ignored invalid client ESP datagram\n");
			continue;
		}
		int echoed = next_header == 4 ? echo_ipv4(payload, &payload_length) :
			     echo_ipv6(payload, &payload_length);
		if (!echoed) {
			fprintf(stderr, "ignored non-echo ESP payload\n");
			continue;
		}
		size_t response_length = 0;
		unsigned char response_next_header = next_header;
		if (peer->send_lzo_after_echo != 0 && peer->server_sequence > 1)
			response_next_header = 5;
		if (!encrypt_esp(peer, payload, payload_length, response_next_header,
				 datagram, &response_length)) {
			fprintf(stderr, "failed to encrypt server ESP datagram\n");
			close(socket_descriptor);
			return 1;
		}
		ssize_t sent = sendto(socket_descriptor, datagram, response_length, 0,
				      (struct sockaddr *)&remote_address, remote_address_length);
		if (sent < 0 || (size_t)sent != response_length) {
			perror("sendto");
			close(socket_descriptor);
			return 1;
		}
		sent = sendto(socket_descriptor, datagram, response_length, 0,
			      (struct sockaddr *)&remote_address, remote_address_length);
		if (sent < 0 || (size_t)sent != response_length) {
			perror("sendto duplicate");
			close(socket_descriptor);
			return 1;
		}
	}
}

int main(int argc, char **argv)
{
	if (argc != 11) {
		fprintf(stderr,
			"usage: %s PORT ENC AUTH C2S_SPI S2C_SPI C2S_ENC_KEY C2S_AUTH_KEY S2C_ENC_KEY S2C_AUTH_KEY MODE\n",
			argv[0]);
		return 2;
	}
	char *port_end = NULL;
	errno = 0;
	unsigned long parsed_port = strtoul(argv[1], &port_end, 10);
	if (errno != 0 || port_end == NULL || *port_end != 0 || parsed_port > UINT16_MAX) {
		fprintf(stderr, "invalid UDP port\n");
		return 2;
	}
	struct esp_peer peer;
	memset(&peer, 0, sizeof(peer));
	if (!select_suite(argv[2], argv[3], &peer.suite) ||
	    !parse_u32(argv[4], &peer.client_spi) ||
	    !parse_u32(argv[5], &peer.server_spi) ||
	    !decode_hex(argv[6], peer.client_encryption_key, peer.suite.encryption_key_length) ||
	    !decode_hex(argv[7], peer.client_authentication_key, peer.suite.authentication_key_length) ||
	    !decode_hex(argv[8], peer.server_encryption_key, peer.suite.encryption_key_length) ||
	    !decode_hex(argv[9], peer.server_authentication_key, peer.suite.authentication_key_length)) {
		fprintf(stderr, "invalid ESP suite, SPI, or key material\n");
		OPENSSL_cleanse(&peer, sizeof(peer));
		return 2;
	}
	if (strcmp(argv[10], "normal") == 0) {
		peer.send_lzo_after_echo = 0;
	} else if (strcmp(argv[10], "lzo-after-echo") == 0) {
		peer.send_lzo_after_echo = 1;
	} else {
		fprintf(stderr, "invalid ESP response mode\n");
		OPENSSL_cleanse(&peer, sizeof(peer));
		return 2;
	}
	int result = run_peer((uint16_t)parsed_port, &peer);
	OPENSSL_cleanse(&peer, sizeof(peer));
	return result;
}

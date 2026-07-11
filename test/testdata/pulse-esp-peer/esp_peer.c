/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Independent Pulse/Juniper ESP UDP peer derived from OpenConnect esp.c,
 * openssl-esp.c, oncp.c, and lzo.c at commit
 * 2035601b64a5360a46d18e08937e7f654b3230f2.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <lzo1x.h>
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

#define ESP_BLOCK_SIZE 16U
#define ESP_HEADER_SIZE 24U
#define MAX_IP_PACKET_SIZE 65535U
#define MAX_CRYPT_SIZE 65536U
#define MAX_UDP_DATAGRAM_SIZE 65507U
#define MAX_LZO_SIZE (MAX_IP_PACKET_SIZE + MAX_IP_PACKET_SIZE / 16U + 64U + 3U)
#define TEST_NEGOTIATED_MTU 1400U

enum invalid_lzo_kind {
	INVALID_LZO_NONE,
	INVALID_LZO_MALFORMED,
	INVALID_LZO_TRAILING,
	INVALID_LZO_OVERSIZE,
};

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
	uint32_t last_client_sequence;
	uint32_t server_sequence;
	unsigned char expected_client_iv[ESP_BLOCK_SIZE];
	unsigned char server_iv[ESP_BLOCK_SIZE];
	int have_expected_client_iv;
	int have_client_sequence;
	int initial_sequence_continuation;
	int initially_established;
	int expected_probe_next_header;
	void *lzo_work_memory;
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

static int hex_nibble(char source, unsigned char *value)
{
	if (source >= '0' && source <= '9') {
		*value = (unsigned char)(source - '0');
		return 1;
	}
	if (source >= 'a' && source <= 'f') {
		*value = (unsigned char)(source - 'a' + 10);
		return 1;
	}
	if (source >= 'A' && source <= 'F') {
		*value = (unsigned char)(source - 'A' + 10);
		return 1;
	}
	return 0;
}

static int decode_hex(const char *source, unsigned char *destination, size_t expected_length)
{
	if (strlen(source) != expected_length * 2)
		return 0;
	for (size_t index = 0; index < expected_length; index++) {
		unsigned char high = 0;
		unsigned char low = 0;
		if (!hex_nibble(source[index * 2], &high) ||
		    !hex_nibble(source[index * 2 + 1], &low))
			return 0;
		destination[index] = (unsigned char)((high << 4) | low);
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
			 const unsigned char input[ESP_BLOCK_SIZE],
			 unsigned char output[ESP_BLOCK_SIZE])
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
		output_length + final_length == (int)ESP_BLOCK_SIZE;
	EVP_CIPHER_CTX_free(context);
	return success;
}

static int decrypt_payload(const struct esp_suite *suite, const unsigned char *key,
			   const unsigned char iv[ESP_BLOCK_SIZE],
			   const unsigned char *ciphertext, size_t ciphertext_length,
			   unsigned char *plaintext)
{
	if (ciphertext_length > INT_MAX)
		return 0;
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
			   const unsigned char iv[ESP_BLOCK_SIZE],
			   const unsigned char *plaintext, size_t plaintext_length,
			   unsigned char *ciphertext)
{
	if (plaintext_length > INT_MAX)
		return 0;
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

static int derive_next_iv(const struct esp_suite *suite, const unsigned char *key,
			  const unsigned char *digest, size_t digest_length,
			  const unsigned char last_ciphertext[ESP_BLOCK_SIZE],
			  unsigned char next_iv[ESP_BLOCK_SIZE])
{
	if (digest_length < ESP_BLOCK_SIZE)
		return 0;
	unsigned char chain_input[ESP_BLOCK_SIZE];
	const unsigned char *digest_tail = digest + digest_length - ESP_BLOCK_SIZE;
	for (size_t index = 0; index < ESP_BLOCK_SIZE; index++)
		chain_input[index] = digest_tail[index] ^ last_ciphertext[index];
	int success = encrypt_block(suite, key, chain_input, next_iv);
	OPENSSL_cleanse(chain_input, sizeof(chain_input));
	return success;
}

static int decrypt_esp(struct esp_peer *peer, const unsigned char *datagram,
		       size_t datagram_length, unsigned char *payload,
		       size_t *payload_length, unsigned char *next_header)
{
	if (datagram_length < ESP_HEADER_SIZE + ESP_BLOCK_SIZE + peer->suite.icv_length)
		return 0;
	if (load_be32(datagram) != peer->client_spi)
		return 0;
	uint32_t sequence = load_be32(datagram + 4);
	if (sequence == UINT32_MAX)
		return 0;
	int continuation = 0;
	if (peer->have_client_sequence != 0) {
		if (sequence < peer->client_sequence)
			return 0;
		continuation = sequence > peer->client_sequence;
	} else if (peer->initial_sequence_continuation != 0) {
		if (sequence == 0)
			return 0;
		continuation = 1;
	} else if (sequence != 0) {
		return 0;
	}
	if (continuation == 0 && peer->have_expected_client_iv != 0 &&
	    CRYPTO_memcmp(datagram + 8, peer->expected_client_iv, ESP_BLOCK_SIZE) != 0)
		return 0;
	size_t ciphertext_length = datagram_length - ESP_HEADER_SIZE - peer->suite.icv_length;
	if (ciphertext_length == 0 || ciphertext_length > MAX_CRYPT_SIZE ||
	    ciphertext_length % ESP_BLOCK_SIZE != 0)
		return 0;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_length = 0;
	if (!calculate_hmac(&peer->suite, peer->client_authentication_key,
			    datagram, datagram_length - peer->suite.icv_length,
			    digest, &digest_length) ||
	    digest_length < peer->suite.icv_length ||
	    CRYPTO_memcmp(digest, datagram + datagram_length - peer->suite.icv_length,
			  peer->suite.icv_length) != 0) {
		OPENSSL_cleanse(digest, sizeof(digest));
		return 0;
	}
	if (!decrypt_payload(&peer->suite, peer->client_encryption_key, datagram + 8,
			     datagram + ESP_HEADER_SIZE, ciphertext_length, payload)) {
		OPENSSL_cleanse(digest, sizeof(digest));
		return 0;
	}
	unsigned int padding_length = payload[ciphertext_length - 2];
	if (ciphertext_length <= (size_t)padding_length + 2) {
		OPENSSL_cleanse(payload, ciphertext_length);
		OPENSSL_cleanse(digest, sizeof(digest));
		return 0;
	}
	*payload_length = ciphertext_length - padding_length - 2;
	for (unsigned int index = 0; index < padding_length; index++) {
		if (payload[*payload_length + index] != (unsigned char)(index + 1)) {
			OPENSSL_cleanse(payload, ciphertext_length);
			OPENSSL_cleanse(digest, sizeof(digest));
			return 0;
		}
	}
	*next_header = payload[ciphertext_length - 1];
	if (*next_header != 4 && *next_header != 41) {
		OPENSSL_cleanse(payload, ciphertext_length);
		OPENSSL_cleanse(digest, sizeof(digest));
		return 0;
	}
	const unsigned char *last_ciphertext =
		datagram + ESP_HEADER_SIZE + ciphertext_length - ESP_BLOCK_SIZE;
	if (!derive_next_iv(&peer->suite, peer->client_encryption_key,
			    digest, digest_length, last_ciphertext,
			    peer->expected_client_iv)) {
		OPENSSL_cleanse(payload, ciphertext_length);
		OPENSSL_cleanse(digest, sizeof(digest));
		return 0;
	}
	OPENSSL_cleanse(digest, sizeof(digest));
	peer->have_expected_client_iv = 1;
	peer->have_client_sequence = 1;
	peer->last_client_sequence = sequence;
	peer->client_sequence = sequence + 1;
	if (continuation != 0) {
		printf("CONTINUATION %u\n", sequence);
		fflush(stdout);
	}
	return 1;
}

static int encrypt_esp(struct esp_peer *peer, const unsigned char *payload,
		       size_t payload_length, unsigned char next_header,
		       unsigned char *datagram, size_t *datagram_length)
{
	size_t padding_length = ESP_BLOCK_SIZE - 1 - ((payload_length + 1) % ESP_BLOCK_SIZE);
	size_t plaintext_length = payload_length + padding_length + 2;
	size_t output_length = ESP_HEADER_SIZE + plaintext_length + peer->suite.icv_length;
	if (plaintext_length > MAX_CRYPT_SIZE || output_length > MAX_UDP_DATAGRAM_SIZE)
		return 0;
	store_be32(datagram, peer->server_spi);
	store_be32(datagram + 4, peer->server_sequence);
	memcpy(datagram + 8, peer->server_iv, ESP_BLOCK_SIZE);
	unsigned char plaintext[MAX_CRYPT_SIZE];
	memcpy(plaintext, payload, payload_length);
	for (size_t index = 0; index < padding_length; index++)
		plaintext[payload_length + index] = (unsigned char)(index + 1);
	plaintext[plaintext_length - 2] = (unsigned char)padding_length;
	plaintext[plaintext_length - 1] = next_header;
	if (!encrypt_payload(&peer->suite, peer->server_encryption_key, peer->server_iv,
			     plaintext, plaintext_length, datagram + ESP_HEADER_SIZE)) {
		OPENSSL_cleanse(plaintext, plaintext_length);
		return 0;
	}
	OPENSSL_cleanse(plaintext, plaintext_length);
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_length = 0;
	if (!calculate_hmac(&peer->suite, peer->server_authentication_key,
			    datagram, ESP_HEADER_SIZE + plaintext_length,
			    digest, &digest_length) ||
	    digest_length < peer->suite.icv_length) {
		OPENSSL_cleanse(digest, sizeof(digest));
		return 0;
	}
	memcpy(datagram + ESP_HEADER_SIZE + plaintext_length, digest,
	       peer->suite.icv_length);
	const unsigned char *last_ciphertext =
		datagram + ESP_HEADER_SIZE + plaintext_length - ESP_BLOCK_SIZE;
	unsigned char next_iv[ESP_BLOCK_SIZE];
	if (!derive_next_iv(&peer->suite, peer->server_encryption_key,
			    digest, digest_length, last_ciphertext, next_iv)) {
		OPENSSL_cleanse(digest, sizeof(digest));
		return 0;
	}
	memcpy(peer->server_iv, next_iv, sizeof(peer->server_iv));
	OPENSSL_cleanse(next_iv, sizeof(next_iv));
	OPENSSL_cleanse(digest, sizeof(digest));
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
	if (total_length < header_length + 8 || total_length > *packet_length ||
	    packet[header_length] != 8 || packet[header_length + 1] != 0)
		return 0;
	if (checksum_finish(checksum_add(0, packet, header_length)) != 0 ||
	    checksum_finish(checksum_add(0, packet + header_length,
					 total_length - header_length)) != 0)
		return 0;
	unsigned char address[4];
	memcpy(address, packet + 12, sizeof(address));
	memcpy(packet + 12, packet + 16, sizeof(address));
	memcpy(packet + 16, address, sizeof(address));
	packet[header_length] = 0;
	packet[header_length + 2] = 0;
	packet[header_length + 3] = 0;
	store_be16(packet + header_length + 2,
		   checksum_finish(checksum_add(0, packet + header_length,
						 total_length - header_length)));
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
	if (payload_length < 8 || 40 + payload_length > *packet_length ||
	    packet[40] != 128 || packet[41] != 0)
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

static int compress_lzo(struct esp_peer *peer, const unsigned char *packet,
			size_t packet_length, unsigned char *compressed,
			size_t *compressed_length)
{
	if (packet_length > MAX_IP_PACKET_SIZE)
		return 0;
	lzo_uint result_length = MAX_LZO_SIZE;
	int result = lzo1x_1_compress(packet, (lzo_uint)packet_length, compressed,
				     &result_length, peer->lzo_work_memory);
	if (result != LZO_E_OK || result_length > MAX_LZO_SIZE)
		return 0;
	*compressed_length = (size_t)result_length;
	return 1;
}

static enum invalid_lzo_kind ipv4_invalid_lzo_kind(const unsigned char *packet,
						   size_t packet_length)
{
	static const unsigned char malformed[] = "pulse-lzo-malformed";
	static const unsigned char trailing[] = "pulse-lzo-trailing";
	static const unsigned char oversize[] = "pulse-lzo-oversize";
	if (packet_length < 28 || (packet[0] >> 4) != 4)
		return INVALID_LZO_NONE;
	size_t header_length = (size_t)(packet[0] & 0x0f) * 4;
	if (header_length < 20 || header_length + 8 > packet_length)
		return INVALID_LZO_NONE;
	const unsigned char *icmp_payload = packet + header_length + 8;
	size_t icmp_payload_length = packet_length - header_length - 8;
	if (icmp_payload_length == sizeof(malformed) - 1 &&
	    memcmp(icmp_payload, malformed, sizeof(malformed) - 1) == 0)
		return INVALID_LZO_MALFORMED;
	if (icmp_payload_length == sizeof(trailing) - 1 &&
	    memcmp(icmp_payload, trailing, sizeof(trailing) - 1) == 0)
		return INVALID_LZO_TRAILING;
	if (icmp_payload_length == sizeof(oversize) - 1 &&
	    memcmp(icmp_payload, oversize, sizeof(oversize) - 1) == 0)
		return INVALID_LZO_OVERSIZE;
	return INVALID_LZO_NONE;
}

static int lzo_self_test(void *work_memory)
{
	unsigned char input[512];
	for (size_t index = 0; index < sizeof(input); index++)
		input[index] = (unsigned char)(index % 13);
	unsigned char compressed[sizeof(input) + sizeof(input) / 16 + 64 + 3];
	lzo_uint compressed_length = sizeof(compressed);
	if (lzo1x_1_compress(input, sizeof(input), compressed, &compressed_length,
			    work_memory) != LZO_E_OK)
		return 0;
	unsigned char output[sizeof(input)];
	lzo_uint output_length = sizeof(output);
	if (lzo1x_decompress_safe(compressed, compressed_length, output,
				 &output_length, NULL) != LZO_E_OK)
		return 0;
	return output_length == sizeof(input) && memcmp(input, output, sizeof(input)) == 0;
}

static int select_suite(const char *encryption, const char *authentication,
			struct esp_suite *suite)
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

static int send_duplicate(int socket_descriptor, const unsigned char *datagram,
			  size_t datagram_length,
			  const struct sockaddr *remote_address,
			  socklen_t remote_address_length)
{
	for (int copy = 0; copy < 2; copy++) {
		ssize_t sent = sendto(socket_descriptor, datagram, datagram_length, 0,
				      remote_address, remote_address_length);
		if (sent < 0 || (size_t)sent != datagram_length)
			return 0;
	}
	return 1;
}

static int send_invalid_lzo(int socket_descriptor, struct esp_peer *peer,
			     enum invalid_lzo_kind kind,
			     const unsigned char *valid_compressed,
			     size_t valid_compressed_length,
			     const struct sockaddr *remote_address,
			     socklen_t remote_address_length)
{
	unsigned char invalid_compressed[MAX_LZO_SIZE];
	size_t invalid_compressed_length = 0;
	const char *kind_name = NULL;
	if (kind == INVALID_LZO_MALFORMED) {
		invalid_compressed[0] = 0;
		invalid_compressed[1] = 0;
		invalid_compressed[2] = 0;
		invalid_compressed_length = 3;
		kind_name = "malformed";
	} else if (kind == INVALID_LZO_TRAILING) {
		if (valid_compressed_length >= sizeof(invalid_compressed))
			return 0;
		memcpy(invalid_compressed, valid_compressed, valid_compressed_length);
		invalid_compressed[valid_compressed_length] = 0x42;
		invalid_compressed_length = valid_compressed_length + 1;
		kind_name = "trailing";
	} else if (kind == INVALID_LZO_OVERSIZE) {
		unsigned char oversized_plaintext[TEST_NEGOTIATED_MTU + 1];
		for (size_t index = 0; index < sizeof(oversized_plaintext); index++)
			oversized_plaintext[index] = (unsigned char)(index % 17);
		if (!compress_lzo(peer, oversized_plaintext, sizeof(oversized_plaintext),
				  invalid_compressed, &invalid_compressed_length)) {
			OPENSSL_cleanse(oversized_plaintext, sizeof(oversized_plaintext));
			return 0;
		}
		OPENSSL_cleanse(oversized_plaintext, sizeof(oversized_plaintext));
		kind_name = "oversize";
	} else {
		return 1;
	}
	unsigned char datagram[MAX_UDP_DATAGRAM_SIZE];
	size_t datagram_length = 0;
	if (!encrypt_esp(peer, invalid_compressed, invalid_compressed_length, 5,
			 datagram, &datagram_length)) {
		OPENSSL_cleanse(invalid_compressed, invalid_compressed_length);
		return 0;
	}
	OPENSSL_cleanse(invalid_compressed, invalid_compressed_length);
	ssize_t sent = sendto(socket_descriptor, datagram, datagram_length, 0,
			      remote_address, remote_address_length);
	if (sent < 0 || (size_t)sent != datagram_length)
		return 0;
	printf("INJECTED LZO %s\n", kind_name);
	fflush(stdout);
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
	if (getsockname(socket_descriptor, (struct sockaddr *)&local_address,
			&local_address_length) < 0) {
		perror("getsockname");
		close(socket_descriptor);
		return 1;
	}
	printf("READY %u\n", ntohs(local_address.sin_port));
	fflush(stdout);
	int established = peer->initially_established;
	for (;;) {
		unsigned char datagram[MAX_UDP_DATAGRAM_SIZE];
		struct sockaddr_storage remote_address;
		socklen_t remote_address_length = sizeof(remote_address);
		ssize_t received = recvfrom(socket_descriptor, datagram, sizeof(datagram), 0,
					    (struct sockaddr *)&remote_address,
					    &remote_address_length);
		if (received < 0) {
			if (errno == EINTR)
				continue;
			perror("recvfrom");
			close(socket_descriptor);
			return 1;
		}
		unsigned char payload[MAX_CRYPT_SIZE];
		size_t payload_length = 0;
		unsigned char next_header = 0;
		if (!decrypt_esp(peer, datagram, (size_t)received, payload,
				 &payload_length, &next_header)) {
			fprintf(stderr, "ignored invalid client ESP datagram\n");
			continue;
		}
		unsigned char response[MAX_LZO_SIZE];
		size_t response_length = 0;
		unsigned char response_next_header = next_header;
		enum invalid_lzo_kind invalid_lzo_kind = INVALID_LZO_NONE;
		if (payload_length == 1 && payload[0] == 0) {
			if (peer->expected_probe_next_header != 0 &&
			    next_header != peer->expected_probe_next_header) {
				fprintf(stderr, "rejected Pulse probe next-header %u; expected %d\n",
					next_header, peer->expected_probe_next_header);
				continue;
			}
			printf("PROBE %u\n", next_header);
			fflush(stdout);
			response[0] = 0;
			response_length = 1;
			established = 1;
		} else if (established == 0) {
			fprintf(stderr, "ignored ESP payload before Pulse probe\n");
			continue;
		} else if (next_header == 4) {
			printf("DATA 4 %u\n", peer->last_client_sequence);
			fflush(stdout);
			invalid_lzo_kind = ipv4_invalid_lzo_kind(payload, payload_length);
			if (!echo_ipv4(payload, &payload_length) ||
			    !compress_lzo(peer, payload, payload_length,
					  response, &response_length)) {
				fprintf(stderr, "ignored invalid ICMPv4 echo request\n");
				continue;
			}
			response_next_header = 5;
		} else {
			printf("DATA 41 %u\n", peer->last_client_sequence);
			fflush(stdout);
			if (!echo_ipv6(payload, &payload_length)) {
				fprintf(stderr, "ignored invalid ICMPv6 echo request\n");
				continue;
			}
			memcpy(response, payload, payload_length);
			response_length = payload_length;
			response_next_header = 41;
		}
		if (!send_invalid_lzo(socket_descriptor, peer, invalid_lzo_kind,
				      response, response_length,
				      (struct sockaddr *)&remote_address,
				      remote_address_length)) {
			fprintf(stderr, "failed to inject invalid LZO ESP datagram\n");
			close(socket_descriptor);
			return 1;
		}
		size_t encrypted_length = 0;
		if (!encrypt_esp(peer, response, response_length, response_next_header,
				 datagram, &encrypted_length)) {
			fprintf(stderr, "failed to encrypt server ESP datagram\n");
			close(socket_descriptor);
			return 1;
		}
		if (!send_duplicate(socket_descriptor, datagram, encrypted_length,
				    (struct sockaddr *)&remote_address,
				    remote_address_length)) {
			perror("sendto");
			close(socket_descriptor);
			return 1;
		}
	}
}

int main(int argc, char **argv)
{
	if (argc != 10 && argc != 11 && argc != 12) {
		fprintf(stderr,
			"usage: %s PORT ENC AUTH C2S_SPI S2C_SPI C2S_ENC_KEY C2S_AUTH_KEY S2C_ENC_KEY S2C_AUTH_KEY [zero|continuation|zero-established] [probe4|probe41]\n",
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
	if (argc >= 11) {
		if (strcmp(argv[10], "continuation") == 0)
			peer.initial_sequence_continuation = 1;
		else if (strcmp(argv[10], "zero-established") == 0)
			peer.initially_established = 1;
		else if (strcmp(argv[10], "zero") != 0) {
			fprintf(stderr, "invalid initial sequence policy\n");
			return 2;
		}
	}
	if (argc == 12) {
		if (strcmp(argv[11], "probe4") == 0)
			peer.expected_probe_next_header = 4;
		else if (strcmp(argv[11], "probe41") == 0)
			peer.expected_probe_next_header = 41;
		else {
			fprintf(stderr, "invalid expected Pulse probe next-header\n");
			return 2;
		}
	}
	if (!select_suite(argv[2], argv[3], &peer.suite) ||
	    !parse_u32(argv[4], &peer.client_spi) ||
	    !parse_u32(argv[5], &peer.server_spi) ||
	    !decode_hex(argv[6], peer.client_encryption_key,
			peer.suite.encryption_key_length) ||
	    !decode_hex(argv[7], peer.client_authentication_key,
			peer.suite.authentication_key_length) ||
	    !decode_hex(argv[8], peer.server_encryption_key,
			peer.suite.encryption_key_length) ||
	    !decode_hex(argv[9], peer.server_authentication_key,
			peer.suite.authentication_key_length)) {
		fprintf(stderr, "invalid ESP suite, SPI, or key material\n");
		OPENSSL_cleanse(&peer, sizeof(peer));
		return 2;
	}
	if (lzo_init() != LZO_E_OK) {
		fprintf(stderr, "liblzo2 initialization failed\n");
		OPENSSL_cleanse(&peer, sizeof(peer));
		return 1;
	}
	peer.lzo_work_memory = malloc(LZO1X_1_MEM_COMPRESS);
	if (peer.lzo_work_memory == NULL || !lzo_self_test(peer.lzo_work_memory)) {
		fprintf(stderr, "liblzo2 round-trip self-test failed\n");
		free(peer.lzo_work_memory);
		OPENSSL_cleanse(&peer, sizeof(peer));
		return 1;
	}
	if (RAND_bytes(peer.server_iv, sizeof(peer.server_iv)) != 1) {
		fprintf(stderr, "failed to generate initial server ESP IV\n");
		OPENSSL_cleanse(peer.lzo_work_memory, LZO1X_1_MEM_COMPRESS);
		free(peer.lzo_work_memory);
		OPENSSL_cleanse(&peer, sizeof(peer));
		return 1;
	}
	int result = run_peer((uint16_t)parsed_port, &peer);
	OPENSSL_cleanse(peer.lzo_work_memory, LZO1X_1_MEM_COMPRESS);
	free(peer.lzo_work_memory);
	peer.lzo_work_memory = NULL;
	OPENSSL_cleanse(&peer, sizeof(peer));
	return result;
}

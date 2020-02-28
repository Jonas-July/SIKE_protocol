#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "aes.h"
#include "Comm_node.h"
#include "P751_api.h"

struct Comm_node create_Comm_node()
{
        struct Comm_node node;

        unsigned char* sk = calloc(sizeof(char), CRYPTO_SECRETKEYBYTES);
        unsigned char* pk = calloc(sizeof(char), CRYPTO_PUBLICKEYBYTES);

        crypto_kem_keypair_SIKEp751(pk, sk);

        unsigned char* ss_from = calloc(sizeof(char), CRYPTO_BYTES);
        unsigned char* ss_to = calloc(sizeof(char), CRYPTO_BYTES);

	unsigned char* sk_eph = calloc(sizeof(char), CRYPTO_SECRETKEYBYTES);
	unsigned char* pk_eph = calloc(sizeof(char), CRYPTO_PUBLICKEYBYTES);

        unsigned char* ss_from_session = calloc(sizeof(char), CRYPTO_BYTES);
        unsigned char* ss_to_session = calloc(sizeof(char), CRYPTO_BYTES);


        node.sk_own	= sk;
        node.pk_own	= pk;
        node.pk_other	= NULL;

        node.ss_channel_from	= ss_from;
        node.ss_channel_to	= ss_to;
	node.aes_from;
	node.aes_to;

	node.pk_eph		= pk_eph;
	node.sk_eph		= sk_eph;
	node.pk_eph_other	= NULL;

	node.ss_channel_from_session	= ss_from_session;
        node.ss_channel_to_session	= ss_to_session;
	node.aes_from_session;
	node.aes_to_session;

        return node;
}

void delete_Comm_node(struct Comm_node* node)
{
        free(node->sk_own);
        free(node->pk_own);
        if (node->pk_other != NULL) free(node->pk_other);

        free(node->ss_channel_from);
        free(node->ss_channel_to);

	free(node->sk_eph);
	free(node->pk_eph);
        if (node->pk_eph_other != NULL) free(node->pk_eph_other);

	free(node->ss_from_session);
	free(node->ss_to_session);
}

void set_other_public_key(struct Comm_node* node, const unsigned char* pk_other)
{
        unsigned char* pk_other_cpy = calloc(sizeof(char), CRYPTO_PUBLICKEYBYTES);
        memcpy(pk_other_cpy, pk_other, CRYPTO_PUBLICKEYBYTES);
        node->pk_other = pk_other_cpy;
}

unsigned char* generate_shared_secret(struct Comm_node* node)
{
        unsigned char* ct = calloc(sizeof(unsigned char), CRYPTO_CIPHERTEXTBYTES);
        crypto_kem_enc_SIKEp751(ct, node->ss_channel_to, node->pk_other);


	struct AES_ctx aes_to;
	uint8_t iv[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
	AES_init_ctx_iv(&aes_to, node->ss_channel_to, iv);
	node->aes_to = aes_to;

	return ct;
}

void decrypt_shared_secret(struct Comm_node* node, const unsigned char* enc_ss)
{
	crypto_kem_dec_SIKEp751(node->ss_channel_from, enc_ss, node->sk_own);
	struct AES_ctx aes_from;
	uint8_t iv[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
	AES_init_ctx_iv(&aes_from, node->ss_channel_from, iv);

	node->aes_from = aes_from;

	free(enc_ss);
}

void generate_ephemeral_keypair(struct Comm_node* node)
{
	crypto_kem_keypair_SIKEp751(node->pk_eph, node->sk_eph);
}

unsigned char* encrypt_ephemeral(struct Comm_node* node)
{
	unsigned char* enc_pk_eph_other = calloc(sizeof(char), CRYPTO_PUBLICKEYBYTES);
	memcpy(enc_pk_eph_other, node->pk_eph, CRYPTO_PUBLICKEYBYTES);
	AES_CTR_xcrypt_buffer(&node->aes_to, enc_pk_eph_other, CRYPTO_PUBLICKEYBYTES);
	return enc_pk_eph_other;
}

void decrypt_ephemeral(struct Comm_node* node, const unsigned char* enc_pk_eph_other)
{
	unsigned char* pk_eph_other = calloc(sizeof(char), CRYPTO_PUBLICKEYBYTES);
	memcpy(pk_eph_other, enc_pk_eph_other, CRYPTO_PUBLICKEYBYTES);
	AES_CTR_xcrypt_buffer(&node->aes_from, pk_eph_other, CRYPTO_PUBLICKEYBYTES);
	node->pk_eph_other = pk_eph_other;

	free(enc_pk_eph_other);
}

unsigned char* generate_shared_session_secret(struct Comm_node* node)
{
        unsigned char* ct = calloc(sizeof(char), CRYPTO_CIPHERTEXTBYTES);
        crypto_kem_enc_SIKEp751(ct, node->ss_channel_to_session, node->pk_other);

	struct AES_ctx aes_to_session;
	uint8_t iv[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
	AES_init_ctx_iv(&aes_to_session, node->ss_channel_to, iv);
	node->aes_to_session = aes_to_session;

        return ct;
}

void decrypt_shared_session_secret(struct Comm_node* node, const unsigned char* enc_ss)
{
        crypto_kem_dec_SIKEp751(node->ss_channel_from_session, enc_ss, node->sk_own);

	struct AES_ctx aes_from_session;
	uint8_t iv[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
	AES_init_ctx_iv(&aes_from_session, node->ss_channel_from, iv);

	node->aes_from_session = aes_from_session;

	free(enc_ss);
}


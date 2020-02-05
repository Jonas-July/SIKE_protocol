#ifndef COMM_NODE_HEADER
#define COMM_NODE_HEADER

#include "aes.h"

struct Comm_node
{
        unsigned char* sk_own;
        unsigned char* pk_own;
        unsigned char* pk_other;

        unsigned char* ss_channel_to;
        unsigned char* ss_channel_from;

	struct AES_ctx aes_to;
	struct AES_ctx aes_from;

	unsigned char* sk_eph;
	unsigned char* pk_eph;
	unsigned char* pk_eph_other;

        unsigned char* ss_channel_to_session;
        unsigned char* ss_channel_from_session;

	struct AES_ctx aes_to_session;
	struct AES_ctx aes_from_session;
};

struct Comm_node create_Comm_node();

void delete_Comm_node(struct Comm_node* node);

void set_other_public_key(struct Comm_node* node, const unsigned char* pk_other);

unsigned char* generate_shared_secret(struct Comm_node* node);

void decrypt_shared_secret(struct Comm_node* node, const unsigned char* enc_ss);

void generate_ephemeral_keypair(struct Comm_node* node);

unsigned char* encrypt_ephemeral(struct Comm_node* node);

void decrypt_ephemeral(struct Comm_node* node, const unsigned char* enc_pk_eph_other);

unsigned char* generate_shared_session_secret(struct Comm_node* node);

void decrypt_shared_session_secret(struct Comm_node* node, const unsigned char* enc_ss);


#endif

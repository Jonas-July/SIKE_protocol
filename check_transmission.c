#include <string.h>

#include "P751_api.h"
#include "Comm_node.h"

int compare_public_keys(const struct Comm_node* node_first, const struct Comm_node* node_second)
{
	return memcmp(node_first->pk_own, node_second->pk_other, CRYPTO_PUBLICKEYBYTES);
}

int compare_ephemeral_public_keys(const struct Comm_node* node_first, const struct Comm_node* node_second)
{
	return memcmp(node_first->pk_eph, node_second->pk_eph_other, CRYPTO_PUBLICKEYBYTES);
}

int compare_shared_secrets(const struct Comm_node* node_first, const struct Comm_node* node_second)
{
	return memcmp(node_first->ss_channel_to, node_second->ss_channel_from, CRYPTO_BYTES);
}

int compare_shared_session_keys(const struct Comm_node* node_first, const struct Comm_node* node_second)
{
	return memcmp(node_first->ss_channel_to_session, node_second->ss_channel_from_session, CRYPTO_BYTES);
}

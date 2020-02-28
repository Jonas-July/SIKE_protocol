#ifndef check_transmission_H
#define check_transmission_H

#include "Comm_node.h"

/*
	Compare node_first's public key to node_second's external public key
	returns true if and only if keys are equal else false
*/
int compare_public_keys(const struct Comm_node* node_first, const struct Comm_node* node_second);

/*
	Compare node_first's ephemeral public key to node_second's external ephemeral public key
	returns true if and only if keys are equal else false
*/
int compare_ephemeral_public_keys(const struct Comm_node* node_first, const struct Comm_node* node_second);

/*
	Compare shared secret from node_first to node_second
	returns true if and only if keys are equal else false
*/
int compare_shared_secrets(const struct Comm_node* node_first, const struct Comm_node* node_second);

/*
	Compare shared session key from node_first to node_second
	returns true if and only if keys are equal else false
*/
int compare_shared_session_keys(const struct Comm_node* node_first, const struct Comm_node* node_second);

#endif

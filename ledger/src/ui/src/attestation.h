#ifndef __ATTESTATION
#define __ATTESTATION

#include "defs.h"

// -----------------------------------------------------------------------
// Custom CA attestation
// -----------------------------------------------------------------------

// Command and sub-operations
#define INS_ATTESTATION 0x50

#define ATT_OP_PUBKEY 0x01
#define ATT_OP_HASH 0x02
#define ATT_OP_SIGNATURE 0x03
#define ATT_OP_GET 0x04
#define ATT_OP_APP_HASH 0x05

// Maximum attestation message to sign size (prefix + CA public key)
#define MAX_ATT_MESSAGE_SIZE 80

// Attestation context
typedef struct att_s {
    cx_ecfp_public_key_t ca_pubkey;

    union {
        uint8_t msg[MAX_ATT_MESSAGE_SIZE];
        uint8_t ca_signed_hash[HASHSIZE];
    };

    uint8_t ca_signature_length;
    uint8_t ca_signature[MAX_SIGNATURE_LENGTH];
    uint8_t flags;
} att_t;

// Attestation flags
#define ATT_PUBKEY_RECV 0x01
#define ATT_HASH_RECV 0x02
#define ATT_SIGNATURE_RECV 0x04

// -----------------------------------------------------------------------
// Protocol
// -----------------------------------------------------------------------

/*
 * Implement the attestation protocol.
 *
 * @arg[in] rx      number of received bytes from the Host
 * @arg[in] att_ctx attestation context
 * @ret             number of transmited bytes to the host
 */
unsigned int get_attestation(volatile unsigned int rx, att_t* att_ctx);

#endif

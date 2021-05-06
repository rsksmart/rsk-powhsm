#ifndef __ATTESTATION
#define __ATTESTATION

#include <stdint.h>
#include "os.h"
#include "defs.h"

// -----------------------------------------------------------------------
// Custom CA attestation
// -----------------------------------------------------------------------

// Command and sub-operations
#define INS_ATTESTATION 0x50

#define ATT_OP_UD_VALUE 0x01
#define ATT_OP_PUBKEY 0x02
#define ATT_OP_HASH 0x03
#define ATT_OP_SIGNATURE 0x04
#define ATT_OP_GET_MSG 0x05
#define ATT_OP_GET 0x06
#define ATT_OP_APP_HASH 0x07

// Attestation message prefix
#define ATT_MSG_PREFIX "HSM:UI:2.1"
#define ATT_MSG_PREFIX_LENGTH (sizeof(ATT_MSG_PREFIX) - sizeof(""))

// User defined value size
#define UD_VALUE_SIZE 32

// Path of the public key to derive for the attestation (m/44'/0'/0'/0/0 - BTC)
#define PUBKEY_PATH "\x2c\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00"
#define PUBKEY_PATH_LENGTH (sizeof(PUBKEY_PATH) - sizeof(""))
#define PATH_PART_COUNT 5

// Maximum attestation message to sign size (prefix + UD value + BTC public key + CA public key)
#define ATT_MESSAGE_SIZE (ATT_MSG_PREFIX_LENGTH + UD_VALUE_SIZE + PUBKEYCOMPRESSEDSIZE + PUBKEYCOMPRESSEDSIZE)

// Attestation SM stages
typedef enum {
    att_stage_wait_ud_value = 0,
    att_stage_wait_ca_pubkey,
    att_stage_wait_ca_hash,
    att_stage_wait_ca_signature,
    att_stage_ready,
} att_stage_t;

// Attestation context
typedef struct {
    att_stage_t stage;

    uint8_t msg[ATT_MESSAGE_SIZE];
    unsigned int msg_offset;

    union {
        struct {
            cx_ecfp_public_key_t ca_pubkey;
            uint8_t ca_signed_hash[HASHSIZE];
            uint8_t ca_signature_length;
            uint8_t ca_signature[MAX_SIGNATURE_LENGTH];
        };

        struct {
            unsigned char path[PUBKEY_PATH_LENGTH];
            unsigned char priv_key_data[SEEDSIZE];
            cx_ecfp_private_key_t priv_key;
            cx_ecfp_public_key_t pub_key;
        };
    };
} att_t;

// -----------------------------------------------------------------------
// Protocol
// -----------------------------------------------------------------------

/*
 * Reset the given attestation context
 *
 * @arg[in] att_ctx attestation context
 */
void reset_attestation(att_t* att_ctx);

/*
 * Implement the attestation protocol.
 *
 * @arg[in] rx      number of received bytes from the Host
 * @arg[in] att_ctx attestation context
 * @ret             number of transmited bytes to the host
 */
unsigned int get_attestation(volatile unsigned int rx, att_t* att_ctx);

#endif

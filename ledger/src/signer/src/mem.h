#ifndef __MEM
#define __MEM

#include "txparser.h"
#include "rlp.h"
#include "bc_block.h"
#include "merkleProof.h"

// -----------------------------------------------------------------------
// Global state for signing, blockchain bookkeeping and attestation.
// -----------------------------------------------------------------------

// Maximum attestation message to sign size (prefix + public keys hash)
#define MAX_ATT_MESSAGE_SIZE 50

typedef struct att_s {
    sha256_ctx_t hash_ctx; // Attestation public keys hashing context
    uint8_t msg[MAX_ATT_MESSAGE_SIZE]; // Attestation message

    unsigned int path[RSK_PATH_LEN];
    cx_ecfp_public_key_t pub_key;
    cx_ecfp_private_key_t priv_key;
    unsigned char priv_key_data[KEYLEN];
} att_t;

typedef union {
    struct {
        // Receipt parsing context
        RLP_CTX rlp_ctx;
        // TX parsing context
        TX_CTX tx_ctx;
        // RLP Receipt keccak256 hash
        SHA3_CTX ReceiptHash_ctx;
    };
    // Trie Merkle Proof context
    MP_CTX mp_ctx;

    struct {
        block_t block;
        aux_bc_state_t aux_bc_st;
    };

    att_t att;
} mem_t;

extern mem_t mem;

#define rlp_ctx (mem.rlp_ctx)
#define tx_ctx (mem.tx_ctx)
#define mp_ctx (mem.mp_ctx)
#define block (mem.block)
#define aux_bc_st (mem.aux_bc_st)
#define attestation (mem.att)
#define ReceiptHash (mem.ReceiptHash_ctx)

#endif

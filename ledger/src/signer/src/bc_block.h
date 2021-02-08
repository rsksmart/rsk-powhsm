#ifndef __BLOCK
#define __BLOCK

#include <stdint.h>

#include "bigdigits.h"
#include "sha256.h"

#include "bc.h"
#include "bc_hash.h"

// -----------------------------------------------------------------------
// State for block under validation
// -----------------------------------------------------------------------

// This is the central data structure used for PoW validation.
// The main premise here is to share the heavyweight portions
// of the state.

typedef struct {
    uint16_t size; // Block size in bytes
    uint16_t recv; // Received bytes so far
    uint8_t field; // Current field number (1-based)
    uint8_t depth; // RLP nesting depth, must not exceed 1
    uint8_t flags; // For controlling validation flow

    uint32_t number;         // Block number
    uint8_t network_upgrade; // Block's network upgrade

    uint16_t mm_rlp_len; // Cached mm RLP length

    uint8_t parent_hash[HASH_SIZE]; // Parent hash
    uint8_t block_hash[HASH_SIZE];  // Block hash
    uint8_t hash_for_mm[HASH_SIZE]; // Merge mining hash from block
    DIGIT_T difficulty[BIGINT_LEN]; // Block's difficulty

    uint8_t umm_root[UMM_ROOT_SIZE]; // Block UMM root, only set if present

    uint8_t cb_txn_hash[HASH_SIZE]; // Coinbase transaction hash (from metadata)

    union {
        uint8_t mm_hdr_hash[HASH_SIZE];  // BTC merge mining header hash
        uint8_t receipt_root[HASH_SIZE]; // Or receipt root hash
    };

    union {
        sha256_ctx_t ctx;   // Global sha256 context
        SHA256_CTX mid_ctx; // Sha256 supporting midstate
    };

    union {
        struct {
            keccak_ctx_t block_ctx; // Block hash Keccak256 context
            keccak_ctx_t mm_ctx;    // Merge mining hash Keccak256 context
        };
        struct {
            uint16_t merkle_off;            // Offset to Merkle proof buffer
            uint8_t merkle_proof_left[HASH_SIZE]; // Merkle proof reduction current left node
            uint8_t merkle_root[HASH_SIZE]; // Merkle root
            uint16_t cb_off;                 // Offset to cb txn buffer
            uint8_t cb_txn[MAX_CB_TXN_SIZE]; // cb txn buffer
        };
    };

#define WA_SIZE 80           // Block's work area
    uint8_t wa_off;          // Work area buffer offset
    uint8_t wa_buf[WA_SIZE]; // Block work area buffer
} block_t;

// Auxiliary volatile blockchain state.
// Used for keeping inter-block validation state
typedef struct {
    uint8_t prev_parent_hash[HASH_SIZE];
    DIGIT_T total_difficulty[BIGINT_LEN];
} aux_bc_state_t;

#endif

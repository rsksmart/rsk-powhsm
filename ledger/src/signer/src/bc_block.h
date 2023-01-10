/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2021 RSK Labs Ltd
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef __BLOCK_H
#define __BLOCK_H

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
    uint16_t size; // Block (or brother) size in bytes
    uint16_t recv; // Received bytes so far
    uint8_t field; // Current field number (1-based)
    uint8_t depth; // RLP nesting depth, must not exceed 1
    uint8_t flags; // For controlling validation flow

    uint32_t number;         // Block number
    uint8_t network_upgrade; // Block's network upgrade
    uint8_t brother_count;   // Brother count

    uint16_t mm_rlp_len; // Cached mm RLP length

    uint8_t parent_hash[HASH_SIZE];     // Parent hash
    uint8_t block_hash[HASH_SIZE];      // Block hash
    uint8_t main_block_hash[HASH_SIZE]; // Block hash
    union {
        uint8_t hash_for_mm[HASH_SIZE];       // Merge mining hash from block
        uint8_t prev_brother_hash[HASH_SIZE]; // Previous brother hash
    };
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
            uint16_t merkle_off; // Offset to Merkle proof buffer
            uint8_t merkle_proof_left[HASH_SIZE]; // Merkle proof reduction
                                                  // current left node
            uint8_t merkle_root[HASH_SIZE];       // Merkle root
            uint16_t cb_off;                      // Offset to cb txn buffer
            uint8_t cb_txn[MAX_CB_TXN_SIZE];      // cb txn buffer
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

#endif // __BLOCK_H

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

#ifndef __MEM_H
#define __MEM_H

#include "bc_block.h"
#include "bc_state.h"
#include "btctx.h"
#include "btcscript.h"
#include "auth.h"
#include "heartbeat.h"

// -----------------------------------------------------------------------
// Global state for signing, blockchain bookkeeping, attestation and
// heartbeat.
// -----------------------------------------------------------------------

// Maximum attestation message to sign size (prefix + public keys hash)
#define MAX_ATT_MESSAGE_SIZE 50

typedef struct att_s {
    sha256_ctx_t hash_ctx; // Attestation public keys hashing context
    uint8_t msg[MAX_ATT_MESSAGE_SIZE]; // Attestation message

    unsigned int path[DERIVATION_PATH_PARTS];
    cx_ecfp_public_key_t pub_key;
    cx_ecfp_private_key_t priv_key;
    unsigned char priv_key_data[PRIVATE_KEY_LENGTH];
} att_t;

typedef union {
    struct {
        block_t block;
        aux_bc_state_t aux_bc_st;
    };

    auth_ctx_t auth;

    att_t att;
    heartbeat_t heartbeat;
} mem_t;

typedef struct {
    bc_state_updating_t bc_st_updating;
} sess_per_mem_t;

extern mem_t mem;
extern sess_per_mem_t sess_per_mem;

#define rlp_ctx (mem.rlp_ctx)
#define tx_ctx (mem.tx_ctx)
#define mp_ctx (mem.mp_ctx)
#define block (mem.block)
#define aux_bc_st (mem.aux_bc_st)
#define bc_st_updating (sess_per_mem.bc_st_updating)
#define auth (mem.auth)
#define attestation (mem.att)
#define heartbeat (mem.heartbeat)
#define ReceiptHash (mem.ReceiptHash_ctx)

#endif // __MEM_H

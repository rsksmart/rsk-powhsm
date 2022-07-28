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

#ifndef __AUTH
#define __AUTH

#include <stdint.h>

#include "auth_path.h"
#include "auth_tx.h"
#include "auth_receipt.h"
#include "auth_trie.h"
#include "defs.h"
#include "srlp.h"
#include "util.h"

// States
#define AUTH_ST_PATH (0)
#define AUTH_ST_START AUTH_ST_PATH
#define AUTH_ST_BTCTX (1)
#define AUTH_ST_RECEIPT (2)
#define AUTH_ST_MERKLEPROOF (3)
#define AUTH_ST_SIGN (99)

// Error codes
// (these are based on the legacy implementation
// to make sure the middleware is compatible)
#define AUTH_ERR_INVALID_DATA_SIZE (0x6A87)
#define AUTH_ERR_INVALID_TX_INPUT_INDEX (0x6A88)
#define AUTH_ERR_INVALID_STATE (0x6A89)
#define AUTH_ERR_RECEIPT_RLP (0x6A8A)
#define AUTH_ERR_RECEIPT_INVALID (0x6A8B)
#define AUTH_ERR_TX_HASH_MISMATCH (0x6A8D)
#define AUTH_ERR_INVALID_TX_VERSION (0x6A8E)
#define AUTH_ERR_INVALID_PATH (0x6A8F)
#define AUTH_ERR_INVALID_DATA_SIZE_AUTH_SIGN (0x6A90)
#define AUTH_ERR_INVALID_DATA_SIZE_UNAUTH_SIGN (0x6A91)
#define AUTH_ERR_NODE_INVALID_VERSION (0x6A92)
#define AUTH_ERR_RECEIPT_HASH_MISMATCH (0x6A94)
#define AUTH_ERR_NODE_CHAINING_MISMATCH (0x6A95)
#define AUTH_ERR_RECEIPT_ROOT_MISMATCH (0x6A96)
#define AUTH_ERR_INTERNAL (0x6A99)

#define AUTH_MAX_EXCHANGE_SIZE RLP_BUFFER_SIZE

typedef struct {
    uint8_t state;
    uint8_t expected_bytes;

    uint32_t path[RSK_PATH_LEN];
    uint32_t input_index_to_sign;

    struct {
        union {
            uint8_t tx_hash[32];
            uint8_t receipt_hash[32];
        };
        uint8_t sig_hash[32];
    };

    union {
        btctx_auth_ctx_t tx;
        receipt_auth_ctx_t receipt;
        trie_auth_ctx_t trie;
    };
} auth_ctx_t;

/*
 * Transition to the given state, performing corresponding
 * initializations.
 *
 * @arg[in] state   the state to transition to
 */
void auth_transition_to(uint8_t state);

/*
 * Implement the signing authorization protocol.
 *
 * @arg[in] rx      number of received bytes from the host
 * @ret             number of transmited bytes to the host
 */
unsigned int auth_sign(volatile unsigned int rx);

#endif
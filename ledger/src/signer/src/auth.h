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

#ifndef __AUTH_H
#define __AUTH_H

#include <stdint.h>
#include <stdbool.h>

#include "auth_path.h"
#include "auth_tx.h"
#include "auth_receipt.h"
#include "auth_trie.h"
#include "apdu.h"
#include "defs.h"
#include "srlp.h"
#include "util.h"

// Operation selectors
typedef enum {
    P1_PATH = 0x01,
    P1_BTC = 0x02,
    P1_RECEIPT = 0x04,
    P1_MERKLEPROOF = 0x08,
    P1_SUCCESS = 0x81,
} op_code_sign_t;

// States
typedef enum {
    STATE_AUTH_PATH = 0,
    STATE_AUTH_START = STATE_AUTH_PATH,
    STATE_AUTH_BTCTX = 1,
    STATE_AUTH_RECEIPT = 2,
    STATE_AUTH_MERKLEPROOF = 3,
    STATE_AUTH_SIGN = 99,
} state_auth_t;

// Error codes
// (these are based on the legacy implementation
// to make sure the middleware is compatible)
typedef enum {
    ERR_AUTH_INVALID_DATA_SIZE = 0x6A87,
    ERR_AUTH_INVALID_TX_INPUT_INDEX = 0x6A88,
    ERR_AUTH_INVALID_STATE = 0x6A89,
    ERR_AUTH_RECEIPT_RLP = 0x6A8A,
    ERR_AUTH_RECEIPT_INVALID = 0x6A8B,
    ERR_AUTH_TX_HASH_MISMATCH = 0x6A8D,
    ERR_AUTH_INVALID_TX_VERSION = 0x6A8E,
    ERR_AUTH_INVALID_PATH = 0x6A8F,
    ERR_AUTH_INVALID_DATA_SIZE_AUTH_SIGN = 0x6A90,
    ERR_AUTH_INVALID_DATA_SIZE_UNAUTH_SIGN = 0x6A91,
    ERR_AUTH_NODE_INVALID_VERSION = 0x6A92,
    ERR_AUTH_RECEIPT_HASH_MISMATCH = 0x6A94,
    ERR_AUTH_NODE_CHAINING_MISMATCH = 0x6A95,
    ERR_AUTH_RECEIPT_ROOT_MISMATCH = 0x6A96,
} err_code_sign_t;

#define AUTH_MAX_EXCHANGE_SIZE RLP_BUFFER_SIZE

typedef struct {
    state_auth_t state;
    uint8_t expected_bytes;
    bool auth_required;

    uint32_t path[DERIVATION_PATH_PARTS];
    uint32_t input_index_to_sign;

    uint8_t tx_hash[HASH_LENGTH];
    uint8_t receipt_hash[HASH_LENGTH];
    uint8_t sig_hash[HASH_LENGTH];

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

#endif // __AUTH_H

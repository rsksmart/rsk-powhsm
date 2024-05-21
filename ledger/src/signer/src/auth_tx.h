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

#ifndef __AUTH_TX_H
#define __AUTH_TX_H

#include <stdint.h>

#include "hal/hash.h"

#include "btctx.h"
#include "btcscript.h"

#define BTCTX_LENGTH_SIZE 4
#define SIGHASH_COMP_MODE_SIZE 1
#define EXTRADATA_SIZE 2
#define SIGHASH_ALL_SIZE 4
#define SIGHASH_ALL_BYTES \
    { 0x01, 0x00, 0x00, 0x00 }

enum {
    SIGHASH_COMPUTE_MODE_LEGACY,
    SIGHASH_COMPUTE_MODE_SEGWIT,
};

typedef struct {
    uint32_t remaining_bytes;
    bool finalise;
    btctx_ctx_t ctx;
    btcscript_ctx_t script_ctx;
    hash_sha256_ctx_t tx_hash_ctx;
    hash_sha256_ctx_t sig_hash_ctx;

    uint8_t sighash_computation_mode;

    // Specifically for segwit
    // sighash computation mode
    bool segwit_processing_extradata;
    uint16_t segwit_extradata_size;
    union {
        hash_sha256_ctx_t prevouts_hash_ctx;
        hash_sha256_ctx_t outputs_hash_ctx;
        uint8_t lock_time[BTCTX_LOCKTIME_SIZE];
    };
    hash_sha256_ctx_t sequence_hash_ctx;
    union {
        uint8_t aux_hash[BTCTX_HASH_SIZE];
        uint8_t outputs_hash[BTCTX_HASH_SIZE];
    };
    uint8_t aux_offset;
    uint8_t ip_prevout[BTCTX_HASH_SIZE + BTCTX_INPUT_INDEX_SIZE];
    uint8_t ip_seqno[BTCTX_INPUT_SEQNO_SIZE];

    uint8_t redeemscript_found;
} btctx_auth_ctx_t;

/*
 * Implement the BTC tx parsing and calculations portion
 * of the signing authorization protocol.
 *
 * @arg[in] rx      number of received bytes from the host
 * @ret             number of transmited bytes to the host
 */
unsigned int auth_sign_handle_btctx(volatile unsigned int rx);

#endif // __AUTH_TX_H

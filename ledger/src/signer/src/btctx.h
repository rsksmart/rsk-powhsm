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

// Streaming BTC tx parser.
//
// Usage:
// Call btctx_init to initialize the parser with the context
// to use for the parsing session
//
// Then feed chunks of the BTC transaction with btctx_consume. This function
// will process them and call your callback accordingly, returning the number
// of bytes actually processed and read.
// Immediately after calling this function, check error conditions and
// parsing state with btctx_result.

#ifndef __BTCTX_H
#define __BTCTX_H

#include <stddef.h>
#include <stdint.h>

#include "svarint.h"

// Miscellaneous constants
#define BTCTX_VERSION_SIZE 4
#define BTCTX_INPUT_INDEX_SIZE 4
#define BTCTX_INPUT_SEQNO_SIZE 4
#define BTCTX_HASH_SIZE 32
#define BTCTX_OUTPUT_VALUE_SIZE 8
#define BTCTX_LOCKTIME_SIZE 4
#define BTCTX_MAX_RAW_SIZE 9

// Callback events
#define BTCTX_EV_VERSION (0)
#define BTCTX_EV_VIN_COUNT (1)
#define BTCTX_EV_VIN_TXH_START (2)
#define BTCTX_EV_VIN_TXH_DATA (3)
#define BTCTX_EV_VIN_TXH_END (4)
#define BTCTX_EV_VIN_TXIX (5)
#define BTCTX_EV_VIN_SLENGTH (6)
#define BTCTX_EV_VIN_SCRIPT_DATA (7)
#define BTCTX_EV_VIN_SEQNO (8)
#define BTCTX_EV_VOUT_COUNT (9)
#define BTCTX_EV_VOUT_VALUE (10)
#define BTCTX_EV_VOUT_SLENGTH (11)
#define BTCTX_EV_VOUT_SCRIPT_DATA (12)
#define BTCTX_EV_LOCKTIME (13)
typedef uint8_t btctx_cb_event_t;

// Callback synonym
typedef void (*btctx_cb_t)(const btctx_cb_event_t event);

// Context state and errors
#define BTCTX_ST_VERSION (0)
#define BTCTX_ST_VIN_COUNT (1)
#define BTCTX_ST_VIN_TXH (2)
#define BTCTX_ST_VIN_TXIX (3)
#define BTCTX_ST_VIN_SLENGTH (4)
#define BTCTX_ST_VIN_SCRIPT (5)
#define BTCTX_ST_VIN_SEQNO (6)
#define BTCTX_ST_VOUT_COUNT (7)
#define BTCTX_ST_VOUT_VALUE (8)
#define BTCTX_ST_VOUT_SLENGTH (9)
#define BTCTX_ST_VOUT_SCRIPT (10)
#define BTCTX_ST_LOCK_TIME (11)
#define BTCTX_ST_DONE (12)

#define BTCTX_ERR_NONE (0)
#define BTCTX_ERR_INVALID (-1)
#define BTCTX_ERR_UNSUPPORTED (-2)

typedef int8_t btctx_state_t;

// Context
typedef struct {
    btctx_state_t state;
    btctx_cb_t callback;

    uint32_t inout_total;
    uint32_t inout_current;
    uint32_t script_remaining;
    uint32_t offset;

    union {
        uint32_t version;
        uint32_t ptxo_index;
        uint32_t seqno;
        svarint_ctx_t varint;
        uint8_t value;
        uint64_t vout_value;
        uint32_t locktime;
    } parsed;

    uint8_t raw[BTCTX_MAX_RAW_SIZE];
    uint8_t raw_size;

} btctx_ctx_t;

/*
 * Initialize the parser.
 *
 * @arg[in] ctx the context to be used for this session
 * @arg[in] cb  the callback to be used for this session
 */
void btctx_init(btctx_ctx_t* ctx, btctx_cb_t cb);

/*
 * Tell whether parsing is finished, and
 * whether it triggered an error (and which one)
 * This should be checked after every call to btctx_consume
 */
int8_t btctx_result();

/*
 * Consume a chunk of bytes.
 *
 * @arg[in] buf: buffer holding bytes to be consumed
 * @arg[in] len: number of bytes to consume in buffer
 *
 * @return the number of bytes actually read and processed
 */
uint8_t btctx_consume(uint8_t* buf, const uint8_t len);

#endif // __BTCTX_H

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

// Streaming BTC script parser.
// Limited to P2SH-compatible scriptSigs atm.
// (i.e., only supporting PUSH operations, everything else is deemed invalid)
//
// Usage:
// Call btcscript_init to initialize the parser with the context and callback
// to use for the parsing session, and the total length of the script
// that's to be parsed.
//
// Then feed chunks of the BTC script with btcscript_consume. This function
// will process them and call your callback accordingly, returning the number
// of bytes actually processed and read.
// Immediately after calling this function, check error conditions and
// parsing state with btcscript_result.

#ifndef __BTCSCRIPT_H
#define __BTCSCRIPT_H

#include <stddef.h>
#include <stdint.h>

// Supported opcodes (taken from
// https://github.com/bitcoin/bitcoin/blob/v0.20.2/src/script/script.h#L54)
#define BTCSCRIPT_OP_0 0x00
#define BTCSCRIPT_OP_FALSE BTCSCRIPT_OP_0
#define BTCSCRIPT_OP_PUSHDATA1 0x4c
#define BTCSCRIPT_OP_PUSHDATA2 0x4d
#define BTCSCRIPT_OP_PUSHDATA4 0x4e
#define BTCSCRIPT_OP_1NEGATE 0x4f
#define BTCSCRIPT_OP_RESERVED 0x50
#define BTCSCRIPT_OP_1 0x51
#define BTCSCRIPT_OP_TRUE BTCSCRIPT_OP_1
#define BTCSCRIPT_OP_2 0x52
#define BTCSCRIPT_OP_3 0x53
#define BTCSCRIPT_OP_4 0x54
#define BTCSCRIPT_OP_5 0x55
#define BTCSCRIPT_OP_6 0x56
#define BTCSCRIPT_OP_7 0x57
#define BTCSCRIPT_OP_8 0x58
#define BTCSCRIPT_OP_9 0x59
#define BTCSCRIPT_OP_10 0x5a
#define BTCSCRIPT_OP_11 0x5b
#define BTCSCRIPT_OP_12 0x5c
#define BTCSCRIPT_OP_13 0x5d
#define BTCSCRIPT_OP_14 0x5e
#define BTCSCRIPT_OP_15 0x5f
#define BTCSCRIPT_OP_16 0x60

// Callback events
#define BTCSCRIPT_EV_OPCODE (0)
#define BTCSCRIPT_EV_OPERAND (1)
#define BTCSCRIPT_EV_OPERAND_END (2)
typedef uint8_t btcscript_cb_event_t;

// Callback synonym
typedef void (*btcscript_cb_t)(const btcscript_cb_event_t event);

// Context state and errors
#define BTCSCRIPT_ST_OPCODE (0)
#define BTCSCRIPT_ST_OPERAND_SIZE (1)
#define BTCSCRIPT_ST_OPERAND (2)
#define BTCSCRIPT_ST_DONE (3)

#define BTCSCRIPT_ERR_NONE (0)
#define BTCSCRIPT_ERR_INVALID (-1)

typedef int8_t btcscript_state_t;

// Context
typedef struct {
    btcscript_state_t state;
    btcscript_cb_t callback;

    uint32_t bytes_remaining;

    uint8_t opcode;
    union {
        uint8_t size_offset;
        uint8_t operand_byte;
    };
    uint32_t operand_size;
} btcscript_ctx_t;

/*
 * Initialize the parser.
 *
 * @arg[in] ctx the context to be used for this session
 * @arg[in] cb  the callback to be used for this session
 */
void btcscript_init(btcscript_ctx_t* ctx,
                    btcscript_cb_t cb,
                    uint32_t script_size);

/*
 * Tell whether parsing is finished, and
 * whether it triggered an error (and which one)
 * This should be checked after every call to btcscript_consume
 */
int8_t btcscript_result();

/*
 * Consume a chunk of bytes.
 *
 * @arg[in] buf: buffer holding bytes to be consumed
 * @arg[in] len: number of bytes to consume in buffer
 *
 * @return the number of bytes actually read and processed
 */
uint8_t btcscript_consume(uint8_t* buf, const uint8_t len);

#endif // __BTCSCRIPT_H

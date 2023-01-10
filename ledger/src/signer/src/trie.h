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

// Streaming RSK (uni)trie node parser.
// See https://github.com/rsksmart/RSKIPs/blob/master/IPs/RSKIP107.md for
// details on the format, and
// https://github.com/rsksmart/rskj/blob/IRIS-3.1.0/rskj-core/
// src/main/java/co/rsk/trie/Trie.java for the reference implementation.
//
// Usage:
// Call trie_init to initialize the parser with the context and callback
// to use for the parsing session, together with the total node length
// in bytes.
//
// Then feed chunks of the BTC transaction with trie_consume. This function
// will process them and call your callback accordingly, returning the number
// of bytes actually processed and read.
// Immediately after calling this function, check error conditions and
// parsing state with trie_result.

#ifndef __TRIE_H
#define __TRIE_H

#include <stddef.h>
#include <stdint.h>

#include "svarint.h"

// Miscellaneous constants
#define TRIE_MAX_RAW_SIZE 10
#define NON_EMBEDDED_NODE_SIZE 32
#define MAX_EMBEDDED_SIZE 40
#define VALUE_HASH_SIZE 32
#define VALUE_LENGTH_SIZE 3

// Callback events
#define TRIE_EV_FLAGS (0)
#define TRIE_EV_SHARED_PREFIX_LENGTH (1)
#define TRIE_EV_SHARED_PREFIX (2)
#define TRIE_EV_LEFT_NODE_START (3)
#define TRIE_EV_LEFT_NODE_DATA (4)
#define TRIE_EV_LEFT_NODE_END (5)
#define TRIE_EV_LEFT_NODE_EMBEDDED_START (6)
#define TRIE_EV_LEFT_NODE_EMBEDDED_DATA (7)
#define TRIE_EV_LEFT_NODE_EMBEDDED_END (8)
#define TRIE_EV_RIGHT_NODE_START (9)
#define TRIE_EV_RIGHT_NODE_DATA (10)
#define TRIE_EV_RIGHT_NODE_END (11)
#define TRIE_EV_RIGHT_NODE_EMBEDDED_START (12)
#define TRIE_EV_RIGHT_NODE_EMBEDDED_DATA (13)
#define TRIE_EV_RIGHT_NODE_EMBEDDED_END (14)
#define TRIE_EV_CHILDREN_SIZE (15)
#define TRIE_EV_VALUE_HASH_START (16)
#define TRIE_EV_VALUE_HASH_DATA (17)
#define TRIE_EV_VALUE_HASH_END (18)
#define TRIE_EV_VALUE_START (19)
#define TRIE_EV_VALUE_DATA (20)
#define TRIE_EV_VALUE_END (21)
typedef uint8_t trie_cb_event_t;

// Callback synonym
typedef void (*trie_cb_t)(const trie_cb_event_t event);

// Context state and errors
#define TRIE_ST_FLAGS (0)
#define TRIE_ST_SHARED_PREFIX_LENGTH (1)
#define TRIE_ST_SHARED_PREFIX_LENGTH_VAR (2)
#define TRIE_ST_SHARED_PREFIX (3)
#define TRIE_ST_LEFT_NODE (4)
#define TRIE_ST_LEFT_NODE_EMBEDDED (5)
#define TRIE_ST_RIGHT_NODE (6)
#define TRIE_ST_RIGHT_NODE_EMBEDDED (7)
#define TRIE_ST_CHILDREN_SIZE (8)
#define TRIE_ST_VALUE (9)
#define TRIE_ST_LONG_VALUE (10)
#define TRIE_ST_DONE (99)

#define TRIE_ERR_NONE (0)
#define TRIE_ERR_INVALID (-1)
#define TRIE_ERR_UNSUPPORTED (-2)

// Flag-reading macros to save space and ease readability
#define TRIE_FG_VERSION(flags) (((flags)&0b11000000) >> 6)
#define TRIE_FG_HAS_LONG_VALUE(flags) (((flags)&0b00100000) > 0)
#define TRIE_FG_SHARED_PREFIX_PRESENT(flags) (((flags)&0b00010000) > 0)
#define TRIE_FG_NODE_PRESENT_LEFT(flags) (((flags)&0b00001000) > 0)
#define TRIE_FG_NODE_PRESENT_RIGHT(flags) (((flags)&0b00000100) > 0)
#define TRIE_FG_NODE_IS_EMBEDDED_LEFT(flags) (((flags)&0b00000010) > 0)
#define TRIE_FG_NODE_IS_EMBEDDED_RIGHT(flags) (((flags)&0b00000001) > 0)

typedef int8_t trie_state_t;

// Context
typedef struct {
    trie_state_t state;
    trie_cb_t callback;

    uint32_t remaining_bytes;
    uint8_t flags;
    uint8_t offset;

    union {
        svarint_ctx_t varint;
        uint32_t length;
        uint32_t children_size;
        uint32_t value_size;
    };

    uint8_t raw[TRIE_MAX_RAW_SIZE];
    uint8_t raw_size;

} trie_ctx_t;

/*
 * Initialize the parser.
 *
 * @arg[in] ctx the context to be used for this session
 * @arg[in] cb  the callback to be used for this session
 * @arg[in] length  the length of the node in bytes
 */
void trie_init(trie_ctx_t* ctx, trie_cb_t cb, uint32_t length);

/*
 * Tell whether parsing is finished, and
 * whether it triggered an error (and which one)
 * This should be checked after every call to trie_consume
 */
int8_t trie_result();

/*
 * Consume a chunk of bytes.
 *
 * @arg[in] buf: buffer holding bytes to be consumed
 * @arg[in] len: number of bytes to consume in buffer
 *
 * @return the number of bytes actually read and processed
 */
uint8_t trie_consume(uint8_t* buf, const uint8_t len);

#endif // __TRIE_H

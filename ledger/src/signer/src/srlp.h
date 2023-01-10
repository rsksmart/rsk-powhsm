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

// srlp: Streaming RLP parser.
// Parse RLP contents with no recursion and small memory footprint.
//
// Usage:
// Call rlp_start to initialize the parser with callbacks for:
//  - Byte array started
//  - Byte array chuk received
//  - Byte array finished
//  - List started
//  - List finished
//
// Then feed chunks of RLP with rlp_consume. This function
// will process them and call your callbacks accordingly.

#ifndef __SRLP_H
#define __SRLP_H

#include <stddef.h>
#include <stdint.h>

// Constant for values returned by rlp_consume
#define RLP_OK (0)
#define RLP_STACK_OVERFLOW (-1)
#define RLP_STACK_UNDERFLOW (-2)
#define RLP_TOO_LONG (-3)
#define RLP_MALFORMED (-4)

// Max RLP buffer size and stack depth
#define RLP_BUFFER_SIZE 80

// Define your own MAX_RLP_CTX_DEPTH to override the default value
#ifndef MAX_RLP_CTX_DEPTH
#define MAX_RLP_CTX_DEPTH 5
#endif

// Context item state:
//  - RLP_BOTTOM: bottom of stack marker
//  - RLP_STR: parser is consuming a byte array
//  - RLP_STR_LEN: parser is consuming a byte array length
//  - RLP_LIST: parser is consuming a list
//  - RLP_LIST_LEN: parser is consuming a list length
typedef enum {
    RLP_BOTTOM,
    RLP_STR,
    RLP_STR_LEN,
    RLP_LIST,
    RLP_LIST_LEN
} rlp_state_t;

// Context item
typedef struct {
    rlp_state_t state;
    uint16_t size;
    uint16_t cursor;
} rlp_ctx_t;

// Type synonyms for callbacks
typedef void (*rlp_start_cb_t)(const uint16_t size);
typedef void (*rlp_end_cb_t)(void);
typedef void (*rlp_chunk_cb_t)(const uint8_t* chunk, const size_t chunk_size);

// Struct grouping all callbacks
typedef struct {
    rlp_start_cb_t bytearray_start;
    rlp_chunk_cb_t bytearray_chunk;
    rlp_end_cb_t bytearray_end;
    rlp_start_cb_t list_start;
    rlp_end_cb_t list_end;
} rlp_callbacks_t;

/*
 * Initialize the parser.
 *
 * @arg[in] cbs struct holding callbacks to be called by the parser
 */
void rlp_start(const rlp_callbacks_t* cbs);

/*
 * Consume a chunk of bytes.
 *
 * @arg[in] buf: buffer holdoing bytes to be consumed
 * @arg[in] len: number of bytes to consume in buffer
 *
 * @return
 *    RLP_OK if bytes were consumed successfully
 *    RLP_TOO_LONG if len greater than RLP_BUFFER_SIZE
 *    RLP_STACK_OVERFLOW if list nesting level is greater than MAX_RLP_CTX_DEPTH
 *    RLP_STACK_UNDERFLOW if RLP to parse is ill-formed (e.g., [[a])
 */
int rlp_consume(uint8_t* buf, const uint8_t len);

// Does the given single byte string has an RLP prefix?
#define HAS_RLP_PREFIX(first_str_byte) ((first_str_byte) > 0x7f)

/*
 * Guess the length in bytes of the RLP prefix for str of the given size.
 *
 * NOTE: This guessing because for single byte strings we need the str
 * value to determine accurately. For single byte strings, this method
 * always return one. It's up to the caller to take this into account.
 *
 * @arg[in] str_size string size
 */
uint8_t guess_rlp_str_prefix_size(uint16_t str_size);

/*
 * Get the length in bytes of the (minimal) RLP prefix for a list of the
 * given size (max size for any given list is 2^16-1 in this
 * implementation)
 *
 * @arg[in] list_size list size
 */
uint8_t rlp_list_prefix_size(uint16_t list_size);

#endif // __SRLP_H

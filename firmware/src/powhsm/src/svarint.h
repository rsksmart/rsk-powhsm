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

// Streaming varint parser.
//
// Usage:
// Call svarint_init to initialize the parser with the context
// to use for the parsing session
//
// Then feed chunks of the varint with varint_consume. This function
// will process them and return the number of bytes actually processed.
// Immediately after calling this function, check error conditions and
// parsing state with svarint_result.
// The parsed value will be available in the 'value' field of the context
// if svarint_result yields VARINT_ST_DONE.
//
// Important: We don't support values larger than 32 bits at the moment.
// We do support up to 32 bit values encoded as 64 bit values though.
//
// Additional utility function to encode a varint provided.

#ifndef __SVARINT_H
#define __SVARINT_H

#include <stddef.h>
#include <stdint.h>

#define MAX_SVARINT_ENCODING_SIZE 5

// Context state and errors
#define SVARINT_ST_HEADER (0)
#define SVARINT_ST_BODY (1)
#define SVARINT_ST_DONE (2)

#define SVARINT_ERR_NONE (0)
#define SVARINT_ERR_INVALID (-1)
#define SVARINT_ERR_UNSUPPORTED (-2)

typedef int8_t svarint_state_t;

// Context
typedef struct {
    svarint_state_t state;
    uint8_t size;
    uint8_t offset;
    uint32_t value;
} svarint_ctx_t;

/*
 * Initialize the parser.
 *
 * @arg[in] ctx the context to be used for this session
 */
void svarint_init(svarint_ctx_t* ctx);

/*
 * Tells whether the parser has not yet consumed any bytes
 */
int8_t svarint_notstarted();

/*
 * Tell whether parsing is finished, and
 * whether it triggered an error (and which one)
 * This should be checked after every call to svarint_consume
 */
int8_t svarint_result();

/*
 * Consume a chunk of bytes.
 *
 * @arg[in] buf: buffer holding bytes to be consumed
 * @arg[in] len: number of bytes to consume in buffer
 *
 * @return the number of bytes actually read and processed
 */
uint8_t svarint_consume(const uint8_t* buf, const uint8_t len);

/*
 * Encode a varint into a buffer.
 * Values longer than a byte are encoded in little endian
 * as per the bitcoin varint spec.
 *
 * @arg[in] value: value to encode
 * @arg[in] buf: destination buffer
 * @arg[in] len: destination buffer size
 *
 * @return the number of bytes actually written
 */
uint8_t svarint_encode(uint32_t value, uint8_t* buf, const uint8_t len);

#endif // __SVARINT_H

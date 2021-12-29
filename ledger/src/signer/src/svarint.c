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

#include <stdint.h>
#include <string.h>

#include "svarint.h"

// Context pointer
static svarint_ctx_t* ctx;

/*
 * Initialize the parser.
 *
 * @arg[in] ctx the context to be used for this session
 */
void svarint_init(svarint_ctx_t* _ctx) {
    ctx = _ctx;
    memset(ctx, 0, sizeof(svarint_ctx_t));
    ctx->state = SVARINT_ST_HEADER;
}

/*
 * Tells whether the parser has not yet consumed any bytes
 */
int8_t svarint_notstarted() {
    return ctx->state == SVARINT_ST_HEADER;
}

/*
 * Tell whether parsing is finished, and
 * whether it triggered an error (and which one)
 * This should be checked after every call to svarint_consume
 */
int8_t svarint_result() {
    if (ctx->state < 0 || ctx->state == SVARINT_ST_DONE)
        return ctx->state;
    return SVARINT_ERR_NONE;
}

/*
 * Consume a chunk of bytes.
 *
 * @arg[in] buf: buffer holding bytes to be consumed
 * @arg[in] len: number of bytes to consume in buffer
 *
 * @return the number of bytes actually read and processed
 */
uint8_t svarint_consume(const uint8_t* buf, const uint8_t len) {
    for (uint8_t i = 0; i < len; i++) {
        switch (ctx->state) {
        case SVARINT_ST_HEADER:
            if (buf[i] < 0xFD) {
                ctx->value = buf[i];
                ctx->state = SVARINT_ST_DONE;
                return 1; // Read one byte, done
            } else {
                ctx->size = 2 << (buf[i] - 0xFD);
                ctx->offset = 0;
                ctx->value = 0;
                ctx->state = SVARINT_ST_BODY;
            }
            break;
        case SVARINT_ST_BODY:
            // We don't support values greater than 32 bits in practice
            // (we do support up to 32 bit values
            // represented as 64 bit values though)
            if (ctx->offset > 3 && buf[i] > 0) {
                ctx->state = SVARINT_ERR_UNSUPPORTED;
                return i + 1;
            }
            // Read little endian varint value
            ctx->value += buf[i] << (8 * ctx->offset++);
            if (--ctx->size == 0) {
                ctx->state = SVARINT_ST_DONE;
                return i + 1;
            }
            break;
        default:
            // Trying to read in any other state triggers an invalid error
            ctx->state = SVARINT_ERR_INVALID;
            return 0;
        }
    }

    return len;
}

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
uint8_t svarint_encode(uint32_t value, uint8_t* buf, const uint8_t len) {
    if (value < 0xFD) {
        if (len < 1)
            return 0;
        buf[0] = (uint8_t)value;
        return 1;
    } else if (value <= 0xFFFF) {
        if (len < 3)
            return 0;
        buf[0] = 0xFD;
        buf[1] = value & 0xFF;
        buf[2] = (value & 0xFF00) >> 8;
        return 3;
    } else if (value <= 0xFFFFFFFF) {
        buf[0] = 0xFE;
        buf[1] = value & 0xFF;
        buf[2] = (value & 0xFF00) >> 8;
        buf[3] = (value & 0xFF0000) >> 16;
        buf[4] = (value & 0xFF000000) >> 24;
        return 5;
    } else {
        // We do not support values greater than 2^32-1
        return 0;
    }
}
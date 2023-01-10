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

#ifndef __AUTH_RECEIPT_H
#define __AUTH_RECEIPT_H

#include <stdint.h>

#include "srlp.h"
#include "keccak256.h"

#define RECEIPT_MAX_DEPTH (4)
#define RECEIPT_MAX_BUFFER_SIZE (32)

typedef struct {
    uint8_t flags;
    uint32_t remaining_bytes;

    uint8_t level;
    uint8_t index[RECEIPT_MAX_DEPTH];

    uint8_t aux[RECEIPT_MAX_BUFFER_SIZE];
    uint8_t aux_offset;

    SHA3_CTX hash_ctx;
} receipt_auth_ctx_t;

/*
 * Implement the RSK receipt parsing and validation portion of the signing
 * authorization protocol.
 *
 * @arg[in] rx      number of received bytes from the host
 * @ret             number of transmited bytes to the host
 */
unsigned int auth_sign_handle_receipt(volatile unsigned int rx);

#endif // __AUTH_RECEIPT_H

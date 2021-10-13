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

#include "os_hash.h"
#include "os_exceptions.h"
#include "dbg.h"

int cx_sha256_init(cx_sha256_t *hash) {
    hash->header.algo = CX_ALGO_SHA256;
    sha256_init(&hash->ctx);
}

int cx_keccak_init(cx_sha3_t *hash, int size) {
    hash->header.algo = CX_ALGO_KECCAK256;
    keccak_init(&hash->ctx);
}

int cx_hash(cx_hash_t *hash,
            int mode,
            unsigned char *in,
            unsigned int len,
            unsigned char *out) {
    switch (hash->algo) {
    case CX_ALGO_SHA256:
        if (!out) {
            sha256_update(&((cx_sha256_t *)hash)->ctx, in, len);
        } else {
            sha256_final(&((cx_sha256_t *)hash)->ctx, out);
        }
        break;
    case CX_ALGO_KECCAK256:
        if (!out) {
            keccak_update(&((cx_sha3_t *)hash)->ctx, in, len);
        } else {
            keccak_final(&((cx_sha3_t *)hash)->ctx, out);
        }
        break;
    default:
        LOG("Invalid hash algorithm given to cx_hash: %d", hash->algo);
        THROW(0x9999); // TODO: define proper simulator-only error codes
    }
}

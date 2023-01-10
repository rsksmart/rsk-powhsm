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

#ifndef __SIMULATOR_OS_HASHING_H
#define __SIMULATOR_OS_HASHING_H

#include "sha256.h"
#include "keccak256.h"

typedef enum { CX_ALGO_SHA256 = 0x01, CX_ALGO_KECCAK256 } cx_algo_t;

typedef struct cx_hash_header_s {
    cx_algo_t algo;
} cx_hash_t;

typedef struct cx_sha256_s {
    cx_hash_t header;
    SHA256_CTX ctx;
} cx_sha256_t;

typedef struct cx_sha3_s {
    cx_hash_t header;
    SHA3_CTX ctx;
} cx_sha3_t;

int cx_sha256_init(cx_sha256_t *hash);

int cx_keccak_init(cx_sha3_t *hash, int size);

int cx_hash(cx_hash_t *hash,
            int mode,
            unsigned char *in,
            unsigned int len,
            unsigned char *out);

#endif // __SIMULATOR_OS_HASHING_H

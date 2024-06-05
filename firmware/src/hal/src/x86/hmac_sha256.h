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

/**
 * Taken from https://github.com/h5p9sl/hmac_sha256 and
 * adapted for use with the TCPSigner by RSK Labs Ltd
 */

/*
    hmac_sha256.c
    Originally written by https://github.com/h5p9sl
 */

#ifndef __HMAC_SHA256_H
#define __HMAC_SHA256_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stddef.h>

#include "sha256.h"

#define HMAC_SHA256_BLOCK_SIZE 64
#define SHA256_HASH_SIZE SHA256_BLOCK_SIZE
#define HMAC_SHA256_SIZE SHA256_HASH_SIZE

// Wrapper for sha256
void* sha256(const void* data,
             const size_t datalen,
             void* out,
             const size_t outlen);

size_t // Returns the number of bytes written to `out`
hmac_sha256(
    // [in]: The key and its length.
    //      Should be at least 32 bytes long for optimal security.
    const void* key,
    const size_t keylen,

    // [in]: The data to hash alongside the key.
    const void* data,
    const size_t datalen,

    // [out]: The output hash.
    //      Should be 32 bytes long. If it's less than 32 bytes,
    //      the resulting hash will be truncated to the specified length.
    void* out,
    const size_t outlen);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // __HMAC_SHA256_H

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

#include "hmac_sha256.h"

#include <stdlib.h>
#include <string.h>

/* LOCAL FUNCTIONS */

// Concatenate X & Y, return hash.
static void* H(const void* x,
               const size_t xlen,
               const void* y,
               const size_t ylen,
               void* out,
               const size_t outlen);

// Declared in hmac_sha256.h
size_t hmac_sha256(const void* key,
                   const size_t keylen,
                   const void* data,
                   const size_t datalen,
                   void* out,
                   const size_t outlen) {
    uint8_t k[HMAC_SHA256_BLOCK_SIZE];
    uint8_t k_ipad[HMAC_SHA256_BLOCK_SIZE];
    uint8_t k_opad[HMAC_SHA256_BLOCK_SIZE];
    uint8_t ihash[SHA256_HASH_SIZE];
    uint8_t ohash[SHA256_HASH_SIZE];
    size_t sz;
    int i;

    memset(k, 0, sizeof(k));
    memset(k_ipad, 0x36, HMAC_SHA256_BLOCK_SIZE);
    memset(k_opad, 0x5c, HMAC_SHA256_BLOCK_SIZE);

    if (keylen > HMAC_SHA256_BLOCK_SIZE) {
        // If the key is larger than the hash algorithm's
        // block size, we must digest it first.
        sha256(key, keylen, k, sizeof(k));
    } else {
        memcpy(k, key, keylen);
    }

    for (i = 0; i < HMAC_SHA256_BLOCK_SIZE; i++) {
        k_ipad[i] ^= k[i];
        k_opad[i] ^= k[i];
    }

    // Perform HMAC algorithm: ( https://tools.ietf.org/html/rfc2104 )
    //      `H(K XOR opad, H(K XOR ipad, data))`
    H(k_ipad, sizeof(k_ipad), data, datalen, ihash, sizeof(ihash));
    H(k_opad, sizeof(k_opad), ihash, sizeof(ihash), ohash, sizeof(ohash));

    sz = (outlen > SHA256_HASH_SIZE) ? SHA256_HASH_SIZE : outlen;
    memcpy(out, ohash, sz);
    return sz;
}

static void* H(const void* x,
               const size_t xlen,
               const void* y,
               const size_t ylen,
               void* out,
               const size_t outlen) {
    void* result;
    size_t buflen = (xlen + ylen);
    uint8_t* buf = (uint8_t*)malloc(buflen);

    memcpy(buf, x, xlen);
    memcpy(buf + xlen, y, ylen);
    result = sha256(buf, buflen, out, outlen);

    free(buf);
    return result;
}

void* sha256(const void* data,
             const size_t datalen,
             void* out,
             const size_t outlen) {
    size_t sz;
    SHA256_CTX ctx;
    uint8_t hash[SHA256_HASH_SIZE];

    sha256_init(&ctx);
    sha256_update(&ctx, data, datalen);
    sha256_final(&ctx, hash);

    sz = (outlen > SHA256_HASH_SIZE) ? SHA256_HASH_SIZE : outlen;
    return memcpy(out, hash, sz);
}

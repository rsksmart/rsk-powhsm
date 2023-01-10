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

#ifndef __HASH_H
#define __HASH_H

#include "bc.h"

// -----------------------------------------------------------------------
// Portable SHA256 and Keccak256 hashing.
// The goal of this file is to abstract out hashing implementation,
// which will depend on the environment where bulk PoW validation is
// executed. Environments can be:
//
//  - TCPSigner: see "os_hash.h"
//  - Ledger (the real thing): use BOLOS_SDK, version 1.3
// -----------------------------------------------------------------------

#include "os.h"

typedef cx_sha256_t sha256_ctx_t;
typedef cx_sha3_t keccak_ctx_t;

#define SHA256_INIT(ctx) cx_sha256_init(ctx)
#define SHA256_UPDATE(ctx, data, len) \
    cx_hash((cx_hash_t*)(ctx), 0, data, len, NULL)
#define SHA256_FINAL(ctx, hash) \
    cx_hash((cx_hash_t*)(ctx), CX_LAST, NULL, 0, hash)

#define KECCAK_INIT(ctx) cx_keccak_init(ctx, 256)
#define KECCAK_UPDATE(ctx, data, len) \
    cx_hash((cx_hash_t*)(ctx), 0, (uint8_t*)data, len, NULL)
#define KECCAK_FINAL(ctx, hash) \
    cx_hash((cx_hash_t*)(ctx), CX_LAST, NULL, 0, hash)

// Convenience macros to deal with frequent hash ops
#define HEQ(h0, h1) (memcmp(h0, h1, HASH_SIZE) == 0)
#define HNEQ(h0, h1) (memcmp(h0, h1, HASH_SIZE) != 0)
#define HLT(h0, h1) (memcmp(h0, h1, HASH_SIZE) < 0)
#define HSTORE(dst, src) (memcpy(dst, src, HASH_SIZE))

// Revert hash in place
#define REV_HASH(hash)                                            \
    {                                                             \
        for (unsigned char __i = 0; __i < HASH_SIZE / 2; __i++) { \
            unsigned char __tmp = (hash)[__i];                    \
            (hash)[__i] = (hash)[HASH_SIZE - __i - 1];            \
            (hash)[HASH_SIZE - __i - 1] = __tmp;                  \
        }                                                         \
    }

/*
 * Compute a double sha256 and a final reversal.
 *
 * @arg[in]  ctx  sha256 context
 * @arg[in]  data pointer tobytes to double hash and reverse
 * @arg[in]  len  length of data to hash in bytes
 * @arg[out] hash 32-byte buffer where hash will be stored
 */
void double_sha256_rev(sha256_ctx_t* ctx,
                       uint8_t* data,
                       size_t len,
                       uint8_t* hash);

/*
 * Perform one step of the Merkle proof validation. The result
 * of the hash step will be stored in `left`, thus clobbering
 * `left`'s input value.
 *
 * @arg[in]     ctx s ha256 context
 * @arg[in/out] left  pointer to left hash, result will be stored here
 * @arg[in]     right pointer to right hash
 */
void fold_left(sha256_ctx_t* ctx, uint8_t* left, uint8_t* right);

#endif // __HASH_H

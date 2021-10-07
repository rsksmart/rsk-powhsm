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

#include "bc.h"
#include "bc_hash.h"

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
                       uint8_t* hash) {
    SHA256_INIT(ctx);
    SHA256_UPDATE(ctx, data, len);
    SHA256_FINAL(ctx, hash);
    SHA256_INIT(ctx);
    SHA256_UPDATE(ctx, hash, HASH_SIZE);
    SHA256_FINAL(ctx, hash);
    REV_HASH(hash);
}

/*
 * Perform one step of the Merkle proof validation. The result
 * of the hash step will be stored in `left`, thus clobbering
 * `left`'s input value.
 *
 * @arg[in]     ctx s ha256 context
 * @arg[in/out] left  pointer to left hash, result will be stored here
 * @arg[in]     right pointer to right hash
 */
void fold_left(sha256_ctx_t* ctx, uint8_t* left, uint8_t* right) {
    REV_HASH(left);
    REV_HASH(right);
    SHA256_INIT(ctx);
    SHA256_UPDATE(ctx, left, HASH_SIZE);
    SHA256_UPDATE(ctx, right, HASH_SIZE);
    SHA256_FINAL(ctx, left);
    SHA256_INIT(ctx);
    SHA256_UPDATE(ctx, left, HASH_SIZE);
    SHA256_FINAL(ctx, left);
    REV_HASH(left);
}

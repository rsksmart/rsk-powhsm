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

#include "hal/hash.h"
#include "sha256.h"
#include "os.h"

// *** sha256 ***
bool hash_sha256_init(hash_sha256_ctx_t* ctx) {
    cx_sha256_init(ctx);
    return true;
}

bool hash_sha256_update(hash_sha256_ctx_t* ctx,
                        const uint8_t* data,
                        size_t len) {
    cx_hash((cx_hash_t*)(ctx), 0, (unsigned char*)data, len, NULL);
    return true;
}

bool hash_sha256_final(hash_sha256_ctx_t* ctx, uint8_t* out_hash) {
    cx_hash((cx_hash_t*)(ctx), CX_LAST, NULL, 0, out_hash);
    return true;
}

// *** sha256 with midstate support ***
bool hash_sha256_ms_init(hash_sha256_ms_ctx_t* ctx) {
    sha256_init(ctx);
    return true;
}

bool hash_sha256_ms_midstate(hash_sha256_ms_ctx_t* ctx, uint8_t* midstate) {
    sha256_midstate(ctx, midstate);
    return true;
}

bool hash_sha256_ms_update(hash_sha256_ms_ctx_t* ctx,
                           const uint8_t* data,
                           size_t len) {
    sha256_update(ctx, data, len);
    return true;
}

bool hash_sha256_ms_final(hash_sha256_ms_ctx_t* ctx, uint8_t* out_hash) {
    sha256_final(ctx, out_hash);
    return true;
}

// *** keccak256 ***
bool hash_keccak256_init(hash_keccak256_ctx_t* ctx) {
    cx_keccak_init(ctx, 256);
    return true;
}

bool hash_keccak256_update(hash_keccak256_ctx_t* ctx,
                           const uint8_t* data,
                           size_t len) {
    cx_hash((cx_hash_t*)(ctx), 0, (unsigned char*)data, len, NULL);
    return true;
}

bool hash_keccak256_final(hash_keccak256_ctx_t* ctx, uint8_t* out_hash) {
    cx_hash((cx_hash_t*)(ctx), CX_LAST, NULL, 0, out_hash);
    return true;
}
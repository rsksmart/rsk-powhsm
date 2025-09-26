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

#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "hal/hash.h"

// Mocks
struct {
    int cx_hash_ret_return;
} G_mocks;

struct {
    bool cx_sha256_init;
    bool cx_hash;
    bool cx_keccak_init;
    bool sha256_init;
    bool sha256_midstate;
    bool sha256_update;
    bool sha256_final;
} G_called;

struct {
    struct {
        cx_sha256_t* ctx;
    } cx_sha256_init;

    struct {
        cx_hash_t* ctx;
        int mode;
        unsigned char* in;
        unsigned int len;
        unsigned char* out;
    } cx_hash;

    struct {
        cx_sha3_t* ctx;
        int size;
    } cx_keccak_init;

    struct {
        hash_sha256_ms_ctx_t* ctx;
    } sha256_init;

    struct {
        hash_sha256_ms_ctx_t* ctx;
        uint8_t* midstate;
    } sha256_midstate;

    struct {
        hash_sha256_ms_ctx_t* ctx;
        const uint8_t* data;
        size_t len;
    } sha256_update;

    struct {
        hash_sha256_ms_ctx_t* ctx;
        uint8_t* hash;
    } sha256_final;
} G_args;

int cx_sha256_init(cx_sha256_t* ctx) {
    G_called.cx_sha256_init = true;
    G_args.cx_sha256_init.ctx = ctx;
    return 0; // Return success
}

int cx_hash(cx_hash_t* ctx,
            int mode,
            unsigned char* in,
            unsigned int len,
            unsigned char* out) {
    G_called.cx_hash = true;
    G_args.cx_hash.ctx = ctx;
    G_args.cx_hash.mode = mode;
    G_args.cx_hash.in = in;
    G_args.cx_hash.len = len;
    G_args.cx_hash.out = out;
    return G_mocks.cx_hash_ret_return;
}

int cx_keccak_init(cx_sha3_t* ctx, int size) {
    G_called.cx_keccak_init = true;
    G_args.cx_keccak_init.ctx = ctx;
    G_args.cx_keccak_init.size = size;
    // Should always be 256 for Keccak-256
    assert(size == 256);
    return 0; // Return success
}

void sha256_init(hash_sha256_ms_ctx_t* ctx) {
    G_called.sha256_init = true;
    G_args.sha256_init.ctx = ctx;
}

void sha256_midstate(hash_sha256_ms_ctx_t* ctx, uint8_t* midstate) {
    G_called.sha256_midstate = true;
    G_args.sha256_midstate.ctx = ctx;
    G_args.sha256_midstate.midstate = midstate;
}

void sha256_update(hash_sha256_ms_ctx_t* ctx, const uint8_t* data, size_t len) {
    G_called.sha256_update = true;
    G_args.sha256_update.ctx = ctx;
    G_args.sha256_update.data = data;
    G_args.sha256_update.len = len;
}

void sha256_final(hash_sha256_ms_ctx_t* ctx, uint8_t* hash) {
    G_called.sha256_final = true;
    G_args.sha256_final.ctx = ctx;
    G_args.sha256_final.hash = hash;
}

// Unit tests
void setup() {
    explicit_bzero(&G_mocks, sizeof(G_mocks));
    explicit_bzero(&G_called, sizeof(G_called));
    explicit_bzero(&G_args, sizeof(G_args));
}

// sha256
void test_hash_sha256_init_ok() {
    setup();
    printf("Testing hash_sha256_init succeeds...\n");

    hash_sha256_ctx_t ctx;
    assert(hash_sha256_init(&ctx));
    assert(G_called.cx_sha256_init);
    assert(G_args.cx_sha256_init.ctx == &ctx);
}

void test_hash_sha256_update_ok() {
    setup();
    printf("Testing hash_sha256_update succeeds...\n");

    hash_sha256_ctx_t ctx;
    const uint8_t data[] = "test data";
    size_t len = sizeof(data) - 1;

    assert(hash_sha256_update(&ctx, data, len));
    assert(G_called.cx_hash);
    assert(G_args.cx_hash.ctx == (cx_hash_t*)&ctx);
    assert(G_args.cx_hash.mode == 0);
    assert(G_args.cx_hash.in == (const unsigned char*)data);
    assert(G_args.cx_hash.len == len);
    assert(G_args.cx_hash.out == NULL);
}

void test_hash_sha256_final_ok() {
    setup();
    printf("Testing hash_sha256_final succeeds...\n");

    hash_sha256_ctx_t ctx;
    uint8_t out_hash[32];

    assert(hash_sha256_final(&ctx, out_hash));
    assert(G_called.cx_hash);
    assert(G_args.cx_hash.ctx == (cx_hash_t*)&ctx);
    assert(G_args.cx_hash.mode == CX_LAST);
    assert(G_args.cx_hash.in == NULL);
    assert(G_args.cx_hash.len == 0);
    assert(G_args.cx_hash.out == (unsigned char*)out_hash);
}

// sha256_ms
void test_hash_sha256_ms_init_ok() {
    setup();
    printf("Testing hash_sha256_ms_init succeeds...\n");

    hash_sha256_ms_ctx_t ctx;
    assert(hash_sha256_ms_init(&ctx));
    assert(G_called.sha256_init);
    assert(G_args.sha256_init.ctx == &ctx);
}

void test_hash_sha256_ms_midstate_ok() {
    setup();
    printf("Testing hash_sha256_ms_midstate succeeds...\n");

    hash_sha256_ms_ctx_t ctx;
    uint8_t midstate[52];

    assert(hash_sha256_ms_midstate(&ctx, midstate));
    assert(G_called.sha256_midstate);
    assert(G_args.sha256_midstate.ctx == &ctx);
    assert(G_args.sha256_midstate.midstate == midstate);
}

void test_hash_sha256_ms_update_ok() {
    setup();
    printf("Testing hash_sha256_ms_update succeeds...\n");

    hash_sha256_ms_ctx_t ctx;
    const uint8_t data[] = "test message";
    size_t len = sizeof(data) - 1;

    assert(hash_sha256_ms_update(&ctx, data, len));
    assert(G_called.sha256_update);
    assert(G_args.sha256_update.ctx == &ctx);
    assert(G_args.sha256_update.data == data);
    assert(G_args.sha256_update.len == len);
}

void test_hash_sha256_ms_final_ok() {
    setup();
    printf("Testing hash_sha256_ms_final succeeds...\n");

    hash_sha256_ms_ctx_t ctx;
    uint8_t out_hash[32];

    assert(hash_sha256_ms_final(&ctx, out_hash));
    assert(G_called.sha256_final);
    assert(G_args.sha256_final.ctx == &ctx);
    assert(G_args.sha256_final.hash == out_hash);
}

// keccak256
void test_hash_keccak256_init_ok() {
    setup();
    printf("Testing hash_keccak256_init succeeds...\n");

    hash_keccak256_ctx_t ctx;
    assert(hash_keccak256_init(&ctx));
    assert(G_called.cx_keccak_init);
    assert(G_args.cx_keccak_init.ctx == &ctx);
    assert(G_args.cx_keccak_init.size == 256);
}

void test_hash_keccak256_update_ok() {
    setup();
    printf("Testing hash_keccak256_update succeeds...\n");

    hash_keccak256_ctx_t ctx;
    const uint8_t data[] = "keccak test data";
    size_t len = sizeof(data) - 1;

    assert(hash_keccak256_update(&ctx, data, len));
    assert(G_called.cx_hash);
    assert(G_args.cx_hash.ctx == (cx_hash_t*)&ctx);
    assert(G_args.cx_hash.mode == 0);
    assert(G_args.cx_hash.in == (const unsigned char*)data);
    assert(G_args.cx_hash.len == len);
    assert(G_args.cx_hash.out == NULL);
}

void test_hash_keccak256_final_ok() {
    setup();
    printf("Testing hash_keccak256_final succeeds...\n");

    hash_keccak256_ctx_t ctx;
    uint8_t out_hash[32];

    assert(hash_keccak256_final(&ctx, out_hash));
    assert(G_called.cx_hash);
    assert(G_args.cx_hash.ctx == (cx_hash_t*)&ctx);
    assert(G_args.cx_hash.mode == CX_LAST);
    assert(G_args.cx_hash.in == NULL);
    assert(G_args.cx_hash.len == 0);
    assert(G_args.cx_hash.out == (unsigned char*)out_hash);
}

int main() {
    test_hash_sha256_init_ok();
    test_hash_sha256_update_ok();
    test_hash_sha256_final_ok();

    test_hash_sha256_ms_init_ok();
    test_hash_sha256_ms_midstate_ok();
    test_hash_sha256_ms_update_ok();
    test_hash_sha256_ms_final_ok();

    test_hash_keccak256_init_ok();
    test_hash_keccak256_update_ok();
    test_hash_keccak256_final_ok();

    printf("All Ledger HAL hash tests passed!\n");
    return 0;
}

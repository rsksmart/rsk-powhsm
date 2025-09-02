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
#include <string.h>

#include "hal/hash.h"

// Mocks for tracking function calls and capturing arguments
struct {
    bool sha256_init;
    bool sha256_update;
    bool sha256_final;
    bool sha256_midstate;
    bool keccak_init;
    bool keccak_update;
    bool keccak_final;
} G_called;

struct {
    struct {
        hash_sha256_ctx_t* ctx;
    } sha256_init;

    struct {
        hash_sha256_ctx_t* ctx;
        const uint8_t* data;
        size_t len;
    } sha256_update;

    struct {
        hash_sha256_ctx_t* ctx;
        uint8_t* hash;
    } sha256_final;

    struct {
        hash_sha256_ms_ctx_t* ctx;
        uint8_t* midstate;
    } sha256_midstate;

    struct {
        hash_keccak256_ctx_t* ctx;
    } keccak_init;

    struct {
        hash_keccak256_ctx_t* ctx;
        const uint8_t* data;
        uint16_t len;
    } keccak_update;

    struct {
        hash_keccak256_ctx_t* ctx;
        uint8_t* out_hash;
    } keccak_final;
} G_args;

// Mock implementations
void sha256_init(hash_sha256_ctx_t* ctx) {
    G_called.sha256_init = true;
    G_args.sha256_init.ctx = ctx;
}

void sha256_update(hash_sha256_ctx_t* ctx, const uint8_t* data, size_t len) {
    G_called.sha256_update = true;
    G_args.sha256_update.ctx = ctx;
    G_args.sha256_update.data = data;
    G_args.sha256_update.len = len;
}

void sha256_final(hash_sha256_ctx_t* ctx, uint8_t* hash) {
    G_called.sha256_final = true;
    G_args.sha256_final.ctx = ctx;
    G_args.sha256_final.hash = hash;
}

void sha256_midstate(hash_sha256_ms_ctx_t* ctx, uint8_t* midstate) {
    G_called.sha256_midstate = true;
    G_args.sha256_midstate.ctx = ctx;
    G_args.sha256_midstate.midstate = midstate;
}

void keccak_init(hash_keccak256_ctx_t* ctx) {
    G_called.keccak_init = true;
    G_args.keccak_init.ctx = ctx;
}

void keccak_update(hash_keccak256_ctx_t* ctx,
                   const uint8_t* data,
                   uint16_t len) {
    G_called.keccak_update = true;
    G_args.keccak_update.ctx = ctx;
    G_args.keccak_update.data = data;
    G_args.keccak_update.len = len;
}

void keccak_final(hash_keccak256_ctx_t* ctx, uint8_t* out_hash) {
    G_called.keccak_final = true;
    G_args.keccak_final.ctx = ctx;
    G_args.keccak_final.out_hash = out_hash;
}

// Test setup function
void setup() {
    memset(&G_called, 0, sizeof(G_called));
    memset(&G_args, 0, sizeof(G_args));
}

// Unit tests for sha256 functions
void test_hash_sha256_init() {
    setup();
    printf("Testing hash_sha256_init calls sha256_init...\n");

    hash_sha256_ctx_t ctx;
    bool result = hash_sha256_init(&ctx);

    assert(result == true);
    assert(G_called.sha256_init);
    assert(G_args.sha256_init.ctx == &ctx);
    assert(!G_called.sha256_update);
    assert(!G_called.sha256_final);
}

void test_hash_sha256_update() {
    setup();
    printf("Testing hash_sha256_update calls sha256_update...\n");

    hash_sha256_ctx_t ctx;
    const uint8_t test_data[] = "test message";
    size_t test_len = sizeof(test_data) - 1;

    bool result = hash_sha256_update(&ctx, test_data, test_len);

    assert(result == true);
    assert(G_called.sha256_update);
    assert(G_args.sha256_update.ctx == &ctx);
    assert(G_args.sha256_update.data == test_data);
    assert(G_args.sha256_update.len == test_len);
    assert(!G_called.sha256_init);
    assert(!G_called.sha256_final);
}

void test_hash_sha256_final() {
    setup();
    printf("Testing hash_sha256_final calls sha256_final...\n");

    hash_sha256_ctx_t ctx;
    uint8_t out_hash[32];

    bool result = hash_sha256_final(&ctx, out_hash);

    assert(result == true);
    assert(G_called.sha256_final);
    assert(G_args.sha256_final.ctx == &ctx);
    assert(G_args.sha256_final.hash == out_hash);
    assert(!G_called.sha256_init);
    assert(!G_called.sha256_update);
}

// Unit tests for sha256_ms functions
void test_hash_sha256_ms_init() {
    setup();
    printf("Testing hash_sha256_ms_init calls sha256_init...\n");

    hash_sha256_ms_ctx_t ctx;
    bool result = hash_sha256_ms_init(&ctx);

    assert(result == true);
    assert(G_called.sha256_init);
    assert(G_args.sha256_init.ctx == &ctx);
    assert(!G_called.sha256_update);
    assert(!G_called.sha256_final);
    assert(!G_called.sha256_midstate);
}

void test_hash_sha256_ms_midstate() {
    setup();
    printf("Testing hash_sha256_ms_midstate calls sha256_midstate...\n");

    hash_sha256_ms_ctx_t ctx;
    uint8_t midstate[52];

    bool result = hash_sha256_ms_midstate(&ctx, midstate);

    assert(result == true);
    assert(G_called.sha256_midstate);
    assert(G_args.sha256_midstate.ctx == &ctx);
    assert(G_args.sha256_midstate.midstate == midstate);
    assert(!G_called.sha256_init);
    assert(!G_called.sha256_update);
    assert(!G_called.sha256_final);
}

void test_hash_sha256_ms_update() {
    setup();
    printf("Testing hash_sha256_ms_update calls sha256_update...\n");

    hash_sha256_ms_ctx_t ctx;
    const uint8_t test_data[] = "midstate test";
    size_t test_len = sizeof(test_data) - 1;

    bool result = hash_sha256_ms_update(&ctx, test_data, test_len);

    assert(result == true);
    assert(G_called.sha256_update);
    assert(G_args.sha256_update.ctx == &ctx);
    assert(G_args.sha256_update.data == test_data);
    assert(G_args.sha256_update.len == test_len);
    assert(!G_called.sha256_init);
    assert(!G_called.sha256_final);
    assert(!G_called.sha256_midstate);
}

void test_hash_sha256_ms_final() {
    setup();
    printf("Testing hash_sha256_ms_final calls sha256_final...\n");

    hash_sha256_ms_ctx_t ctx;
    uint8_t out_hash[32];

    bool result = hash_sha256_ms_final(&ctx, out_hash);

    assert(result == true);
    assert(G_called.sha256_final);
    assert(G_args.sha256_final.ctx == &ctx);
    assert(G_args.sha256_final.hash == out_hash);
    assert(!G_called.sha256_init);
    assert(!G_called.sha256_update);
    assert(!G_called.sha256_midstate);
}

// Unit tests for keccak256 functions
void test_hash_keccak256_init() {
    setup();
    printf("Testing hash_keccak256_init calls keccak_init...\n");

    hash_keccak256_ctx_t ctx;
    bool result = hash_keccak256_init(&ctx);

    assert(result == true);
    assert(G_called.keccak_init);
    assert(G_args.keccak_init.ctx == &ctx);
    assert(!G_called.keccak_update);
    assert(!G_called.keccak_final);
}

void test_hash_keccak256_update() {
    setup();
    printf("Testing hash_keccak256_update calls keccak_update...\n");

    hash_keccak256_ctx_t ctx;
    const uint8_t test_data[] = "keccak test message";
    size_t test_len = sizeof(test_data) - 1;

    bool result = hash_keccak256_update(&ctx, test_data, test_len);

    assert(result == true);
    assert(G_called.keccak_update);
    assert(G_args.keccak_update.ctx == &ctx);
    assert(G_args.keccak_update.data == test_data);
    assert(G_args.keccak_update.len == test_len);
    assert(!G_called.keccak_init);
    assert(!G_called.keccak_final);
}

void test_hash_keccak256_final() {
    setup();
    printf("Testing hash_keccak256_final calls keccak_final...\n");

    hash_keccak256_ctx_t ctx;
    uint8_t out_hash[32];

    bool result = hash_keccak256_final(&ctx, out_hash);

    assert(result == true);
    assert(G_called.keccak_final);
    assert(G_args.keccak_final.ctx == &ctx);
    assert(G_args.keccak_final.out_hash == out_hash);
    assert(!G_called.keccak_init);
    assert(!G_called.keccak_update);
}

int main() {
    // SHA256 tests
    test_hash_sha256_init();
    test_hash_sha256_update();
    test_hash_sha256_final();

    // SHA256 with midstate tests
    test_hash_sha256_ms_init();
    test_hash_sha256_ms_midstate();
    test_hash_sha256_ms_update();
    test_hash_sha256_ms_final();

    // keccak256 tests
    test_hash_keccak256_init();
    test_hash_keccak256_update();
    test_hash_keccak256_final();

    printf("All hash tests passed!\n");
    return 0;
}
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

// Mocks
struct {
    int mbedtls_sha256_starts_ret_return;
    int mbedtls_sha256_update_ret_return;
    int mbedtls_sha256_finish_ret_return;
} G_mocks;

struct {
    bool mbedtls_sha256_init;
    bool mbedtls_sha256_starts_ret;
    bool mbedtls_sha256_update_ret;
    bool mbedtls_sha256_finish_ret;
    bool mbedtls_sha256_free;
    bool sha256_init;
    bool sha256_midstate;
    bool sha256_update;
    bool sha256_final;
    bool keccak_init;
    bool keccak_update;
    bool keccak_final;
} G_called;

struct {
    struct {
        hash_sha256_ctx_t* ctx;
    } mbedtls_sha256_init;

    struct {
        hash_sha256_ctx_t* ctx;
        int is_224;
    } mbedtls_sha256_starts_ret;

    struct {
        hash_sha256_ctx_t* ctx;
        const uint8_t* data;
        size_t len;
    } mbedtls_sha256_update_ret;

    struct {
        hash_sha256_ctx_t* ctx;
        uint8_t* out_hash;
    } mbedtls_sha256_finish_ret;

    struct {
        hash_sha256_ctx_t* ctx;
    } mbedtls_sha256_free;

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

    struct {
        hash_keccak256_ctx_t* ctx;
    } keccak_init;

    struct {
        hash_keccak256_ctx_t* ctx;
        const unsigned char* msg;
        uint16_t size;
    } keccak_update;

    struct {
        hash_keccak256_ctx_t* ctx;
        unsigned char* result;
    } keccak_final;
} G_args;

void mbedtls_sha256_init(hash_sha256_ctx_t* ctx) {
    G_called.mbedtls_sha256_init = true;
    G_args.mbedtls_sha256_init.ctx = ctx;
}

int mbedtls_sha256_starts_ret(hash_sha256_ctx_t* ctx, int is_224) {
    G_called.mbedtls_sha256_starts_ret = true;
    G_args.mbedtls_sha256_starts_ret.ctx = ctx;
    G_args.mbedtls_sha256_starts_ret.is_224 = is_224;
    // Should always be 0 for SHA-256
    assert(is_224 == 0);
    return G_mocks.mbedtls_sha256_starts_ret_return;
}

int mbedtls_sha256_update_ret(hash_sha256_ctx_t* ctx,
                              const uint8_t* data,
                              size_t len) {
    G_called.mbedtls_sha256_update_ret = true;
    G_args.mbedtls_sha256_update_ret.ctx = ctx;
    G_args.mbedtls_sha256_update_ret.data = data;
    G_args.mbedtls_sha256_update_ret.len = len;
    return G_mocks.mbedtls_sha256_update_ret_return;
}

int mbedtls_sha256_finish_ret(hash_sha256_ctx_t* ctx,
                              unsigned char output[32]) {
    G_called.mbedtls_sha256_finish_ret = true;
    G_args.mbedtls_sha256_finish_ret.ctx = ctx;
    G_args.mbedtls_sha256_finish_ret.out_hash = output;

    return G_mocks.mbedtls_sha256_finish_ret_return;
}

void mbedtls_sha256_free(hash_sha256_ctx_t* ctx) {
    G_called.mbedtls_sha256_free = true;
    G_args.mbedtls_sha256_free.ctx = ctx;
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

void keccak_init(hash_keccak256_ctx_t* ctx) {
    G_called.keccak_init = true;
    G_args.keccak_init.ctx = ctx;
}

void keccak_update(hash_keccak256_ctx_t* ctx,
                   const unsigned char* msg,
                   uint16_t size) {
    G_called.keccak_update = true;
    G_args.keccak_update.ctx = ctx;
    G_args.keccak_update.msg = msg;
    G_args.keccak_update.size = size;
}

void keccak_final(hash_keccak256_ctx_t* ctx, unsigned char* result) {
    G_called.keccak_final = true;
    G_args.keccak_final.ctx = ctx;
    G_args.keccak_final.result = result;
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
    bool result = hash_sha256_init(&ctx);

    assert(result == true);
    assert(G_called.mbedtls_sha256_init);
    assert(G_called.mbedtls_sha256_starts_ret);
    assert(!G_called.mbedtls_sha256_free);
    assert(G_args.mbedtls_sha256_init.ctx == &ctx);
    assert(G_args.mbedtls_sha256_starts_ret.ctx == &ctx);
}

void test_hash_sha256_init_starts_fails() {
    setup();
    printf("Testing hash_sha256_init fails when starts_ret fails...\n");

    G_mocks.mbedtls_sha256_starts_ret_return = -1;

    hash_sha256_ctx_t ctx;
    bool result = hash_sha256_init(&ctx);

    assert(result == false);
    assert(G_called.mbedtls_sha256_init);
    assert(G_called.mbedtls_sha256_starts_ret);
    assert(G_called.mbedtls_sha256_free);
    assert(G_args.mbedtls_sha256_init.ctx == &ctx);
    assert(G_args.mbedtls_sha256_starts_ret.ctx == &ctx);
    assert(G_args.mbedtls_sha256_free.ctx == &ctx);
}

void test_hash_sha256_update_ok() {
    setup();
    printf("Testing hash_sha256_update succeeds...\n");

    hash_sha256_ctx_t ctx;
    const uint8_t data[] = "test data";
    size_t len = sizeof(data) - 1;

    bool result = hash_sha256_update(&ctx, data, len);

    assert(result == true);
    assert(G_called.mbedtls_sha256_update_ret);
    assert(G_args.mbedtls_sha256_update_ret.ctx == &ctx);
    assert(G_args.mbedtls_sha256_update_ret.data == data);
    assert(G_args.mbedtls_sha256_update_ret.len == len);
    assert(!G_called.mbedtls_sha256_free);
}

void test_hash_sha256_update_fails() {
    setup();
    printf("Testing hash_sha256_update fails when update_ret fails...\n");

    G_mocks.mbedtls_sha256_update_ret_return = -1;

    hash_sha256_ctx_t ctx;
    const uint8_t data[] = "test data";
    size_t len = sizeof(data) - 1;

    bool result = hash_sha256_update(&ctx, data, len);

    assert(result == false);
    assert(G_called.mbedtls_sha256_update_ret);
    assert(G_called.mbedtls_sha256_free);
    assert(G_args.mbedtls_sha256_update_ret.ctx == &ctx);
    assert(G_args.mbedtls_sha256_update_ret.data == data);
    assert(G_args.mbedtls_sha256_update_ret.len == len);
}

void test_hash_sha256_final_ok() {
    setup();
    printf("Testing hash_sha256_final succeeds...\n");

    hash_sha256_ctx_t ctx;
    uint8_t out_hash[32];

    bool result = hash_sha256_final(&ctx, out_hash);

    assert(result == true);
    assert(G_called.mbedtls_sha256_finish_ret);
    assert(G_called.mbedtls_sha256_free);
    assert(G_args.mbedtls_sha256_finish_ret.ctx == &ctx);
    assert(G_args.mbedtls_sha256_finish_ret.out_hash == out_hash);
    assert(G_args.mbedtls_sha256_free.ctx == &ctx);
}

void test_hash_sha256_final_fails() {
    setup();
    printf("Testing hash_sha256_final fails when finish_ret fails...\n");

    G_mocks.mbedtls_sha256_finish_ret_return = -1;

    hash_sha256_ctx_t ctx;
    uint8_t out_hash[32];

    bool result = hash_sha256_final(&ctx, out_hash);

    assert(result == false);
    assert(G_called.mbedtls_sha256_finish_ret);
    assert(G_called.mbedtls_sha256_free);
    assert(G_args.mbedtls_sha256_finish_ret.ctx == &ctx);
    assert(G_args.mbedtls_sha256_finish_ret.out_hash == out_hash);
    assert(G_args.mbedtls_sha256_free.ctx == &ctx);
}

// sha256_ms
void test_hash_sha256_ms_init_ok() {
    setup();
    printf("Testing hash_sha256_ms_init succeeds...\n");

    hash_sha256_ms_ctx_t ctx;
    bool result = hash_sha256_ms_init(&ctx);

    assert(result == true);
    assert(G_called.sha256_init);
    assert(G_args.sha256_init.ctx == &ctx);
}

void test_hash_sha256_ms_midstate_ok() {
    setup();
    printf("Testing hash_sha256_ms_midstate succeeds...\n");

    hash_sha256_ms_ctx_t ctx;
    uint8_t midstate[52];

    bool result = hash_sha256_ms_midstate(&ctx, midstate);

    assert(result == true);
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

    bool result = hash_sha256_ms_update(&ctx, data, len);

    assert(result == true);
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

    bool result = hash_sha256_ms_final(&ctx, out_hash);

    assert(result == true);
    assert(G_called.sha256_final);
    assert(G_args.sha256_final.ctx == &ctx);
    assert(G_args.sha256_final.hash == out_hash);
}

// keccak256
void test_hash_keccak256_init_ok() {
    setup();
    printf("Testing hash_keccak256_init succeeds...\n");

    hash_keccak256_ctx_t ctx;
    bool result = hash_keccak256_init(&ctx);

    assert(result == true);
    assert(G_called.keccak_init);
    assert(G_args.keccak_init.ctx == &ctx);
}

void test_hash_keccak256_update_ok() {
    setup();
    printf("Testing hash_keccak256_update succeeds...\n");

    hash_keccak256_ctx_t ctx;
    const uint8_t data[] = "keccak test data";
    size_t len = sizeof(data) - 1;

    bool result = hash_keccak256_update(&ctx, data, len);

    assert(result == true);
    assert(G_called.keccak_update);
    assert(G_args.keccak_update.ctx == &ctx);
    assert(G_args.keccak_update.msg == data);
    assert(G_args.keccak_update.size == len);
}

void test_hash_keccak256_final_ok() {
    setup();
    printf("Testing hash_keccak256_final succeeds...\n");

    hash_keccak256_ctx_t ctx;
    uint8_t out_hash[32];

    bool result = hash_keccak256_final(&ctx, out_hash);

    assert(result == true);
    assert(G_called.keccak_final);
    assert(G_args.keccak_final.ctx == &ctx);
    assert(G_args.keccak_final.result == out_hash);
}

int main() {
    test_hash_sha256_init_ok();
    test_hash_sha256_init_starts_fails();
    test_hash_sha256_update_ok();
    test_hash_sha256_update_fails();
    test_hash_sha256_final_ok();
    test_hash_sha256_final_fails();

    test_hash_sha256_ms_init_ok();
    test_hash_sha256_ms_midstate_ok();
    test_hash_sha256_ms_update_ok();
    test_hash_sha256_ms_final_ok();

    test_hash_keccak256_init_ok();
    test_hash_keccak256_update_ok();
    test_hash_keccak256_final_ok();

    printf("All hash tests passed!\n");
    return 0;
}

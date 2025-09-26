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
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXP  RESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "mock.h"

#include "hal/constants.h"
#include "hal/seed.h"
#include "hal/exceptions.h"

// Mocks
struct {
    bool os_perso_isonboarded;
    bool os_perso_derive_node_bip32;
    bool cx_ecdsa_init_private_key;
    bool cx_ecfp_generate_pair;
    bool cx_ecdsa_sign;
    bool os_memmove;
} G_called;

struct {
    int os_perso_isonboarded_ret;
} G_mocks;

struct {
    struct {
        int curve;
        uint32_t *path;
        uint8_t path_length;
        unsigned char *out;
        void *chain;
    } os_perso_derive_node_bip32;
    struct {
        int curve;
        unsigned char *key;
        int key_len;
        cx_ecfp_private_key_t *private_key;
    } cx_ecdsa_init_private_key;
    struct {
        int curve;
        cx_ecfp_public_key_t *pub;
        cx_ecfp_private_key_t *priv;
        int keep_private;
    } cx_ecfp_generate_pair;
    struct {
        void *private_key;
        int mode;
        int hash_id;
        uint8_t *hash32;
        int hash_len;
        uint8_t *sig_out;
    } cx_ecdsa_sign;
    struct {
        void *dst;
        const void *src;
        size_t length;
    } os_memmove;
} G_args;

// Extend G_throws for additional throw cases
static struct {
    bool os_perso_derive_node_bip32;
    bool cx_ecdsa_init_private_key;
    bool cx_ecfp_generate_pair;
    bool cx_ecdsa_sign;
} G_throws;

// Helper: returns true if all bytes in buf[0..len-1] are equal to val
static bool memis(const unsigned char *buf, unsigned char val, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] != val)
            return false;
    }
    return true;
}

// Ledger-specific mocks
unsigned int os_perso_isonboarded() {
    G_called.os_perso_isonboarded = true;
    return G_mocks.os_perso_isonboarded_ret;
}

void os_memmove(void *dst, const void *src, unsigned int length) {
    G_called.os_memmove = true;
    G_args.os_memmove.dst = dst;
    G_args.os_memmove.src = src;
    G_args.os_memmove.length = length;
    memcpy(dst, src, length);
}

void os_perso_derive_node_bip32(cx_curve_t curve,
                                unsigned int *path,
                                unsigned int pathLength,
                                unsigned char *privateKey,
                                unsigned char *chain) {
    G_called.os_perso_derive_node_bip32 = true;
    G_args.os_perso_derive_node_bip32.curve = curve;
    G_args.os_perso_derive_node_bip32.path = path;
    G_args.os_perso_derive_node_bip32.path_length = pathLength;
    G_args.os_perso_derive_node_bip32.out = privateKey;
    G_args.os_perso_derive_node_bip32.chain = chain;
    if (G_throws.os_perso_derive_node_bip32) {
        THROW(1);
    }
    memset(privateKey, 0x42, 32); // Fill with dummy data
}

int cx_ecdsa_init_private_key(cx_curve_t curve,
                              unsigned char *rawkey,
                              unsigned int key_len,
                              cx_ecfp_private_key_t *key) {
    G_called.cx_ecdsa_init_private_key = true;
    G_args.cx_ecdsa_init_private_key.curve = curve;
    G_args.cx_ecdsa_init_private_key.key = rawkey;
    G_args.cx_ecdsa_init_private_key.key_len = key_len;
    G_args.cx_ecdsa_init_private_key.private_key = key;
    if (G_throws.cx_ecdsa_init_private_key) {
        THROW(2);
    }
    return 0;
}

int cx_ecfp_generate_pair(cx_curve_t curve,
                          cx_ecfp_public_key_t *pubkey,
                          cx_ecfp_private_key_t *privkey,
                          int keepprivate) {
    G_called.cx_ecfp_generate_pair = true;
    G_args.cx_ecfp_generate_pair.curve = curve;
    G_args.cx_ecfp_generate_pair.pub = pubkey;
    G_args.cx_ecfp_generate_pair.priv = privkey;
    G_args.cx_ecfp_generate_pair.keep_private = keepprivate;
    if (G_throws.cx_ecfp_generate_pair) {
        THROW(3);
    }
    pubkey->W_len = 65;
    memset(pubkey->W, 0xAA, 65);
    return 0;
}

int cx_ecdsa_sign(cx_ecfp_private_key_t *key,
                  int mode,
                  cx_md_t hashID,
                  unsigned char *hash,
                  unsigned int hash_len,
                  unsigned char *sig) {
    G_called.cx_ecdsa_sign = true;
    G_args.cx_ecdsa_sign.private_key = key;
    G_args.cx_ecdsa_sign.mode = mode;
    G_args.cx_ecdsa_sign.hash_id = hashID;
    G_args.cx_ecdsa_sign.hash32 = hash;
    G_args.cx_ecdsa_sign.hash_len = hash_len;
    G_args.cx_ecdsa_sign.sig_out = sig;
    if (G_throws.cx_ecdsa_sign) {
        THROW(4);
    }
    memset(sig, 0xBB, 72);
    return 72;
}

// Tests
void setup() {
    memset(&G_called, 0, sizeof(G_called));
    memset(&G_mocks, 0, sizeof(G_mocks));
    memset(&G_args, 0, sizeof(G_args));
    memset(&G_throws, 0, sizeof(G_throws));
}

void test_seed_available() {
    printf("Testing seed_available()...\n");
    setup();
    G_mocks.os_perso_isonboarded_ret = 1;
    assert(seed_available());
    G_mocks.os_perso_isonboarded_ret = 0;
    assert(!seed_available());
}

void test_seed_derive_pubkey_success() {
    printf("Testing seed_derive_pubkey() ok...\n");
    setup();
    unsigned int path[5] = {0};
    unsigned char path_length = 5;
    unsigned char pubkey_out[82];
    unsigned char pubkey_out_length = sizeof(pubkey_out);
    memset(pubkey_out, 0, sizeof(pubkey_out));
    assert(
        seed_derive_pubkey(path, path_length, pubkey_out, &pubkey_out_length));
    assert(pubkey_out_length == 65);
    assert(memis(pubkey_out, 0xAA, 65));
    assert(G_called.os_perso_derive_node_bip32);
    assert(G_called.cx_ecdsa_init_private_key);
    assert(G_called.cx_ecfp_generate_pair);
    assert(G_called.os_memmove);

    assert(G_args.os_perso_derive_node_bip32.curve == CX_CURVE_256K1);
    assert(G_args.os_perso_derive_node_bip32.path == path);
    assert(G_args.os_perso_derive_node_bip32.path_length == path_length);
    assert(G_args.os_perso_derive_node_bip32.out != NULL);
    assert(G_args.os_perso_derive_node_bip32.chain == NULL);

    assert(G_args.cx_ecdsa_init_private_key.curve == CX_CURVE_256K1);
    assert(G_args.cx_ecdsa_init_private_key.key != NULL);
    assert(G_args.cx_ecdsa_init_private_key.key_len == 32);
    assert(G_args.cx_ecdsa_init_private_key.private_key != NULL);

    assert(G_args.cx_ecfp_generate_pair.curve == CX_CURVE_256K1);
    assert(G_args.cx_ecfp_generate_pair.pub != NULL);
    assert(G_args.cx_ecfp_generate_pair.priv != NULL);
    assert(G_args.cx_ecfp_generate_pair.keep_private == 1);

    assert(G_args.os_memmove.dst == pubkey_out);
    assert(G_args.os_memmove.src != NULL);
    assert(G_args.os_memmove.length == 65);
}

void test_seed_derive_pubkey_os_perso_derive_node_bip32_throws() {
    printf("Testing seed_derive_pubkey() when os_perso_derive_node_bip32 "
           "throws...\n");
    setup();
    unsigned int path[5] = {0};
    unsigned char path_length = 5;
    unsigned char pubkey_out[65];
    unsigned char pubkey_out_length = sizeof(pubkey_out);
    memset(pubkey_out, 0x11, sizeof(pubkey_out));
    G_throws.os_perso_derive_node_bip32 = true;
    assert(
        !seed_derive_pubkey(path, path_length, pubkey_out, &pubkey_out_length));
    assert(memis(pubkey_out, 0x11, 65));
}

void test_seed_derive_pubkey_cx_ecdsa_init_private_key_throws() {
    printf("Testing seed_derive_pubkey() when cx_ecdsa_init_private_key "
           "throws...\n");
    setup();
    unsigned int path[5] = {0};
    unsigned char path_length = 5;
    unsigned char pubkey_out[65];
    unsigned char pubkey_out_length = sizeof(pubkey_out);
    memset(pubkey_out, 0x22, sizeof(pubkey_out));
    G_throws.cx_ecdsa_init_private_key = true;
    assert(
        !seed_derive_pubkey(path, path_length, pubkey_out, &pubkey_out_length));
    assert(memis(pubkey_out, 0x22, 65));
}

void test_seed_derive_pubkey_cx_ecfp_generate_pair_throws() {
    printf(
        "Testing seed_derive_pubkey() when cx_ecfp_generate_pair throws...\n");
    setup();
    unsigned int path[5] = {0};
    unsigned char path_length = 5;
    unsigned char pubkey_out[65];
    unsigned char pubkey_out_length = sizeof(pubkey_out);
    memset(pubkey_out, 0x33, sizeof(pubkey_out));
    G_throws.cx_ecfp_generate_pair = true;
    assert(
        !seed_derive_pubkey(path, path_length, pubkey_out, &pubkey_out_length));
    assert(memis(pubkey_out, 0x33, 65));
}

void test_seed_derive_pubkey_buftoosmall() {
    printf("Testing seed_derive_pubkey() when output buffer too small...\n");
    setup();
    unsigned int path[5] = {0};
    unsigned char path_length = 5;
    unsigned char pubkey_out[65];
    unsigned char pubkey_out_length = 10; // too small
    memset(pubkey_out, 0x44, sizeof(pubkey_out));
    assert(
        !seed_derive_pubkey(path, path_length, pubkey_out, &pubkey_out_length));
    assert(memis(pubkey_out, 0x44, 65));
}

void test_seed_sign_success() {
    printf("Testing seed_sign() ok...\n");
    setup();
    unsigned int path[5] = {0};
    unsigned char path_length = 5;
    unsigned char hash32[32] = {0};
    unsigned char sig_out[80];
    unsigned char sig_out_length = sizeof(sig_out);
    memset(sig_out, 0, sizeof(sig_out));
    assert(seed_sign(path, path_length, hash32, sig_out, &sig_out_length));
    assert(sig_out_length == 72);
    assert(memis(sig_out, 0xBB, 72));
    assert(G_called.os_perso_derive_node_bip32);
    assert(G_called.cx_ecdsa_init_private_key);
    assert(G_called.cx_ecdsa_sign);
    // Argument checks
    assert(G_args.os_perso_derive_node_bip32.curve == CX_CURVE_256K1);
    assert(G_args.os_perso_derive_node_bip32.path == path);
    assert(G_args.os_perso_derive_node_bip32.path_length == path_length);
    assert(G_args.os_perso_derive_node_bip32.out != NULL);
    assert(G_args.os_perso_derive_node_bip32.chain == NULL);

    assert(G_args.cx_ecdsa_init_private_key.curve == CX_CURVE_256K1);
    assert(G_args.cx_ecdsa_init_private_key.key != NULL);
    assert(G_args.cx_ecdsa_init_private_key.key_len == 32);
    assert(G_args.cx_ecdsa_init_private_key.private_key != NULL);

    assert(G_args.cx_ecdsa_sign.private_key != NULL);
    assert(G_args.cx_ecdsa_sign.mode == (CX_RND_RFC6979 | CX_LAST));
    assert(G_args.cx_ecdsa_sign.hash_id == CX_SHA256);
    assert(G_args.cx_ecdsa_sign.hash32 == hash32);
    assert(G_args.cx_ecdsa_sign.hash_len == 32);
    assert(G_args.cx_ecdsa_sign.sig_out == sig_out);
}

void test_seed_sign_buftoosmall() {
    printf("Testing seed_sign() when output buffer too small...\n");
    setup();
    unsigned int path[5] = {0};
    unsigned char path_length = 5;
    unsigned char hash32[32] = {0};
    unsigned char sig_out[72];
    unsigned char sig_out_length = 10; // too small
    memset(sig_out, 0x44, sizeof(sig_out));
    assert(!seed_sign(path, path_length, hash32, sig_out, &sig_out_length));
    assert(memis(sig_out, 0x44, 72));
}

void test_seed_sign_os_perso_derive_node_bip32_throws() {
    printf("Testing seed_sign() when os_perso_derive_node_bip32 throws...\n");
    setup();
    unsigned int path[5] = {0};
    unsigned char path_length = 5;
    unsigned char hash32[32] = {0};
    unsigned char sig_out[72];
    unsigned char sig_out_length = sizeof(sig_out);
    memset(sig_out, 0x11, sizeof(sig_out));
    G_throws.os_perso_derive_node_bip32 = true;
    assert(!seed_sign(path, path_length, hash32, sig_out, &sig_out_length));
    assert(memis(sig_out, 0x11, 72));
}

void test_seed_sign_cx_ecdsa_init_private_key_throws() {
    printf("Testing seed_sign() when cx_ecdsa_init_private_key throws...\n");
    setup();
    unsigned int path[5] = {0};
    unsigned char path_length = 5;
    unsigned char hash32[32] = {0};
    unsigned char sig_out[72];
    unsigned char sig_out_length = sizeof(sig_out);
    memset(sig_out, 0x22, sizeof(sig_out));
    G_throws.cx_ecdsa_init_private_key = true;
    assert(!seed_sign(path, path_length, hash32, sig_out, &sig_out_length));
    assert(memis(sig_out, 0x22, 72));
}

void test_seed_sign_cx_ecdsa_sign_throws() {
    printf("Testing seed_sign() when cx_ecdsa_sign throws...\n");
    setup();
    unsigned int path[5] = {0};
    unsigned char path_length = 5;
    unsigned char hash32[32] = {0};
    unsigned char sig_out[72];
    unsigned char sig_out_length = sizeof(sig_out);
    memset(sig_out, 0x33, sizeof(sig_out));
    G_throws.cx_ecdsa_sign = true;
    assert(!seed_sign(path, path_length, hash32, sig_out, &sig_out_length));
    assert(memis(sig_out, 0x33, 72));
}

int main() {
    test_seed_available();

    test_seed_derive_pubkey_success();
    test_seed_derive_pubkey_os_perso_derive_node_bip32_throws();
    test_seed_derive_pubkey_cx_ecdsa_init_private_key_throws();
    test_seed_derive_pubkey_cx_ecfp_generate_pair_throws();
    test_seed_derive_pubkey_buftoosmall();

    test_seed_sign_success();
    test_seed_sign_buftoosmall();
    test_seed_sign_os_perso_derive_node_bip32_throws();
    test_seed_sign_cx_ecdsa_init_private_key_throws();
    test_seed_sign_cx_ecdsa_sign_throws();

    printf("All Ledger HAL seed tests passed!\n");
    return 0;
}

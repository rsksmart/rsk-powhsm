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

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "hal/endorsement.h"
#include "hal/constants.h"

// Mocks for os_endorsement_* functions

struct {
    unsigned int sign;
    unsigned int code_hash;
    unsigned int pubkey;
} G_return;

struct {
    bool sign;
    bool code_hash;
    bool pubkey;
} G_called;

unsigned int os_endorsement_key2_derive_sign_data(unsigned char *src,
                                                  unsigned int srcLength,
                                                  unsigned char *signature) {
    G_called.sign = true;
    if (src && signature && srcLength > 0) {
        memset(signature, 0xAB, G_return.sign);
        return G_return.sign;
    }
    return 0;
}

unsigned int os_endorsement_get_code_hash(unsigned char *buffer) {
    G_called.code_hash = true;
    if (buffer) {
        memset(buffer, 0xCD, G_return.code_hash);
        return G_return.code_hash;
    }
    return 0;
}

unsigned int os_endorsement_get_public_key(unsigned char index,
                                           unsigned char *buffer) {
    G_called.pubkey = true;
    if (buffer) {
        memset(buffer, 0xEF, G_return.pubkey);
        return G_return.pubkey;
    }
    return 0;
}

// Test vectors and helpers

uint8_t msg[] = "test message";
uint8_t signature[MAX_SIGNATURE_LENGTH];
uint8_t signature_length;
uint8_t code_hash[HASH_LENGTH];
uint8_t code_hash_length;
uint8_t pubkey[PUBKEY_UNCMP_LENGTH];
uint8_t pubkey_length;

void setup() {
    memset(&G_return, 0, sizeof(G_return));
    memset(&G_called, 0, sizeof(G_called));
    G_return.sign = 64;
    G_return.code_hash = 32;
    G_return.pubkey = 65;
    endorsement_init();
}

void test_init_ok() {
    printf("Testing endorsement_init succeeds...\n");
    setup();
    // Always returns true for Ledger
    assert(endorsement_init());
}

void test_sign_ok() {
    printf("Testing endorsement_sign succeeds...\n");
    setup();
    signature_length = sizeof(signature);
    assert(endorsement_sign(msg, sizeof(msg), signature, &signature_length));
    assert(G_called.sign);
    assert(signature_length == G_return.sign);
    for (int i = 0; i < signature_length; ++i) {
        assert(signature[i] == 0xAB);
    }
}

void test_sign_err_sigbuftoosmall() {
    printf("Testing endorsement_sign fails if signature buffer too small...\n");
    setup();
    signature_length = 10; // Too small
    assert(!endorsement_sign(msg, sizeof(msg), signature, &signature_length));
}

void test_get_envelope_always_null() {
    printf("Testing endorsement_get_envelope returns NULL...\n");
    setup();
    assert(endorsement_get_envelope() == NULL);
    assert(endorsement_get_envelope_length() == 0);
}

void test_get_code_hash_ok() {
    printf("Testing endorsement_get_code_hash succeeds after sign...\n");
    setup();
    signature_length = sizeof(signature);
    assert(endorsement_sign(msg, sizeof(msg), signature, &signature_length));
    code_hash_length = sizeof(code_hash);
    assert(endorsement_get_code_hash(code_hash, &code_hash_length));
    assert(G_called.code_hash);
    assert(code_hash_length == G_return.code_hash);
    unsigned char expected_code_hash[] = {
        0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
        0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
        0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD};
    assert(memcmp(code_hash, expected_code_hash, code_hash_length) == 0);
}

void test_get_code_hash_err_nosignature() {
    printf("Testing endorsement_get_code_hash fails if not signed...\n");
    setup();
    code_hash_length = sizeof(code_hash);
    assert(!endorsement_get_code_hash(code_hash, &code_hash_length));
}

void test_get_code_hash_err_buftoosmall() {
    printf("Testing endorsement_get_code_hash fails if buffer too small...\n");
    setup();
    signature_length = sizeof(signature);
    assert(endorsement_sign(msg, sizeof(msg), signature, &signature_length));
    code_hash_length = 10; // Too small
    assert(!endorsement_get_code_hash(code_hash, &code_hash_length));
}

void test_get_public_key_ok() {
    printf("Testing endorsement_get_public_key succeeds after sign...\n");
    setup();
    signature_length = sizeof(signature);
    assert(endorsement_sign(msg, sizeof(msg), signature, &signature_length));
    pubkey_length = sizeof(pubkey);
    assert(endorsement_get_public_key(pubkey, &pubkey_length));
    assert(G_called.pubkey);
    assert(pubkey_length == G_return.pubkey);
    unsigned char expected_pubkey[] = {
        0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF,
        0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF,
        0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF,
        0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF,
        0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF,
        0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF};
    assert(memcmp(pubkey, expected_pubkey, pubkey_length) == 0);
}

void test_get_public_key_err_nosignature() {
    printf("Testing endorsement_get_public_key fails if not signed...\n");
    setup();
    pubkey_length = sizeof(pubkey);
    assert(!endorsement_get_public_key(pubkey, &pubkey_length));
}

void test_get_public_key_err_buftoosmall() {
    printf("Testing endorsement_get_public_key fails if buffer too small...\n");
    setup();
    signature_length = sizeof(signature);
    assert(endorsement_sign(msg, sizeof(msg), signature, &signature_length));
    pubkey_length = 10; // Too small
    assert(!endorsement_get_public_key(pubkey, &pubkey_length));
}

int main() {
    test_init_ok();
    test_sign_ok();
    test_sign_err_sigbuftoosmall();
    test_get_envelope_always_null();
    test_get_code_hash_ok();
    test_get_code_hash_err_nosignature();
    test_get_code_hash_err_buftoosmall();
    test_get_public_key_ok();
    test_get_public_key_err_nosignature();
    test_get_public_key_err_buftoosmall();
    printf("All Ledger HAL endorsement module tests passed!\n");
    return 0;
}
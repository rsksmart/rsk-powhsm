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

#include <openenclave/common.h>
#include "mocks.h"

uint8_t msg[] = "this is a message";
uint8_t signature[MAX_SIGNATURE_LENGTH];
uint8_t signature_length;
extern uint8_t mock_evidence[];

void setup_no_init() {
    // This has the side effect of clearing the initialized state of the
    // endorsement module
    G_mock_config.result_oe_attester_initialize = false;
    endorsement_init();

    G_mock_config.result_oe_attester_initialize = true;
    G_mock_config.result_oe_attester_select_format = true;
    G_mock_config.result_oe_get_evidence = true;
    G_mock_config.oe_get_evidence_buffer_freed = false;

    signature_length = sizeof(signature);
    if (G_mock_config.oe_get_evidence_buffer != NULL) {
        free(G_mock_config.oe_get_evidence_buffer);
        G_mock_config.oe_get_evidence_buffer = NULL;
    }
    G_mock_config.oe_get_evidence_buffer_size = 0;
}

void setup() {
    setup_no_init();
    assert(endorsement_init());
}

void setup_and_sign() {
    setup();
    assert(endorsement_sign(msg, sizeof(msg), signature, &signature_length));
    assert(G_mock_config.oe_get_evidence_buffer_freed);
}

void test_endorsement_init_ok() {
    setup_no_init();
    assert(endorsement_init() == true);
}

void test_endorsement_init_err_attinit() {
    setup_no_init();
    G_mock_config.result_oe_attester_initialize = false;
    assert(endorsement_init() == false);
}

void test_endorsement_init_err_selfmt() {
    setup_no_init();
    G_mock_config.result_oe_attester_select_format = false;
    assert(endorsement_init() == false);
}

void test_signature_ok() {
    setup();

    assert(endorsement_sign(msg, sizeof(msg), signature, &signature_length));

    sgx_ecdsa256_signature_t* sig =
        &((sgx_quote_auth_data_t*)(mock_evidence + sizeof(sgx_quote_t)))
             ->signature;
    assert(!memcmp(signature, sig->r, sizeof(sig->r)));
    assert(!memcmp(signature + sizeof(sig->r), sig->s, sizeof(sig->s)));
    assert(signature_length == sizeof(sig->r) + sizeof(sig->s));

    assert(G_mock_config.oe_get_evidence_buffer_freed);
}

void test_signature_err_notinit() {
    setup_no_init();

    assert(!endorsement_sign(msg, sizeof(msg), signature, &signature_length));
}

void test_signature_err_sigbuftoosmall() {
    setup();

    signature_length = 10;
    assert(!endorsement_sign(msg, sizeof(msg), signature, &signature_length));

    assert(!G_mock_config.oe_get_evidence_buffer_freed);
}

void test_signature_err_evibuftoobig() {
    setup();

    G_mock_config.oe_get_evidence_buffer_size = 100000;
    assert(!endorsement_sign(msg, sizeof(msg), signature, &signature_length));

    assert(G_mock_config.oe_get_evidence_buffer_freed);
}

void test_signature_err_evidencebroken() {
    setup();

    G_mock_config.oe_get_evidence_buffer_size = 1000;
    assert(!endorsement_sign(msg, sizeof(msg), signature, &signature_length));

    assert(G_mock_config.oe_get_evidence_buffer_freed);
}

void test_get_envelope_ok() {
    setup_and_sign();
    assert(!memcmp(endorsement_get_envelope(),
                   mock_evidence,
                   sizeof(sgx_quote_t) - sizeof(uint32_t)));
    assert(!memcmp(endorsement_get_envelope() + sizeof(sgx_quote_t),
                   mock_evidence + sizeof(sgx_quote_t),
                   endorsement_get_envelope_length() - sizeof(sgx_quote_t) -
                       sizeof(msg)));
    assert(!memcmp(endorsement_get_envelope() +
                       endorsement_get_envelope_length() - sizeof(msg),
                   msg,
                   sizeof(msg)));
}

void test_get_envelope_nosignature() {
    setup();
    assert(endorsement_get_envelope() == NULL);
    assert(endorsement_get_envelope_length() == 0);
}

void test_get_code_hash_ok() {
    setup_and_sign();

    uint8_t expected_code_hash[] = {
        0xd3, 0x26, 0x88, 0xd3, 0xc1, 0xf3, 0xdf, 0xcc, 0x8b, 0x0b, 0x36,
        0xea, 0xc7, 0xc8, 0x9d, 0x49, 0xaf, 0x33, 0x18, 0x00, 0xbd, 0x56,
        0x24, 0x80, 0x44, 0x16, 0x6f, 0xa6, 0x69, 0x94, 0x42, 0xc1};

    uint8_t code_hash[sizeof(expected_code_hash) + 10];
    uint8_t code_hash_length = sizeof(code_hash);

    assert(endorsement_get_code_hash(code_hash, &code_hash_length));
    assert(code_hash_length == sizeof(expected_code_hash));
    assert(!memcmp(code_hash, expected_code_hash, sizeof(expected_code_hash)));
}

void test_get_code_hash_err_nullbuf() {
    setup_and_sign();

    uint8_t* code_hash = NULL;
    uint8_t code_hash_length = 100;

    assert(!endorsement_get_code_hash(code_hash, &code_hash_length));
    assert(code_hash_length == 100);
}

void test_get_code_hash_err_nosignature() {
    setup();

    uint8_t code_hash[123];
    uint8_t code_hash_length = sizeof(code_hash);

    assert(!endorsement_get_code_hash(code_hash, &code_hash_length));
    assert(code_hash_length == sizeof(code_hash));
}

void test_get_code_hash_err_buftoosmall() {
    setup_and_sign();

    uint8_t code_hash[10];
    uint8_t code_hash_length = sizeof(code_hash);

    assert(!endorsement_get_code_hash(code_hash, &code_hash_length));
    assert(code_hash_length == sizeof(code_hash));
}

void test_get_public_key_ok() {
    setup_and_sign();

    uint8_t expected_public_key[] = {
        0x04, 0xa0, 0x24, 0xcb, 0x34, 0xc9, 0x0e, 0xa6, 0xa8, 0xf9, 0xf2,
        0x18, 0x1c, 0x90, 0x20, 0xcb, 0xcc, 0x7c, 0x07, 0x3e, 0x69, 0x98,
        0x17, 0x33, 0xc8, 0xde, 0xed, 0x6f, 0x6c, 0x45, 0x18, 0x22, 0xaa,
        0x08, 0x37, 0x63, 0x50, 0xff, 0x7d, 0xa0, 0x1f, 0x84, 0x2b, 0xb4,
        0x0c, 0x63, 0x1c, 0xbb, 0x71, 0x1f, 0x8b, 0x6f, 0x7a, 0x4f, 0xae,
        0x39, 0x83, 0x20, 0xa3, 0x88, 0x47, 0x74, 0xd2, 0x50, 0xad};

    uint8_t public_key[sizeof(expected_public_key) + 10];
    uint8_t public_key_length = sizeof(public_key);

    assert(endorsement_get_public_key(public_key, &public_key_length));
    assert(public_key_length == sizeof(expected_public_key));
    assert(
        !memcmp(public_key, expected_public_key, sizeof(expected_public_key)));
}

void test_get_public_key_err_nullbuf() {
    setup_and_sign();

    uint8_t* public_key = NULL;
    uint8_t public_key_length = 100;

    assert(!endorsement_get_public_key(public_key, &public_key_length));
    assert(public_key_length == 100);
}

void test_get_public_key_err_nosignature() {
    setup();

    uint8_t public_key[123];
    uint8_t public_key_length = sizeof(public_key);

    assert(!endorsement_get_public_key(public_key, &public_key_length));
    assert(public_key_length == sizeof(public_key));
}

void test_get_public_key_err_buftoosmall() {
    setup_and_sign();

    uint8_t public_key[10];
    uint8_t public_key_length = sizeof(public_key);

    assert(!endorsement_get_public_key(public_key, &public_key_length));
    assert(public_key_length == sizeof(public_key));
}

int main() {
    printf("Testing endorsement_init()...\n");
    test_endorsement_init_ok();
    test_endorsement_init_err_attinit();
    test_endorsement_init_err_selfmt();

    printf("Testing endorsement_sign()...\n");
    test_signature_ok();
    test_signature_err_notinit();
    test_signature_err_sigbuftoosmall();
    test_signature_err_evibuftoobig();
    test_signature_err_evidencebroken();

    printf("Testing endorsement_get_envelope()...\n");
    test_get_envelope_ok();
    test_get_envelope_nosignature();

    printf("Testing endorsement_get_code_hash()...\n");
    test_get_code_hash_ok();
    test_get_code_hash_err_nullbuf();
    test_get_code_hash_err_nosignature();
    test_get_code_hash_err_buftoosmall();

    printf("Testing endorsement_get_public_key()...\n");
    test_get_public_key_ok();
    test_get_public_key_err_nullbuf();
    test_get_public_key_err_nosignature();
    test_get_public_key_err_buftoosmall();
}

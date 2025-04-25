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
#include "evidence.h"

#include "mock_evidence.h"

#include <openenclave/common.h>

// Mocks
struct {
    bool der_encode_signature;
    bool evidence_supports_format;
    bool evidence_generate;
    size_t evidence_generate_bufsize;
} G_mocks;

struct {
    bool evidence_supports_format;
    bool evidence_generate;
    bool evidence_free;
} G_called;

const uint8_t mock_evidence[] = MOCK_EVIDENCE;

uint8_t der_encode_signature(uint8_t* dest,
                             size_t dest_size,
                             sgx_ecdsa256_signature_t* sig) {
    if (!G_mocks.der_encode_signature)
        return 0;

    assert(dest_size >= sizeof(sig->r) + sizeof(sig->s));
    memcpy(dest, sig->r, sizeof(sig->r));
    memcpy(dest + sizeof(sig->r), sig->s, sizeof(sig->s));
    return sizeof(sig->r) + sizeof(sig->s);
}

bool evidence_supports_format(oe_uuid_t format_id) {
    G_called.evidence_supports_format = true;

    const oe_uuid_t expected_format_id = EVIDENCE_FORMAT_SGX_ECDSA;
    assert(!memcmp(&expected_format_id, &format_id, sizeof(format_id)));

    return G_mocks.evidence_supports_format;
}

bool evidence_generate(oe_uuid_t format_id,
                       uint8_t* ccs,
                       size_t ccs_size,
                       uint8_t** evidence_buffer,
                       size_t* evidence_buffer_size) {
    G_called.evidence_generate = true;

    const oe_uuid_t expected_format_id = EVIDENCE_FORMAT_SGX_ECDSA;
    assert(!memcmp(&expected_format_id, &format_id, sizeof(format_id)));
    assert(ccs && ccs_size);
    assert(evidence_buffer && evidence_buffer_size);
    assert(!*evidence_buffer);

    if (G_mocks.evidence_generate) {
        size_t sz = G_mocks.evidence_generate_bufsize > 0
                        ? G_mocks.evidence_generate_bufsize
                        : sizeof(mock_evidence) + ccs_size;
        *evidence_buffer = malloc(sz);
        memcpy(*evidence_buffer,
               mock_evidence,
               sizeof(mock_evidence) > sz ? sz : sizeof(mock_evidence));
        memcpy(*evidence_buffer + sizeof(mock_evidence), ccs, ccs_size);
        ((sgx_quote_t*)(*evidence_buffer))->signature_len =
            sz - sizeof(sgx_quote_t) - ccs_size;
        *evidence_buffer_size = sz;
    }

    return G_mocks.evidence_generate;
}

void evidence_free(uint8_t* evidence_buffer) {
    // Should never be called with a NULL pointer
    G_called.evidence_free = true;
    assert(evidence_buffer != NULL);
}

// Unit tests

uint8_t msg[] = "this is a message";
uint8_t signature[MAX_SIGNATURE_LENGTH];
uint8_t signature_length;

void setup() {
    // This has the side effect of clearing the initialized state of the
    // endorsement module
    endorsement_finalise();

    explicit_bzero(&G_mocks, sizeof(G_mocks));
    explicit_bzero(&G_called, sizeof(G_called));
}

void setup_nosign() {
    setup();

    G_mocks.evidence_supports_format = true;
    G_mocks.evidence_generate = true;
    G_mocks.der_encode_signature = true;

    endorsement_init();
}

void setup_and_sign() {
    setup_nosign();

    signature_length = sizeof(signature);
    assert(endorsement_sign(msg, sizeof(msg), signature, &signature_length));
}

void test_init_ok() {
    printf("Testing endorsement_init succeeds...\n");
    setup();

    G_mocks.evidence_supports_format = true;

    assert(endorsement_init());
    assert(G_called.evidence_supports_format);
}

void test_init_err_fmtunsupported() {
    printf("Testing endorsement_init fails when format is unsupported...\n");
    setup();

    G_mocks.evidence_supports_format = false;

    assert(!endorsement_init());
    assert(G_called.evidence_supports_format);
}

void test_sign_ok() {
    printf("Testing endorsement_sign succeeds...\n");
    setup();

    G_mocks.evidence_supports_format = true;
    G_mocks.evidence_generate = true;
    G_mocks.der_encode_signature = true;
    endorsement_init();

    signature_length = sizeof(signature);
    assert(endorsement_sign(msg, sizeof(msg), signature, &signature_length));

    sgx_ecdsa256_signature_t* sig =
        &((sgx_quote_auth_data_t*)(mock_evidence + sizeof(sgx_quote_t)))
             ->signature;
    assert(!memcmp(signature, sig->r, sizeof(sig->r)));
    assert(!memcmp(signature + sizeof(sig->r), sig->s, sizeof(sig->s)));
    assert(signature_length == sizeof(sig->r) + sizeof(sig->s));

    assert(!G_called.evidence_free);
}

void test_sign_err_notinit() {
    printf("Testing endorsement_sign fails when module not initialised...\n");
    setup();

    G_mocks.evidence_supports_format = true;
    G_mocks.evidence_generate = true;
    G_mocks.der_encode_signature = true;

    signature_length = sizeof(signature);
    assert(!endorsement_sign(msg, sizeof(msg), signature, &signature_length));
}

void test_sign_err_sigbuftoosmall() {
    printf("Testing endorsement_sign fails when signature buffer is too "
           "small...\n");
    setup();

    G_mocks.evidence_supports_format = true;
    G_mocks.evidence_generate = true;
    G_mocks.der_encode_signature = true;
    endorsement_init();

    signature_length = sizeof(signature) - 1;
    assert(!endorsement_sign(msg, sizeof(msg), signature, &signature_length));
}

void test_sign_err_evigenerate() {
    printf(
        "Testing endorsement_sign fails when evidence generation fails...\n");
    setup();

    G_mocks.evidence_supports_format = true;
    G_mocks.evidence_generate = false;
    G_mocks.der_encode_signature = true;
    endorsement_init();

    signature_length = sizeof(signature);
    assert(!endorsement_sign(msg, sizeof(msg), signature, &signature_length));
}

void test_sign_err_evidencebroken() {
    printf("Testing endorsement_sign fails when evidence is broken...\n");
    setup();

    G_mocks.evidence_supports_format = true;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_generate_bufsize = 100;
    G_mocks.der_encode_signature = true;
    endorsement_init();

    signature_length = sizeof(signature);
    assert(!endorsement_sign(msg, sizeof(msg), signature, &signature_length));
}

void test_sign_err_evidencetoolarge() {
    printf("Testing endorsement_sign fails when evidence is too large...\n");
    setup();

    G_mocks.evidence_supports_format = true;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_generate_bufsize = 10000;
    G_mocks.der_encode_signature = true;
    endorsement_init();

    signature_length = sizeof(signature);
    assert(!endorsement_sign(msg, sizeof(msg), signature, &signature_length));
}

void test_sign_err_sigencoding() {
    printf("Testing endorsement_sign fails when signature encoding fails...\n");
    setup();

    G_mocks.evidence_supports_format = true;
    G_mocks.evidence_generate = true;
    G_mocks.der_encode_signature = false;
    endorsement_init();

    signature_length = sizeof(signature);
    assert(!endorsement_sign(msg, sizeof(msg), signature, &signature_length));
}

void test_get_envelope_ok() {
    printf("Testing endorsement_get_envelope succeeds...\n");
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

void test_get_envelope_noinit() {
    printf("Testing endorsement_get_envelope when module hasn't been "
           "initialised...\n");
    setup();

    assert(endorsement_get_envelope() == NULL);
    assert(endorsement_get_envelope_length() == 0);
}

void test_get_envelope_nosignature() {
    printf("Testing endorsement_get_envelope when no signature present...\n");
    setup_nosign();

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
    setup_nosign();

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
    setup_nosign();

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
    test_init_ok();
    test_init_err_fmtunsupported();

    test_sign_ok();
    test_sign_err_notinit();
    test_sign_err_sigbuftoosmall();
    test_sign_err_evigenerate();
    test_sign_err_evidencebroken();
    test_sign_err_evidencetoolarge();
    test_sign_err_sigencoding();

    test_get_envelope_ok();
    test_get_envelope_noinit();
    test_get_envelope_nosignature();

    test_get_code_hash_ok();
    test_get_code_hash_err_nullbuf();
    test_get_code_hash_err_nosignature();
    test_get_code_hash_err_buftoosmall();

    test_get_public_key_ok();
    test_get_public_key_err_nullbuf();
    test_get_public_key_err_nosignature();
    test_get_public_key_err_buftoosmall();
}

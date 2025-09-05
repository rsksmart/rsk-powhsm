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

#include "evidence.h"

#include <openenclave/common.h>

// Mocks
struct {
    oe_result_t oe_attester_initialize;
    oe_result_t oe_verifier_initialize;
    oe_result_t oe_attester_select_format;
    oe_result_t oe_verifier_get_format_settings;
    oe_result_t oe_get_evidence;
    bool oe_get_evidence_custom_settings;
    oe_result_t oe_verify_evidence;
    oe_result_t oe_free_claims;
    oe_result_t oe_verifier_free_format_settings;
} G_mocks;

struct {
    bool oe_attester_initialize;
    bool oe_verifier_initialize;
    bool oe_attester_shutdown;
    bool oe_verifier_shutdown;
    bool oe_free_evidence;
    bool oe_verifier_get_format_settings;
    bool oe_free_claims;
    bool oe_verifier_free_format_settings;
} G_called;

oe_result_t oe_attester_initialize(void) {
    G_called.oe_attester_initialize = true;
    return G_mocks.oe_attester_initialize;
}

oe_result_t oe_verifier_initialize(void) {
    G_called.oe_verifier_initialize = true;
    return G_mocks.oe_verifier_initialize;
}

oe_result_t oe_attester_shutdown(void) {
    G_called.oe_attester_shutdown = true;
    return OE_OK;
}

oe_result_t oe_verifier_shutdown(void) {
    G_called.oe_verifier_shutdown = true;
    return OE_OK;
}

oe_result_t oe_free_claims(oe_claim_t* claims, size_t claims_length) {
    assert(claims);
    G_called.oe_free_claims = true;
    return G_mocks.oe_free_claims;
}

oe_result_t oe_verifier_free_format_settings(uint8_t* settings) {
    assert(settings);
    G_called.oe_verifier_free_format_settings = true;
    return G_mocks.oe_verifier_free_format_settings;
}

#define TEST_FORMAT_ID \
    { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF }
#define TEST_FORMAT_SETTINGS                                              \
    {                                                                     \
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, \
            0xBB, 0xCC, 0xDD, 0xEE, 0xFF                                  \
    }
#define CUSTOM_FORMAT_SETTINGS \
    { 0x01, 0x02, 0x03, 0x04, 0x05 }

#define TEST_EVIDENCE_HEADER "<evidence-header>"
#define TEST_EVIDENCE_HEADER_SIZE strlen(TEST_EVIDENCE_HEADER)

// clang-format off
const uint8_t MOCK_EVIDENCE_LOCAL_P1[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // cpusvn
    0x00, 0x11, 0x22, 0x33, // miscselect
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, // reserved1
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // isvextprodid
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // attributes
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, // mrenclave
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, // reserved2
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, // mrsigner
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, // reserved3
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd, // configid
    0x00, 0x01, // isvprodid
    0x00, 0x01, // isvsvn
    0x00, 0x01, // configsvn
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, // reserved4
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // isvfamilyid
};

const uint8_t MOCK_EVIDENCE_LOCAL_P2[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, // report data right
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, // keyid
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // mac
};

const uint8_t MOCK_EVIDENCE_REMOTE_P1[] = {
    0xaa, 0xbb, // version
    0xaa, 0xbb, // sign_type;
    0xaa, 0xbb, 0xcc, 0xdd, // tee_type
    0xaa, 0xbb, // qe_svn
    0xaa, 0xbb, // pce_svn
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // uuid
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, // user_data
};
// clang-format on

#define MOCK_EVIDENCE_REMOTE_P2 MOCK_EVIDENCE_LOCAL_P1

void mock_evidence_local(uint8_t** evidence,
                         size_t* evidence_size,
                         uint8_t* report_data_left,
                         uint8_t* custom_claims,
                         size_t custom_claims_size) {
    *evidence_size = sizeof(MOCK_EVIDENCE_LOCAL_P1) + 32 /*report_data_left*/ +
                     sizeof(MOCK_EVIDENCE_LOCAL_P2) + custom_claims_size;
    uint8_t* result = malloc(*evidence_size);
    size_t offset = 0;
    memcpy(result + offset,
           MOCK_EVIDENCE_LOCAL_P1,
           sizeof(MOCK_EVIDENCE_LOCAL_P1));
    offset += sizeof(MOCK_EVIDENCE_LOCAL_P1);
    memcpy(result + offset, report_data_left, 32);
    offset += 32;
    memcpy(result + offset,
           MOCK_EVIDENCE_LOCAL_P2,
           sizeof(MOCK_EVIDENCE_LOCAL_P2));
    offset += sizeof(MOCK_EVIDENCE_LOCAL_P2);
    if (custom_claims) {
        memcpy(result + offset, custom_claims, custom_claims_size);
        offset += custom_claims_size;
    }
    *evidence = result;
}

void mock_evidence_remote(uint8_t** evidence,
                          size_t* evidence_size,
                          uint8_t* report_data_left,
                          uint8_t* custom_claims,
                          size_t custom_claims_size) {
    const uint8_t signature[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    const uint8_t report_data_right[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    };
    *evidence_size = sizeof(MOCK_EVIDENCE_REMOTE_P1) +
                     sizeof(MOCK_EVIDENCE_REMOTE_P2) + 64 /*report_data*/ +
                     sizeof(uint32_t) + sizeof(signature) + custom_claims_size;
    uint8_t* result = malloc(*evidence_size);
    size_t offset = 0;
    memcpy(result + offset,
           MOCK_EVIDENCE_REMOTE_P1,
           sizeof(MOCK_EVIDENCE_REMOTE_P1));
    offset += sizeof(MOCK_EVIDENCE_REMOTE_P1);
    memcpy(result + offset,
           MOCK_EVIDENCE_REMOTE_P2,
           sizeof(MOCK_EVIDENCE_REMOTE_P2));
    offset += sizeof(MOCK_EVIDENCE_REMOTE_P2);
    memcpy(result + offset, report_data_left, 32);
    offset += 32;
    memcpy(result + offset, report_data_right, sizeof(report_data_right));
    offset += sizeof(report_data_right);
    uint32_t sigsize = sizeof(signature);
    memcpy(result + offset, &sigsize, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    memcpy(result + offset, signature, sizeof(signature));
    offset += sizeof(signature);
    if (custom_claims) {
        memcpy(result + offset, custom_claims, custom_claims_size);
        offset += custom_claims_size;
    }
    *evidence = result;
}

oe_result_t oe_attester_select_format(const oe_uuid_t* format_ids,
                                      size_t format_ids_length,
                                      oe_uuid_t* selected_format_id) {

    const uint8_t expected_format_id[] = TEST_FORMAT_ID;
    const oe_uuid_t assigned_format_id = {.b = TEST_FORMAT_ID};

    assert(format_ids_length == 1);
    assert(!memcmp(
        format_ids[0].b, expected_format_id, sizeof(expected_format_id)));
    *selected_format_id = assigned_format_id;

    return G_mocks.oe_attester_select_format;
}

oe_result_t oe_verifier_get_format_settings(const oe_uuid_t* format_id,
                                            uint8_t** settings,
                                            size_t* settings_size) {
    G_called.oe_verifier_get_format_settings = true;
    const uint8_t expected_format_id[] = TEST_FORMAT_ID;
    const uint8_t mock_format_settings[] = TEST_FORMAT_SETTINGS;

    assert(
        !memcmp(format_id->b, expected_format_id, sizeof(expected_format_id)));
    assert(settings_size != NULL);
    *settings = malloc(sizeof(mock_format_settings));
    memcpy(*settings, mock_format_settings, sizeof(mock_format_settings));
    *settings_size = sizeof(mock_format_settings);

    return G_mocks.oe_verifier_get_format_settings;
}

oe_result_t oe_get_evidence(const oe_uuid_t* format_id,
                            uint32_t flags,
                            const void* custom_claims_buffer,
                            size_t custom_claims_buffer_size,
                            const void* optional_parameters,
                            size_t optional_parameters_size,
                            uint8_t** evidence_buffer,
                            size_t* evidence_buffer_size,
                            uint8_t** endorsements_buffer,
                            size_t* endorsements_buffer_size) {
    if (G_mocks.oe_get_evidence != OE_OK)
        return G_mocks.oe_get_evidence;

    const uint8_t expected_format_id[] = TEST_FORMAT_ID;
    const uint8_t mock_format_settings[] = TEST_FORMAT_SETTINGS;
    const uint8_t custom_format_settings[] = CUSTOM_FORMAT_SETTINGS;

    assert(flags == 0);
    assert(
        !memcmp(format_id->b, expected_format_id, sizeof(expected_format_id)));
    assert(custom_claims_buffer);
    assert(custom_claims_buffer_size > 0);
    if (G_mocks.oe_get_evidence_custom_settings) {
        assert(!memcmp(optional_parameters,
                       custom_format_settings,
                       sizeof(custom_format_settings)));
        assert(optional_parameters_size == sizeof(custom_format_settings));
    } else {
        assert(!memcmp(optional_parameters,
                       mock_format_settings,
                       sizeof(mock_format_settings)));
        assert(optional_parameters_size == sizeof(mock_format_settings));
    }
    assert(evidence_buffer != NULL);
    assert(evidence_buffer_size != NULL);
    assert(endorsements_buffer == NULL);
    assert(endorsements_buffer_size == NULL);

    // Mock evidence
    size_t sz = TEST_EVIDENCE_HEADER_SIZE + custom_claims_buffer_size;
    *evidence_buffer = malloc(sz);
    memcpy(*evidence_buffer, TEST_EVIDENCE_HEADER, TEST_EVIDENCE_HEADER_SIZE);
    memcpy(*evidence_buffer + TEST_EVIDENCE_HEADER_SIZE,
           custom_claims_buffer,
           custom_claims_buffer_size);
    *evidence_buffer_size = sz;

    return OE_OK;
}

oe_result_t oe_verify_evidence(const oe_uuid_t* format_id,
                               const uint8_t* evidence_buffer,
                               size_t evidence_buffer_size,
                               const uint8_t* endorsements_buffer,
                               size_t endorsements_buffer_size,
                               const oe_policy_t* policies,
                               size_t policies_size,
                               oe_claim_t** claims,
                               size_t* claims_length) {
    if (G_mocks.oe_verify_evidence != OE_OK)
        return G_mocks.oe_verify_evidence;

    const oe_uuid_t* expected_format_id_ecdsa = &EVIDENCE_FORMAT_SGX_ECDSA;
    const oe_uuid_t* expected_format_id_local = &EVIDENCE_FORMAT_SGX_LOCAL;

    size_t evidence_body_size;
    assert(evidence_buffer);
    if (!memcmp(format_id->b,
                expected_format_id_ecdsa->b,
                sizeof(expected_format_id_ecdsa->b))) {
        // ECDSA format
        assert(evidence_buffer_size >= sizeof(sgx_quote_t));
        sgx_quote_t* quote = (sgx_quote_t*)evidence_buffer;
        evidence_body_size = sizeof(*quote) + quote->signature_len;
        assert(!memcmp(evidence_buffer,
                       MOCK_EVIDENCE_REMOTE_P1,
                       sizeof(MOCK_EVIDENCE_REMOTE_P1)));
    } else if (!memcmp(format_id->b,
                       expected_format_id_local->b,
                       sizeof(expected_format_id_local->b))) {
        // LOCAL format
        assert(evidence_buffer_size >= sizeof(sgx_report_t));
        evidence_body_size = sizeof(sgx_report_t);
        assert(!memcmp(evidence_buffer,
                       MOCK_EVIDENCE_LOCAL_P1,
                       sizeof(MOCK_EVIDENCE_LOCAL_P1)));
    } else {
        // Invalid format
        assert(false);
    }
    assert(!endorsements_buffer && !endorsements_buffer_size);
    assert(!policies && !policies_size);
    assert(claims && claims_length);

    // Mock claims
    *claims_length = 2 + (evidence_body_size < evidence_buffer_size ? 1 : 0);
    *claims = malloc(sizeof(oe_claim_t) * *claims_length);
    (*claims)[0].name = "claim_one";
    (*claims)[0].value = (uint8_t*)"\xAA\xBB\xCC";
    (*claims)[0].value_size = 3;
    (*claims)[1].name = "claim_two";
    (*claims)[1].value = (uint8_t*)"\x11\x22\x33\x44";
    (*claims)[1].value_size = 4;
    if (*claims_length == 3) {
        (*claims)[2].name = OE_CLAIM_CUSTOM_CLAIMS_BUFFER;
        (*claims)[2].value = (uint8_t*)(evidence_buffer + evidence_body_size);
        (*claims)[2].value_size = evidence_buffer_size - evidence_body_size;
    }

    return OE_OK;
}

oe_result_t oe_free_evidence(uint8_t* evidence_buffer) {
    assert(!evidence_buffer || evidence_buffer == (uint8_t*)1234);
    G_called.oe_free_evidence = true;
    return OE_OK;
}

// Unit tests
void setup() {
    explicit_bzero(&G_mocks, sizeof(G_mocks));
    explicit_bzero(&G_called, sizeof(G_called));
    evidence_finalise(); // Side effect of clearing the context
}

void test_evidence_init_ok() {
    printf("Testing evidence_init succeeds...\n");
    setup();

    G_mocks.oe_attester_initialize = OE_OK;
    G_mocks.oe_verifier_initialize = OE_OK;
    assert(evidence_init());
    assert(G_called.oe_attester_initialize);
    assert(G_called.oe_verifier_initialize);
}

void test_evidence_init_err_attester_init() {
    printf("Testing evidence_init fails when attester init fails...\n");
    setup();

    G_mocks.oe_attester_initialize = OE_FAILURE;
    G_mocks.oe_verifier_initialize = OE_OK;
    assert(!evidence_init());
    assert(G_called.oe_attester_initialize);
    assert(!G_called.oe_verifier_initialize);
}

void test_evidence_init_err_verifier_init() {
    printf("Testing evidence_init fails when verifier init fails...\n");
    setup();

    G_mocks.oe_attester_initialize = OE_OK;
    G_mocks.oe_verifier_initialize = OE_FAILURE;
    assert(!evidence_init());
    assert(G_called.oe_attester_initialize);
    assert(G_called.oe_verifier_initialize);
}

void test_evidence_finalise() {
    printf("Testing evidence_finalise succeeds...\n");
    setup();

    evidence_finalise();
    assert(G_called.oe_attester_shutdown);
    assert(G_called.oe_verifier_shutdown);
}

void test_evidence_supports_format_ok() {
    printf("Testing evidence_supports_format succeeds...\n");
    setup();

    evidence_init();
    G_mocks.oe_attester_select_format = OE_OK;
    G_mocks.oe_verifier_get_format_settings = OE_OK;

    oe_uuid_t format_id = {.b = TEST_FORMAT_ID};
    assert(evidence_supports_format(format_id));
    assert(G_called.oe_verifier_free_format_settings);
}

void test_evidence_supports_format_err_notinit() {
    printf("Testing evidence_supports_format fails when module not "
           "initialised...\n");
    setup();

    G_mocks.oe_attester_select_format = OE_OK;
    G_mocks.oe_verifier_get_format_settings = OE_OK;

    oe_uuid_t format_id = {.b = TEST_FORMAT_ID};
    assert(!evidence_supports_format(format_id));
    assert(!G_called.oe_verifier_free_format_settings);
}

void test_evidence_supports_format_err_selectfails() {
    printf("Testing evidence_supports_format fails when attester select "
           "fails...\n");
    setup();

    evidence_init();
    G_mocks.oe_attester_select_format = OE_FAILURE;
    G_mocks.oe_verifier_get_format_settings = OE_OK;

    oe_uuid_t format_id = {.b = TEST_FORMAT_ID};
    assert(!evidence_supports_format(format_id));
    assert(G_called.oe_verifier_free_format_settings);
}

void test_evidence_supports_format_err_getsettingsfails() {
    printf("Testing evidence_supports_format fails when verifier get settings "
           "fails...\n");
    setup();

    evidence_init();
    G_mocks.oe_attester_select_format = OE_OK;
    G_mocks.oe_verifier_get_format_settings = OE_FAILURE;

    oe_uuid_t format_id = {.b = TEST_FORMAT_ID};
    assert(!evidence_supports_format(format_id));
    assert(!G_called.oe_verifier_free_format_settings);
}

void test_evidence_get_format_settings_ok() {
    printf("Testing evidence_get_format_settings succeeds...\n");
    setup();

    const uint8_t mock_format_settings[] = TEST_FORMAT_SETTINGS;

    evidence_init();
    G_mocks.oe_verifier_get_format_settings = OE_OK;

    evidence_format_t format = {
        .id = {.b = TEST_FORMAT_ID},
        .settings = NULL,
        .settings_size = 0,
    };
    assert(evidence_get_format_settings(&format));

    assert(format.settings);
    assert(sizeof(mock_format_settings) == format.settings_size);
    assert(
        !memcmp(mock_format_settings, format.settings, format.settings_size));
}

void test_evidence_get_format_settings_err_notinit() {
    printf("Testing evidence_get_format_settings fails when module not "
           "initialised...\n");
    setup();

    G_mocks.oe_verifier_get_format_settings = OE_OK;

    evidence_format_t format = {
        .id = {.b = TEST_FORMAT_ID},
        .settings = NULL,
        .settings_size = 0,
    };
    assert(!evidence_get_format_settings(&format));
}

void test_evidence_get_format_settings_invalid_args() {
    printf("Testing evidence_get_format_settings fails when invalid args are "
           "given...\n");
    setup();

    evidence_init();
    G_mocks.oe_verifier_get_format_settings = OE_OK;

    evidence_format_t format = {
        .id = {.b = TEST_FORMAT_ID},
        .settings = (uint8_t*)1234,
        .settings_size = 0,
    };
    assert(!evidence_get_format_settings(&format));

    format.settings = NULL;
    format.settings_size = 12;
    assert(!evidence_get_format_settings(&format));
}

void test_evidence_get_format_settings_get_fails() {
    printf("Testing evidence_get_format_settings fails when getting settings "
           "fails...\n");
    setup();

    evidence_init();
    G_mocks.oe_verifier_get_format_settings = OE_FAILURE;

    evidence_format_t format = {
        .id = {.b = TEST_FORMAT_ID},
        .settings = NULL,
        .settings_size = 0,
    };
    assert(!evidence_get_format_settings(&format));
}

void test_evidence_free_format_settings_ok() {
    printf("Testing evidence_free_format_settings succeeds...\n");
    setup();

    uint8_t mock_format_settings[] = TEST_FORMAT_SETTINGS;

    assert(evidence_free_format_settings(mock_format_settings));
    assert(G_called.oe_verifier_free_format_settings);
}

void test_evidence_free_format_settings_ok_wth_no_settings() {
    printf("Testing evidence_free_format_settings succeeds...\n");
    setup();

    assert(evidence_free_format_settings(NULL));
    assert(!G_called.oe_verifier_free_format_settings);
}

void test_evidence_free_format_settings_fails_if_freeing_fails() {
    printf("Testing evidence_free_format_settings fails if freeing fails...\n");
    setup();

    uint8_t mock_format_settings[] = TEST_FORMAT_SETTINGS;
    G_mocks.oe_verifier_free_format_settings = OE_FAILURE;

    assert(!evidence_free_format_settings(mock_format_settings));
    assert(G_called.oe_verifier_free_format_settings);
}

void test_evidence_generate_ok() {
    printf("Testing evidence_generate succeeds...\n");
    setup();

    evidence_init();
    G_mocks.oe_verifier_get_format_settings = OE_OK;
    G_mocks.oe_get_evidence = OE_OK;

    uint8_t* eb = NULL;
    size_t ebs = 0;

    evidence_format_t format = {
        .id = {.b = TEST_FORMAT_ID},
        .settings = NULL,
        .settings_size = 0,
    };
    assert(evidence_generate(
        &format, (uint8_t*)"some custom claims", 18, &eb, &ebs));

    assert(ebs == TEST_EVIDENCE_HEADER_SIZE + 18);
    assert(!memcmp(eb, TEST_EVIDENCE_HEADER "some custom claims", ebs));
    assert(G_called.oe_verifier_get_format_settings);
    assert(G_called.oe_verifier_free_format_settings);
    free(eb);
}

void test_evidence_generate_ok_with_custom_settings() {
    printf(
        "Testing evidence_generate succeeds with custom format settings...\n");
    setup();

    evidence_init();
    G_mocks.oe_verifier_get_format_settings = OE_OK;
    G_mocks.oe_get_evidence = OE_OK;
    G_mocks.oe_get_evidence_custom_settings = true;

    uint8_t* eb = NULL;
    size_t ebs = 0;

    uint8_t custom_format_settings[] = CUSTOM_FORMAT_SETTINGS;

    evidence_format_t format = {
        .id = {.b = TEST_FORMAT_ID},
        .settings = custom_format_settings,
        .settings_size = sizeof(custom_format_settings),
    };
    assert(evidence_generate(
        &format, (uint8_t*)"some custom claims", 18, &eb, &ebs));

    assert(ebs == TEST_EVIDENCE_HEADER_SIZE + 18);
    assert(!memcmp(eb, TEST_EVIDENCE_HEADER "some custom claims", ebs));
    assert(!G_called.oe_verifier_get_format_settings);
    assert(!G_called.oe_verifier_free_format_settings);
    free(eb);
}

void test_evidence_generate_err_notinit() {
    printf("Testing evidence_generate fails when module not initialised...\n");
    setup();

    G_mocks.oe_verifier_get_format_settings = OE_OK;
    G_mocks.oe_get_evidence = OE_OK;

    uint8_t* eb = NULL;
    size_t ebs = 0;

    evidence_format_t format = {
        .id = {.b = TEST_FORMAT_ID},
        .settings = NULL,
        .settings_size = 0,
    };
    assert(!evidence_generate(
        &format, (uint8_t*)"some custom claims", 18, &eb, &ebs));
    assert(!eb && !ebs);
    assert(!G_called.oe_verifier_get_format_settings);
    assert(!G_called.oe_verifier_free_format_settings);
}

void test_evidence_generate_err_arguments() {
    printf("Testing evidence_generate fails when given evidence buffer "
           "invalid...\n");
    setup();

    evidence_init();
    G_mocks.oe_verifier_get_format_settings = OE_OK;
    G_mocks.oe_get_evidence = OE_OK;

    uint8_t* eb = NULL;
    size_t ebs = 0;

    evidence_format_t format = {
        .id = {.b = TEST_FORMAT_ID},
        .settings = NULL,
        .settings_size = 0,
    };
    assert(!evidence_generate(
        NULL, (uint8_t*)"some custom claims", 18, &eb, &ebs));
    assert(!eb && ebs == 0);

    assert(!evidence_generate(
        &format, (uint8_t*)"some custom claims", 18, NULL, &ebs));
    assert(!eb && ebs == 0);

    assert(!evidence_generate(
        &format, (uint8_t*)"some custom claims", 18, &eb, NULL));
    assert(!eb && ebs == 0);

    assert(!G_called.oe_verifier_get_format_settings);
    assert(!G_called.oe_verifier_free_format_settings);
}

void test_evidence_generate_err_getsettingsfails() {
    printf("Testing evidence_generate fails when verifier select format "
           "fails...\n");
    setup();

    evidence_init();
    G_mocks.oe_verifier_get_format_settings = OE_FAILURE;
    G_mocks.oe_get_evidence = OE_OK;

    uint8_t* eb = NULL;
    size_t ebs = 0;

    evidence_format_t format = {
        .id = {.b = TEST_FORMAT_ID},
        .settings = NULL,
        .settings_size = 0,
    };
    assert(!evidence_generate(
        &format, (uint8_t*)"some custom claims", 18, &eb, &ebs));
    assert(!eb && !ebs);
    assert(G_called.oe_verifier_get_format_settings);
    assert(!G_called.oe_verifier_free_format_settings);
}

void test_evidence_generate_err_getevidencefails() {
    printf("Testing evidence_generate fails when get evidence fails...\n");
    setup();

    evidence_init();
    G_mocks.oe_verifier_get_format_settings = OE_OK;
    G_mocks.oe_get_evidence = OE_FAILURE;

    uint8_t* eb = NULL;
    size_t ebs = 0;

    evidence_format_t format = {
        .id = {.b = TEST_FORMAT_ID},
        .settings = NULL,
        .settings_size = 0,
    };
    assert(!evidence_generate(
        &format, (uint8_t*)"some custom claims", 18, &eb, &ebs));
    assert(!eb && !ebs);
    assert(G_called.oe_verifier_get_format_settings);
    assert(G_called.oe_verifier_free_format_settings);
}

void test_evidence_verify_and_extract_claims_local_ok() {
    printf("Testing evidence_verify_and_extract_claims with local evidence "
           "succeeds...\n");
    setup();

    evidence_init();
    G_mocks.oe_verify_evidence = OE_OK;

    oe_claim_t* cl = NULL;
    size_t cls = 0;

    uint8_t* evidence;
    size_t evidence_size;
    mock_evidence_local(
        &evidence,
        &evidence_size,
        (uint8_t*)"\x91\xe2\x7a\x29\xcb\x42\x7c\x2c\xc7\xf8\x9d\x33\xb0\xfc\x4b"
                  "\x03\x9a\xac\x90\xc9\x15\xdd\x6b\x61\x94\x1e\xd1\x5b\x91\x3a"
                  "\x02\x3d",
        (uint8_t*)"this-is-the-custom-claim",
        24);
    oe_uuid_t format_id = {.b = OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
    assert(evidence_verify_and_extract_claims(
        format_id, evidence, evidence_size, &cl, &cls));

    assert(!G_called.oe_free_claims);
    assert(cl);
    assert(cls == 3);

    assert(evidence_get_claim(cl, cls, "claim_one"));
    assert(evidence_get_claim(cl, cls, "claim_two"));
    assert(!evidence_get_claim(cl, cls, "not_there"));
    oe_claim_t* cc = evidence_get_custom_claim(cl, cls);
    assert(!memcmp(cc->value, "this-is-the-custom-claim", cc->value_size));

    free(cl);
    free(evidence);
}

void test_evidence_verify_and_extract_claims_local_ok_nocc() {
    printf("Testing evidence_verify_and_extract_claims with local evidence and "
           "no custom claims succeeds...\n");
    setup();

    evidence_init();
    G_mocks.oe_verify_evidence = OE_OK;

    oe_claim_t* cl = NULL;
    size_t cls = 0;

    uint8_t* evidence;
    size_t evidence_size;
    mock_evidence_local(&evidence,
                        &evidence_size,
                        (uint8_t*)"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4"
                                  "\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b"
                                  "\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55",
                        NULL,
                        0);
    oe_uuid_t format_id = {.b = OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
    assert(evidence_verify_and_extract_claims(
        format_id, evidence, evidence_size, &cl, &cls));

    assert(!G_called.oe_free_claims);
    assert(cl);
    assert(cls == 2);

    assert(evidence_get_claim(cl, cls, "claim_one"));
    assert(evidence_get_claim(cl, cls, "claim_two"));
    assert(!evidence_get_claim(cl, cls, "not_there"));
    assert(!evidence_get_custom_claim(cl, cls));

    free(cl);
    free(evidence);
}

void test_evidence_verify_and_extract_claims_local_cchash_differs() {
    printf("Testing evidence_verify_and_extract_claims with local evidence "
           "fails when custom claims hash not in evidence...\n");
    setup();

    evidence_init();
    G_mocks.oe_verify_evidence = OE_OK;

    oe_claim_t* cl = NULL;
    size_t cls = 0;

    uint8_t* evidence;
    size_t evidence_size;
    mock_evidence_local(
        &evidence,
        &evidence_size,
        (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                  "\xaa"
                  "\xaa\xaa",
        (uint8_t*)"this-is-the-custom-claim",
        24);
    oe_uuid_t format_id = {.b = OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
    assert(!evidence_verify_and_extract_claims(
        format_id, evidence, evidence_size, &cl, &cls));

    assert(G_called.oe_free_claims);
    assert(!cl);
    assert(!cls);
    free(evidence);
}

void test_evidence_verify_and_extract_claims_local_cchash_differs_nocc() {
    printf(
        "Testing evidence_verify_and_extract_claims with local evidence fails "
        "when custom claims hash not in evidence and no custom claims...\n");
    setup();

    evidence_init();
    G_mocks.oe_verify_evidence = OE_OK;

    oe_claim_t* cl = NULL;
    size_t cls = 0;

    uint8_t* evidence;
    size_t evidence_size;
    mock_evidence_local(
        &evidence,
        &evidence_size,
        (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                  "\xaa"
                  "\xaa\xaa",
        NULL,
        0);
    oe_uuid_t format_id = {.b = OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
    assert(!evidence_verify_and_extract_claims(
        format_id, evidence, evidence_size, &cl, &cls));

    assert(G_called.oe_free_claims);
    assert(!cl);
    assert(!cls);
    free(evidence);
}

void test_evidence_verify_and_extract_claims_remote_ok() {
    printf("Testing evidence_verify_and_extract_claims with remote evidence "
           "succeeds...\n");
    setup();

    evidence_init();
    G_mocks.oe_verify_evidence = OE_OK;

    oe_claim_t* cl = NULL;
    size_t cls = 0;

    uint8_t* evidence;
    size_t evidence_size;
    mock_evidence_remote(
        &evidence,
        &evidence_size,
        (uint8_t*)"\x91\xe2\x7a\x29\xcb\x42\x7c\x2c\xc7\xf8\x9d\x33\xb0\xfc\x4b"
                  "\x03\x9a\xac\x90\xc9\x15\xdd\x6b\x61\x94\x1e\xd1\x5b\x91\x3a"
                  "\x02\x3d",
        (uint8_t*)"this-is-the-custom-claim",
        24);
    oe_uuid_t format_id = {.b = OE_FORMAT_UUID_SGX_ECDSA};
    assert(evidence_verify_and_extract_claims(
        format_id, evidence, evidence_size, &cl, &cls));

    assert(!G_called.oe_free_claims);
    assert(cl);
    assert(cls == 3);

    assert(evidence_get_claim(cl, cls, "claim_one"));
    assert(evidence_get_claim(cl, cls, "claim_two"));
    assert(!evidence_get_claim(cl, cls, "not_there"));
    oe_claim_t* cc = evidence_get_custom_claim(cl, cls);
    assert(!memcmp(cc->value, "this-is-the-custom-claim", cc->value_size));

    free(cl);
    free(evidence);
}

void test_evidence_verify_and_extract_claims_remote_ok_nocc() {
    printf("Testing evidence_verify_and_extract_claims with remote evidence "
           "and no custom claims succeeds...\n");
    setup();

    evidence_init();
    G_mocks.oe_verify_evidence = OE_OK;

    oe_claim_t* cl = NULL;
    size_t cls = 0;

    uint8_t* evidence;
    size_t evidence_size;
    mock_evidence_remote(
        &evidence,
        &evidence_size,
        (uint8_t*)"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4"
                  "\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b"
                  "\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55",
        NULL,
        0);
    oe_uuid_t format_id = {.b = OE_FORMAT_UUID_SGX_ECDSA};
    assert(evidence_verify_and_extract_claims(
        format_id, evidence, evidence_size, &cl, &cls));

    assert(!G_called.oe_free_claims);
    assert(cl);
    assert(cls == 2);

    assert(evidence_get_claim(cl, cls, "claim_one"));
    assert(evidence_get_claim(cl, cls, "claim_two"));
    assert(!evidence_get_claim(cl, cls, "not_there"));
    assert(!evidence_get_custom_claim(cl, cls));

    free(cl);
    free(evidence);
}

void test_evidence_verify_and_extract_claims_remote_cchash_differs() {
    printf("Testing evidence_verify_and_extract_claims with remote evidence "
           "fails when custom claims hash not in evidence...\n");
    setup();

    evidence_init();
    G_mocks.oe_verify_evidence = OE_OK;

    oe_claim_t* cl = NULL;
    size_t cls = 0;

    uint8_t* evidence;
    size_t evidence_size;
    mock_evidence_remote(
        &evidence,
        &evidence_size,
        (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                  "\xaa"
                  "\xaa\xaa",
        (uint8_t*)"this-is-the-custom-claim",
        24);
    oe_uuid_t format_id = {.b = OE_FORMAT_UUID_SGX_ECDSA};
    assert(!evidence_verify_and_extract_claims(
        format_id, evidence, evidence_size, &cl, &cls));

    assert(G_called.oe_free_claims);
    assert(!cl);
    assert(!cls);
    free(evidence);
}

void test_evidence_verify_and_extract_claims_remote_cchash_differs_nocc() {
    printf(
        "Testing evidence_verify_and_extract_claims with remote evidence fails "
        "when custom claims hash not in evidence and no custom claims...\n");
    setup();

    evidence_init();
    G_mocks.oe_verify_evidence = OE_OK;

    oe_claim_t* cl = NULL;
    size_t cls = 0;

    uint8_t* evidence;
    size_t evidence_size;
    mock_evidence_remote(
        &evidence,
        &evidence_size,
        (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                  "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                  "\xaa"
                  "\xaa\xaa",
        NULL,
        0);
    oe_uuid_t format_id = {.b = OE_FORMAT_UUID_SGX_ECDSA};
    assert(!evidence_verify_and_extract_claims(
        format_id, evidence, evidence_size, &cl, &cls));

    assert(G_called.oe_free_claims);
    assert(!cl);
    assert(!cls);
    free(evidence);
}

void test_evidence_verify_and_extract_claims_err_notinit() {
    printf("Testing evidence_verify_and_extract_claims fails when module not "
           "initialised...\n");
    setup();

    G_mocks.oe_verify_evidence = OE_OK;

    oe_claim_t* cl = NULL;
    size_t cls = 0;

    oe_uuid_t format_id = {.b = TEST_FORMAT_ID};
    assert(!evidence_verify_and_extract_claims(
        format_id, (uint8_t*)"<evidence-header>this is custom", 31, &cl, &cls));

    assert(!cl && !cls);
}

void test_evidence_verify_and_extract_claims_err_verification() {
    printf("Testing evidence_verify_and_extract_claims fails when verification "
           "fails...\n");
    setup();

    evidence_init();
    G_mocks.oe_verify_evidence = OE_FAILURE;

    oe_claim_t* cl = NULL;
    size_t cls = 0;

    oe_uuid_t format_id = {.b = TEST_FORMAT_ID};
    assert(!evidence_verify_and_extract_claims(
        format_id, (uint8_t*)"<evidence-header>this is custom", 31, &cl, &cls));

    assert(!cl && !cls);
}

void test_evidence_free_claims_ok() {
    printf("Testing evidence_free_claims succeeds...\n");
    setup();
    uint8_t claims[] = {11, 22};
    size_t claims_length = sizeof(claims);
    assert(evidence_free_claims((oe_claim_t*)claims, claims_length));
    assert(G_called.oe_free_claims);
}

void test_evidence_free_claims_ok_with_no_claims() {
    printf("Testing evidence_free_claims succeeds with no claims...\n");
    setup();
    uint8_t claims[] = {11, 22};
    size_t claims_length = sizeof(claims);
    assert(evidence_free_claims(NULL, claims_length));
    assert(evidence_free_claims(NULL, 0));
    assert(!G_called.oe_free_claims);
    assert(evidence_free_claims((oe_claim_t*)claims, 0));
    assert(G_called.oe_free_claims);
}

void test_evidence_free_claims_fails_when_freeing_fails() {
    printf("Testing evidence_free_claims fails when freeing fails...\n");
    setup();
    uint8_t claims[] = {11, 22};
    size_t claims_length = sizeof(claims);
    G_mocks.oe_free_claims = OE_FAILURE;
    assert(!evidence_free_claims((oe_claim_t*)claims, claims_length));
    assert(G_called.oe_free_claims);
}

void test_evidence_get_claim_ok() {
    printf("Testing evidence_get_claim succeeds...\n");

    char value[] = "a-custom-claim-value";
    char value2[] = "another-value";
    oe_claim_t claims[] = {{
                               .name = "a-custom-claim-name",
                               .value = (uint8_t*)value,
                               .value_size = strlen(value),
                           },
                           {
                               .name = "another-claim",
                               .value = (uint8_t*)value2,
                               .value_size = strlen(value2),
                           }};

    oe_claim_t* found = evidence_get_claim(
        claims, sizeof(claims) / sizeof(claims[0]), "a-custom-claim-name");
    assert(found);
    assert(!memcmp(
        found->name, "a-custom-claim-name", strlen("a-custom-claim-name")));
    assert(strlen("a-custom-claim-value") == found->value_size);
    assert(!memcmp(found->value, "a-custom-claim-value", found->value_size));

    found = evidence_get_claim(
        claims, sizeof(claims) / sizeof(claims[0]), "another-claim");
    assert(found);
    assert(!memcmp(found->name, "another-claim", strlen("another-claim")));
    assert(strlen("another-value") == found->value_size);
    assert(!memcmp(found->value, "another-value", found->value_size));

    found = evidence_get_claim(
        claims, sizeof(claims) / sizeof(claims[0]), "inexistent-claim");
    assert(!found);
}

void test_evidence_get_claim_behaves_ok_with_invalid_params() {
    printf("Testing evidence_get_claim behaves correctly with invalid "
           "parameters...\n");
    setup();

    assert(!evidence_get_claim(NULL, 123, "a-custom-claim-name"));
    assert(!evidence_get_claim(
        (oe_claim_t*)"valid-pointer", 0, "a-custom-claim-name"));
    assert(!evidence_get_claim((oe_claim_t*)"valid-pointer", 13, NULL));
}

void test_evidence_get_custom_claim_ok() {
    printf("Testing evidence_get_custom_claim succeeds...\n");

    oe_claim_t claim1 = {
        .name = "claim1_name",
        .value = (uint8_t*)"claim1_value",
        .value_size = strlen("claim1_value"),
    };
    oe_claim_t claim2 = {
        .name = "claim2_name",
        .value = (uint8_t*)"claim2_value",
        .value_size = strlen("claim2_value"),
    };
    oe_claim_t custom_claims = {
        .name = "custom_claims_buffer",
        .value = (uint8_t*)"the custom claim buffer",
        .value_size = strlen("the custom claim buffer"),
    };

    oe_claim_t claims[] = {claim1, custom_claims, claim2};
    oe_claim_t claims_nocustom[] = {claim1, claim2};

    oe_claim_t* found =
        evidence_get_custom_claim(claims, sizeof(claims) / sizeof(claims[0]));
    assert(found);
    assert(!memcmp(
        found->name, "custom_claims_buffer", strlen("custom_claims_buffer")));
    assert(strlen("the custom claim buffer") == found->value_size);
    assert(!memcmp(found->value, "the custom claim buffer", found->value_size));

    assert(!evidence_get_custom_claim(
        claims_nocustom, sizeof(claims_nocustom) / sizeof(claims_nocustom[0])));
}

void test_evidence_get_custom_claim_behaves_ok_with_invalid_params() {
    printf("Testing evidence_get_custom_claim behaves correctly with invalid "
           "parameters...\n");
    setup();

    assert(!evidence_get_custom_claim(NULL, 123));
    assert(!evidence_get_custom_claim((oe_claim_t*)"valid-pointer", 0));
}

void test_evidence_free() {
    printf("Testing evidence_free...\n");
    setup();

    evidence_free(NULL);
    assert(!G_called.oe_free_evidence);
    evidence_free((uint8_t*)1234);
    assert(G_called.oe_free_evidence);
}

int main() {
    test_evidence_init_ok();
    test_evidence_init_err_attester_init();

    test_evidence_finalise();

    test_evidence_supports_format_ok();
    test_evidence_supports_format_err_notinit();
    test_evidence_supports_format_err_selectfails();
    test_evidence_supports_format_err_getsettingsfails();

    test_evidence_get_format_settings_ok();
    test_evidence_get_format_settings_err_notinit();
    test_evidence_get_format_settings_invalid_args();
    test_evidence_get_format_settings_get_fails();

    test_evidence_free_format_settings_ok();
    test_evidence_free_format_settings_ok_wth_no_settings();
    test_evidence_free_format_settings_fails_if_freeing_fails();

    test_evidence_generate_ok();
    test_evidence_generate_ok_with_custom_settings();
    test_evidence_generate_err_notinit();
    test_evidence_generate_err_arguments();
    test_evidence_generate_err_getsettingsfails();
    test_evidence_generate_err_getevidencefails();

    test_evidence_verify_and_extract_claims_local_ok();
    test_evidence_verify_and_extract_claims_local_ok_nocc();
    test_evidence_verify_and_extract_claims_local_cchash_differs();
    test_evidence_verify_and_extract_claims_local_cchash_differs_nocc();

    test_evidence_verify_and_extract_claims_remote_ok();
    test_evidence_verify_and_extract_claims_remote_ok_nocc();
    test_evidence_verify_and_extract_claims_remote_cchash_differs();
    test_evidence_verify_and_extract_claims_remote_cchash_differs_nocc();

    test_evidence_verify_and_extract_claims_err_notinit();
    test_evidence_verify_and_extract_claims_err_verification();

    test_evidence_free_claims_ok();
    test_evidence_free_claims_ok_with_no_claims();
    test_evidence_free_claims_fails_when_freeing_fails();

    test_evidence_get_claim_ok();
    test_evidence_get_claim_behaves_ok_with_invalid_params();

    test_evidence_get_custom_claim_ok();
    test_evidence_get_custom_claim_behaves_ok_with_invalid_params();

    test_evidence_free();
}

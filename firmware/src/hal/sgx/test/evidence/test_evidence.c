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
    oe_result_t oe_verify_evidence;
} G_mocks;

struct {
    bool oe_attester_initialize;
    bool oe_verifier_initialize;
    bool oe_attester_shutdown;
    bool oe_verifier_shutdown;
    bool oe_free_evidence;
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

#define TEST_FORMAT_ID \
    { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF }
#define TEST_FORMAT_SETTINGS                                              \
    {                                                                     \
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, \
            0xBB, 0xCC, 0xDD, 0xEE, 0xFF                                  \
    }
#define TEST_EVIDENCE_HEADER "<evidence-header>"
#define TEST_EVIDENCE_HEADER_SIZE strlen(TEST_EVIDENCE_HEADER)

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

    assert(flags == 0);
    assert(
        !memcmp(format_id->b, expected_format_id, sizeof(expected_format_id)));
    assert(custom_claims_buffer);
    assert(custom_claims_buffer_size > 0);
    assert(!memcmp(optional_parameters,
                   mock_format_settings,
                   sizeof(mock_format_settings)));
    assert(optional_parameters_size == sizeof(mock_format_settings));
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

    const uint8_t expected_format_id[] = TEST_FORMAT_ID;

    assert(
        !memcmp(format_id->b, expected_format_id, sizeof(expected_format_id)));
    assert(evidence_buffer);
    assert(evidence_buffer_size > TEST_EVIDENCE_HEADER_SIZE);
    assert(!memcmp(
        TEST_EVIDENCE_HEADER, evidence_buffer, TEST_EVIDENCE_HEADER_SIZE));
    assert(!endorsements_buffer && !endorsements_buffer_size);
    assert(!policies && !policies_size);
    assert(claims && claims_length);

    // Mock claims
    *claims_length = evidence_buffer_size - TEST_EVIDENCE_HEADER_SIZE;
    *claims = malloc(*claims_length);
    memcpy(
        *claims, evidence_buffer + TEST_EVIDENCE_HEADER_SIZE, *claims_length);

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
}

void test_evidence_supports_format_err_notinit() {
    printf("Testing evidence_supports_format fails when module not "
           "initialised...\n");
    setup();

    G_mocks.oe_attester_select_format = OE_OK;
    G_mocks.oe_verifier_get_format_settings = OE_OK;

    oe_uuid_t format_id = {.b = TEST_FORMAT_ID};
    assert(!evidence_supports_format(format_id));
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
}

void test_evidence_generate_ok() {
    printf("Testing evidence_generate succeeds...\n");
    setup();

    evidence_init();
    G_mocks.oe_attester_select_format = OE_OK;
    G_mocks.oe_verifier_get_format_settings = OE_OK;
    G_mocks.oe_get_evidence = OE_OK;

    uint8_t* eb = NULL;
    size_t ebs = 0;

    oe_uuid_t format_id = {.b = TEST_FORMAT_ID};
    assert(evidence_generate(
        format_id, (uint8_t*)"some custom claims", 18, &eb, &ebs));

    assert(ebs == TEST_EVIDENCE_HEADER_SIZE + 18);
    assert(!memcmp(eb, TEST_EVIDENCE_HEADER "some custom claims", ebs));
    free(eb);
}

void test_evidence_generate_err_notinit() {
    printf("Testing evidence_generate fails when module not initialised...\n");
    setup();

    G_mocks.oe_attester_select_format = OE_OK;
    G_mocks.oe_verifier_get_format_settings = OE_OK;
    G_mocks.oe_get_evidence = OE_OK;

    uint8_t* eb = NULL;
    size_t ebs = 0;

    oe_uuid_t format_id = {.b = TEST_FORMAT_ID};
    assert(!evidence_generate(
        format_id, (uint8_t*)"some custom claims", 18, &eb, &ebs));
    assert(!eb && !ebs);
}

void test_evidence_generate_err_arguments() {
    printf("Testing evidence_generate fails when given evidence buffer "
           "invalid...\n");
    setup();

    evidence_init();
    G_mocks.oe_attester_select_format = OE_OK;
    G_mocks.oe_verifier_get_format_settings = OE_OK;
    G_mocks.oe_get_evidence = OE_OK;

    uint8_t* eb = NULL;
    size_t ebs = 0;

    oe_uuid_t format_id = {.b = TEST_FORMAT_ID};
    assert(!evidence_generate(
        format_id, (uint8_t*)"some custom claims", 18, NULL, &ebs));
    assert(!eb && ebs == 0);
    assert(!evidence_generate(
        format_id, (uint8_t*)"some custom claims", 18, &eb, NULL));
    assert(!eb && ebs == 0);
}

void test_evidence_generate_err_selectfails() {
    printf("Testing evidence_generate fails when attester select fails...\n");
    setup();

    evidence_init();
    G_mocks.oe_attester_select_format = OE_FAILURE;
    G_mocks.oe_verifier_get_format_settings = OE_OK;
    G_mocks.oe_get_evidence = OE_OK;

    uint8_t* eb = NULL;
    size_t ebs = 0;

    oe_uuid_t format_id = {.b = TEST_FORMAT_ID};
    assert(!evidence_generate(
        format_id, (uint8_t*)"some custom claims", 18, &eb, &ebs));
    assert(!eb && !ebs);
}

void test_evidence_generate_err_getsettingsfails() {
    printf("Testing evidence_generate fails when verifier select format "
           "fails...\n");
    setup();

    evidence_init();
    G_mocks.oe_attester_select_format = OE_OK;
    G_mocks.oe_verifier_get_format_settings = OE_FAILURE;
    G_mocks.oe_get_evidence = OE_OK;

    uint8_t* eb = NULL;
    size_t ebs = 0;

    oe_uuid_t format_id = {.b = TEST_FORMAT_ID};
    assert(!evidence_generate(
        format_id, (uint8_t*)"some custom claims", 18, &eb, &ebs));
    assert(!eb && !ebs);
}

void test_evidence_generate_err_getevidencefails() {
    printf("Testing evidence_generate fails when get evidence fails...\n");
    setup();

    evidence_init();
    G_mocks.oe_attester_select_format = OE_OK;
    G_mocks.oe_verifier_get_format_settings = OE_OK;
    G_mocks.oe_get_evidence = OE_FAILURE;

    uint8_t* eb = NULL;
    size_t ebs = 0;

    oe_uuid_t format_id = {.b = TEST_FORMAT_ID};
    assert(!evidence_generate(
        format_id, (uint8_t*)"some custom claims", 18, &eb, &ebs));
    assert(!eb && !ebs);
}

void test_evidence_verify_and_extract_claims_ok() {
    printf("Testing evidence_verify_and_extract_claims succeeds...\n");
    setup();

    evidence_init();
    G_mocks.oe_verify_evidence = OE_OK;

    oe_claim_t* cl = NULL;
    size_t cls = 0;

    oe_uuid_t format_id = {.b = TEST_FORMAT_ID};
    assert(evidence_verify_and_extract_claims(
        format_id, (uint8_t*)"<evidence-header>this is custom", 31, &cl, &cls));

    assert(cl);
    assert(cls == 14);
    assert(!memcmp("this is custom", cl, cls));

    free(cl);
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

    test_evidence_generate_ok();
    test_evidence_generate_err_notinit();
    test_evidence_generate_err_arguments();
    test_evidence_generate_err_selectfails();
    test_evidence_generate_err_getsettingsfails();
    test_evidence_generate_err_getevidencefails();

    test_evidence_verify_and_extract_claims_ok();
    test_evidence_verify_and_extract_claims_err_notinit();
    test_evidence_verify_and_extract_claims_err_verification();

    test_evidence_get_claim_ok();
    test_evidence_get_claim_behaves_ok_with_invalid_params();
    test_evidence_free();
}

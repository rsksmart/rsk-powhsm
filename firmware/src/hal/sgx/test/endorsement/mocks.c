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

#include <openenclave/common.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "mocks.h"

mock_config_t G_mock_config;

#define MOCK_RESULT(fn) return G_mock_config.result_##fn ? OE_OK : OE_FAILURE

uint8_t mock_format_id[] = {11, 22, 33};
uint8_t mock_format_settings[] = {44, 55, 66, 77};
uint8_t mock_evidence[] = MOCK_EVIDENCE;

uint8_t der_encode_signature(uint8_t* dest,
                             size_t dest_size,
                             sgx_ecdsa256_signature_t* sig) {
    assert(dest_size >= sizeof(sig->r) + sizeof(sig->s));
    memcpy(dest, sig->r, sizeof(sig->r));
    memcpy(dest + sizeof(sig->r), sig->s, sizeof(sig->s));
    return sizeof(sig->r) + sizeof(sig->s);
}

oe_result_t oe_attester_initialize(void) {
    MOCK_RESULT(oe_attester_initialize);
}

oe_result_t oe_attester_select_format(const oe_uuid_t* format_ids,
                                      size_t format_ids_length,
                                      oe_uuid_t* selected_format_id) {

    const uint8_t expected_format_id[] = OE_FORMAT_UUID_SGX_ECDSA;
    const oe_uuid_t assigned_format_id = {.b = {11, 22, 33}};

    assert(format_ids_length == 1);
    assert(!memcmp(
        format_ids[0].b, expected_format_id, sizeof(expected_format_id)));
    *selected_format_id = assigned_format_id;
    MOCK_RESULT(oe_attester_select_format);
}

oe_result_t oe_verifier_get_format_settings(const oe_uuid_t* format_id,
                                            uint8_t** settings,
                                            size_t* settings_size) {

    const uint8_t expected_format_id[] = {11, 22, 33};
    assert(
        !memcmp(format_id->b, expected_format_id, sizeof(expected_format_id)));
    assert(settings_size != NULL);
    *settings = mock_format_settings;
    *settings_size = sizeof(mock_format_settings);

    MOCK_RESULT(oe_verifier_get_format_settings);
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

    // Test parameters
    assert(flags == 0);
    assert(!memcmp(format_id, mock_format_id, sizeof(mock_format_id)));
    assert(!memcmp(optional_parameters,
                   mock_format_settings,
                   sizeof(mock_format_settings)));
    assert(optional_parameters_size == sizeof(mock_format_settings));
    assert(endorsements_buffer == NULL);
    assert(endorsements_buffer_size == NULL);

    // Mock evidence
    size_t sz = G_mock_config.oe_get_evidence_buffer_size > 0
                    ? G_mock_config.oe_get_evidence_buffer_size
                    : (sizeof(mock_evidence) + custom_claims_buffer_size);
    G_mock_config.oe_get_evidence_buffer = malloc(sz);
    if (G_mock_config.oe_get_evidence_buffer_size == 0) {
        memcpy(G_mock_config.oe_get_evidence_buffer,
               mock_evidence,
               sizeof(mock_evidence));
        memcpy(G_mock_config.oe_get_evidence_buffer + sizeof(mock_evidence),
               custom_claims_buffer,
               custom_claims_buffer_size);
        ((sgx_quote_t*)G_mock_config.oe_get_evidence_buffer)->signature_len =
            sz - sizeof(sgx_quote_t) - custom_claims_buffer_size;
    }

    // Result
    *evidence_buffer = G_mock_config.oe_get_evidence_buffer;
    *evidence_buffer_size = sz;

    MOCK_RESULT(oe_get_evidence);
}

oe_result_t oe_free_evidence(uint8_t* evidence_buffer) {
    G_mock_config.oe_get_evidence_buffer_freed |=
        evidence_buffer == G_mock_config.oe_get_evidence_buffer;
    MOCK_RESULT(oe_free_evidence);
}

oe_result_t oe_attester_shutdown(void) {
    MOCK_RESULT(oe_attester_shutdown);
}

oe_result_t oe_verifier_initialize(void) {
    MOCK_RESULT(oe_verifier_initialize);
}

oe_result_t oe_verifier_shutdown(void) {
    MOCK_RESULT(oe_verifier_shutdown);
}
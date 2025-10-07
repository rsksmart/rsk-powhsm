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

#include "evidence.h"

#include <string.h>
#include "hal/hash.h"
#include "hal/log.h"
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/verifier.h>

static struct { bool initialised; } G_evidence_ctx;

#define EVIDENCE_CHECK(oe_result, error_msg, statement) \
    {                                                   \
        if (OE_OK != oe_result) {                       \
            LOG("%s: result=%u (%s)\n",                 \
                error_msg,                              \
                result,                                 \
                oe_result_str(oe_result));              \
            { statement; }                              \
        }                                               \
    }

// ****************************************************** //
// ********** Public interface implemenetation ********** //
// ****************************************************** //

bool evidence_init() {
    oe_result_t result;

    explicit_bzero(&G_evidence_ctx, sizeof(G_evidence_ctx));

    // Initialize modules
    result = oe_attester_initialize();
    EVIDENCE_CHECK(result, "Failed to initialize attester", return false);
    result = oe_verifier_initialize();
    EVIDENCE_CHECK(result, "Failed to initialize verifier", return false);

    G_evidence_ctx.initialised = true;
    LOG("Evidence module initialized\n");
    return true;
}

void evidence_finalise() {
    oe_verifier_shutdown();
    oe_attester_shutdown();
    explicit_bzero(&G_evidence_ctx, sizeof(G_evidence_ctx));
}

bool evidence_get_format_settings(evidence_format_t* format) {
    oe_result_t result;

    if (!G_evidence_ctx.initialised) {
        LOG("Evidence module not initialised\n");
        return false;
    }

    if (!format || format->settings || format->settings_size) {
        LOG("Invalid format getter spec given\n");
        return false;
    }

    result = oe_verifier_get_format_settings(
        &format->id, &format->settings, &format->settings_size);
    EVIDENCE_CHECK(result, "Failed to gather format settings", return false);

    return true;
}

bool evidence_free_format_settings(uint8_t* settings) {
    if (!settings)
        return true;

    return oe_verifier_free_format_settings(settings) == OE_OK;
}

bool evidence_supports_format(oe_uuid_t format_id) {
    evidence_format_t format = {
        .id = format_id,
        .settings = NULL,
        .settings_size = 0,
    };
    oe_uuid_t selected_format;
    oe_result_t result;

    // Make sure we can get format settings
    if (!evidence_get_format_settings(&format))
        return false;
    evidence_free_format_settings(format.settings);

    // Make sure we can select format for attestation
    result = oe_attester_select_format(&format.id, 1, &selected_format);
    EVIDENCE_CHECK(result, "Failed to select attestation format", return false);

    return true;
}

// Generates evidence with the given format id and custom claims.
bool evidence_generate(evidence_format_t* format,
                       uint8_t* ccs,
                       size_t ccs_size,
                       uint8_t** evidence_buffer,
                       size_t* evidence_buffer_size) {
    oe_result_t result;
    bool gathered_settings = false;

    if (!G_evidence_ctx.initialised) {
        LOG("Evidence module not initialised\n");
        goto generate_evidence_error;
    }

    if (!format) {
        LOG("Invalid evidence format\n");
        goto generate_evidence_error;
    }

    if (!evidence_buffer || !evidence_buffer_size) {
        LOG("Invalid evidence buffer/size pointers\n");
        goto generate_evidence_error;
    }

    // Gather the corresponding format settings if needed
    // Otherwise make sure the format is supported
    gathered_settings = false;
    if (!format->settings) {
        if (!evidence_get_format_settings(format)) {
            LOG("Error gathering format settings\n");
            goto generate_evidence_error;
        }
        gathered_settings = true;
        LOG("Gathered settings\n");
    }

    result = oe_get_evidence(&format->id,
                             0,
                             ccs,
                             ccs_size,
                             format->settings,
                             format->settings_size,
                             evidence_buffer,
                             evidence_buffer_size,
                             NULL,
                             NULL);
    EVIDENCE_CHECK(
        result, "Evidence generation failed", goto generate_evidence_error);

    if (gathered_settings) {
        evidence_free_format_settings(format->settings);
        format->settings = NULL;
        format->settings_size = 0;
    }

    LOG("Evidence generated successfully\n");

    return true;

generate_evidence_error:
    if (evidence_buffer && *evidence_buffer) {
        oe_free_evidence(*evidence_buffer);
        *evidence_buffer = NULL;
    }
    if (evidence_buffer_size) {
        *evidence_buffer_size = 0;
    }
    if (gathered_settings && format->settings) {
        evidence_free_format_settings(format->settings);
        format->settings = NULL;
        format->settings_size = 0;
    }
    return false;
}

bool evidence_verify_and_extract_claims(oe_uuid_t format_id,
                                        uint8_t* evidence_buffer,
                                        size_t evidence_buffer_size,
                                        oe_claim_t** claims,
                                        size_t* claims_length) {
    if (!G_evidence_ctx.initialised) {
        LOG("Evidence module not initialised\n");
        return false;
    }

    if (!evidence_buffer) {
        LOG("Invalid evidence buffer pointer\n");
        return false;
    }

    if (!claims || !claims_length) {
        claims = NULL;
        claims_length = NULL;
    }

    oe_result_t result = oe_verify_evidence(&format_id,
                                            evidence_buffer,
                                            evidence_buffer_size,
                                            NULL,
                                            0,
                                            NULL,
                                            0,
                                            claims,
                                            claims_length);
    EVIDENCE_CHECK(result, "Evidence verification failed", return false);

    // Make sure claims were succesfully extracted
    // if that was the intention
    if (claims && claims_length && (!*claims || !*claims_length)) {
        LOG("Failed to extract claims from evidence\n");
        return false;
    }

    // Verify the custom claims hash is included in the evidence
    // and that the extracted custom claims match the custom claims
    // in the evidence (just for completeness' sake)
    // Hashing of the custom claims based on OpenEnclave's
    // common/sgx/verifier.c::oe_sgx_hash_custom_claims_buffer

    // Gather the report body and the custom claims buffer directly from the
    // evidence This depends on the evidence format
    sgx_report_data_t* report_data = NULL;
    uint8_t* custom_claims_buffer = NULL;
    size_t custom_claims_buffer_size = 0;
    if (!memcmp(&format_id, &EVIDENCE_FORMAT_SGX_LOCAL, sizeof(oe_uuid_t))) {
        if (evidence_buffer_size > sizeof(sgx_report_t)) {
            custom_claims_buffer = evidence_buffer + sizeof(sgx_report_t);
            custom_claims_buffer_size =
                evidence_buffer_size - sizeof(sgx_report_t);
        }
        report_data = &((sgx_report_t*)evidence_buffer)->body.report_data;
    } else if (!memcmp(
                   &format_id, &EVIDENCE_FORMAT_SGX_ECDSA, sizeof(oe_uuid_t))) {
        sgx_quote_t* quote = (sgx_quote_t*)evidence_buffer;
        size_t report_body_size = sizeof(*quote) + quote->signature_len;

        if (evidence_buffer_size > report_body_size) {
            custom_claims_buffer = evidence_buffer + report_body_size;
            custom_claims_buffer_size = evidence_buffer_size - report_body_size;
        }
        report_data = &((sgx_quote_t*)evidence_buffer)->report_body.report_data;
    } else {
        LOG("Unexpected evidence format encountered\n");
        goto evidence_verify_and_extract_claims_fail;
    }

    if (claims && *claims) {
        // Extract the custom claims buffer from the extracted claims
        oe_claim_t* custom_claim =
            evidence_get_custom_claim(*claims, *claims_length);

        // Make sure the extracted custom claim value and the custom claims
        // buffer match
        if (custom_claim && custom_claims_buffer && custom_claims_buffer_size) {
            if (custom_claim->value_size != custom_claims_buffer_size ||
                memcmp(custom_claim->value,
                       custom_claims_buffer,
                       custom_claims_buffer_size)) {
                LOG("Custom claims buffer and extracted custom claims do not "
                    "match\n");
                goto evidence_verify_and_extract_claims_fail;
            }
        } else if (!(!custom_claim && !custom_claims_buffer &&
                     !custom_claims_buffer_size)) {
            LOG("Inconsistent custom claims detected\n");
            goto evidence_verify_and_extract_claims_fail;
        }
    }

    // Hash the custom claims buffer, setting to the default value if empty
    uint8_t custom_claims_hash[32];
    // Default hash for empty string
    static const uint8_t sha256_for_empty_string[] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
        0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
        0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

    if (!custom_claims_buffer || !custom_claims_buffer_size) {
        memcpy(custom_claims_hash,
               sha256_for_empty_string,
               sizeof(sha256_for_empty_string));
    } else {
        hash_sha256_ctx_t hash_ctx;
        if (!hash_sha256_init(&hash_ctx))
            goto evidence_verify_and_extract_claims_fail;
        if (!hash_sha256_update(
                &hash_ctx, custom_claims_buffer, custom_claims_buffer_size))
            goto evidence_verify_and_extract_claims_fail;
        if (!hash_sha256_final(&hash_ctx, custom_claims_hash))
            goto evidence_verify_and_extract_claims_fail;
    }

    if (sizeof(report_data->field) < sizeof(custom_claims_hash) ||
        memcmp(report_data->field,
               custom_claims_hash,
               sizeof(custom_claims_hash))) {
        LOG("Custom claims hash not contained within the evidence\n");
        goto evidence_verify_and_extract_claims_fail;
    }

    LOG("Evidence verified successfully\n");

    return true;
evidence_verify_and_extract_claims_fail:
    if (claims && *claims) {
        oe_free_claims(*claims, *claims_length);
        *claims = NULL;
        *claims_length = 0;
    }
    return false;
}

bool evidence_free_claims(oe_claim_t* claims, size_t claims_length) {
    if (claims) {
        if (oe_free_claims(claims, claims_length) != OE_OK)
            return false;
    }
    return true;
}

oe_claim_t* evidence_get_claim(oe_claim_t* claims,
                               size_t claims_size,
                               const char* claim_name) {
    if (!claims || !claims_size || !claim_name)
        return NULL;

    for (size_t i = 0; i < claims_size; i++) {
        if (strcmp(claims[i].name, claim_name) == 0)
            return &claims[i];
    }
    return NULL;
}

oe_claim_t* evidence_get_custom_claim(oe_claim_t* claims, size_t claims_size) {
    return evidence_get_claim(
        claims, claims_size, OE_CLAIM_CUSTOM_CLAIMS_BUFFER);
}

void evidence_free(uint8_t* evidence_buffer) {
    if (evidence_buffer)
        oe_free_evidence(evidence_buffer);
}

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
#include "hal/log.h"
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/verifier.h>

static struct { bool initialised; } G_evidence_ctx;

typedef struct {
    // The format ID.
    // See openenclave/attestation/sgx/evidence.h for supported formats.
    oe_uuid_t id;
    // The format settings buffer for the corresponding format id.
    // This is returned by oe_verifier_get_format_settings.
    uint8_t* settings;
    // The size of the format settings buffer.
    size_t settings_size;
} evidence_format_t;

#define EVIDENCE_CHECK(oe_result, error_msg, statement)                  \
    {                                                                    \
        if (OE_OK != oe_result) {                                        \
            LOG(error_msg);                                              \
            LOG(": result=%u (%s)\n", result, oe_result_str(oe_result)); \
            { statement; }                                               \
        }                                                                \
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

bool evidence_supports_format(oe_uuid_t format_id) {
    if (!G_evidence_ctx.initialised) {
        LOG("Evidence module not initialised\n");
        return false;
    }

    oe_result_t result;
    evidence_format_t format = {
        .id = format_id,
        .settings = NULL,
        .settings_size = 0,
    };
    oe_uuid_t selected_format;

    result = oe_attester_select_format(&format.id, 1, &selected_format);
    EVIDENCE_CHECK(result, "Failed to select attestation format", return false);

    result = oe_verifier_get_format_settings(
        &format.id, &format.settings, &format.settings_size);
    EVIDENCE_CHECK(result, "Failed to gather format settings", return false);
    oe_free(format.settings);

    return true;
}

// Generates evidence with the given format id and custom claims.
bool evidence_generate(oe_uuid_t format_id,
                       uint8_t* ccs,
                       size_t ccs_size,
                       uint8_t** evidence_buffer,
                       size_t* evidence_buffer_size) {
    oe_result_t result;

    evidence_format_t format = {
        .id = format_id,
        .settings = NULL,
        .settings_size = 0,
    };
    oe_uuid_t selected_format;

    if (!G_evidence_ctx.initialised) {
        LOG("Evidence module not initialised\n");
        goto generate_evidence_error;
    }

    if (!evidence_buffer || !evidence_buffer_size) {
        LOG("Invalid evidence buffer/size pointers\n");
        goto generate_evidence_error;
    }

    // Make sure the desired format is supported and
    // gather the corresponding settings

    result = oe_attester_select_format(&format.id, 1, &selected_format);
    EVIDENCE_CHECK(result,
                   "Failed to select attestation format",
                   goto generate_evidence_error);

    result = oe_verifier_get_format_settings(
        &format.id, &format.settings, &format.settings_size);
    EVIDENCE_CHECK(result,
                   "Failed to gather format settings",
                   goto generate_evidence_error);

    *evidence_buffer = NULL;
    *evidence_buffer_size = 0;
    result = oe_get_evidence(&format.id,
                             0,
                             ccs,
                             ccs_size,
                             format.settings,
                             format.settings_size,
                             evidence_buffer,
                             evidence_buffer_size,
                             NULL,
                             NULL);
    EVIDENCE_CHECK(
        result, "Evidence generation failed", goto generate_evidence_error);

    oe_free(format.settings);

    LOG("Evidence generated successfully\n");

    return true;

generate_evidence_error:
    if (evidence_buffer && *evidence_buffer) {
        oe_free_evidence(*evidence_buffer);
        *evidence_buffer = NULL;
        *evidence_buffer_size = 0;
    }
    if (format.settings)
        oe_free(format.settings);
    return false;
}

bool evidence_verify_and_extract_claims(oe_uuid_t format_id,
                                        uint8_t* evidence_buffer,
                                        size_t evidence_buffer_size,
                                        oe_claim_t** claims,
                                        size_t* claims_size) {
    if (!G_evidence_ctx.initialised) {
        LOG("Evidence module not initialised\n");
        return false;
    }

    if (!claims || !claims_size) {
        claims = NULL;
        claims_size = NULL;
    }

    oe_result_t result = oe_verify_evidence(&format_id,
                                            evidence_buffer,
                                            evidence_buffer_size,
                                            NULL,
                                            0,
                                            NULL,
                                            0,
                                            claims,
                                            claims_size);
    EVIDENCE_CHECK(result, "Evidence verification failed", return false);

    LOG("Evidence verified successfully\n");

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

void evidence_free(uint8_t* evidence_buffer) {
    if (evidence_buffer)
        oe_free_evidence(evidence_buffer);
}

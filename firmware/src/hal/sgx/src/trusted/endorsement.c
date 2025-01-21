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

#include "hal/constants.h"
#include "hal/endorsement.h"
#include "hal/exceptions.h"
#include "hal/log.h"
#include "der_utils.h"

#include <string.h>

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/bits/attestation.h>
#include <openenclave/bits/defs.h>

#define RAW_ENVELOPE_BUFFER_SIZE (10 * 1024)

static struct {
    bool initialised;
    // The format ID used for attestation.
    // See openenclave/attestation/sgx/evidence.h for supported formats.
    oe_uuid_t format_id;
    // The format settings buffer for the selected format.
    // This is returned by oe_verifier_get_format_settings.
    uint8_t* format_settings;
    // The size of the format settings buffer.
    size_t format_settings_size;
    // Current envelope
    struct {
        uint8_t raw[RAW_ENVELOPE_BUFFER_SIZE];
        size_t raw_size;
        sgx_quote_t* quote;
        sgx_quote_auth_data_t* quote_auth_data;
        sgx_qe_auth_data_t qe_auth_data;
        sgx_qe_cert_data_t qe_cert_data;
    } envelope;
} G_endorsement_ctx;

#define ENDORSEMENT_FORMAT OE_FORMAT_UUID_SGX_ECDSA

#define ENDORSEMENT_CHECK(oe_result, error_msg)                          \
    {                                                                    \
        if (OE_OK != oe_result) {                                        \
            LOG(error_msg);                                              \
            LOG(": result=%u (%s)\n", result, oe_result_str(oe_result)); \
            return false;                                                \
        }                                                                \
    }

// Taken from OpenEnclave's common/sgx/quote.c
OE_INLINE uint16_t ReadUint16(const uint8_t* p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

// Taken from OpenEnclave's common/sgx/quote.c
OE_INLINE uint32_t ReadUint32(const uint8_t* p) {
    return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

// Generates an envelop with the provided message as a custom claim.
static bool generate_envelope(uint8_t* msg, size_t msg_size) {
    if (!G_endorsement_ctx.initialised) {
        LOG("Endorsement module has not been initialised\n");
        return false;
    }

    oe_result_t result = OE_FAILURE;
    uint8_t* evidence_buffer = NULL;
    size_t evidence_buffer_size = 0;
    result = oe_get_evidence(&G_endorsement_ctx.format_id,
                             0,
                             msg,
                             msg_size,
                             G_endorsement_ctx.format_settings,
                             G_endorsement_ctx.format_settings_size,
                             &evidence_buffer,
                             &evidence_buffer_size,
                             NULL,
                             NULL);
    ENDORSEMENT_CHECK(result, "Envelope generation failed");
    if (evidence_buffer_size > sizeof(G_endorsement_ctx.envelope.raw)) {
        LOG("Envelope generation failed: buffer needs %lu bytes but "
            "only %ld available\n",
            evidence_buffer_size,
            sizeof(G_endorsement_ctx.envelope.raw));
        oe_free_evidence(evidence_buffer);
        return false;
    }

    memcpy(
        G_endorsement_ctx.envelope.raw, evidence_buffer, evidence_buffer_size);
    G_endorsement_ctx.envelope.raw_size = evidence_buffer_size;
    oe_free_evidence(evidence_buffer);

    return true;
}

// Based on OpenEnclave's common/sgx/quote.c::_parse_quote()
// No validation is performed. Left to the end user.
// Maybe we could do some minimal validation in the future.
static bool parse_envelope(uint8_t* msg, size_t msg_size) {
    const uint8_t* p = G_endorsement_ctx.envelope.raw;
    const uint8_t* const quote_end = p + G_endorsement_ctx.envelope.raw_size;
    sgx_quote_t* _sgx_quote = (sgx_quote_t*)p;
    G_endorsement_ctx.envelope.quote = _sgx_quote;

    if (quote_end < p) {
        LOG("SGX quote parsing error. Pointer wrapper around\n");
        return false;
    }

    p += sizeof(sgx_quote_t);

    if (p > quote_end) {
        LOG("Parse error after parsing SGX quote, before signature\n");
        return false;
    }
    if (p + _sgx_quote->signature_len + msg_size != quote_end) {
        LOG("Parse error after parsing SGX signature\n");
        return false;
    }

    G_endorsement_ctx.envelope.quote_auth_data = (sgx_quote_auth_data_t*)p;

    p += sizeof(sgx_quote_auth_data_t);

    sgx_qe_auth_data_t* qe_auth_data = &G_endorsement_ctx.envelope.qe_auth_data;
    qe_auth_data->size = ReadUint16(p);
    p += 2;
    qe_auth_data->data = (uint8_t*)p;
    p += qe_auth_data->size;

    if (p > quote_end) {
        LOG("Parse error after parsing QE authorization data\n");
        return false;
    }

    sgx_qe_cert_data_t* qe_cert_data = &G_endorsement_ctx.envelope.qe_cert_data;
    qe_cert_data->type = ReadUint16(p);
    p += 2;
    qe_cert_data->size = ReadUint32(p);
    p += 4;
    qe_cert_data->data = (uint8_t*)p;
    p += qe_cert_data->size;

    if (memcmp(p, msg, msg_size)) {
        LOG("Parse error: got inconsistent custom message\n");
        return false;
    }

    p += msg_size;

    if (p != quote_end) {
        LOG("Unexpected quote length while parsing\n");
        return false;
    }

    return true;
}

// ****************************************************** //
// ********** Public interface implemenetation ********** //
// ****************************************************** //

bool endorsement_init() {
    oe_result_t result = OE_FAILURE;

    explicit_bzero(&G_endorsement_ctx, sizeof(G_endorsement_ctx));

    // Initialize modules
    result = oe_attester_initialize();
    ENDORSEMENT_CHECK(result, "Failed to initialize attester");
    result = oe_verifier_initialize();
    ENDORSEMENT_CHECK(result, "Failed to initialize verifier");

    // Make sure the desired format is supported and
    // get the corresponding settings
    const oe_uuid_t format_id = {ENDORSEMENT_FORMAT};
    result =
        oe_attester_select_format(&format_id, 1, &G_endorsement_ctx.format_id);
    ENDORSEMENT_CHECK(result, "Failed to select attestation format");

    result = oe_verifier_get_format_settings(
        &G_endorsement_ctx.format_id,
        &G_endorsement_ctx.format_settings,
        &G_endorsement_ctx.format_settings_size);
    ENDORSEMENT_CHECK(result, "Format is not supported by verifier");

    G_endorsement_ctx.initialised = true;
    LOG("Attestation module initialized\n");
    return true;
}

void endorsement_finalise() {
    oe_verifier_shutdown();
    oe_attester_shutdown();
}

bool endorsement_sign(uint8_t* msg,
                      size_t msg_size,
                      uint8_t* signature_out,
                      uint8_t* signature_out_length) {
    if (*signature_out_length < MAX_SIGNATURE_LENGTH) {
        LOG("Output buffer for signature too small: %u bytes\n",
            *signature_out_length);
        goto endorsement_sign_fail;
    }

    if (!generate_envelope(msg, msg_size)) {
        LOG("Error generating envelope\n");
        goto endorsement_sign_fail;
    }

    if (!parse_envelope(msg, msg_size)) {
        LOG("Error parsing envelope\n");
        goto endorsement_sign_fail;
    }

    // Output signature in DER format
    sgx_ecdsa256_signature_t* sig =
        &G_endorsement_ctx.envelope.quote_auth_data->signature;
    *signature_out_length = der_encode_signature(signature_out, sig);

    return true;

endorsement_sign_fail:
    explicit_bzero(&G_endorsement_ctx.envelope,
                   sizeof(G_endorsement_ctx.envelope));
    return false;
}

uint8_t* endorsement_get_envelope() {
    if (G_endorsement_ctx.envelope.raw_size == 0) {
        return 0;
    }
    return G_endorsement_ctx.envelope.raw;
}

size_t endorsement_get_envelope_length() {
    return G_endorsement_ctx.envelope.raw_size;
}

bool endorsement_get_code_hash(uint8_t* code_hash_out,
                               uint8_t* code_hash_out_length) {

    if (G_endorsement_ctx.envelope.raw_size == 0) {
        LOG("No envelope available\n");
        return false;
    }

    if (code_hash_out == NULL) {
        LOG("Output buffer is NULL\n");
        return false;
    }

    if (*code_hash_out_length < HASH_LENGTH) {
        LOG("Output buffer for code hash too small: %u bytes\n",
            *code_hash_out_length);
        return false;
    }

    memcpy(code_hash_out,
           G_endorsement_ctx.envelope.quote->report_body.mrenclave,
           sizeof(G_endorsement_ctx.envelope.quote->report_body.mrenclave));
    *code_hash_out_length =
        sizeof(G_endorsement_ctx.envelope.quote->report_body.mrenclave);

    return true;
}

bool endorsement_get_public_key(uint8_t* public_key_out,
                                uint8_t* public_key_out_length) {
    if (G_endorsement_ctx.envelope.raw_size == 0) {
        LOG("No envelope available\n");
        return false;
    }

    if (public_key_out == NULL) {
        LOG("Output buffer is NULL\n");
        return false;
    }

    if (*public_key_out_length < PUBKEY_UNCMP_LENGTH) {
        LOG("Output buffer for public key too small: %u bytes\n",
            *public_key_out_length);
        return false;
    }

    size_t off = 0;
    public_key_out[off++] = 0x04;
    memcpy(
        public_key_out + off,
        G_endorsement_ctx.envelope.quote_auth_data->attestation_key.x,
        sizeof(G_endorsement_ctx.envelope.quote_auth_data->attestation_key.x));
    off +=
        sizeof(G_endorsement_ctx.envelope.quote_auth_data->attestation_key.x);
    memcpy(
        public_key_out + off,
        G_endorsement_ctx.envelope.quote_auth_data->attestation_key.y,
        sizeof(G_endorsement_ctx.envelope.quote_auth_data->attestation_key.y));
    off +=
        sizeof(G_endorsement_ctx.envelope.quote_auth_data->attestation_key.y);
    *public_key_out_length = off;

    // Sanity check
    if (off != PUBKEY_UNCMP_LENGTH) {
        LOG("Unexpected attestation public key length\n");
        return false;
    }

    return true;
}

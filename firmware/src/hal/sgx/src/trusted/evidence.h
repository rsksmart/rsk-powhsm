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

#ifndef __EVIDENCE_H
#define __EVIDENCE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <openenclave/bits/evidence.h>
#include <openenclave/attestation/sgx/evidence.h>

#define EVIDENCE_FORMAT_SGX_ECDSA ((oe_uuid_t){OE_FORMAT_UUID_SGX_ECDSA})
#define EVIDENCE_FORMAT_SGX_LOCAL \
    ((oe_uuid_t){OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION})

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

/**
 * @brief Initializes the evidence module
 *
 * @returns whether the initialisation succeeded
 */
bool evidence_init();

/**
 * @brief Finalises the evidence module
 */
void evidence_finalise();

/**
 * Get the format settings for the given format id
 *
 * @param format [in/out] the format. should only have id set (rest to ZEROES)
 *
 * @returns whether the format settings were gathered successfully
 */
bool evidence_get_format_settings(evidence_format_t* format);

/**
 * Tells whether a given format is supported for
 * evidence generation and verification
 *
 * @param format_id the format id
 *
 * @returns whether the format is supported
 */
bool evidence_supports_format(oe_uuid_t format_id);

/**
 * @brief Generates evidence with the
 * given format id and custom claims
 *
 * @param format                evidence format to use
 * @param ccs                   custom claims buffer
 * @param ccs_size              custom claims buffer size
 * @param evidence_buffer       [out] evidence buffer pointer
 * @param evidence_buffer_size  [out] evidence buffer size
 *
 * @returns true iff evidence was successfully generated
 */
bool evidence_generate(evidence_format_t* format,
                       uint8_t* ccs,
                       size_t ccs_size,
                       uint8_t** evidence_buffer,
                       size_t* evidence_buffer_size);

bool evidence_verify_and_extract_claims(oe_uuid_t format_id,
                                        uint8_t* evidence_buffer,
                                        size_t evidence_buffer_size,
                                        oe_claim_t** claims,
                                        size_t* claims_size);

oe_claim_t* evidence_get_claim(oe_claim_t* claims,
                               size_t claims_size,
                               const char* claim_name);

/**
 * @brief Frees a buffer previously output by evidence_generate
 *
 * @param evidence_buffer evidence buffer
 */
void evidence_free(uint8_t* evidence_buffer);

#endif // __EVIDENCE_H

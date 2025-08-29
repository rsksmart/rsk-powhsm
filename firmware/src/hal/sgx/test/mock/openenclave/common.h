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

#ifndef __MOCK_OE_COMMON_H
#define __MOCK_OE_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#define oe_malloc(sz) malloc(sz)
#define oe_free(ptr) free(ptr)

// Taken from OpenEnclave's include/openenclave/bits/defs.h

#define OE_PACK_BEGIN _Pragma("pack(push, 1)")
#define OE_PACK_END _Pragma("pack(pop)")

// Taken from OpenEnclave's include/openenclave/bits/result.h

typedef enum _oe_result {
    OE_OK,
    OE_FAILURE,
} oe_result_t;

#define oe_result_str(result) ((result) == OE_OK ? "OE_OK" : "OE_FAILURE")

// Taken from OpenEnclave's include/openenclave/bits/sgx/sgxtypes.h

#define SGX_USERDATA_SIZE 20
#define OE_ZERO_SIZED_ARRAY
#define OE_SHA256_SIZE 32
#define SGX_CPUSVN_SIZE 16
#define SGX_KEYID_SIZE 32
#define SGX_MAC_SIZE 16
#define OE_INLINE

typedef struct _sgx_report_data {
    unsigned char field[64];
} sgx_report_data_t;

OE_PACK_BEGIN
typedef struct _sgx_qe_auth_data {
    uint16_t size;
    uint8_t* data;
} sgx_qe_auth_data_t;
OE_PACK_END

OE_PACK_BEGIN
typedef struct _sgx_qe_cert_data {
    uint16_t type;
    uint32_t size;
    uint8_t* data;
} sgx_qe_cert_data_t;
OE_PACK_END

OE_PACK_BEGIN
typedef struct _sgx_attributes {
    uint64_t flags;
    uint64_t xfrm;
} sgx_attributes_t;
OE_PACK_END

typedef struct _sgx_report_body {
    /* (0) CPU security version */
    uint8_t cpusvn[SGX_CPUSVN_SIZE];

    /* (16) Selector for which fields are defined in SSA.MISC */
    uint32_t miscselect;

    /* (20) Reserved */
    uint8_t reserved1[12];

    /* (32) Enclave extended product ID */
    uint8_t isvextprodid[16];

    /* (48) Enclave attributes */
    sgx_attributes_t attributes;

    /* (64) Enclave measurement */
    uint8_t mrenclave[OE_SHA256_SIZE];

    /* (96) Reserved */
    uint8_t reserved2[32];

    /* (128) The value of the enclave's SIGNER measurement */
    uint8_t mrsigner[OE_SHA256_SIZE];

    /* (160) Reserved */
    uint8_t reserved3[32];

    /* (192) Enclave Configuration ID*/
    uint8_t configid[64];

    /* (256) Enclave product ID */
    uint16_t isvprodid;

    /* (258) Enclave security version */
    uint16_t isvsvn;

    /* (260) Enclave Configuration Security Version*/
    uint16_t configsvn;

    /* (262) Reserved */
    uint8_t reserved4[42];

    /* (304) Enclave family ID */
    uint8_t isvfamilyid[16];

    /* (320) User report data */
    sgx_report_data_t report_data;
} sgx_report_body_t;

typedef struct _sgx_report {
    /* (0) */
    sgx_report_body_t body;

    /* (384) Id of key (?) */
    uint8_t keyid[SGX_KEYID_SIZE];

    /* (416) Message authentication code over fields of this structure */
    uint8_t mac[SGX_MAC_SIZE];
} sgx_report_t;

OE_PACK_BEGIN
typedef struct _sgx_quote {
    /* (0) */
    uint16_t version;

    /* (2) */
    uint16_t sign_type;

    /* (4) */
    uint32_t tee_type;

    /* (8) */
    uint16_t qe_svn;

    /* (10) */
    uint16_t pce_svn;

    /* (12) */
    uint8_t uuid[16];

    /* (28) */
    uint8_t user_data[SGX_USERDATA_SIZE];

    /* (48) */
    sgx_report_body_t report_body;

    /* (432) */
    uint32_t signature_len;

    /* (436) signature array (varying length) */
    OE_ZERO_SIZED_ARRAY uint8_t signature[];
} sgx_quote_t;
OE_PACK_END

typedef struct _sgx_ecdsa256_signature {
    uint8_t r[32];
    uint8_t s[32];
} sgx_ecdsa256_signature_t;

typedef struct _sgx_ecdsa256_key {
    uint8_t x[32];
    uint8_t y[32];
} sgx_ecdsa256_key_t;

typedef struct _sgx_quote_auth_data {
    /* (0) Pair of 256 bit ECDSA Signature. */
    sgx_ecdsa256_signature_t signature;

    /* (64) Pair of 256 bit ECDSA Key. */
    sgx_ecdsa256_key_t attestation_key;

    /* (128) Quoting Enclave Report Body */
    sgx_report_body_t qe_report_body;

    /* (512) Quoting Enclave Report Body Signature */
    sgx_ecdsa256_signature_t qe_report_body_signature;
} sgx_quote_auth_data_t;

// Taken from OpenEnclave's include/openenclave/attestation/sgx/evidence.h

#define OE_FORMAT_UUID_SGX_ECDSA                                          \
    {                                                                     \
        0xa3, 0xa2, 0x1e, 0x87, 0x1b, 0x4d, 0x40, 0x14, 0xb7, 0x0a, 0xa1, \
            0x25, 0xd2, 0xfb, 0xcd, 0x8c                                  \
    }

#define OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION                              \
    {                                                                     \
        0x09, 0x26, 0x8c, 0x33, 0x6e, 0x0b, 0x45, 0xe5, 0x8a, 0x27, 0x15, \
            0x64, 0x4d, 0x0e, 0xf8, 0x9a                                  \
    }

// Taken from OpenEnclave's include/openenclave/bits/evidence.h

#define OE_UUID_SIZE 16

#define OE_CLAIM_UNIQUE_ID "unique_id"

#define OE_CLAIM_CUSTOM_CLAIMS_BUFFER "custom_claims_buffer"

typedef struct _oe_uuid_t {
    uint8_t b[OE_UUID_SIZE];
} oe_uuid_t;

typedef struct _oe_claim {
    char* name;
    uint8_t* value;
    size_t value_size;
} oe_claim_t;

typedef enum _oe_policy_type {
    OE_POLICY_ENDORSEMENTS_TIME = 1,
    OE_POLICY_ENDORSEMENTS_BASELINE = 2
} oe_policy_type_t;

typedef struct _oe_policy {
    oe_policy_type_t type;
    void* policy;
    size_t policy_size;
} oe_policy_t;

// Taken from OpenEnclave's include/openenclave/attestation/attester.h

oe_result_t oe_attester_initialize(void);

oe_result_t oe_attester_select_format(const oe_uuid_t* format_ids,
                                      size_t format_ids_length,
                                      oe_uuid_t* selected_format_id);

oe_result_t oe_get_evidence(const oe_uuid_t* format_id,
                            uint32_t flags,
                            const void* custom_claims_buffer,
                            size_t custom_claims_buffer_size,
                            const void* optional_parameters,
                            size_t optional_parameters_size,
                            uint8_t** evidence_buffer,
                            size_t* evidence_buffer_size,
                            uint8_t** endorsements_buffer,
                            size_t* endorsements_buffer_size);

oe_result_t oe_free_evidence(uint8_t* evidence_buffer);

oe_result_t oe_attester_shutdown(void);

// Taken from OpenEnclave's include/openenclave/attestation/verifier.h

oe_result_t oe_verifier_initialize(void);

oe_result_t oe_verifier_get_format_settings(const oe_uuid_t* format_id,
                                            uint8_t** settings,
                                            size_t* settings_size);

oe_result_t oe_verify_evidence(const oe_uuid_t* format_id,
                               const uint8_t* evidence_buffer,
                               size_t evidence_buffer_size,
                               const uint8_t* endorsements_buffer,
                               size_t endorsements_buffer_size,
                               const oe_policy_t* policies,
                               size_t policies_size,
                               oe_claim_t** claims,
                               size_t* claims_length);

oe_result_t oe_verifier_shutdown(void);

oe_result_t oe_free_claims(oe_claim_t* claims, size_t claims_length);

// Taken from OpenEnclave's include/openenclave/enclave.h

bool oe_is_within_enclave(const void* ptr, size_t size);

bool oe_is_outside_enclave(const void* ptr, size_t size);

#endif // #ifndef __MOCK_OE_COMMON_H

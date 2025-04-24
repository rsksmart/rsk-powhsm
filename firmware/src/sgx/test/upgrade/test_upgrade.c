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

#include <stdio.h>
#include <stdbool.h>

#include "upgrade.h"

#include "hal/exceptions.h"
#include "openenclave/common.h"
#include "apdu_utils.h"

#define SRC_MRE                                \
    "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA" \
    "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA" \
    "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA" \
    "\xAA\xAA"

#define DST_MRE                                \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB" \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB" \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB" \
    "\xBB\xBB"

#define OTH_MRE                                \
    "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC" \
    "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC" \
    "\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC" \
    "\xCC\xCC"

const uint8_t src_mre[] = SRC_MRE;
const uint8_t dst_mre[] = DST_MRE;
const uint8_t oth_mre[] = OTH_MRE;

const oe_claim_t source_mrenclave_claim = {
    .name = OE_CLAIM_UNIQUE_ID,
    .value = (uint8_t*)src_mre,
    .value_size = sizeof(src_mre) - 1,
};

const oe_claim_t destination_mrenclave_claim = {
    .name = OE_CLAIM_UNIQUE_ID,
    .value = (uint8_t*)dst_mre,
    .value_size = sizeof(dst_mre) - 1,
};

const oe_claim_t other_mrenclave_claim = {
    .name = OE_CLAIM_UNIQUE_ID,
    .value = (uint8_t*)oth_mre,
    .value_size = sizeof(oth_mre) - 1,
};

// Two valid signatures and one invalid for the above
// source and destination
#define SIG_VALID_1                                                            \
    "\x30\x45\x02\x21\x00\xac\x85\x67\x3c\xae\x22\x65\x10\x07\x2e\x29\x29\x8c" \
    "\xab\x1f\x59\xa1\x0f\xd3\xb7\xe1\x31\xed\x1f\x66\x1b\x44\xd0\xff\xe3\xfd" \
    "\xe1\x02\x20\x6c\x28\x77\xa0\xa3\x21\x9d\xdb\x90\xe9\x03\x30\x9b\xbc\xc8" \
    "\x61\x00\xcd\x1a\xa8\xe9\x41\x8e\xef\xd8\x71\x63\x90\x3b\x9f\xb5\x9f"
#define SIG_VALID_2                                                            \
    "\x30\x44\x02\x20\x05\xb6\x07\x70\x3d\x82\x0f\x12\x17\x3c\xe1\x5b\x0e\x9a" \
    "\x3b\x1c\xcb\x4b\x95\x4c\xeb\x60\x67\x1d\x55\xb6\xd9\x74\xf4\x28\x4f\x56" \
    "\x02\x20\x44\xe0\x3b\xac\x7a\xa5\x21\xa6\xc3\x83\xe0\x52\x15\xf7\xa8\x46" \
    "\x7b\x45\xbc\xe1\x19\x91\x5a\x73\xc3\x90\xc3\x8d\x82\xab\xc0\x54"
#define SIG_INVALID                                                            \
    "\x30\x45\x02\x21\x00\xd4\xaa\x43\xb0\x9e\x97\xf8\x5e\xff\x1e\xd1\x9d\x01" \
    "\xa5\xe8\x1a\x64\xe9\x7a\x5f\xad\xf0\x1e\x06\x5f\x4d\x77\xcf\x9d\x60\x35" \
    "\x1f\x02\x20\x4a\xa9\xbc\xe0\x0e\x03\x09\xed\xb1\xbc\x61\xb3\xfd\x1c\xb3" \
    "\x76\x0e\x43\x44\x82\xf8\x9b\x06\x94\x04\xa2\xfd\xf5\x05\x39\xd7\x7a"

// Globals
static try_context_t G_try_last_open_context_var;
try_context_t* G_try_last_open_context = &G_try_last_open_context_var;
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

// Testing helpers
#define ASSERT_DOESNT_THROW(st)             \
    {                                       \
        BEGIN_TRY {                         \
            TRY{st} CATCH_OTHER(e) {        \
                printf("Expected no "       \
                       "exception but got " \
                       "0x%x\n",            \
                       e);                  \
                assert(false);              \
            }                               \
            FINALLY {                       \
            }                               \
        }                                   \
        END_TRY;                            \
    }

#define ASSERT_THROWS(st, ex)               \
    {                                       \
        BEGIN_TRY {                         \
            TRY {                           \
                { st; }                     \
                printf("Expected a 0x%x "   \
                       "exception but "     \
                       "none was thrown\n", \
                       ex);                 \
                assert(false);              \
            }                               \
            CATCH_OTHER(e) {                \
                if (e != ex) {              \
                    printf("Expected a "    \
                           "0x%x exception" \
                           " but got 0x%x " \
                           "instead\n",     \
                           ex,              \
                           e);              \
                    assert(false);          \
                }                           \
            }                               \
            FINALLY {                       \
            }                               \
        }                                   \
        END_TRY;                            \
    }

// Mocks
struct {
    bool seed_available;
    bool access_is_locked;
    bool migrate_export;
    bool migrate_import;
    bool evidence_generate;
    bool evidence_verify_and_extract_claims;
    char local_enclave_id;
    bool evidence_get_claim;
} G_mocks;

unsigned char* communication_get_msg_buffer() {
    return G_io_apdu_buffer;
}

size_t communication_get_msg_buffer_size() {
    return sizeof(G_io_apdu_buffer);
}

bool seed_available() {
    return G_mocks.seed_available;
}

bool access_is_locked() {
    return G_mocks.access_is_locked;
}

bool migrate_export(uint8_t* key,
                    size_t key_size,
                    uint8_t* out,
                    size_t* out_size) {
    if (!G_mocks.migrate_export)
        return false;
    assert(32 == key_size);
    assert(!memcmp("\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
                   "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"
                   "\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33"
                   "\x44\x44",
                   key,
                   key_size));
    *out_size = sizeof("data_export_result") - 1;
    memcpy(out, "data_export_result", *out_size);
    return true;
}

bool migrate_import(uint8_t* key,
                    size_t key_size,
                    uint8_t* in,
                    size_t in_size) {
    if (!G_mocks.migrate_import)
        return false;
    assert(32 == key_size);
    assert(!memcmp("\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
                   "\x22\x22\x22\x22\x22\x22\x22\x22\x22\x22"
                   "\x33\x33\x33\x33\x33\x33\x33\x33\x33\x33"
                   "\x44\x44",
                   key,
                   key_size));
    assert(in_size == sizeof("doto_import_result") - 1);
    assert(!memcmp(in, "doto_import_result", in_size));
    return true;
}

static const oe_uuid_t expected_format = {
    .b = OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};

bool evidence_generate(oe_uuid_t format_id,
                       uint8_t* ccs,
                       size_t ccs_size,
                       uint8_t** evidence_buffer,
                       size_t* evidence_buffer_size) {
    if (!G_mocks.evidence_generate)
        return false;

    assert(OE_UUID_SIZE == sizeof(expected_format));
    assert(!memcmp(&format_id, &expected_format, sizeof(expected_format)));
    assert(!ccs && ccs_size == 0);
    *evidence_buffer_size = strlen("local_evidence_mock_xxx");
    *evidence_buffer = malloc(*evidence_buffer_size);
    switch (G_mocks.local_enclave_id) {
    case 's':
        memcpy(
            *evidence_buffer, "local_evidence_mock_src", *evidence_buffer_size);
        break;
    case 'd':
        memcpy(
            *evidence_buffer, "local_evidence_mock_dst", *evidence_buffer_size);
        break;
    default:
        memcpy(
            *evidence_buffer, "local_evidence_mock_oth", *evidence_buffer_size);
        break;
    }
    return true;
}

bool evidence_verify_and_extract_claims(oe_uuid_t format_id,
                                        uint8_t* evidence_buffer,
                                        size_t evidence_buffer_size,
                                        oe_claim_t** claims,
                                        size_t* claims_size) {
    if (!G_mocks.evidence_verify_and_extract_claims)
        return false;

    assert(OE_UUID_SIZE == sizeof(expected_format));
    assert(!memcmp(&format_id, &expected_format, sizeof(expected_format)));
    assert(evidence_buffer);
    assert(evidence_buffer_size == strlen("local_evidence_mock_xxx"));
    *claims_size = strlen("local_claims_xxx");
    *claims = malloc(*claims_size);
    if (!memcmp(
            "local_evidence_mock_src", evidence_buffer, evidence_buffer_size)) {
        memcpy(*claims, "local_claims_src", *claims_size);
    } else if (!memcmp("local_evidence_mock_dst",
                       evidence_buffer,
                       evidence_buffer_size)) {
        memcpy(*claims, "local_claims_dst", *claims_size);
    } else if (!memcmp("local_evidence_mock_oth",
                       evidence_buffer,
                       evidence_buffer_size)) {
        memcpy(*claims, "local_claims_oth", *claims_size);
    } else {
        assert(false);
    }

    return true;
}

oe_claim_t* evidence_get_claim(oe_claim_t* claims,
                               size_t claims_size,
                               const char* claim_name) {
    if (!G_mocks.evidence_get_claim)
        return NULL;

    if (!strcmp(OE_CLAIM_UNIQUE_ID, claim_name)) {
        if (!memcmp(claims, "local_claims_src", claims_size)) {
            return (oe_claim_t*)&source_mrenclave_claim;
        } else if (!memcmp(claims, "local_claims_dst", claims_size)) {
            return (oe_claim_t*)&destination_mrenclave_claim;
        } else if (!memcmp(claims, "local_claims_oth", claims_size)) {
            return (oe_claim_t*)&other_mrenclave_claim;
        }
    }
    printf("Unexpected claim get\n");
    assert(false);
}

void evidence_free(uint8_t* evidence_buffer) {
    assert(evidence_buffer != NULL);
}

// Unit tests
void setup() {
    upgrade_init();
    explicit_bzero(&G_mocks, sizeof(G_mocks));
}

// Exporting
void test_do_upgrade_export_ok() {
    unsigned int rx;

    setup();
    printf("Test exporting...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.migrate_export = true;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_verify_and_extract_claims = true;
    G_mocks.local_enclave_id = 's';
    G_mocks.evidence_get_claim = true;

    ASSERT_DOESNT_THROW({
        // Start export
        SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
        assert(3 == do_upgrade(rx));
        // Spec auth
        SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
        assert(3 == do_upgrade(rx));
        ASSERT_APDU("\x80\xA6\x01");
        SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
        assert(3 == do_upgrade(rx));
        ASSERT_APDU("\x80\xA6\x00");
        // Identify peer
        SET_APDU("\x80\xA6\x03"
                 "peer-id:" DST_MRE,
                 rx);
        assert(3 == do_upgrade(rx));
        // Process data
        SET_APDU("\x80\xA6\x04", rx);
        assert(3 + sizeof("data_export_result") - 1 == do_upgrade(rx));
        ASSERT_APDU("\x80\xA6\x04"
                    "data_export_result");
    });
}

void test_do_upgrade_export_not_onboarded() {
    unsigned int rx;

    setup();
    printf("Test exporting when not onboarded...\n");

    G_mocks.seed_available = false;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            do_upgrade(rx);
        },
        0x6BEE);
}

void test_do_upgrade_export_not_unlocked() {
    unsigned int rx;

    setup();
    printf("Test exporting when not unlocked...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = true;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            do_upgrade(rx);
        },
        0x6BF1);
}

void test_do_upgrade_export_invalid_spec() {
    unsigned int rx;

    setup();
    printf("Test exporting when invalid spec given...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01"
                     "not a valid spec",
                     rx);
            do_upgrade(rx);
        },
        0x6A00);
}

void test_do_upgrade_export_spec_differs_from_local_mre() {
    unsigned int rx;

    setup();
    printf("Test exporting when local mrenclave differs from spec source...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_verify_and_extract_claims = true;
    G_mocks.local_enclave_id = 'o';
    G_mocks.evidence_get_claim = true;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            do_upgrade(rx);
        },
        0x6A01);
}

void test_do_upgrade_export_cant_get_local_evidence() {
    unsigned int rx;

    setup();
    printf("Test exporting when can't generate local evidence...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.evidence_generate = false;
    G_mocks.evidence_verify_and_extract_claims = true;
    G_mocks.local_enclave_id = 's';
    G_mocks.evidence_get_claim = true;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            do_upgrade(rx);
        },
        0x6A01);
}

void test_do_upgrade_export_cant_verify_local_evidence() {
    unsigned int rx;

    setup();
    printf("Test exporting when can't verify local evidence...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_verify_and_extract_claims = false;
    G_mocks.local_enclave_id = 's';
    G_mocks.evidence_get_claim = true;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            do_upgrade(rx);
        },
        0x6A01);
}

void test_do_upgrade_export_cant_find_local_mrenclave() {
    unsigned int rx;

    setup();
    printf("Test exporting when can't extract local mrenclave...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_verify_and_extract_claims = true;
    G_mocks.local_enclave_id = 's';
    G_mocks.evidence_get_claim = false;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            do_upgrade(rx);
        },
        0x6A01);
}

void test_do_upgrade_export_invalid_spec_auth() {
    unsigned int rx;

    setup();
    printf("Test exporting when invalid spec auth given...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_verify_and_extract_claims = true;
    G_mocks.local_enclave_id = 's';
    G_mocks.evidence_get_claim = true;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            assert(3 == do_upgrade(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == do_upgrade(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02" SIG_INVALID, rx);
            assert(3 == do_upgrade(rx));
            ASSERT_APDU("\x80\xA6\x01");
            // Attempting to identify peer fails
            SET_APDU("\x80\xA6\x03"
                     "peer-id:" DST_MRE,
                     rx);
            do_upgrade(rx);
        },
        0x6A00);
}

void test_do_upgrade_export_invalid_spec_auth_format() {
    unsigned int rx;

    setup();
    printf("Test exporting when invalid spec auth given...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_verify_and_extract_claims = true;
    G_mocks.local_enclave_id = 's';
    G_mocks.evidence_get_claim = true;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            assert(3 == do_upgrade(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == do_upgrade(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02"
                     "invalid signature",
                     rx);
            do_upgrade(rx);
        },
        0x6A02);
}

void test_do_upgrade_export_invalid_peer_id() {
    unsigned int rx;

    setup();
    printf("Test exporting when invalid peer id given...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_verify_and_extract_claims = true;
    G_mocks.local_enclave_id = 's';
    G_mocks.evidence_get_claim = true;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            assert(3 == do_upgrade(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == do_upgrade(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
            assert(3 == do_upgrade(rx));
            ASSERT_APDU("\x80\xA6\x00");
            // Identify peer
            SET_APDU("\x80\xA6\x03"
                     "invalid peer id",
                     rx);
            do_upgrade(rx);
        },
        0x6A03);
}

void test_do_upgrade_export_migrate_fails() {
    unsigned int rx;

    setup();
    printf("Test exporting...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.migrate_export = false;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_verify_and_extract_claims = true;
    G_mocks.local_enclave_id = 's';
    G_mocks.evidence_get_claim = true;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            assert(3 == do_upgrade(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == do_upgrade(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
            assert(3 == do_upgrade(rx));
            ASSERT_APDU("\x80\xA6\x00");
            // Identify peer
            SET_APDU("\x80\xA6\x03"
                     "peer-id:" DST_MRE,
                     rx);
            assert(3 == do_upgrade(rx));
            // Process data
            SET_APDU("\x80\xA6\x04", rx);
            do_upgrade(rx);
        },
        0x6A04);
}

// Importing
void test_do_upgrade_import_ok() {
    unsigned int rx;

    setup();
    printf("Test importing...\n");

    G_mocks.seed_available = false;
    G_mocks.migrate_import = true;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_verify_and_extract_claims = true;
    G_mocks.local_enclave_id = 'd';
    G_mocks.evidence_get_claim = true;

    ASSERT_DOESNT_THROW({
        // Start import
        SET_APDU("\x80\xA6\x01\x02" SRC_MRE DST_MRE, rx);
        assert(3 == do_upgrade(rx));
        // Spec auth
        SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
        assert(3 == do_upgrade(rx));
        ASSERT_APDU("\x80\xA6\x01");
        SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
        assert(3 == do_upgrade(rx));
        ASSERT_APDU("\x80\xA6\x00");
        // Identify peer
        SET_APDU("\x80\xA6\x03"
                 "peer-id:" SRC_MRE,
                 rx);
        assert(3 == do_upgrade(rx));
        // Process data
        SET_APDU("\x80\xA6\x04"
                 "doto_import_result",
                 rx);
        assert(3 == do_upgrade(rx));
    });
}

void test_do_upgrade_import_onboarded() {
    unsigned int rx;

    setup();
    printf("Test importing when onboarded...\n");

    G_mocks.seed_available = true;
    G_mocks.migrate_import = true;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x02" SRC_MRE DST_MRE, rx);
            do_upgrade(rx);
        },
        0x6BEF);
}

void test_do_upgrade_import_invalid_spec() {
    unsigned int rx;

    setup();
    printf("Test importing when invalid spec given...\n");

    G_mocks.seed_available = false;
    G_mocks.migrate_import = true;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x02"
                     "not a valid spec",
                     rx);
            do_upgrade(rx);
        },
        0x6A00);
}

void test_do_upgrade_import_spec_differs_from_local_mre() {
    unsigned int rx;

    setup();
    printf(
        "Test import when local mrenclave differs from spec destination...\n");

    G_mocks.seed_available = false;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_verify_and_extract_claims = true;
    G_mocks.local_enclave_id = 'o';
    G_mocks.evidence_get_claim = true;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x02" SRC_MRE DST_MRE, rx);
            do_upgrade(rx);
        },
        0x6A01);
}

void test_do_upgrade_import_cant_get_local_evidence() {
    unsigned int rx;

    setup();
    printf("Test import when can't generate local evidence...\n");

    G_mocks.seed_available = false;
    G_mocks.evidence_generate = false;
    G_mocks.evidence_verify_and_extract_claims = true;
    G_mocks.local_enclave_id = 'd';
    G_mocks.evidence_get_claim = true;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x02" SRC_MRE DST_MRE, rx);
            do_upgrade(rx);
        },
        0x6A01);
}

void test_do_upgrade_import_cant_verify_local_evidence() {
    unsigned int rx;

    setup();
    printf("Test import when can't verify local evidence...\n");

    G_mocks.seed_available = false;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_verify_and_extract_claims = false;
    G_mocks.local_enclave_id = 'd';
    G_mocks.evidence_get_claim = true;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x02" SRC_MRE DST_MRE, rx);
            do_upgrade(rx);
        },
        0x6A01);
}

void test_do_upgrade_import_cant_find_local_mrenclave() {
    unsigned int rx;

    setup();
    printf("Test import when can't verify local evidence...\n");

    G_mocks.seed_available = false;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_verify_and_extract_claims = true;
    G_mocks.local_enclave_id = 'd';
    G_mocks.evidence_get_claim = false;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x02" SRC_MRE DST_MRE, rx);
            do_upgrade(rx);
        },
        0x6A01);
}

void test_do_upgrade_import_invalid_peer_id() {
    unsigned int rx;

    setup();
    printf("Test importing when invalid peer id given...\n");

    G_mocks.seed_available = false;
    G_mocks.migrate_import = true;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_verify_and_extract_claims = true;
    G_mocks.local_enclave_id = 'd';
    G_mocks.evidence_get_claim = true;

    ASSERT_THROWS(
        {
            // Start import
            SET_APDU("\x80\xA6\x01\x02" SRC_MRE DST_MRE, rx);
            assert(3 == do_upgrade(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == do_upgrade(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
            assert(3 == do_upgrade(rx));
            ASSERT_APDU("\x80\xA6\x00");
            // Identify peer
            SET_APDU("\x80\xA6\x03"
                     "invalid peer id",
                     rx);
            do_upgrade(rx);
        },
        0x6A03);
}

void test_do_upgrade_import_migrate_fails() {
    unsigned int rx;

    setup();
    printf("Test importing when migration fails...\n");

    G_mocks.seed_available = false;
    G_mocks.migrate_import = false;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_verify_and_extract_claims = true;
    G_mocks.local_enclave_id = 'd';
    G_mocks.evidence_get_claim = true;

    ASSERT_THROWS(
        {
            // Start import
            SET_APDU("\x80\xA6\x01\x02" SRC_MRE DST_MRE, rx);
            assert(3 == do_upgrade(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == do_upgrade(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
            assert(3 == do_upgrade(rx));
            ASSERT_APDU("\x80\xA6\x00");
            // Identify peer
            SET_APDU("\x80\xA6\x03"
                     "peer-id:" SRC_MRE,
                     rx);
            assert(3 == do_upgrade(rx));
            // Process data
            SET_APDU("\x80\xA6\x04"
                     "doto_import_result",
                     rx);
            do_upgrade(rx);
        },
        0x6A04);
}

void test_do_upgrade_invalid_op() {
    unsigned int rx;

    setup();
    printf("Test when feeding invalid OP...\n");

    ASSERT_THROWS(
        {
            // Start import
            SET_APDU("\x80\xA6\xAB", rx);
            do_upgrade(rx);
        },
        0x6A00);
}

int main() {
    test_do_upgrade_export_ok();
    test_do_upgrade_export_not_onboarded();
    test_do_upgrade_export_not_unlocked();
    test_do_upgrade_export_invalid_spec();
    test_do_upgrade_export_spec_differs_from_local_mre();
    test_do_upgrade_export_cant_get_local_evidence();
    test_do_upgrade_export_cant_verify_local_evidence();
    test_do_upgrade_export_cant_find_local_mrenclave();
    test_do_upgrade_export_invalid_spec_auth();
    test_do_upgrade_export_invalid_spec_auth_format();
    test_do_upgrade_export_invalid_peer_id();
    test_do_upgrade_export_migrate_fails();

    test_do_upgrade_import_ok();
    test_do_upgrade_import_onboarded();
    test_do_upgrade_import_invalid_spec();
    test_do_upgrade_import_spec_differs_from_local_mre();
    test_do_upgrade_import_cant_get_local_evidence();
    test_do_upgrade_import_cant_verify_local_evidence();
    test_do_upgrade_import_cant_find_local_mrenclave();
    test_do_upgrade_import_invalid_peer_id();
    test_do_upgrade_import_migrate_fails();

    test_do_upgrade_invalid_op();

    return 0;
}

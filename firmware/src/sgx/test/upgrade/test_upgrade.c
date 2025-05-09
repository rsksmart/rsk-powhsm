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
#include "evidence.h"
#include "apdu.h"

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
const size_t mre_size = sizeof(src_mre) - 1;

const uint8_t mock_format_settings[] = {
    0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5,
    0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5,
    0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5,
    0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5,
    0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5, 0xE5,
};

#define EVIDENCE_MAGIC 0xD4
#define EVIDENCE_PRELUDE "mock_evidence:"
#define EVIDENCE_HEADER                                                \
    EVIDENCE_PRELUDE                                                   \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
    "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT"
#define EVIDENCE_OH_SIZE 200
#define EVIDENCE_SIZE (strlen(EVIDENCE_HEADER) + EVIDENCE_OH_SIZE)
#define EVIDENCE_FR_OFFSET (strlen(EVIDENCE_PRELUDE))
#define EVIDENCE_TO_OFFSET (strlen(EVIDENCE_PRELUDE) + mre_size)

const oe_claim_t source_mrenclave_claim = {
    .name = OE_CLAIM_UNIQUE_ID,
    .value = (uint8_t*)src_mre,
    .value_size = mre_size,
};

const oe_claim_t destination_mrenclave_claim = {
    .name = OE_CLAIM_UNIQUE_ID,
    .value = (uint8_t*)dst_mre,
    .value_size = mre_size,
};

const oe_claim_t other_mrenclave_claim = {
    .name = OE_CLAIM_UNIQUE_ID,
    .value = (uint8_t*)oth_mre,
    .value_size = mre_size,
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
    bool evidence_get_format_settings;
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

bool evidence_get_format_settings(evidence_format_t* format) {
    if (!G_mocks.evidence_get_format_settings)
        return false;

    assert(!memcmp(&format->id, &expected_format, sizeof(expected_format)));
    assert(!format->settings);
    assert(format->settings_size == 0);

    format->settings = malloc(sizeof(mock_format_settings));
    memcpy(
        format->settings, mock_format_settings, sizeof(mock_format_settings));
    format->settings_size = sizeof(mock_format_settings);

    return true;
}

bool evidence_generate(evidence_format_t* format,
                       uint8_t* ccs,
                       size_t ccs_size,
                       uint8_t** evidence_buffer,
                       size_t* evidence_buffer_size) {
    if (!G_mocks.evidence_generate)
        return false;

    assert(OE_UUID_SIZE == sizeof(expected_format));
    assert(!memcmp(&format->id, &expected_format, sizeof(expected_format)));
    if (!format->settings) {
        assert(format->settings_size == 0);
    } else {
        assert(sizeof(mock_format_settings) == format->settings_size);
        assert(!memcmp(mock_format_settings,
                       format->settings + 32,
                       format->settings_size - 32));
    }
    assert(!ccs && ccs_size == 0);
    *evidence_buffer_size = EVIDENCE_SIZE;
    *evidence_buffer = malloc(*evidence_buffer_size);
    memset(*evidence_buffer, EVIDENCE_MAGIC, *evidence_buffer_size);
    memcpy(*evidence_buffer, EVIDENCE_PRELUDE, strlen(EVIDENCE_PRELUDE));
    switch (G_mocks.local_enclave_id) {
    case 's':
        memcpy(*evidence_buffer + EVIDENCE_FR_OFFSET, src_mre, mre_size);
        memcpy(*evidence_buffer + EVIDENCE_TO_OFFSET,
               format->settings ? dst_mre : src_mre,
               mre_size);
        if (format->settings) {
            assert(!memcmp(dst_mre, format->settings, mre_size));
        }
        break;
    case 'd':
        memcpy(*evidence_buffer + EVIDENCE_FR_OFFSET, dst_mre, mre_size);
        memcpy(*evidence_buffer + EVIDENCE_TO_OFFSET,
               format->settings ? src_mre : dst_mre,
               mre_size);
        if (format->settings) {
            assert(!memcmp(src_mre, format->settings, mre_size));
        }
        break;
    default:
        memcpy(*evidence_buffer + EVIDENCE_FR_OFFSET, oth_mre, mre_size);
        memcpy(*evidence_buffer + EVIDENCE_TO_OFFSET, oth_mre, mre_size);
        if (format->settings) {
            assert(!memcmp(oth_mre, format->settings, mre_size));
        }
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
    if (evidence_buffer_size != EVIDENCE_SIZE)
        return false;
    if (memcmp(EVIDENCE_PRELUDE, evidence_buffer, strlen(EVIDENCE_PRELUDE)))
        return false;
    for (size_t i = strlen(EVIDENCE_PRELUDE) + 2 * mre_size; i < EVIDENCE_SIZE;
         i++)
        if (EVIDENCE_MAGIC != evidence_buffer[i])
            return false;

    *claims_size = 1;
    *claims = malloc(sizeof(oe_claim_t));
    (*claims)[0].name = OE_CLAIM_UNIQUE_ID;
    (*claims)[0].value = evidence_buffer + EVIDENCE_FR_OFFSET;
    (*claims)[0].value_size = mre_size;

    return true;
}

oe_claim_t* evidence_get_claim(oe_claim_t* claims,
                               size_t claims_size,
                               const char* claim_name) {
    if (!G_mocks.evidence_get_claim)
        return NULL;

    assert(claims_size == 1);
    assert(!strcmp(OE_CLAIM_UNIQUE_ID, claim_name));
    assert(!strcmp(OE_CLAIM_UNIQUE_ID, claims[0].name));
    return &claims[0];
}

void evidence_free(uint8_t* evidence_buffer) {
    assert(evidence_buffer != NULL);
}

// Unit tests
void setup() {
    upgrade_init();
    explicit_bzero(&G_mocks, sizeof(G_mocks));
}

void identify_self() {
    unsigned int rx;
    uint8_t buf[EVIDENCE_SIZE + 10];
    size_t total = 0;
    uint8_t* expected_fr;
    uint8_t* expected_to;

    while (true) {
        SET_APDU("\x80\xA6\x03", rx);
        rx = do_upgrade(rx);
        memcpy(buf + total, APDU_DATA_PTR, rx - 3);
        total += rx - 3;
        if (!APDU_OP())
            break;
        if (total >= EVIDENCE_SIZE) {
            printf("Self evidence too big\n");
            assert(false);
        }
    }

    assert(EVIDENCE_SIZE == total);
    assert(!memcmp(EVIDENCE_PRELUDE, buf, strlen(EVIDENCE_PRELUDE)));
    for (size_t i = strlen(EVIDENCE_HEADER); i < EVIDENCE_SIZE; i++)
        assert(EVIDENCE_MAGIC == buf[i]);
    switch (G_mocks.local_enclave_id) {
    case 's':
        expected_fr = (uint8_t*)src_mre;
        expected_to = (uint8_t*)dst_mre;
        break;
    case 'd':
        expected_fr = (uint8_t*)dst_mre;
        expected_to = (uint8_t*)src_mre;
        break;
    default:
        expected_fr = (uint8_t*)oth_mre;
        expected_to = (uint8_t*)oth_mre;
    }
    assert(!memcmp(expected_fr, buf + EVIDENCE_FR_OFFSET, mre_size));
    assert(!memcmp(expected_to, buf + EVIDENCE_TO_OFFSET, mre_size));
}

void identify_peer(bool correct) {
    unsigned int rx;
    uint8_t* peer_evidence;
    uint8_t* mre_fr;
    uint8_t* mre_to;
    uint8_t* datap;
    size_t offset;
    size_t chunk;

    peer_evidence = malloc(EVIDENCE_SIZE);
    memset(peer_evidence, EVIDENCE_MAGIC, EVIDENCE_SIZE);
    memcpy(peer_evidence, EVIDENCE_PRELUDE, strlen(EVIDENCE_PRELUDE));
    if (correct) {
        switch (G_mocks.local_enclave_id) {
        case 's':
            mre_fr = (uint8_t*)dst_mre;
            mre_to = (uint8_t*)src_mre;
            break;
        case 'd':
            mre_fr = (uint8_t*)src_mre;
            mre_to = (uint8_t*)dst_mre;
            break;
        }
        memcpy(peer_evidence + EVIDENCE_FR_OFFSET, mre_fr, mre_size);
        memcpy(peer_evidence + EVIDENCE_TO_OFFSET, mre_to, mre_size);
    }

    offset = 0;
    while (true) {
        datap = APDU_DATA_PTR;
        SET_APDU("\x80\xA6\x04", rx);
        if (offset == 0) {
            APDU_DATA_PTR[0] = (EVIDENCE_SIZE & 0xFF00) >> 8;
            APDU_DATA_PTR[1] = EVIDENCE_SIZE & 0xFF;
            datap = APDU_DATA_PTR + 2;
            rx += 2;
        }
        chunk = offset + APDU_TOTAL_DATA_SIZE <= EVIDENCE_SIZE
                    ? APDU_TOTAL_DATA_SIZE
                    : EVIDENCE_SIZE - offset;
        memcpy(datap, peer_evidence + offset, chunk);
        rx += chunk;
        offset += chunk;
        rx = do_upgrade(rx);
        if (offset < EVIDENCE_SIZE) {
            assert(APDU_OP() == 1);
        } else {
            assert(APDU_OP() == 0);
            break;
        }
    }

    free(peer_evidence);
}

// Exporting
void test_do_upgrade_export_ok() {
    unsigned int rx;

    setup();
    printf("Test exporting...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.migrate_export = true;
    G_mocks.evidence_get_format_settings = true;
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
        identify_self();
        identify_peer(true);
        // Process data
        SET_APDU("\x80\xA6\x05", rx);
        assert(3 + sizeof("data_export_result") - 1 == do_upgrade(rx));
        ASSERT_APDU("\x80\xA6\x05"
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
    G_mocks.evidence_get_format_settings = true;
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
    G_mocks.evidence_get_format_settings = true;
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
        0x6A99);
}

void test_do_upgrade_export_cant_verify_local_evidence() {
    unsigned int rx;

    setup();
    printf("Test exporting when can't verify local evidence...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.evidence_get_format_settings = true;
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
        0x6A99);
}

void test_do_upgrade_export_cant_find_local_mrenclave() {
    unsigned int rx;

    setup();
    printf("Test exporting when can't find local mrenclave...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.evidence_get_format_settings = true;
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
        0x6A99);
}

void test_do_upgrade_export_invalid_spec_auth() {
    unsigned int rx;

    setup();
    printf("Test exporting when invalid spec auth given...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.evidence_get_format_settings = true;
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
    printf("Test exporting when invalid spec auth format given...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.evidence_get_format_settings = true;
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

void test_do_upgrade_export_peer_id_empty_packet() {
    unsigned int rx;

    setup();
    printf("Test exporting when peer id wants to send an empty packet...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.evidence_get_format_settings = true;
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
            identify_self();
            SET_APDU("\x80\xA6\x04", rx);
            do_upgrade(rx);
        },
        0x6A00);
}

void test_do_upgrade_export_peer_id_packet_too_big() {
    unsigned int rx;

    setup();
    printf("Test exporting when peer id wants to send a packet too big...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.evidence_get_format_settings = true;
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
            identify_self();
            SET_APDU("\x80\xA6\x04"
                     "\x23\x28"
                     "\x01\x02",
                     rx);
            do_upgrade(rx);
        },
        0x6A00);
}

void test_do_upgrade_export_peer_id_packet_overflows() {
    unsigned int rx;

    setup();
    printf("Test exporting when peer id wants to send a packet that "
           "overflows...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.evidence_get_format_settings = true;
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
            identify_self();
            SET_APDU("\x80\xA6\x04"
                     "\x00\x05"
                     "\x01\x02",
                     rx);
            assert(3 == do_upgrade(rx));
            assert(1 == APDU_OP());
            SET_APDU("\x80\xA6\x04"
                     "\x03\x04\x05\x06",
                     rx);
            do_upgrade(rx);
        },
        0x6A00);
}

void test_do_upgrade_export_peer_id_invalid_evidence() {
    unsigned int rx;

    setup();
    printf("Test exporting when peer id wants to send invalid evidence...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.evidence_get_format_settings = true;
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
            identify_self();
            SET_APDU("\x80\xA6\x04"
                     "\x00\x07"
                     "\x01\x02\x03",
                     rx);
            assert(3 == do_upgrade(rx));
            assert(1 == APDU_OP());
            SET_APDU("\x80\xA6\x04"
                     "\xAA\xBB\xCC\xDD",
                     rx);
            do_upgrade(rx);
        },
        0x6A03);
}

void test_do_upgrade_export_invalid_peer_id() {
    unsigned int rx;

    setup();
    printf("Test exporting when invalid peer id given...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.evidence_get_format_settings = true;
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
            identify_self();
            identify_peer(false);
        },
        0x6A03);
}

void test_do_upgrade_export_migrate_fails() {
    unsigned int rx;

    setup();
    printf("Test exporting when migration fails...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;
    G_mocks.migrate_export = false;
    G_mocks.evidence_get_format_settings = true;
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
            identify_self();
            identify_peer(true);
            // Process data
            SET_APDU("\x80\xA6\x05", rx);
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
    G_mocks.evidence_get_format_settings = true;
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
        identify_self();
        identify_peer(true);
        // Process data
        SET_APDU("\x80\xA6\x05"
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
    G_mocks.evidence_get_format_settings = true;
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
    G_mocks.evidence_get_format_settings = true;
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
        0x6A99);
}

void test_do_upgrade_import_cant_verify_local_evidence() {
    unsigned int rx;

    setup();
    printf("Test import when can't verify local evidence...\n");

    G_mocks.seed_available = false;
    G_mocks.evidence_get_format_settings = true;
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
        0x6A99);
}

void test_do_upgrade_import_cant_find_local_mrenclave() {
    unsigned int rx;

    setup();
    printf("Test import when can't find local mrenclave...\n");

    G_mocks.seed_available = false;
    G_mocks.evidence_get_format_settings = true;
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
        0x6A99);
}

void test_do_upgrade_import_invalid_peer_id() {
    unsigned int rx;

    setup();
    printf("Test importing when invalid peer id given...\n");

    G_mocks.seed_available = false;
    G_mocks.migrate_import = true;
    G_mocks.evidence_get_format_settings = true;
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
            identify_self();
            identify_peer(false);
        },
        0x6A03);
}

void test_do_upgrade_import_migrate_fails() {
    unsigned int rx;

    setup();
    printf("Test importing when migration fails...\n");

    G_mocks.seed_available = false;
    G_mocks.migrate_import = false;
    G_mocks.evidence_get_format_settings = true;
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
            identify_self();
            identify_peer(true);
            // Process data
            SET_APDU("\x80\xA6\x05"
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
    test_do_upgrade_export_peer_id_empty_packet();
    test_do_upgrade_export_peer_id_packet_too_big();
    test_do_upgrade_export_peer_id_packet_overflows();
    test_do_upgrade_export_peer_id_invalid_evidence();
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

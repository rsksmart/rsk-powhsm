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

const uint8_t mock_private_key_src[] =
    "\x9a\x5c\xa4\x5d\xeb\x0b\x1d\x18\x1d\xca\x82\x41\x4d\xfb\x5f\x5f\xb5\x1a"
    "\x59\x02\xbc\xbe\x4a\xf8\x87\xc3\x2b\xd6\x08\x1d\x87\x06";
const uint8_t mock_pub_key_src[] =
    "\x03\x84\x00\xd0\xcd\x88\xa4\x2c\xe8\x28\x98\x16\xec\x37\x1c\x3c\x5d\xb4"
    "\x41\xb4\xcb\x00\xa0\xf1\xae\x84\xed\x00\xb1\xdf\x0f\x36\x21";
const uint8_t mock_private_key_dst[] =
    "\xfd\x6e\x84\xd7\x3f\x26\x61\x98\xe9\x1a\xc5\x53\x7e\x71\x9a\x96\x05\x05"
    "\x8e\x1e\x16\xb4\x67\xa8\x80\x72\x52\xba\x31\xa6\xa6\xfb";
const uint8_t mock_pub_key_dst[] =
    "\x03\x4f\xbd\xb9\x75\x85\x75\xe6\x5a\xfa\xcd\x1a\xe0\x42\xe8\x2d\xac\x60"
    "\x0d\xec\x14\xfa\x67\xf6\xc2\x7a\xed\xd4\x25\x08\x2b\x48\xfb";
const uint8_t expected_shared_key[] =
    "\x26\x38\x3c\x62\x0f\xc2\xbd\x16\xdf\x47\x42\x64\x85\x6a\x5e\x3e\x04\x1b"
    "\xe3\xb1\xa0\xb9\x3e\x9b\x23\x93\x14\x7b\xcb\xf0\x1e\x6f";
#define CLAIM_PK_SIZE 33

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
#define EVIDENCE_PK_OFFSET (strlen(EVIDENCE_PRELUDE) + mre_size * 2)

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

// Two valid signatures and one invalid for the above
// source and destination
#define SIG_VALID_1                                                            \
    "\x30\x45\x02\x21\x00\xf8\xe4\xc8\x4a\x8a\xd2\xfa\x8b\x1a\x94\x84\x65\x28" \
    "\xdf\x5e\x2a\xf2\xb6\xda\x31\x50\xfb\xa6\xf6\x82\x3f\x51\x86\x2e\x20\x95" \
    "\x2e\x02\x20\x65\x77\x92\x82\xeb\xd7\xdc\xeb\xc9\x2a\x3e\x29\x0e\x80\x52" \
    "\xf1\xdb\xc0\x26\xdb\xd5\x93\x41\x9c\x03\x47\x7e\x04\x06\xf9\x06\x4c"
#define SIG_VALID_2                                                            \
    "\x30\x45\x02\x21\x00\x98\x14\xae\xe1\x02\x20\xf0\x53\xb6\x1a\x4f\xc1\x89" \
    "\x40\x00\xee\x9e\x3a\xb3\xb6\xb5\xfc\xbf\x3c\xdc\xdc\xbb\x16\x75\x3e\x55" \
    "\xad\x02\x20\x51\xb9\x65\xbf\xc5\xa0\x52\x11\xd3\x35\xc8\x3e\x10\x16\x07" \
    "\x6a\x54\xe7\xb0\xc8\x92\x21\x60\x12\x9e\xfb\x1b\x3e\x04\xc4\x91\x21"
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
    bool random_getrandom;
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
    assert(!memcmp(expected_shared_key, key, key_size));
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
    assert(!memcmp(expected_shared_key, key, key_size));
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
        assert(!ccs && ccs_size == 0);
        assert(format->settings_size == 0);
    } else {
        assert(sizeof(mock_format_settings) == format->settings_size);
        assert(!memcmp(mock_format_settings,
                       format->settings + 32,
                       format->settings_size - 32));
        assert(ccs && ccs_size == CLAIM_PK_SIZE);
    }
    *evidence_buffer_size = EVIDENCE_SIZE;
    *evidence_buffer = malloc(*evidence_buffer_size);
    memset(*evidence_buffer, EVIDENCE_MAGIC, *evidence_buffer_size);
    memcpy(*evidence_buffer, EVIDENCE_PRELUDE, strlen(EVIDENCE_PRELUDE));
    memcpy(*evidence_buffer + EVIDENCE_PK_OFFSET, ccs, ccs_size);
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
    for (size_t i = EVIDENCE_PK_OFFSET + CLAIM_PK_SIZE; i < EVIDENCE_SIZE; i++)
        if (EVIDENCE_MAGIC != evidence_buffer[i])
            return false;

    bool has_pk = false;
    for (size_t i = EVIDENCE_PK_OFFSET; i < EVIDENCE_PK_OFFSET + CLAIM_PK_SIZE;
         i++)
        has_pk |= evidence_buffer[i] != EVIDENCE_MAGIC;

    *claims_size = has_pk ? 2 : 1;
    *claims = malloc(sizeof(oe_claim_t) * (*claims_size));
    (*claims)[0].name = OE_CLAIM_UNIQUE_ID;
    (*claims)[0].value = evidence_buffer + EVIDENCE_FR_OFFSET;
    (*claims)[0].value_size = mre_size;
    if (has_pk) {
        (*claims)[1].name = OE_CLAIM_CUSTOM_CLAIMS_BUFFER;
        (*claims)[1].value = evidence_buffer + EVIDENCE_PK_OFFSET;
        (*claims)[1].value_size = CLAIM_PK_SIZE;
    }

    return true;
}

bool evidence_free_claims(oe_claim_t* claims, size_t claims_length) {
    assert(claims);
    assert(claims_length);
    return true;
}

oe_claim_t* evidence_get_claim(oe_claim_t* claims,
                               size_t claims_size,
                               const char* claim_name) {
    if (!G_mocks.evidence_get_claim)
        return NULL;

    assert(claims_size == 1 || claims_size == 2);
    assert(!strcmp(OE_CLAIM_UNIQUE_ID, claim_name) ||
           !strcmp(OE_CLAIM_CUSTOM_CLAIMS_BUFFER, claim_name));

    if (!strcmp(OE_CLAIM_UNIQUE_ID, claim_name))
        return &claims[0];
    if (claims_size == 2 && !strcmp(OE_CLAIM_CUSTOM_CLAIMS_BUFFER, claim_name))
        return &claims[1];

    return NULL;
}

oe_claim_t* evidence_get_custom_claim(oe_claim_t* claims, size_t claims_size) {
    return evidence_get_claim(
        claims, claims_size, OE_CLAIM_CUSTOM_CLAIMS_BUFFER);
}

void evidence_free(uint8_t* evidence_buffer) {
    assert(evidence_buffer != NULL);
}

bool random_getrandom(void* buffer, size_t length) {
    assert(buffer);
    assert(length == 32);

    if (!G_mocks.random_getrandom)
        return false;

    switch (G_mocks.local_enclave_id) {
    case 's':
        memcpy(buffer, mock_private_key_src, length);
        break;
    case 'd':
        memcpy(buffer, mock_private_key_dst, length);
        break;
    default:
        memset(buffer, 0x11, length);
    }

    return true;
}

// Unit tests
void setup(char local_enclave_id) {
    upgrade_init();
    explicit_bzero(&G_mocks, sizeof(G_mocks));

    G_mocks.local_enclave_id = local_enclave_id;
    G_mocks.seed_available = local_enclave_id != 'd';
    G_mocks.access_is_locked = false;
    G_mocks.migrate_export = true;
    G_mocks.migrate_import = true;
    G_mocks.evidence_get_format_settings = true;
    G_mocks.evidence_generate = true;
    G_mocks.evidence_verify_and_extract_claims = true;
    G_mocks.evidence_get_claim = true;
    G_mocks.random_getrandom = true;
}

void identify_self() {
    unsigned int rx;
    uint8_t buf[EVIDENCE_SIZE + 10];
    size_t total = 0;
    uint8_t* expected_fr;
    uint8_t* expected_to;
    uint8_t* expected_pk;

    while (true) {
        SET_APDU("\x80\xA6\x03", rx);
        rx = upgrade_process_apdu(rx);
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
        expected_pk = (uint8_t*)mock_pub_key_src;
        break;
    case 'd':
        expected_fr = (uint8_t*)dst_mre;
        expected_to = (uint8_t*)src_mre;
        expected_pk = (uint8_t*)mock_pub_key_dst;
        break;
    default:
        assert(false);
    }
    assert(!memcmp(expected_fr, buf + EVIDENCE_FR_OFFSET, mre_size));
    assert(!memcmp(expected_to, buf + EVIDENCE_TO_OFFSET, mre_size));
    assert(!memcmp(expected_pk, buf + EVIDENCE_PK_OFFSET, CLAIM_PK_SIZE));
}

void identify_peer(bool correct, bool pubkey) {
    unsigned int rx;
    uint8_t* peer_evidence;
    uint8_t* mre_fr;
    uint8_t* mre_to;
    uint8_t* pk;
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
            pk = (uint8_t*)mock_pub_key_dst;
            break;
        case 'd':
            mre_fr = (uint8_t*)src_mre;
            mre_to = (uint8_t*)dst_mre;
            pk = (uint8_t*)mock_pub_key_src;
            break;
        }
        memcpy(peer_evidence + EVIDENCE_FR_OFFSET, mre_fr, mre_size);
        memcpy(peer_evidence + EVIDENCE_TO_OFFSET, mre_to, mre_size);
        if (pubkey)
            memcpy(peer_evidence + EVIDENCE_PK_OFFSET, pk, CLAIM_PK_SIZE);
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
        rx = upgrade_process_apdu(rx);
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
void test_upgrade_export_ok() {
    unsigned int rx;

    setup('s');
    printf("Test exporting...\n");

    ASSERT_DOESNT_THROW({
        // Start export
        SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
        assert(3 == upgrade_process_apdu(rx));
        // Spec auth
        SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
        assert(3 == upgrade_process_apdu(rx));
        ASSERT_APDU("\x80\xA6\x01");
        SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
        assert(3 == upgrade_process_apdu(rx));
        ASSERT_APDU("\x80\xA6\x00");
        identify_self();
        identify_peer(true, true);
        // Process data
        SET_APDU("\x80\xA6\x05", rx);
        assert(3 + sizeof("data_export_result") - 1 ==
               upgrade_process_apdu(rx));
        ASSERT_APDU("\x80\xA6\x05"
                    "data_export_result");
    });
}

void test_upgrade_export_twice_fails() {
    unsigned int rx;

    setup('s');
    printf("Test starting an export (import) twice in a row fails...\n");

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            assert(3 == upgrade_process_apdu(rx));

            // Starting again should throw
            SET_APDU("\x80\xA6\x01\x02" SRC_MRE DST_MRE, rx);
            assert(3 == upgrade_process_apdu(rx));
        },
        0x6A00);
}

void test_upgrade_export_not_onboarded() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when not onboarded...\n");

    G_mocks.seed_available = false;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            upgrade_process_apdu(rx);
        },
        0x6BEE);
}

void test_upgrade_export_not_unlocked() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when not unlocked...\n");

    G_mocks.access_is_locked = true;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            upgrade_process_apdu(rx);
        },
        0x6BF1);
}

void test_upgrade_export_invalid_spec() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when invalid spec given...\n");

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01"
                     "not a valid spec",
                     rx);
            upgrade_process_apdu(rx);
        },
        0x6A00);
}

void test_upgrade_export_spec_differs_from_local_mre() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when local mrenclave differs from spec source...\n");

    G_mocks.local_enclave_id = 'o';

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            upgrade_process_apdu(rx);
        },
        0x6A01);
}

void test_upgrade_export_cant_get_local_evidence() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when can't generate local evidence...\n");

    G_mocks.evidence_generate = false;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            upgrade_process_apdu(rx);
        },
        0x6A99);
}

void test_upgrade_export_cant_verify_local_evidence() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when can't verify local evidence...\n");

    G_mocks.evidence_verify_and_extract_claims = false;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            upgrade_process_apdu(rx);
        },
        0x6A99);
}

void test_upgrade_export_cant_find_local_mrenclave() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when can't find local mrenclave...\n");

    G_mocks.evidence_get_claim = false;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            upgrade_process_apdu(rx);
        },
        0x6A99);
}

void test_upgrade_export_invalid_spec_auth() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when invalid spec auth given...\n");

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            assert(3 == upgrade_process_apdu(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02" SIG_INVALID, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x01");
            // Attempting to identify peer fails
            SET_APDU("\x80\xA6\x03"
                     "peer-id:" DST_MRE,
                     rx);
            upgrade_process_apdu(rx);
        },
        0x6A00);
}

void test_upgrade_export_invalid_spec_auth_format() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when invalid spec auth format given...\n");

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            assert(3 == upgrade_process_apdu(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02"
                     "invalid signature",
                     rx);
            upgrade_process_apdu(rx);
        },
        0x6A02);
}

void test_upgrade_export_peer_id_empty_packet() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when peer id wants to send an empty packet...\n");

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            assert(3 == upgrade_process_apdu(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x00");
            identify_self();
            SET_APDU("\x80\xA6\x04", rx);
            upgrade_process_apdu(rx);
        },
        0x6A00);
}

void test_upgrade_export_peer_id_packet_too_big() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when peer id wants to send a packet too big...\n");

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            assert(3 == upgrade_process_apdu(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x00");
            identify_self();
            SET_APDU("\x80\xA6\x04"
                     "\x23\x28"
                     "\x01\x02",
                     rx);
            upgrade_process_apdu(rx);
        },
        0x6A00);
}

void test_upgrade_export_peer_id_packet_overflows() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when peer id wants to send a packet that "
           "overflows...\n");

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            assert(3 == upgrade_process_apdu(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x00");
            identify_self();
            SET_APDU("\x80\xA6\x04"
                     "\x00\x05"
                     "\x01\x02",
                     rx);
            assert(3 == upgrade_process_apdu(rx));
            assert(1 == APDU_OP());
            SET_APDU("\x80\xA6\x04"
                     "\x03\x04\x05\x06",
                     rx);
            upgrade_process_apdu(rx);
        },
        0x6A00);
}

void test_upgrade_export_peer_id_invalid_evidence() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when peer id wants to send invalid evidence...\n");

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            assert(3 == upgrade_process_apdu(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x00");
            identify_self();
            SET_APDU("\x80\xA6\x04"
                     "\x00\x07"
                     "\x01\x02\x03",
                     rx);
            assert(3 == upgrade_process_apdu(rx));
            assert(1 == APDU_OP());
            SET_APDU("\x80\xA6\x04"
                     "\xAA\xBB\xCC\xDD",
                     rx);
            upgrade_process_apdu(rx);
        },
        0x6A03);
}

void test_upgrade_export_cant_get_randomness() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when invalid peer id given...\n");

    G_mocks.random_getrandom = false;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            assert(3 == upgrade_process_apdu(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x00");
            identify_self();
        },
        0x6A99);
}

void test_upgrade_export_invalid_peer_id() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when invalid peer id given...\n");

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            assert(3 == upgrade_process_apdu(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x00");
            identify_self();
            identify_peer(false, true);
        },
        0x6A03);
}

void test_upgrade_export_peer_id_nopubkey() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when peer id has no public key...\n");

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            assert(3 == upgrade_process_apdu(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x00");
            identify_self();
            identify_peer(true, false);
        },
        0x6A03);
}

void test_upgrade_export_migrate_fails() {
    unsigned int rx;

    setup('s');
    printf("Test exporting when migration fails...\n");

    G_mocks.migrate_export = false;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
            assert(3 == upgrade_process_apdu(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x00");
            identify_self();
            identify_peer(true, true);
            // Process data
            SET_APDU("\x80\xA6\x05", rx);
            upgrade_process_apdu(rx);
        },
        0x6A04);
}

// Importing
void test_upgrade_import_ok() {
    unsigned int rx;

    setup('d');
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
        assert(3 == upgrade_process_apdu(rx));
        // Spec auth
        SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
        assert(3 == upgrade_process_apdu(rx));
        ASSERT_APDU("\x80\xA6\x01");
        SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
        assert(3 == upgrade_process_apdu(rx));
        ASSERT_APDU("\x80\xA6\x00");
        identify_self();
        identify_peer(true, true);
        // Process data
        SET_APDU("\x80\xA6\x05"
                 "doto_import_result",
                 rx);
        assert(3 == upgrade_process_apdu(rx));
    });
}

void test_upgrade_import_onboarded() {
    unsigned int rx;

    setup('d');
    printf("Test importing when onboarded...\n");

    G_mocks.seed_available = true;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x02" SRC_MRE DST_MRE, rx);
            upgrade_process_apdu(rx);
        },
        0x6BEF);
}

void test_upgrade_import_invalid_spec() {
    unsigned int rx;

    setup('d');
    printf("Test importing when invalid spec given...\n");

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x02"
                     "not a valid spec",
                     rx);
            upgrade_process_apdu(rx);
        },
        0x6A00);
}

void test_upgrade_import_spec_differs_from_local_mre() {
    unsigned int rx;

    setup('d');
    printf(
        "Test import when local mrenclave differs from spec destination...\n");

    G_mocks.local_enclave_id = 'o';

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x02" SRC_MRE DST_MRE, rx);
            upgrade_process_apdu(rx);
        },
        0x6A01);
}

void test_upgrade_import_cant_get_local_evidence() {
    unsigned int rx;

    setup('d');
    printf("Test import when can't generate local evidence...\n");

    G_mocks.evidence_generate = false;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x02" SRC_MRE DST_MRE, rx);
            upgrade_process_apdu(rx);
        },
        0x6A99);
}

void test_upgrade_import_cant_verify_local_evidence() {
    unsigned int rx;

    setup('d');
    printf("Test import when can't verify local evidence...\n");

    G_mocks.evidence_verify_and_extract_claims = false;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x02" SRC_MRE DST_MRE, rx);
            upgrade_process_apdu(rx);
        },
        0x6A99);
}

void test_upgrade_import_cant_find_local_mrenclave() {
    unsigned int rx;

    setup('d');
    printf("Test import when can't find local mrenclave...\n");

    G_mocks.evidence_get_claim = false;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01\x02" SRC_MRE DST_MRE, rx);
            upgrade_process_apdu(rx);
        },
        0x6A99);
}

void test_upgrade_import_invalid_peer_id() {
    unsigned int rx;

    setup('d');
    printf("Test importing when invalid peer id given...\n");

    ASSERT_THROWS(
        {
            // Start import
            SET_APDU("\x80\xA6\x01\x02" SRC_MRE DST_MRE, rx);
            assert(3 == upgrade_process_apdu(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x00");
            identify_self();
            identify_peer(false, true);
        },
        0x6A03);
}

void test_upgrade_import_migrate_fails() {
    unsigned int rx;

    setup('d');
    printf("Test importing when migration fails...\n");

    G_mocks.migrate_import = false;

    ASSERT_THROWS(
        {
            // Start import
            SET_APDU("\x80\xA6\x01\x02" SRC_MRE DST_MRE, rx);
            assert(3 == upgrade_process_apdu(rx));
            // Spec auth
            SET_APDU("\x80\xA6\x02" SIG_VALID_1, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x01");
            SET_APDU("\x80\xA6\x02" SIG_VALID_2, rx);
            assert(3 == upgrade_process_apdu(rx));
            ASSERT_APDU("\x80\xA6\x00");
            identify_self();
            identify_peer(true, true);
            // Process data
            SET_APDU("\x80\xA6\x05"
                     "doto_import_result",
                     rx);
            upgrade_process_apdu(rx);
        },
        0x6A04);
}

void test_upgrade_invalid_op() {
    unsigned int rx;

    setup('d');
    printf("Test when feeding invalid OP...\n");

    ASSERT_THROWS(
        {
            // Start import
            SET_APDU("\x80\xA6\xAB", rx);
            upgrade_process_apdu(rx);
        },
        0x6A00);
}

void test_upgrade_reset_ok() {
    unsigned int rx;

    setup('s');
    printf("Test upgrade_reset...\n");

    ASSERT_DOESNT_THROW({
        // Start export
        SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
        assert(3 == upgrade_process_apdu(rx));

        upgrade_reset();

        // Start again shouldn't throw due to a reset
        SET_APDU("\x80\xA6\x01\x01" SRC_MRE DST_MRE, rx);
        assert(3 == upgrade_process_apdu(rx));
    });
}

int main() {
    test_upgrade_export_ok();
    test_upgrade_export_twice_fails();
    test_upgrade_export_not_onboarded();
    test_upgrade_export_not_unlocked();
    test_upgrade_export_invalid_spec();
    test_upgrade_export_spec_differs_from_local_mre();
    test_upgrade_export_cant_get_local_evidence();
    test_upgrade_export_cant_verify_local_evidence();
    test_upgrade_export_cant_find_local_mrenclave();
    test_upgrade_export_invalid_spec_auth();
    test_upgrade_export_invalid_spec_auth_format();
    test_upgrade_export_cant_get_randomness();
    test_upgrade_export_invalid_peer_id();
    test_upgrade_export_peer_id_nopubkey();
    test_upgrade_export_peer_id_empty_packet();
    test_upgrade_export_peer_id_packet_too_big();
    test_upgrade_export_peer_id_packet_overflows();
    test_upgrade_export_peer_id_invalid_evidence();
    test_upgrade_export_migrate_fails();

    test_upgrade_import_ok();
    test_upgrade_import_onboarded();
    test_upgrade_import_invalid_spec();
    test_upgrade_import_spec_differs_from_local_mre();
    test_upgrade_import_cant_get_local_evidence();
    test_upgrade_import_cant_verify_local_evidence();
    test_upgrade_import_cant_find_local_mrenclave();
    test_upgrade_import_invalid_peer_id();
    test_upgrade_import_migrate_fails();

    test_upgrade_invalid_op();

    test_upgrade_reset_ok();

    return 0;
}

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
} G_mocks;

unsigned char* communication_get_msg_buffer() {
    return G_io_apdu_buffer;
}

bool seed_available() {
    return G_mocks.seed_available;
}

bool access_is_locked() {
    return G_mocks.access_is_locked;
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

    ASSERT_DOESNT_THROW({
        // Start export
        SET_APDU("\x80\xA6\x01" SRC_MRE DST_MRE, rx);
        assert(3 == do_upgrade(rx));
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
            SET_APDU("\x80\xA6\x01" SRC_MRE DST_MRE, rx);
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
            SET_APDU("\x80\xA6\x01" SRC_MRE DST_MRE, rx);
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
            SET_APDU("\x80\xA6\x01"
                     "not a valid spec",
                     rx);
            do_upgrade(rx);
        },
        0x6A01);
}

void test_do_upgrade_export_invalid_peer_id() {
    unsigned int rx;

    setup();
    printf("Test exporting when invalid peer id given...\n");

    G_mocks.seed_available = true;
    G_mocks.access_is_locked = false;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x01" SRC_MRE DST_MRE, rx);
            assert(3 == do_upgrade(rx));
            SET_APDU("\x80\xA6\x03"
                     "invalid peer id",
                     rx);
            do_upgrade(rx);
        },
        0x6A02);
}

// Importing
void test_do_upgrade_import_ok() {
    unsigned int rx;

    setup();
    printf("Test importing...\n");

    G_mocks.seed_available = false;

    ASSERT_DOESNT_THROW({
        // Start import
        SET_APDU("\x80\xA6\x02" SRC_MRE DST_MRE, rx);
        assert(3 == do_upgrade(rx));
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

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x02" SRC_MRE DST_MRE, rx);
            do_upgrade(rx);
        },
        0x6BEF);
}

void test_do_upgrade_import_invalid_spec() {
    unsigned int rx;

    setup();
    printf("Test importing when invalid spec given...\n");

    G_mocks.seed_available = false;

    ASSERT_THROWS(
        {
            // Start export
            SET_APDU("\x80\xA6\x02"
                     "not a valid spec",
                     rx);
            do_upgrade(rx);
        },
        0x6A01);
}

void test_do_upgrade_import_invalid_peer_id() {
    unsigned int rx;

    setup();
    printf("Test importing when invalid peer id given...\n");

    G_mocks.seed_available = false;

    ASSERT_THROWS(
        {
            // Start import
            SET_APDU("\x80\xA6\x02" SRC_MRE DST_MRE, rx);
            assert(3 == do_upgrade(rx));
            SET_APDU("\x80\xA6\x03"
                     "invalid peer id",
                     rx);
            do_upgrade(rx);
        },
        0x6A02);
}

void test_do_upgrade_import_invalid_data() {
    unsigned int rx;

    setup();
    printf("Test importing when invalid data given...\n");

    G_mocks.seed_available = false;

    ASSERT_THROWS(
        {
            // Start import
            SET_APDU("\x80\xA6\x02" SRC_MRE DST_MRE, rx);
            assert(3 == do_upgrade(rx));
            SET_APDU("\x80\xA6\x03"
                     "peer-id:" SRC_MRE,
                     rx);
            assert(3 == do_upgrade(rx));
            SET_APDU("\x80\xA6\x04"
                     "invalid data",
                     rx);
            do_upgrade(rx);
        },
        0x6A03);
}

void test_do_upgrade_invalid_op() {
    unsigned int rx;

    setup();
    printf("Test when feeding invalid OP...\n");

    G_mocks.seed_available = false;

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
    test_do_upgrade_export_invalid_peer_id();

    test_do_upgrade_import_ok();
    test_do_upgrade_import_onboarded();
    test_do_upgrade_import_invalid_spec();
    test_do_upgrade_import_invalid_peer_id();
    test_do_upgrade_import_invalid_data();

    test_do_upgrade_invalid_op();

    return 0;
}

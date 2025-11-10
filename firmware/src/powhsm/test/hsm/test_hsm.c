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

#include "hsm.h"
#include "mem.h"
#include "apdu.h"
#include "hal/exceptions.h"
#include "assert_utils.h"
#include "apdu_utils.h"

// Global mock variables
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

mem_t mem;
sess_per_mem_t sess_per_mem;

struct {
    bool seed_available;
    bool access_is_locked;
    bool pathRequireAuth;
    bool pathDontRequireAuth;
    bool seed_derive_pubkey_fail;
    bool mock_processor_fail;
    uint8_t mock_processor_step;
} G_mocks;

struct {
    bool bc_init_state;
    bool bc_init_advance;
    bool bc_init_upd_ancestor;
    bool platform_request_exit;
    bool bc_backup_partial_state;
} G_called;

// Mocked constant values
#define MOCK_PATH                              \
    "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA" \
    "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
#define EXPECTED_PUBKEY                        \
    "\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB" \
    "\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB\xAB"

// Mock functions
bool seed_available() {
    return G_mocks.seed_available;
}

bool seed_derive_pubkey(uint32_t* path,
                        uint8_t path_length,
                        uint8_t* pubkey_out,
                        uint8_t* pubkey_out_length) {
    assert(*pubkey_out_length == APDU_TOTAL_DATA_SIZE_OUT + DATA);

    if (G_mocks.seed_derive_pubkey_fail)
        return false;

    size_t path_bytes = path_length * sizeof(path[0]);
    for (size_t i = 0; i < path_bytes; i++)
        pubkey_out[i] = ((uint8_t*)path)[i] + 1;
    *pubkey_out_length = path_bytes;

    return true;
}

void bc_init_state() {
    G_called.bc_init_state = true;
}

void bc_init_advance() {
    G_called.bc_init_advance = true;
}

void bc_init_upd_ancestor() {
    G_called.bc_init_upd_ancestor = true;
}

void platform_memmove(void* dst, const void* src, unsigned int length) {
    memmove(dst, src, length);
}

void platform_request_exit() {
    G_called.platform_request_exit = true;
}

unsigned char* communication_get_msg_buffer() {
    return G_io_apdu_buffer;
}

size_t communication_get_msg_buffer_size() {
    return sizeof(G_io_apdu_buffer);
}

bool access_is_locked() {
    return G_mocks.access_is_locked;
}

bool pathRequireAuth(unsigned char* path) {
    return G_mocks.pathRequireAuth;
}

bool pathDontRequireAuth(unsigned char* path) {
    return G_mocks.pathDontRequireAuth;
}

unsigned int mock_processor(volatile unsigned int rx) {
    if (G_mocks.mock_processor_fail)
        THROW(0x6500 + APDU_OP() + G_mocks.mock_processor_step);

    for (size_t i = 0; i < rx - DATA; i++)
        APDU_DATA_PTR[i] += G_mocks.mock_processor_step;
    APDU_DATA_PTR[rx - DATA] = 0xDD;
    APDU_DATA_PTR[rx - DATA + 1] = 0xEE;
    return rx + 2;
}

unsigned int auth_sign(volatile unsigned int rx) {
    G_mocks.mock_processor_step = 1;
    return mock_processor(rx);
}

unsigned int get_attestation(volatile unsigned int rx, att_t* att_ctx) {
    assert(att_ctx == &mem.att);
    G_mocks.mock_processor_step = 2;
    return mock_processor(rx);
}

unsigned int get_heartbeat(volatile unsigned int rx,
                           heartbeat_t* heartbeat_ctx) {
    assert(heartbeat_ctx == &heartbeat);
    G_mocks.mock_processor_step = 3;
    return mock_processor(rx);
}

unsigned int bc_get_state(volatile unsigned int rx) {
    G_mocks.mock_processor_step = 4;
    return mock_processor(rx);
}

unsigned int bc_reset_state(volatile unsigned int rx) {
    G_mocks.mock_processor_step = 5;
    return mock_processor(rx);
}

unsigned int bc_advance(volatile unsigned int rx) {
    G_mocks.mock_processor_step = 6;
    return mock_processor(rx);
}

unsigned int bc_advance_get_params() {
    G_mocks.mock_processor_step = 7;
    return mock_processor(5);
}

unsigned int bc_upd_ancestor(volatile unsigned int rx) {
    G_mocks.mock_processor_step = 8;
    return mock_processor(rx);
}

void bc_backup_partial_state() {
    G_called.bc_backup_partial_state = true;
}

// Assertion helpers
void assert_bc_state_reset() {
    for (size_t i = 0; i < sizeof(bc_st_updating); i++)
        assert(!((uint8_t*)&bc_st_updating)[i]);
    bc_st_updating.in_progress = true;
}

void assert_bc_state_kept() {
    assert(bc_st_updating.in_progress);
}

void assert_state_reset() {
    assert(G_called.bc_init_advance);
    assert(G_called.bc_init_upd_ancestor);
    for (size_t i = 0; i < sizeof(mem); i++)
        assert(!((uint8_t*)&mem)[i]);

    // Mark state as "dirty" for next tests
    ((uint8_t*)&mem)[0] = 1;
    G_called.bc_init_advance = false;
    G_called.bc_init_upd_ancestor = false;
}

void assert_state_kept() {
    assert(!G_called.bc_init_advance);
    assert(!G_called.bc_init_upd_ancestor);
    assert(((uint8_t*)&mem)[0]);
}

#define ASSERT_PROCESS_APDU(in_literal, out_literal) \
    {                                                \
        unsigned int __rx__;                         \
        SET_APDU(in_literal, __rx__);                \
        __rx__ = hsm_process_apdu(__rx__);           \
        printf("=> ");                               \
        for (int i = 0; i < __rx__; i++)             \
            printf("%02X", G_io_apdu_buffer[i]);     \
        printf("\n");                                \
        ASSERT_APDU_RX(out_literal, __rx__);         \
    }

// Unit tests
void setup() {
    memset(&mem, 0, sizeof(mem));
    memset(&G_mocks, 0, sizeof(G_mocks));
    memset(&G_called, 0, sizeof(G_called));
    CLEAR_APDU();
}

void setup_and_init() {
    setup();
    hsm_init();
    // Mark state as "dirty"
    ASSERT_PROCESS_APDU("\x80\x43", "\x80\x03\x90\x00");
    ((uint8_t*)&mem)[0] = 1;
    bc_st_updating.in_progress = true;
}

void test_require_onboarded_pass() {
    printf("Test REQUIRE_ONBOARDED() pass...\n");
    setup();
    G_mocks.seed_available = true;
    BEGIN_TRY {
        TRY {
            REQUIRE_ONBOARDED();
        }
        CATCH_ALL {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_require_onboarded_fail() {
    printf("Test REQUIRE_ONBOARDED() fail...\n");
    setup();
    G_mocks.seed_available = false;
    BEGIN_TRY {
        TRY {
            REQUIRE_ONBOARDED();
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(ERR_DEVICE_NOT_ONBOARDED == e);
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_require_not_onboarded_pass() {
    printf("Test REQUIRE_NOT_ONBOARDED() pass...\n");
    setup();
    G_mocks.seed_available = false;
    BEGIN_TRY {
        TRY {
            REQUIRE_NOT_ONBOARDED();
        }
        CATCH_ALL {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_require_not_onboarded_fail() {
    printf("Test REQUIRE_NOT_ONBOARDED() fail...\n");
    setup();
    G_mocks.seed_available = true;
    BEGIN_TRY {
        TRY {
            REQUIRE_NOT_ONBOARDED();
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(ERR_DEVICE_ONBOARDED == e);
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_require_unlocked_pass() {
    printf("Test REQUIRE_UNLOCKED() pass...\n");
    setup();
    G_mocks.access_is_locked = false;
    BEGIN_TRY {
        TRY {
            REQUIRE_UNLOCKED();
        }
        CATCH_ALL {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_require_unlocked_fail() {
    printf("Test REQUIRE_UNLOCKED() fail...\n");
    setup();
    G_mocks.access_is_locked = true;
    BEGIN_TRY {
        TRY {
            REQUIRE_UNLOCKED();
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(ERR_DEVICE_LOCKED == e);
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_hsm_init() {
    printf("Test hsm_init()...\n");
    setup();

    hsm_init();

    assert(!hsm_exit_requested());
    assert(G_called.bc_init_state);
}

void test_hsm_process_apdu_no_rx() {
    printf("Test hsm_process_apdu() with empty APDU...\n");
    setup_and_init();
    unsigned int rx;

    rx = hsm_process_apdu(0);
    ASSERT_APDU_RX("\x69\x82", rx);
    assert_state_reset();
    assert_bc_state_reset();
}

void test_hsm_process_apdu_rx_too_big() {
    printf("Test hsm_process_apdu() with APDU that's too big...\n");
    setup_and_init();
    unsigned int rx;

    rx = hsm_process_apdu(sizeof(G_io_apdu_buffer) + 1);
    ASSERT_APDU_RX("\x69\x82", rx);
    assert_state_reset();
    assert_bc_state_reset();
}

void test_hsm_process_apdu_invalid_cla() {
    printf("Test hsm_process_apdu() with invalid CLA...\n");
    setup_and_init();
    unsigned int rx;

    SET_APDU("\x79\x12\x34\x56\x78\x90", rx);
    rx = hsm_process_apdu(rx);
    assert(rx == 2);
    ASSERT_APDU("\x6E\x11\x34\x56\x78\x90");
    assert_state_reset();
    assert_bc_state_reset();

    // Test clearing of minimum arbitrarily readable excedent APDU bytes
    SET_APDU("\x79\x12\x34\x56", rx);
    rx = hsm_process_apdu(3);
    assert(rx == 2);
    ASSERT_APDU("\x6E\x11\x34\x00");
}

void test_hsm_process_apdu_instruction_not_supported() {
    printf("Test hsm_process_apdu() with unsupported instruction...\n");
    setup_and_init();

    ASSERT_PROCESS_APDU("\x80\x99", "\x6D\x00");
    assert_state_reset();
    assert_bc_state_reset();
}

external_processor_result_t test_hsm_process_apdu_ext_processor_handled__ep(
    unsigned int rx) {
    external_processor_result_t result;
    ASSERT_APDU_RX("\x80\x99\x00", rx);
    SET_APDU_OP(0x11);
    memcpy(APDU_DATA_PTR, "\xaa\xbb\xcc", 3);
    result.handled = true;
    result.tx = TX_FOR_DATA_SIZE(3);
    return result;
}

void test_hsm_process_apdu_ext_processor_handled() {
    printf("Test hsm_process_apdu() with external processor marked as "
           "handled...\n");
    setup_and_init();

    hsm_set_external_processor(
        &test_hsm_process_apdu_ext_processor_handled__ep);

    ASSERT_PROCESS_APDU("\x80\x99\x00", "\x80\x99\x11\xaa\xbb\xcc\x90\x00");
}

external_processor_result_t test_hsm_process_apdu_ext_processor_not_handled__ep(
    unsigned int rx) {
    external_processor_result_t result;
    ASSERT_APDU_RX("\x80\x99\x00", rx);
    SET_APDU_OP(0x11);
    memcpy(APDU_DATA_PTR, "\xaa\xbb\xcc", 3);
    result.handled = false;
    result.tx = TX_FOR_DATA_SIZE(3);
    return result;
}

void test_hsm_process_apdu_ext_processor_not_handled() {
    printf("Test hsm_process_apdu() with external processor marked as not "
           "handled...\n");
    setup_and_init();

    hsm_set_external_processor(
        &test_hsm_process_apdu_ext_processor_not_handled__ep);

    ASSERT_PROCESS_APDU("\x80\x99\x00", "\x6D\x00");
    assert_state_reset();
}

void test_hsm_process_apdu__rsk_mode_cmd() {
    printf("Test hsm_process_apdu() with RSK_MODE_CMD...\n");
    setup_and_init();

    ASSERT_PROCESS_APDU("\x80\x99", "\x6D\x00");
    assert_state_reset();
    assert_bc_state_reset();
    ASSERT_PROCESS_APDU("\x80\x43", "\x80\x03\x90\x00");
    assert_state_reset();
    assert_bc_state_kept();
    ASSERT_PROCESS_APDU("\x80\x43", "\x80\x03\x90\x00");
    assert_state_kept();
    assert_bc_state_kept();
}

void test_hsm_process_apdu__rsk_is_onboard() {
    printf("Test hsm_process_apdu() with RSK_IS_ONBOARD...\n");
    setup_and_init();

    G_mocks.seed_available = 1;
    ASSERT_PROCESS_APDU("\x80\x06", "\x80\x01\x05\x06\x01\x90\x00");
    assert_state_reset();
    assert_bc_state_kept();
    G_mocks.seed_available = 0;
    ASSERT_PROCESS_APDU("\x80\x06", "\x80\x00\x05\x06\x01\x90\x00");
    assert_state_kept();
    assert_bc_state_kept();
}

#define ASSERT_REQUIRE_UNLOCKED(apdu_literal)          \
    {                                                  \
        G_mocks.access_is_locked = true;               \
        ASSERT_PROCESS_APDU(apdu_literal, "\x6B\xF1"); \
        G_mocks.access_is_locked = false;              \
    }

#define ASSERT_REQUIRE_ONBOARDED(apdu_literal)         \
    {                                                  \
        G_mocks.seed_available = false;                \
        ASSERT_PROCESS_APDU(apdu_literal, "\x6B\xEE"); \
        G_mocks.seed_available = true;                 \
    }

void test_hsm_process_apdu__ins_get_public_key() {
    printf("Test hsm_process_apdu() with INS_GET_PUBLIC_KEY...\n");
    setup_and_init();

    ASSERT_REQUIRE_UNLOCKED("\x80\x04");
    ASSERT_REQUIRE_ONBOARDED("\x80\x04");

    assert_state_reset();
    assert_bc_state_reset();

    ASSERT_PROCESS_APDU("\x80\x04\xAA\xBB", "\x6A\x87");

    G_mocks.pathDontRequireAuth = false;
    G_mocks.pathRequireAuth = false;
    ASSERT_PROCESS_APDU("\x80\x04\x00" MOCK_PATH, "\x6A\x8F");

    G_mocks.pathRequireAuth = true;
    G_mocks.seed_derive_pubkey_fail = true;
    ASSERT_PROCESS_APDU("\x80\x04\x00" MOCK_PATH, "\x6A\x99");

    G_mocks.seed_derive_pubkey_fail = false;
    ASSERT_PROCESS_APDU("\x80\x04\x00" MOCK_PATH, EXPECTED_PUBKEY "\x90\x00");
}

void test_hsm_process_apdu__ins_sign() {
    printf("Test hsm_process_apdu() with INS_SIGN...\n");
    setup_and_init();

    ASSERT_REQUIRE_UNLOCKED("\x80\x02");
    ASSERT_REQUIRE_ONBOARDED("\x80\x02");

    assert_state_reset();
    assert_bc_state_reset();

    G_mocks.mock_processor_fail = true;
    ASSERT_PROCESS_APDU("\x80\x02\x55", "\x65\x56");

    G_mocks.mock_processor_fail = false;
    ASSERT_PROCESS_APDU("\x80\x02\x33\x10\x12\x14",
                        "\x80\x02\x33\x11\x13\x15\xDD\xEE\x90\x00");
}

void test_hsm_process_apdu__ins_attestation() {
    printf("Test hsm_process_apdu() with INS_ATTESTATION...\n");
    setup_and_init();

    ASSERT_REQUIRE_UNLOCKED("\x80\x50");
    ASSERT_REQUIRE_ONBOARDED("\x80\x50");

    assert_state_reset();
    assert_bc_state_reset();

    G_mocks.mock_processor_fail = true;
    ASSERT_PROCESS_APDU("\x80\x50\x22", "\x65\x24");

    G_mocks.mock_processor_fail = false;
    ASSERT_PROCESS_APDU("\x80\x50\x11\x45\x46\x47\x48",
                        "\x80\x50\x11\x47\x48\x49\x4A\xDD\xEE\x90\x00");
}

void test_hsm_process_apdu__ins_heartbeat() {
    printf("Test hsm_process_apdu() with INS_HEARTBEAT...\n");
    setup_and_init();

    ASSERT_REQUIRE_UNLOCKED("\x80\x60");
    ASSERT_REQUIRE_ONBOARDED("\x80\x60");

    assert_state_reset();
    assert_bc_state_reset();

    G_mocks.mock_processor_fail = true;
    ASSERT_PROCESS_APDU("\x80\x60\x22", "\x65\x25");

    G_mocks.mock_processor_fail = false;
    ASSERT_PROCESS_APDU("\x80\x60\x51\x00\x05\x08\x0A",
                        "\x80\x60\x51\x03\x08\x0B\x0D\xDD\xEE\x90\x00");
}

void test_hsm_process_apdu__ins_get_state() {
    printf("Test hsm_process_apdu() with INS_GET_STATE...\n");
    setup_and_init();

    ASSERT_REQUIRE_UNLOCKED("\x80\x20");
    ASSERT_REQUIRE_ONBOARDED("\x80\x20");

    assert_state_reset();
    assert_bc_state_reset();

    G_mocks.mock_processor_fail = true;
    ASSERT_PROCESS_APDU("\x80\x20\x44", "\x65\x48");

    G_mocks.mock_processor_fail = false;
    ASSERT_PROCESS_APDU("\x80\x20\x76\x32\x41",
                        "\x80\x20\x76\x36\x45\xDD\xEE\x90\x00");
}

void test_hsm_process_apdu__ins_reset_state() {
    printf("Test hsm_process_apdu() with INS_RESET_STATE...\n");
    setup_and_init();

    ASSERT_REQUIRE_UNLOCKED("\x80\x21");
    ASSERT_REQUIRE_ONBOARDED("\x80\x21");

    assert_state_reset();
    assert_bc_state_reset();

    G_mocks.mock_processor_fail = true;
    ASSERT_PROCESS_APDU("\x80\x21\x20", "\x65\x25");

    G_mocks.mock_processor_fail = false;
    ASSERT_PROCESS_APDU("\x80\x21\x55\x65", "\x80\x21\x55\x6A\xDD\xEE\x90\x00");
}

void test_hsm_process_apdu__ins_advance() {
    printf("Test hsm_process_apdu() with INS_ADVANCE...\n");
    setup_and_init();

    ASSERT_REQUIRE_UNLOCKED("\x80\x10");
    ASSERT_REQUIRE_ONBOARDED("\x80\x10");

    assert_state_reset();
    assert_bc_state_reset();

    G_mocks.mock_processor_fail = true;
    ASSERT_PROCESS_APDU("\x80\x10\x15", "\x65\x1B");

    G_mocks.mock_processor_fail = false;
    ASSERT_PROCESS_APDU("\x80\x10\x33\x20\x21\x22",
                        "\x80\x10\x33\x26\x27\x28\xDD\xEE\x90\x00");
}

void test_hsm_process_apdu__ins_advance_params() {
    printf("Test hsm_process_apdu() with INS_ADVANCE_PARAMS...\n");
    setup_and_init();

    ASSERT_REQUIRE_UNLOCKED("\x80\x11");
    ASSERT_REQUIRE_ONBOARDED("\x80\x11");

    assert_state_reset();
    assert_bc_state_reset();

    G_mocks.mock_processor_fail = true;
    ASSERT_PROCESS_APDU("\x80\x11\x34", "\x65\x3B");

    G_mocks.mock_processor_fail = false;
    ASSERT_PROCESS_APDU("\x80\x11\x12\x05\x07\xAA\xBB",
                        "\x80\x11\x12\x0C\x0E\xDD\xEE\x90\x00");
}

void test_hsm_process_apdu__ins_upd_ancestor() {
    printf("Test hsm_process_apdu() with INS_UPD_ANCESTOR...\n");
    setup_and_init();

    ASSERT_REQUIRE_UNLOCKED("\x80\x30");
    ASSERT_REQUIRE_ONBOARDED("\x80\x30");

    assert_state_reset();
    assert_bc_state_reset();

    G_mocks.mock_processor_fail = true;
    ASSERT_PROCESS_APDU("\x80\x30\x08", "\x65\x10");

    G_mocks.mock_processor_fail = false;
    ASSERT_PROCESS_APDU("\x80\x30\x55\x67\x70",
                        "\x80\x30\x55\x6F\x78\xDD\xEE\x90\x00");
}

void test_hsm_process_apdu__ins_exit() {
    printf("Test hsm_process_apdu() with INS_EXIT...\n");
    setup_and_init();

    ASSERT_REQUIRE_UNLOCKED("\x80\xFF");

    assert(!hsm_exit_requested());
    assert(!G_called.platform_request_exit);
    assert(!G_called.bc_backup_partial_state);
    ASSERT_PROCESS_APDU("\x80\xFF\x23", "\x80\xFF\x23\x90\x00");
    assert(hsm_exit_requested());
    assert(G_called.platform_request_exit);
    assert(G_called.bc_backup_partial_state);
}

void test_hsm_reset_if_starting() {
    printf("Test hsm_reset_if_starting()...\n");
    setup();
    hsm_reset_if_starting(12);
    assert_state_reset();
    hsm_reset_if_starting(12);
    assert_state_kept();
    hsm_reset_if_starting(13);
    assert_state_reset();
    hsm_reset_if_starting(13);
    assert_state_kept();
    hsm_reset_if_starting(12);
    assert_state_reset();
}

int main() {
    test_require_onboarded_pass();
    test_require_onboarded_fail();

    test_require_not_onboarded_pass();
    test_require_not_onboarded_fail();

    test_require_unlocked_pass();
    test_require_unlocked_fail();

    test_hsm_init();

    test_hsm_process_apdu_no_rx();
    test_hsm_process_apdu_rx_too_big();
    test_hsm_process_apdu_invalid_cla();

    test_hsm_process_apdu_instruction_not_supported();

    test_hsm_process_apdu_ext_processor_handled();
    test_hsm_process_apdu_ext_processor_not_handled();

    test_hsm_process_apdu__rsk_mode_cmd();
    test_hsm_process_apdu__rsk_is_onboard();

    test_hsm_process_apdu__ins_get_public_key();
    test_hsm_process_apdu__ins_sign();
    test_hsm_process_apdu__ins_attestation();
    test_hsm_process_apdu__ins_heartbeat();
    test_hsm_process_apdu__ins_get_state();
    test_hsm_process_apdu__ins_reset_state();
    test_hsm_process_apdu__ins_advance();
    test_hsm_process_apdu__ins_advance_params();
    test_hsm_process_apdu__ins_upd_ancestor();
    test_hsm_process_apdu__ins_exit();

    test_hsm_reset_if_starting();

    return 0;
}

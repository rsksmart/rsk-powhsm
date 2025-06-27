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

#include "meta_bc.h"

#include "apdu.h"
#include "hal/exceptions.h"
#include "apdu_utils.h"
#include "assert_utils.h"

// Shorthands
#define BS_A "\xAA\xAA\xBB\xBB\xCC\xCC\xDD\xDD\xEE\xEE"
#define BS_B "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99"

#define BS_A_50 BS_A BS_A BS_A BS_A BS_A
#define BS_B_50 BS_B BS_B BS_B BS_B BS_B
#define BS_A_100 BS_A_50 BS_A_50
#define BS_B_100 BS_B_50 BS_B_50

// Utils
#define ASSERT_BC_REQUEST(ix, str_literal)                                \
    {                                                                     \
        assert(bc_request_count > ix);                                    \
        assert(sizeof(str_literal) - 1 == bc_requests[ix].rx);            \
        assert(!memcmp(                                                   \
            bc_requests[ix].apdu, str_literal, sizeof(str_literal) - 1)); \
    }

// Globals
static try_context_t G_try_last_open_context_var;
try_context_t* G_try_last_open_context = &G_try_last_open_context_var;
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

// Function mocks
static unsigned char* communication_msg_buffer;
static size_t communication_msg_buffer_size;
static bool bc_change_op;
static unsigned char bc_tx_len;
static unsigned char bc_force_tx_len;
static unsigned int bc_force_tx_len_when_btpleq;
static unsigned int bc_throw;
static unsigned int bc_total_bytes_to_process;
static bool bc_add_extra_response;
static bool bc_change_cla;
static bool bc_change_cmd;

static unsigned communication_set_msg_buffer_callcount;
static unsigned bc_advance_callcount;
static unsigned bc_upd_ancestor_callcount;

typedef struct {
    unsigned int rx;
    unsigned char apdu[100];
} request_t;
static request_t bc_requests[1000];
static unsigned bc_request_count;

static unsigned int bc_op(volatile unsigned int rx) {
    bc_requests[bc_request_count].rx = rx;
    bc_requests[bc_request_count].rx = rx;
    memcpy(bc_requests[bc_request_count].apdu, communication_msg_buffer, rx);
    bc_request_count++;
    if (bc_total_bytes_to_process)
        bc_total_bytes_to_process -= (rx - 3);

    if (bc_throw)
        THROW(bc_throw);
    if (bc_change_op && !bc_total_bytes_to_process)
        SET_APDU_OP(APDU_OP() + 0x11);
    if (bc_force_tx_len &&
        bc_total_bytes_to_process <= bc_force_tx_len_when_btpleq) {
        SET_APDU_TXLEN(bc_force_tx_len);
    } else if (bc_total_bytes_to_process) {
        SET_APDU_TXLEN(
            bc_total_bytes_to_process > 80 ? 80 : bc_total_bytes_to_process);
    } else if (bc_tx_len) {
        SET_APDU_TXLEN(bc_tx_len);
    }
    // Optional tweaks to trigger error handling behaviors
    if (bc_add_extra_response)
        APDU_DATA_PTR[1] = 0x33;
    if (bc_change_cla)
        SET_APDU_AT(0, 0x70);
    if (bc_change_cmd)
        SET_APDU_AT(1, 0x88);
    return ((bc_force_tx_len || bc_total_bytes_to_process || bc_tx_len)
                ? TX_FOR_TXLEN()
                : TX_NO_DATA()) +
           (bc_add_extra_response ? 1 : 0);
}

unsigned int bc_advance(volatile unsigned int rx) {
    bc_advance_callcount++;
    return bc_op(rx);
}

unsigned int bc_upd_ancestor(volatile unsigned int rx) {
    bc_upd_ancestor_callcount++;
    return bc_op(rx);
}

unsigned char* communication_get_msg_buffer() {
    return communication_msg_buffer;
}

size_t communication_get_msg_buffer_size() {
    return communication_msg_buffer_size;
}

bool communication_set_msg_buffer(unsigned char* msg_buffer,
                                  size_t msg_buffer_size) {
    communication_msg_buffer = msg_buffer;
    communication_msg_buffer_size = msg_buffer_size;
    communication_set_msg_buffer_callcount++;
    return true;
}

void setup() {
    communication_msg_buffer = G_io_apdu_buffer;
    communication_msg_buffer_size = sizeof(G_io_apdu_buffer);
    communication_set_msg_buffer_callcount = 0;
    bc_advance_callcount = 0;
    bc_upd_ancestor_callcount = 0;
    bc_request_count = 0;
    bc_total_bytes_to_process = 0;
    bc_force_tx_len = 0;
    bc_add_extra_response = false;
    bc_change_cla = false;
    bc_change_cmd = false;
}

void assert_buffer_changed_and_restored() {
    assert(2 == communication_set_msg_buffer_callcount);
    assert(communication_msg_buffer == G_io_apdu_buffer);
    assert(communication_msg_buffer_size == sizeof(G_io_apdu_buffer));
}

#define FOR_BOOL(var) for (int var = 0; var < 2; var++)

void test_meta_advupd_small_payload_ok() {
    unsigned int rx;

    FOR_BOOL(cmd_upd) {
        FOR_BOOL(tx_len) {
            FOR_BOOL(op_change) {
                setup();
                printf("Test meta_advupd %s with small payload, %sop change "
                       "and %stx len...\n",
                       cmd_upd ? "update ancestor" : "advance blockchain",
                       op_change ? "" : "NO ",
                       tx_len ? "" : "NO ");

                // Setup mocks
                bc_throw = 0;
                bc_change_op = !!op_change;
                bc_tx_len = tx_len ? 5 : 0;

                ASSERT_DOESNT_THROW({
                    // Send command
                    if (cmd_upd) {
                        SET_APDU("\x80\x30\x55" BS_A_50, rx);
                    } else {
                        SET_APDU("\x80\x10\xAA" BS_B_50, rx);
                    }
                    assert((tx_len ? 4 : 3) == do_meta_advupd(rx));
                    unsigned char expected_apdu[tx_len ? 5 : 4];
                    expected_apdu[0] = 0x80;
                    expected_apdu[1] = cmd_upd ? 0x30 : 0x10;
                    expected_apdu[2] =
                        (cmd_upd ? 0x55 : 0xAA) + (op_change ? 0x11 : 0);
                    if (tx_len)
                        expected_apdu[3] = 0x05;
                    expected_apdu[sizeof(expected_apdu) - 1] = 0;
                    ASSERT_APDU(expected_apdu);
                    assert_buffer_changed_and_restored();
                    assert((cmd_upd ? 0 : 1) == bc_advance_callcount);
                    assert((cmd_upd ? 1 : 0) == bc_upd_ancestor_callcount);
                    assert(1 == bc_request_count);
                    if (cmd_upd) {
                        ASSERT_BC_REQUEST(0, "\x80\x30\x55" BS_A_50);
                    } else {
                        ASSERT_BC_REQUEST(0, "\x80\x10\xAA" BS_B_50);
                    }
                });
            }
        }
    }
}

void test_meta_advupd_large_payload_ok() {
    unsigned int rx;

    FOR_BOOL(cmd_upd) {
        FOR_BOOL(tx_len) {
            FOR_BOOL(op_change) {
                setup();
                printf("Test meta_advupd %s with large payload, %sop change "
                       "and %stx len...\n",
                       cmd_upd ? "update ancestor" : "advance blockchain",
                       op_change ? "" : "NO ",
                       tx_len ? "" : "NO ");

                // Setup mocks
                bc_throw = 0;
                bc_change_op = !!op_change;
                bc_tx_len = tx_len ? 18 : 0;
                bc_total_bytes_to_process = cmd_upd ? 250 : 180;

                ASSERT_DOESNT_THROW({
                    // Send command
                    if (cmd_upd) {
                        SET_APDU("\x80\x30\x33" BS_A_100 BS_B_100 BS_A BS_B BS_A
                                     BS_B BS_A,
                                 rx);
                    } else {
                        SET_APDU("\x80\x10\x11" BS_B_100 BS_A_50 BS_B BS_A BS_B,
                                 rx);
                    }
                    assert((tx_len ? 4 : 3) == do_meta_advupd(rx));
                    unsigned char expected_apdu[tx_len ? 5 : 4];
                    expected_apdu[0] = 0x80;
                    expected_apdu[1] = cmd_upd ? 0x30 : 0x10;
                    expected_apdu[2] =
                        (cmd_upd ? 0x33 : 0x11) + (op_change ? 0x11 : 0);
                    if (tx_len)
                        expected_apdu[3] = 0x12;
                    expected_apdu[sizeof(expected_apdu) - 1] = 0;
                    ASSERT_APDU(expected_apdu);
                    assert_buffer_changed_and_restored();
                    assert((cmd_upd ? 0 : 3) == bc_advance_callcount);
                    assert((cmd_upd ? 4 : 0) == bc_upd_ancestor_callcount);
                    assert((cmd_upd ? 4 : 3) == bc_request_count);
                    if (cmd_upd) {
                        ASSERT_BC_REQUEST(
                            0, "\x80\x30\x33" BS_A_50 BS_A BS_A BS_A);
                        ASSERT_BC_REQUEST(
                            1, "\x80\x30\x33" BS_A BS_A BS_B_50 BS_B);
                        ASSERT_BC_REQUEST(2,
                                          "\x80\x30\x33" BS_B BS_B BS_B BS_B
                                              BS_A BS_B BS_A BS_B);
                        ASSERT_BC_REQUEST(3, "\x80\x30\x33" BS_A);
                    } else {
                        ASSERT_BC_REQUEST(
                            0, "\x80\x10\x11" BS_B_50 BS_B BS_B BS_B);
                        ASSERT_BC_REQUEST(
                            1, "\x80\x10\x11" BS_B BS_B BS_A_50 BS_B);
                        ASSERT_BC_REQUEST(2, "\x80\x10\x11" BS_A BS_B);
                    }
                });
            }
        }
    }
}

void test_meta_advupd_chunk_larger_than_apdu() {
    unsigned int rx;

    setup();
    printf("Test meta_advupd when tx len requests chunk larger than APDU...\n");

    // Setup mocks
    bc_throw = 0;
    bc_change_op = true;
    bc_tx_len = 0;
    bc_force_tx_len = 100;
    bc_force_tx_len_when_btpleq = 50;
    bc_total_bytes_to_process = 200;

    ASSERT_THROWS(
        {
            // Send command
            SET_APDU("\x80\x10\x11" BS_B_100 BS_A_100, rx);
            do_meta_advupd(rx);
        },
        0x6A99);

    assert_buffer_changed_and_restored();
    assert(2 == bc_advance_callcount);
    assert(0 == bc_upd_ancestor_callcount);
    assert(2 == bc_request_count);
    ASSERT_BC_REQUEST(0, "\x80\x10\x11" BS_B_50 BS_B BS_B BS_B);
    ASSERT_BC_REQUEST(1, "\x80\x10\x11" BS_B BS_B BS_A_50 BS_A);
}

void test_meta_advupd_chunk_larger_than_data_available() {
    unsigned int rx;

    setup();
    printf("Test meta_advupd when tx len requests more than the available "
           "data...\n");

    // Setup mocks
    bc_throw = 0;
    bc_change_op = true;
    bc_tx_len = 0;
    bc_total_bytes_to_process = 300;

    ASSERT_THROWS(
        {
            // Send command
            SET_APDU("\x80\x30\x22" BS_B_100 BS_A_100, rx);
            do_meta_advupd(rx);
        },
        0x6B87);

    assert_buffer_changed_and_restored();
    assert(0 == bc_advance_callcount);
    assert(2 == bc_upd_ancestor_callcount);
    assert(2 == bc_request_count);
    ASSERT_BC_REQUEST(0, "\x80\x30\x22" BS_B_50 BS_B BS_B BS_B);
    ASSERT_BC_REQUEST(1, "\x80\x30\x22" BS_B BS_B BS_A_50 BS_A);
}

void test_meta_advupd_advance_throws() {
    unsigned int rx;

    setup();
    printf("Test meta_advupd when advance blockchain throws...\n");

    // Setup mocks
    bc_throw = 0x6A77;
    bc_change_op = true;
    bc_tx_len = 0;
    bc_total_bytes_to_process = 100;

    ASSERT_THROWS(
        {
            // Send command
            SET_APDU("\x80\x10\x33" BS_A_100, rx);
            do_meta_advupd(rx);
        },
        0x6A77);

    assert_buffer_changed_and_restored();
    assert(1 == bc_advance_callcount);
    assert(0 == bc_upd_ancestor_callcount);
    assert(1 == bc_request_count);
    ASSERT_BC_REQUEST(0, "\x80\x10\x33" BS_A_50 BS_A BS_A BS_A);
}

void test_meta_advupd_upd_ancestor_throws() {
    unsigned int rx;

    setup();
    printf("Test meta_advupd when update ancestor throws...\n");

    // Setup mocks
    bc_throw = 0x6A88;
    bc_change_op = true;
    bc_tx_len = 0;
    bc_total_bytes_to_process = 50;

    ASSERT_THROWS(
        {
            // Send command
            SET_APDU("\x80\x30\x44" BS_B_50, rx);
            do_meta_advupd(rx);
        },
        0x6A88);

    assert_buffer_changed_and_restored();
    assert(0 == bc_advance_callcount);
    assert(1 == bc_upd_ancestor_callcount);
    assert(1 == bc_request_count);
    ASSERT_BC_REQUEST(0, "\x80\x30\x44" BS_B_50);
}

void test_meta_advupd_unexpected_cmd() {
    unsigned int rx;

    setup();
    printf("Test meta_advupd when unexpected command received...\n");

    // Setup mocks
    bc_throw = 0;
    bc_change_op = true;
    bc_tx_len = 0;
    bc_total_bytes_to_process = 20;

    ASSERT_THROWS(
        {
            // Send command
            SET_APDU("\x80\x05\x00" BS_B BS_B, rx);
            do_meta_advupd(rx);
        },
        0x6A99);

    assert_buffer_changed_and_restored();
    assert(0 == bc_advance_callcount);
    assert(0 == bc_upd_ancestor_callcount);
    assert(0 == bc_request_count);
}

void test_meta_advupd_unexpected_bc_response_size() {
    unsigned int rx;

    setup();
    printf("Test meta_advupd when unexpected response size from bc "
           "operation...\n");

    // Setup mocks
    bc_throw = 0;
    bc_change_op = true;
    bc_tx_len = 1;
    bc_total_bytes_to_process = 70;
    bc_add_extra_response = true;

    ASSERT_THROWS(
        {
            // Send command
            SET_APDU("\x80\x10\x55" BS_B_50 BS_A BS_A, rx);
            do_meta_advupd(rx);
        },
        0x6A99);

    assert_buffer_changed_and_restored();
    assert(1 == bc_advance_callcount);
    assert(0 == bc_upd_ancestor_callcount);
    assert(1 == bc_request_count);
    ASSERT_BC_REQUEST(0, "\x80\x10\x55" BS_B_50 BS_A BS_A);
}

void test_meta_advupd_unexpected_cla() {
    unsigned int rx;

    setup();
    printf("Test meta_advupd when unexpected cla from bc operation...\n");

    // Setup mocks
    bc_throw = 0;
    bc_change_op = true;
    bc_tx_len = 0;
    bc_total_bytes_to_process = 60;
    bc_change_cla = true;

    ASSERT_THROWS(
        {
            // Send command
            SET_APDU("\x80\x10\x66" BS_B_50 BS_A, rx);
            do_meta_advupd(rx);
        },
        0x6A99);

    assert_buffer_changed_and_restored();
    assert(1 == bc_advance_callcount);
    assert(0 == bc_upd_ancestor_callcount);
    assert(1 == bc_request_count);
    ASSERT_BC_REQUEST(0, "\x80\x10\x66" BS_B_50 BS_A);
}

void test_meta_advupd_unexpected_cmd_response() {
    unsigned int rx;

    setup();
    printf(
        "Test meta_advupd when unexpected cmd response from bc operation...\n");

    // Setup mocks
    bc_throw = 0;
    bc_change_op = true;
    bc_tx_len = 0;
    bc_total_bytes_to_process = 60;
    bc_change_cmd = true;

    ASSERT_THROWS(
        {
            // Send command
            SET_APDU("\x80\x10\x66" BS_B_50 BS_A, rx);
            do_meta_advupd(rx);
        },
        0x6A99);

    assert_buffer_changed_and_restored();
    assert(1 == bc_advance_callcount);
    assert(0 == bc_upd_ancestor_callcount);
    assert(1 == bc_request_count);
    ASSERT_BC_REQUEST(0, "\x80\x10\x66" BS_B_50 BS_A);
}

int main() {
    test_meta_advupd_small_payload_ok();
    test_meta_advupd_large_payload_ok();

    test_meta_advupd_chunk_larger_than_apdu();
    test_meta_advupd_chunk_larger_than_data_available();

    test_meta_advupd_advance_throws();
    test_meta_advupd_upd_ancestor_throws();

    test_meta_advupd_unexpected_cmd();
    test_meta_advupd_unexpected_bc_response_size();
    test_meta_advupd_unexpected_cla();
    test_meta_advupd_unexpected_cmd_response();

    return 0;
}

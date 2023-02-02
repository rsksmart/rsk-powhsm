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

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "assert_utils.h"
#include "bootloader.h"
#include "ux_handlers.h"
#include "defs.h"
#include "modes.h"
#include "ui_err.h"
#include "bootloader_mock.h"
#include "communication.h"

// Mock variables needed for bootloader module
bolos_ux_context_t G_bolos_ux_context;

// Mock variable used to assert function calls
static bootloader_mode_t G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
static bool G_host_seed_is_set = false;
static bool G_pin_buffer_updated = false;
static unsigned int G_device_onboarded = 0;
static bool G_is_onboarded = false;
static bool G_is_pin_set = false;
static bool G_is_pin_buffer_cleared = false;
static bool G_get_attestation_called = false;
static bool G_authorize_signer_called = false;
static bool G_get_retries_called = false;
static bool G_unlock_called = false;
static dashboard_action_t G_dashboard_action = 0xFF;
static bool G_reset_attestation_called = false;
static bool G_reset_signer_authorization_called = false;
static bool G_reset_onboard_called = false;
static bool G_is_onboarded_called = false;

#define RESET_IF_STARTED_CALLED()                                         \
    (G_reset_attestation_called && G_reset_signer_authorization_called && \
     G_reset_onboard_called)

// Helper functions
static void reset_flags() {
    G_host_seed_is_set = false;
    G_pin_buffer_updated = false;
    G_is_onboarded = false;
    G_device_onboarded = 0;
    G_is_pin_set = false;
    G_is_pin_buffer_cleared = false;
    G_get_attestation_called = false;
    G_authorize_signer_called = false;
    G_get_retries_called = false;
    G_unlock_called = false;
    G_dashboard_action = 0xFF;
    G_reset_attestation_called = false;
    G_reset_signer_authorization_called = false;
    G_reset_onboard_called = false;
    G_is_onboarded_called = false;
}

// Mock function calls
unsigned int set_host_seed(volatile unsigned int rx, onboard_t* onboard_ctx) {
    assert(NULL != onboard_ctx);
    assert(onboard_ctx == &G_bolos_ux_context.onboard);
    G_host_seed_is_set = true;
    return 0;
}

unsigned int update_pin_buffer(volatile unsigned int rx) {
    G_pin_buffer_updated = true;
    return 3;
}

unsigned int os_perso_isonboarded(void) {
    return G_device_onboarded;
}

unsigned int is_onboarded() {
    G_is_onboarded_called = true;
    SET_APDU_AT(1, G_is_onboarded);
    return 5;
}

unsigned int onboard_device(onboard_t* onboard_ctx) {
    G_is_onboarded = true;
    return 3;
}

void clear_pin() {
    G_is_pin_buffer_cleared = true;
}

unsigned int set_pin() {
    G_is_pin_set = true;
    return 3;
}

unsigned int echo(unsigned int rx) {
    return rx;
}

unsigned int get_mode_bootloader() {
    SET_APDU_AT(1, APP_MODE_BOOTLOADER);
    return 2;
}

unsigned int get_attestation(volatile unsigned int rx, att_t* att_ctx) {
    assert(NULL != att_ctx);
    assert(att_ctx == &G_bolos_ux_context.attestation);
    G_get_attestation_called = true;
    return 3;
}

unsigned int do_authorize_signer(volatile unsigned int rx,
                                 sigaut_t* sigaut_ctx) {
    assert(NULL != sigaut_ctx);
    assert(sigaut_ctx == &G_bolos_ux_context.sigaut);
    G_authorize_signer_called = true;
    return 3;
}

unsigned int get_retries() {
    G_get_retries_called = true;
    return 3;
}

unsigned int unlock() {
    G_unlock_called = true;
    return 3;
}

void reset_attestation(att_t* att_ctx) {
    G_reset_attestation_called = true;
}

void reset_signer_authorization(sigaut_t* sigaut_ctx) {
    G_reset_signer_authorization_called = true;
}

void reset_onboard_ctx(onboard_t* onboard_ctx) {
    G_reset_onboard_called = true;
}

void set_dashboard_action(dashboard_action_t action) {
    G_dashboard_action = action;
}

// Function definitions required for compiling bootloader.c
void init_signer_authorization() {
}

unsigned short io_exchange(unsigned char channel, unsigned short tx_len) {
    assert(CHANNEL_APDU == channel);
    return 0;
}

unsigned int comm_process_exception(unsigned short ex,
                                    unsigned int tx,
                                    comm_reset_cb_t comm_reset_cb) {
    return 0;
}

void test_init() {
    printf("Test bootloader init...\n");

    reset_flags();

    bootloader_init();

    assert(G_reset_attestation_called);
    assert(G_reset_signer_authorization_called);
    assert(G_reset_onboard_called);
}

void test_seed() {
    printf("Test RSK_SEED_CMD...\n");

    unsigned int rx;
    unsigned int tx;
    bootloader_init();
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_host_seed_is_set = false;
    SET_APDU("\x80\x44", rx); // RSK_SEED_CMD
    tx = bootloader_process_apdu(rx, G_bootloader_mode);
    assert(0 == tx);
    assert(G_host_seed_is_set);
    assert(RESET_IF_STARTED_CALLED());
}

void test_seed_onboarded() {
    printf("Test RSK_SEED_CMD when onboarded...\n");

    unsigned int rx;
    unsigned int tx;
    bootloader_init();
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_device_onboarded = 1;
    G_host_seed_is_set = false;
    SET_APDU("\x80\x44", rx); // RSK_SEED_CMD
    BEGIN_TRY {
        TRY {
            bootloader_process_apdu(rx, G_bootloader_mode);
            // bootloader_process_apdu should throw EX_BOOTLOADER_RSK_END
            ASSERT_FAIL();
        }
        CATCH(ERR_UI_DEVICE_ONBOARDED) {
            assert(!G_host_seed_is_set);
            return;
        }
        CATCH_OTHER(e) {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_pin() {
    printf("Test RSK_PIN_CMD...\n");

    unsigned int rx;
    unsigned int tx;
    bootloader_init();
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_host_seed_is_set = false;
    SET_APDU("\x80\x41", rx); // RSK_PIN_CMD
    tx = bootloader_process_apdu(rx, G_bootloader_mode);
    assert(3 == tx);
    assert(G_pin_buffer_updated);
    assert(RESET_IF_STARTED_CALLED());
}

void test_is_onboard() {
    printf("Test RSK_IS_ONBOARD...\n");

    unsigned int rx;
    unsigned int tx;
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;

    bootloader_init();
    reset_flags();
    G_is_onboarded = false;
    SET_APDU("\x80\x06", rx); // RSK_IS_ONBOARD
    tx = bootloader_process_apdu(rx, G_bootloader_mode);
    assert(G_is_onboarded_called);
    assert(5 == tx);
    ASSERT_APDU("\x80\x00");
    assert(RESET_IF_STARTED_CALLED());

    bootloader_init();
    reset_flags();
    G_is_onboarded = true;
    SET_APDU("\x80\x06", rx); // RSK_IS_ONBOARD
    tx = bootloader_process_apdu(rx, G_bootloader_mode);
    assert(G_is_onboarded_called);
    assert(5 == tx);
    ASSERT_APDU("\x80\x01");
    assert(RESET_IF_STARTED_CALLED());
}

void test_wipe_default_mode() {
    printf("Test RSK_WIPE (default mode)...\n");

    unsigned int rx;
    unsigned int tx;
    bootloader_init();
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_is_onboarded = false;
    G_is_pin_buffer_cleared = false;
    G_is_pin_set = true;
    SET_APDU("\x80\x07", rx); // RSK_WIPE
    tx = bootloader_process_apdu(rx, G_bootloader_mode);
    assert(3 == tx);
    assert(G_is_onboarded);
    assert(G_is_pin_buffer_cleared);
    assert(RESET_IF_STARTED_CALLED());
}

void test_wipe_default_mode_onboarded() {
    printf("Test RSK_WIPE (default mode) when onboarded...\n");

    unsigned int rx;
    unsigned int tx;
    bootloader_init();
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_device_onboarded = 1;
    G_is_onboarded = false;
    G_is_pin_buffer_cleared = false;
    G_is_pin_set = true;
    SET_APDU("\x80\x07", rx); // RSK_WIPE
    BEGIN_TRY {
        TRY {
            bootloader_process_apdu(rx, G_bootloader_mode);
            // bootloader_process_apdu should throw EX_BOOTLOADER_RSK_END
            ASSERT_FAIL();
        }
        CATCH(ERR_UI_DEVICE_ONBOARDED) {
            assert(!G_is_onboarded);
            assert(!G_is_pin_buffer_cleared);
            assert(G_is_pin_set);
            return;
        }
        CATCH_OTHER(e) {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_wipe_onboard_mode() {
    printf("Test RSK_WIPE (onboard mode)...\n");

    unsigned int rx;
    unsigned int tx;
    bootloader_init();
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_ONBOARD;
    G_is_onboarded = false;
    G_is_pin_buffer_cleared = false;
    G_is_pin_set = true;
    SET_APDU("\x80\x07", rx); // RSK_WIPE
    tx = bootloader_process_apdu(rx, G_bootloader_mode);
    assert(3 == tx);
    assert(G_is_onboarded);
    assert(G_is_pin_buffer_cleared);
    assert(RESET_IF_STARTED_CALLED());
}

void test_wipe_onboard_mode_onboarded() {
    printf("Test RSK_WIPE (onboard mode) when onboarded...\n");

    unsigned int rx;
    unsigned int tx;
    bootloader_init();
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_ONBOARD;
    G_device_onboarded = 1;
    G_is_onboarded = false;
    G_is_pin_buffer_cleared = false;
    G_is_pin_set = true;
    SET_APDU("\x80\x07", rx); // RSK_WIPE
    BEGIN_TRY {
        TRY {
            bootloader_process_apdu(rx, G_bootloader_mode);
            // bootloader_process_apdu should throw EX_BOOTLOADER_RSK_END
            ASSERT_FAIL();
        }
        CATCH(ERR_UI_DEVICE_ONBOARDED) {
            assert(!G_is_onboarded);
            assert(!G_is_pin_buffer_cleared);
            assert(G_is_pin_set);
            return;
        }
        CATCH_OTHER(e) {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_newpin() {
    printf("Test RSK_NEWPIN...\n");

    unsigned int rx;
    unsigned int tx;
    bootloader_init();
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_is_pin_set = false;
    G_is_pin_buffer_cleared = false;
    SET_APDU("\x80\x08", rx); // RSK_NEWPIN
    tx = bootloader_process_apdu(rx, G_bootloader_mode);
    assert(3 == tx);
    assert(G_is_pin_set);
    assert(G_is_pin_buffer_cleared);
    assert(RESET_IF_STARTED_CALLED());
}

void test_echo() {
    printf("Test RSK_ECHO_CMD...\n");

    unsigned int rx;
    unsigned int tx;
    bootloader_init();
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    SET_APDU("\x80\x02", rx); // RSK_ECHO_CMD
    tx = bootloader_process_apdu(rx, G_bootloader_mode);
    assert(rx == tx);
    assert(RESET_IF_STARTED_CALLED());
}

void test_mode() {
    printf("Test RSK_MODE_CMD...\n");

    unsigned int rx;
    unsigned int tx;
    bootloader_init();
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    SET_APDU("\x80\x43", rx); // RSK_MODE_CMD
    tx = bootloader_process_apdu(rx, G_bootloader_mode);
    assert(2 == tx);
    ASSERT_APDU("\x80\x02");
}

void test_attestation() {
    printf("Test INS_ATTESTATION...\n");

    unsigned int rx;
    unsigned int tx;
    bootloader_init();
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_get_attestation_called = false;
    SET_APDU("\x80\x50", rx); // INS_ATTESTATION
    tx = bootloader_process_apdu(rx, G_bootloader_mode);
    assert(3 == tx);
    assert(G_get_attestation_called);
}

void test_signer_authorization() {
    printf("Test INS_SIGNER_AUTHORIZATION...\n");

    unsigned int rx;
    unsigned int tx;
    bootloader_init();
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_authorize_signer_called = false;
    SET_APDU("\x80\x51", rx); // INS_SIGNER_AUTHORIZATION
    tx = bootloader_process_apdu(rx, G_bootloader_mode);
    assert(3 == tx);
    assert(G_authorize_signer_called);
    assert(RESET_IF_STARTED_CALLED());
}

void test_retries() {
    printf("Test RSK_RETRIES...\n");

    unsigned int rx;
    unsigned int tx;
    bootloader_init();
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_get_retries_called = false;
    SET_APDU("\x80\x45", rx); // RSK_RETRIES
    tx = bootloader_process_apdu(rx, G_bootloader_mode);
    assert(3 == tx);
    assert(G_get_retries_called);
    assert(RESET_IF_STARTED_CALLED());
}

void test_unlock() {
    printf("Test RSK_UNLOCK_CMD...\n");

    unsigned int rx;
    unsigned int tx;
    bootloader_init();
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_unlock_called = false;
    SET_APDU("\x80\xfe", rx); // RSK_UNLOCK_CMD
    tx = bootloader_process_apdu(rx, G_bootloader_mode);
    assert(3 == tx);
    assert(G_unlock_called);
    assert(RESET_IF_STARTED_CALLED());
}

void test_end() {
    printf("Test RSK_END_CMD...\n");

    unsigned int rx;
    bootloader_init();
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_dashboard_action = 0xFF;
    SET_APDU("\x80\xff", rx); // RSK_END_CMD
    BEGIN_TRY {
        TRY {
            bootloader_process_apdu(rx, G_bootloader_mode);
            // bootloader_process_apdu should throw EX_BOOTLOADER_RSK_END
            ASSERT_FAIL();
        }
        CATCH(EX_BOOTLOADER_RSK_END) {
            assert(DASHBOARD_ACTION_APP == G_dashboard_action);
            assert(RESET_IF_STARTED_CALLED());
            return;
        }
        CATCH_OTHER(e) {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_end_nosig() {
    printf("Test RSK_END_CMD_NOSIG...\n");

    unsigned int rx;
    bootloader_init();
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_dashboard_action = 0xFF;
    SET_APDU("\x80\xfa", rx); // RSK_END_CMD_NOSIG
    BEGIN_TRY {
        TRY {
            bootloader_process_apdu(rx, G_bootloader_mode);
            // bootloader_process_apdu should throw EX_BOOTLOADER_RSK_END
            ASSERT_FAIL();
        }
        CATCH(EX_BOOTLOADER_RSK_END) {
            assert(DASHBOARD_ACTION_DASHBOARD == G_dashboard_action);
            assert(RESET_IF_STARTED_CALLED());
            return;
        }
        CATCH_OTHER(e) {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_invalid_command() {
    printf("Test invalid command...\n");

    unsigned int rx;
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    // 0x09 is not an accepted command
    SET_APDU("\x80\x09", rx);
    BEGIN_TRY {
        TRY {
            bootloader_process_apdu(rx, G_bootloader_mode);
            // bootloader_process_apdu should throw ERR_UI_INS_NOT_SUPPORTED
            ASSERT_FAIL();
        }
        CATCH(ERR_INS_NOT_SUPPORTED) {
            return;
        }
        CATCH_OTHER(e) {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_empty_buffer() {
    printf("Test empty buffer...\n");

    unsigned int rx;
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    rx = 0;
    BEGIN_TRY {
        TRY {
            bootloader_process_apdu(rx, G_bootloader_mode);
            // bootloader_process_apdu should throw ERR_EMPTY_BUFFER
            ASSERT_FAIL();
        }
        CATCH(ERR_EMPTY_BUFFER) {
            return;
        }
        CATCH_OTHER(e) {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_no_cla() {
    printf("Test no CLA...\n");

    unsigned int rx;
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    CLEAR_APDU();
    rx = 2;

    BEGIN_TRY {
        TRY {
            bootloader_process_apdu(rx, G_bootloader_mode);
            // bootloader_process_apdu should throw ERR_UI_INVALID_CLA
            ASSERT_FAIL();
        }
        CATCH(ERR_UI_INVALID_CLA) {
            return;
        }
        CATCH_OTHER(e) {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_onboard_mode() {
    printf("Test send command after onboard...\n");

    unsigned int rx;
    unsigned int tx;
    bootloader_init();
    reset_flags();

    BEGIN_TRY {
        TRY {
            G_bootloader_mode = BOOTLOADER_MODE_ONBOARD;
            // Set onboard_performed flag
            SET_APDU("\x80\x07", rx); // RSK_WIPE
            tx = bootloader_process_apdu(rx, G_bootloader_mode);
            assert(3 == tx);

            // Echo command must fail after onboard is performed
            SET_APDU("\x80\x02", rx); // RSK_ECHO_CMD
            bootloader_process_apdu(rx, G_bootloader_mode);
            // bootloader_process_apdu should throw ERR_INS_NOT_SUPPORTED
            ASSERT_FAIL();
        }
        CATCH(ERR_INS_NOT_SUPPORTED) {
            return;
        }
        CATCH_OTHER(e) {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

int main() {
    test_init();
    test_seed();
    test_seed_onboarded();
    test_pin();
    test_is_onboard();
    test_wipe_default_mode();
    test_wipe_default_mode_onboarded();
    test_wipe_onboard_mode();
    test_wipe_onboard_mode_onboarded();
    test_newpin();
    test_echo();
    test_mode();
    test_attestation();
    test_signer_authorization();
    test_retries();
    test_unlock();
    test_end();
    test_end_nosig();
    test_invalid_command();
    test_empty_buffer();
    test_no_cla();
    test_onboard_mode();

    return 0;
}

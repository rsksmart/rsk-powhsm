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
#include <pthread.h>

#include "bootloader.h"
#include "defs.h"
#include "err.h"
#include "mock.h"

// Mock variables needed for bootloader module
#define IO_APDU_BUFFER_SIZE (5 + 255)
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];
bolos_ux_context_t G_bolos_ux_context;
static try_context_t G_try_last_open_context_var;
try_context_t* G_try_last_open_context = &G_try_last_open_context_var;

// Mock variable used to assert function calls
static unsigned char G_onboard_performed = 0;
static bootloader_mode_t G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
static bool G_host_seed_is_set = false;
static bool G_pin_buffer_updated = false;
static bool G_is_onboarded = false;
static bool G_is_pin_set = false;
static bool G_is_pin_buffer_cleared = false;
static bool G_get_attestation_called = false;
static bool G_authorize_signer_called = false;
static bool G_get_retries_called = false;
static bool G_unlock_called = false;
static unsigned char G_autoexec = 0;
static bool G_reset_attestation_called = false;
static bool G_reset_signer_authorization_called = false;
static bool G_reset_onboard_called = false;

#define RESET_IF_STARTED_CALLED()                                         \
    (G_reset_attestation_called && G_reset_signer_authorization_called && \
     G_reset_onboard_called)
#define ASSERT_RESET_IF_STARTED_CALLED() ASSERT_TRUE(RESET_IF_STARTED_CALLED())

// Helper functions
static unsigned int set_apdu_cmd(unsigned char cmd) {
    G_io_apdu_buffer[0] = CLA;
    G_io_apdu_buffer[1] = cmd;
    return 2;
}

static void clear_apdu_buffer() {
    memset(G_io_apdu_buffer, 0, sizeof(G_io_apdu_buffer));
}

static void reset_flags() {
    G_host_seed_is_set = false;
    G_pin_buffer_updated = false;
    G_is_onboarded = false;
    G_is_pin_set = false;
    G_is_pin_buffer_cleared = false;
    G_get_attestation_called = false;
    G_authorize_signer_called = false;
    G_get_retries_called = false;
    G_unlock_called = false;
    G_autoexec = 0;
    G_reset_attestation_called = false;
    G_reset_signer_authorization_called = false;
    G_reset_onboard_called = false;
}

// Helper function used to set last command sent bootloader.c
static void set_last_cmd(unsigned char cmd) {
    unsigned int rx = set_apdu_cmd(cmd);
    bootloader_process_apdu(rx, BOOTLOADER_MODE_DEFAULT, &G_onboard_performed);
}

// Mock function calls
unsigned int set_host_seed(volatile unsigned int rx, onboard_t* onboard_ctx) {
    ASSERT_NOT_NULL(onboard_ctx);
    G_host_seed_is_set = true;
    return 0;
}

unsigned int update_pin_buffer(volatile unsigned int rx) {
    G_pin_buffer_updated = true;
    return 3;
}

unsigned int is_onboarded() {
    SET_APDU_AT(1, G_is_onboarded);
    SET_APDU_AT(2, VERSION_MAJOR);
    SET_APDU_AT(3, VERSION_MINOR);
    SET_APDU_AT(4, VERSION_PATCH);
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

unsigned int get_mode() {
    SET_APDU_AT(1, RSK_MODE_BOOTLOADER);
    return 2;
}

unsigned int get_attestation(volatile unsigned int rx, att_t* att_ctx) {
    ASSERT_NOT_NULL(att_ctx);
    G_get_attestation_called = true;
    return 3;
}

unsigned int do_authorize_signer(volatile unsigned int rx,
                                 sigaut_t* sigaut_ctx) {
    ASSERT_NOT_NULL(sigaut_ctx);
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

void set_autoexec(char value) {
    G_autoexec = value;
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

// Function definitions required for compiling bootloader.c
void init_signer_authorization() {
}

unsigned short io_exchange(unsigned char channel, unsigned short tx_len) {
    return 0;
}

void test_seed() {
    printf("Test RSK_SEED_CMD...\n");

    unsigned int rx;
    unsigned int tx;
    set_last_cmd(RSK_ECHO_CMD);
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_onboard_performed = 0;
    G_host_seed_is_set = false;
    rx = set_apdu_cmd(RSK_SEED_CMD);
    tx = bootloader_process_apdu(rx, G_bootloader_mode, &G_onboard_performed);
    ASSERT_EQUALS(0, tx);
    ASSERT_EQUALS(0, G_onboard_performed);
    ASSERT_TRUE(G_host_seed_is_set);
    ASSERT_RESET_IF_STARTED_CALLED();
}

void test_pin() {
    printf("Test RSK_PIN_CMD...\n");

    unsigned int rx;
    unsigned int tx;
    set_last_cmd(RSK_ECHO_CMD);
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_onboard_performed = 0;
    G_host_seed_is_set = false;
    rx = set_apdu_cmd(RSK_PIN_CMD);
    tx = bootloader_process_apdu(rx, G_bootloader_mode, &G_onboard_performed);
    ASSERT_EQUALS(3, tx);
    ASSERT_EQUALS(0, G_onboard_performed);
    ASSERT_TRUE(G_pin_buffer_updated);
    ASSERT_RESET_IF_STARTED_CALLED();
}

void test_is_onboard() {
    printf("Test RSK_IS_ONBOARD...\n");

    unsigned int rx;
    unsigned int tx;
    set_last_cmd(RSK_ECHO_CMD);
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_onboard_performed = 0;

    G_is_onboarded = false;
    rx = set_apdu_cmd(RSK_IS_ONBOARD);
    tx = bootloader_process_apdu(rx, G_bootloader_mode, &G_onboard_performed);
    ASSERT_EQUALS(5, tx);
    ASSERT_APDU_AT(1, G_is_onboarded);
    ASSERT_APDU_AT(2, VERSION_MAJOR);
    ASSERT_APDU_AT(3, VERSION_MINOR);
    ASSERT_APDU_AT(4, VERSION_PATCH);

    G_is_onboarded = true;
    rx = set_apdu_cmd(RSK_IS_ONBOARD);
    tx = bootloader_process_apdu(rx, G_bootloader_mode, &G_onboard_performed);
    ASSERT_EQUALS(5, tx);
    ASSERT_APDU_AT(1, G_is_onboarded);
    ASSERT_APDU_AT(2, VERSION_MAJOR);
    ASSERT_APDU_AT(3, VERSION_MINOR);
    ASSERT_APDU_AT(4, VERSION_PATCH);
    ASSERT_RESET_IF_STARTED_CALLED();
}

void test_wipe_default_mode() {
    printf("Test RSK_WIPE (default mode)...\n");

    unsigned int rx;
    unsigned int tx;
    set_last_cmd(RSK_ECHO_CMD);
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_onboard_performed = 0;
    G_is_onboarded = false;
    G_is_pin_buffer_cleared = false;
    G_is_pin_set = true;
    rx = set_apdu_cmd(RSK_WIPE);
    tx = bootloader_process_apdu(rx, G_bootloader_mode, &G_onboard_performed);
    ASSERT_EQUALS(3, tx);
    ASSERT_TRUE(G_is_onboarded);
    ASSERT_EQUALS(0, G_onboard_performed);
    ASSERT_TRUE(G_is_pin_buffer_cleared);
    ASSERT_RESET_IF_STARTED_CALLED();
}

void test_wipe_onboard_mode() {
    printf("Test RSK_WIPE (onboard mode)...\n");

    unsigned int rx;
    unsigned int tx;
    set_last_cmd(RSK_ECHO_CMD);
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_ONBOARD;
    G_onboard_performed = 0;
    G_is_onboarded = false;
    G_is_pin_buffer_cleared = false;
    G_is_pin_set = true;
    rx = set_apdu_cmd(RSK_WIPE);
    tx = bootloader_process_apdu(rx, G_bootloader_mode, &G_onboard_performed);
    ASSERT_EQUALS(3, tx);
    ASSERT_TRUE(G_is_onboarded);
    ASSERT_EQUALS(1, G_onboard_performed);
    ASSERT_TRUE(G_is_pin_buffer_cleared);
    ASSERT_RESET_IF_STARTED_CALLED();
}

void test_newpin() {
    printf("Test RSK_NEWPIN...\n");

    unsigned int rx;
    unsigned int tx;
    set_last_cmd(RSK_ECHO_CMD);
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_onboard_performed = 0;
    G_is_pin_set = false;
    G_is_pin_buffer_cleared = false;
    rx = set_apdu_cmd(RSK_NEWPIN);
    tx = bootloader_process_apdu(rx, G_bootloader_mode, &G_onboard_performed);
    ASSERT_EQUALS(3, tx);
    ASSERT_TRUE(G_is_pin_set);
    ASSERT_TRUE(G_is_pin_buffer_cleared);
    ASSERT_EQUALS(0, G_onboard_performed);
    ASSERT_RESET_IF_STARTED_CALLED();
}

void test_echo() {
    printf("Test RSK_ECHO_CMD...\n");

    unsigned int rx;
    unsigned int tx;
    set_last_cmd(RSK_RETRIES);
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_onboard_performed = 0;
    rx = set_apdu_cmd(RSK_ECHO_CMD);
    tx = bootloader_process_apdu(rx, G_bootloader_mode, &G_onboard_performed);
    ASSERT_EQUALS(rx, tx);
    ASSERT_EQUALS(0, G_onboard_performed);
    ASSERT_RESET_IF_STARTED_CALLED();
}

void test_mode() {
    printf("Test RSK_MODE_CMD...\n");

    unsigned int rx;
    unsigned int tx;
    set_last_cmd(RSK_ECHO_CMD);
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_onboard_performed = 0;
    rx = set_apdu_cmd(RSK_MODE_CMD);
    tx = bootloader_process_apdu(rx, G_bootloader_mode, &G_onboard_performed);
    ASSERT_EQUALS(2, tx);
    ASSERT_APDU_AT(1, RSK_MODE_BOOTLOADER);
    ASSERT_EQUALS(0, G_onboard_performed);
}

void test_attestation() {
    printf("Test INS_ATTESTATION...\n");

    unsigned int rx;
    unsigned int tx;
    set_last_cmd(RSK_ECHO_CMD);
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_onboard_performed = 0;
    G_get_attestation_called = false;
    rx = set_apdu_cmd(INS_ATTESTATION);
    tx = bootloader_process_apdu(rx, G_bootloader_mode, &G_onboard_performed);
    ASSERT_EQUALS(3, tx);
    ASSERT_TRUE(G_get_attestation_called);
    ASSERT_EQUALS(0, G_onboard_performed);
}

void test_signer_authorization() {
    printf("Test INS_SIGNER_AUTHORIZATION...\n");

    unsigned int rx;
    unsigned int tx;
    set_last_cmd(RSK_ECHO_CMD);
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_onboard_performed = 0;
    G_authorize_signer_called = false;
    rx = set_apdu_cmd(INS_SIGNER_AUTHORIZATION);
    tx = bootloader_process_apdu(rx, G_bootloader_mode, &G_onboard_performed);
    ASSERT_EQUALS(3, tx);
    ASSERT_TRUE(G_authorize_signer_called);
    ASSERT_EQUALS(0, G_onboard_performed);
    ASSERT_RESET_IF_STARTED_CALLED();
}

void test_retries() {
    printf("Test RSK_RETRIES...\n");

    unsigned int rx;
    unsigned int tx;
    set_last_cmd(RSK_ECHO_CMD);
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_onboard_performed = 0;
    G_get_retries_called = false;
    rx = set_apdu_cmd(RSK_RETRIES);
    tx = bootloader_process_apdu(rx, G_bootloader_mode, &G_onboard_performed);
    ASSERT_EQUALS(3, tx);
    ASSERT_TRUE(G_get_retries_called);
    ASSERT_EQUALS(0, G_onboard_performed);
    ASSERT_RESET_IF_STARTED_CALLED();
}

void test_unlock() {
    printf("Test RSK_UNLOCK_CMD...\n");

    unsigned int rx;
    unsigned int tx;
    set_last_cmd(RSK_ECHO_CMD);
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_onboard_performed = 0;
    G_unlock_called = false;
    rx = set_apdu_cmd(RSK_UNLOCK_CMD);
    tx = bootloader_process_apdu(rx, G_bootloader_mode, &G_onboard_performed);
    ASSERT_EQUALS(3, tx);
    ASSERT_TRUE(G_unlock_called);
    ASSERT_EQUALS(0, G_onboard_performed);
    ASSERT_RESET_IF_STARTED_CALLED();
}

void test_end() {
    printf("Test RSK_END_CMD...\n");

    unsigned int rx;
    set_last_cmd(RSK_ECHO_CMD);
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_onboard_performed = 0;
    G_autoexec = 0;
    rx = set_apdu_cmd(RSK_END_CMD);
    BEGIN_TRY {
        TRY {
            bootloader_process_apdu(
                rx, G_bootloader_mode, &G_onboard_performed);
            // bootloader_process_apdu should throw EX_BOOTLOADER_RSK_END
            ASSERT_FAIL();
        }
        CATCH(EX_BOOTLOADER_RSK_END) {
            ASSERT_EQUALS(1, G_autoexec);
            ASSERT_EQUALS(0, G_onboard_performed);
            ASSERT_RESET_IF_STARTED_CALLED();
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
    set_last_cmd(RSK_ECHO_CMD);
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;
    G_onboard_performed = 0;
    G_autoexec = 0;
    rx = set_apdu_cmd(RSK_END_CMD_NOSIG);
    BEGIN_TRY {
        TRY {
            bootloader_process_apdu(
                rx, G_bootloader_mode, &G_onboard_performed);
            // bootloader_process_apdu should throw EX_BOOTLOADER_RSK_END
            ASSERT_FAIL();
        }
        CATCH(EX_BOOTLOADER_RSK_END) {
            ASSERT_EQUALS(0, G_autoexec);
            ASSERT_EQUALS(0, G_onboard_performed);
            ASSERT_RESET_IF_STARTED_CALLED();
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
    G_onboard_performed = 0;
    rx = set_apdu_cmd(0x9);
    BEGIN_TRY {
        TRY {
            bootloader_process_apdu(
                rx, G_bootloader_mode, &G_onboard_performed);
            // bootloader_process_apdu should throw ERR_INS_NOT_SUPPORTED
            ASSERT_FAIL();
        }
        CATCH(ERR_INS_NOT_SUPPORTED) {
            ASSERT_EQUALS(0, G_onboard_performed);
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
    G_onboard_performed = 0;
    rx = 0;
    BEGIN_TRY {
        TRY {
            bootloader_process_apdu(
                rx, G_bootloader_mode, &G_onboard_performed);
            // bootloader_process_apdu should throw ERR_EMPTY_BUFFER
            ASSERT_FAIL();
        }
        CATCH(ERR_EMPTY_BUFFER) {
            ASSERT_EQUALS(0, G_onboard_performed);
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
    G_onboard_performed = 0;
    clear_apdu_buffer();
    rx = 2;

    BEGIN_TRY {
        TRY {
            bootloader_process_apdu(
                rx, G_bootloader_mode, &G_onboard_performed);
            // bootloader_process_apdu should throw ERR_INVALID_CLA
            ASSERT_FAIL();
        }
        CATCH(ERR_INVALID_CLA) {
            ASSERT_EQUALS(0, G_onboard_performed);
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
    reset_flags();
    G_bootloader_mode = BOOTLOADER_MODE_ONBOARD;
    G_onboard_performed = 1;
    rx = set_apdu_cmd(RSK_ECHO_CMD);

    BEGIN_TRY {
        TRY {
            bootloader_process_apdu(
                rx, G_bootloader_mode, &G_onboard_performed);
            // bootloader_process_apdu should throw ERR_INS_NOT_SUPPORTED
            ASSERT_FAIL();
        }
        CATCH(ERR_INS_NOT_SUPPORTED) {
            ASSERT_EQUALS(1, G_onboard_performed);
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
    test_seed();
    test_pin();
    test_is_onboard();
    test_wipe_default_mode();
    test_wipe_onboard_mode();
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

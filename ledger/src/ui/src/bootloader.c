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

#include "apdu.h"
#include "bolos_ux_common.h"
#include "bolos_ux_handlers.h"
#include "bootloader.h"
#include "defs.h"
#include "err.h"
#include "communication.h"
#include "unlock.h"

// Attestation context shorthand
#define attestation_ctx (G_bolos_ux_context.attestation)

// Signer authorization context shorthand
#define sigaut_ctx (G_bolos_ux_context.sigaut)

// Onboard context shorthand
#define onboard_ctx (G_bolos_ux_context.onboard)

// Operation being currently executed
static unsigned char current_cmd;

/*
 * Reset all reseteable operations, only if the given operation is starting.
 *
 * @arg[in] cmd operation code
 */
static void reset_if_starting(unsigned char cmd) {
    // Reset only if starting new operation (cmd != current_cmd).
    // Otherwise we already reset when current_cmd started.
    if (cmd != current_cmd) {
        current_cmd = cmd;
        reset_attestation(&attestation_ctx);
        reset_signer_authorization(&sigaut_ctx);
        reset_onboard_ctx(&onboard_ctx);
    }
}

unsigned int bootloader_process_apdu(
    volatile unsigned int rx,
    bootloader_mode_t mode,
    volatile unsigned char *onboard_performed) {
    unsigned int tx = 0;

    // no apdu received, well, reset the session, and reset the
    // bootloader configuration
    if (rx == 0) {
        THROW(ERR_EMPTY_BUFFER);
    }

    if (APDU_CLA() != CLA) {
        THROW(ERR_INVALID_CLA);
    }

    // We don't accept any command after onboard is performed in
    // onboard mode, the user is required to unplug the device
    // before proceeding
    if (mode == BOOTLOADER_MODE_ONBOARD && *onboard_performed) {
        THROW(ERR_INS_NOT_SUPPORTED);
    }

    // unauthenticated instruction
    switch (APDU_CMD()) {
    case RSK_SEED_CMD: // Send wordlist
        reset_if_starting(RSK_META_CMD_UIOP);
        tx = set_host_seed(rx, &onboard_ctx);
        break;
    case RSK_PIN_CMD: // Send pin_buffer
        reset_if_starting(RSK_META_CMD_UIOP);
        tx = update_pin_buffer(rx);
        break;
    case RSK_IS_ONBOARD: // Wheter it's onboarded or not
        reset_if_starting(RSK_IS_ONBOARD);
        tx = is_onboarded();
        break;
    case RSK_WIPE: //--- wipe and onboard device ---
        reset_if_starting(RSK_META_CMD_UIOP);
        tx = onboard_device(&onboard_ctx);
        clear_pin();
        if (mode == BOOTLOADER_MODE_ONBOARD) {
            *onboard_performed = 1;
        }
        break;
    case RSK_NEWPIN:
        reset_if_starting(RSK_META_CMD_UIOP);
        tx = set_pin();
        clear_pin();
        break;
    case RSK_ECHO_CMD: // echo
        reset_if_starting(RSK_ECHO_CMD);
        tx = echo(rx);
        break;
    case RSK_MODE_CMD: // print mode
        reset_if_starting(RSK_MODE_CMD);
        tx = get_mode();
        break;
    case INS_ATTESTATION:
        reset_if_starting(INS_ATTESTATION);
        tx = get_attestation(rx, &attestation_ctx);
        break;
    case INS_SIGNER_AUTHORIZATION:
        reset_if_starting(INS_SIGNER_AUTHORIZATION);
        tx = do_authorize_signer(rx, &sigaut_ctx);
        break;
    case RSK_RETRIES:
        reset_if_starting(RSK_RETRIES);
        tx = get_retries();
        break;
    case RSK_UNLOCK_CMD: // Unlock
        reset_if_starting(RSK_META_CMD_UIOP);
        tx = unlock();
        // The pin value will also be used in
        // BOLOS_UX_CONSENT_APP_ADD command, so we can't wipe the
        // pin buffer here
        break;
    case RSK_END_CMD: // return to dashboard
        reset_if_starting(RSK_END_CMD);
        set_autoexec(1);
        THROW(EX_BOOTLOADER_RSK_END);
    case RSK_END_CMD_NOSIG: // return to dashboard
        reset_if_starting(RSK_END_CMD_NOSIG);
        set_autoexec(0);
        THROW(EX_BOOTLOADER_RSK_END);
    default:
        THROW(ERR_INS_NOT_SUPPORTED);
        break;
    }

    return tx;
}

unsigned int bootloader_process_exception(unsigned short ex, unsigned int tx) {
    unsigned short sw = 0;

    // Reset the state in case of an error
    if (ex != APDU_OK) {
        reset_if_starting(0);
    }

    switch (ex & 0xF000) {
    case 0x6000:
    case 0x9000:
        sw = ex;
        break;
    default:
        sw = 0x6800 | (ex & 0x7FF);
        break;
    }

    // Unexpected exception => report
    // (check for a potential overflow first)
    if (tx + 2 > sizeof(G_io_apdu_buffer)) {
        tx = 0;
        sw = 0x6983;
    }
    SET_APDU_AT(tx++, sw >> 8);
    SET_APDU_AT(tx++, sw);

    return tx;
}

// Main function for the bootloader. If mode == BOOTLOADER_MODE_ONBOARD,
// commands are not accepted after the onboard is performed.
void bootloader_main(bootloader_mode_t mode) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned char onboard_performed = 0;

    // Initialize current operation
    current_cmd = 0; // 0 = no operation being executed

    // Initialize signer authorization
    init_signer_authorization();

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU, rx);

                tx = bootloader_process_apdu(rx, mode, &onboard_performed);
                THROW(APDU_OK);
            }
            CATCH(EX_BOOTLOADER_RSK_END) {
                break;
            }
            CATCH_OTHER(e) {
                tx = bootloader_process_exception(e, tx);
            }
            FINALLY {
            }
        }
        END_TRY;
    }
}

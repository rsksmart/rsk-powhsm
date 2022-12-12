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
#include "bolos_ux.h"
#include "bolos_ux_common.h"
#include "bootloader.h"
#include "defs.h"
#include "err.h"
#include "communication.h"
#include "unlock.h"

// Accepted modes for bootloader_main
typedef enum {
    BOOTLOADER_MODE_ONBOARD,
    BOOTLOADER_MODE_DEFAULT
} bootloader_mode_t;

// Attestation context shorthand
#define attestation_ctx (G_bolos_ux_context.attestation)

// Signer authorization context shorthand
#define sigaut_ctx (G_bolos_ux_context.sigaut)

// Onboard context shorthand
#define onboard_ctx (G_bolos_ux_context.onboard)

// Operation being currently executed
static unsigned char current_cmd;
// autoexec signature app
static char autoexec;

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

// run the signer application
static void run_signer_app(void) {
    unsigned int i = 0;
    while (i < os_registry_count()) {
        application_t app;
        os_registry_get(i, &app);
        if (!(app.flags & APPLICATION_FLAG_BOLOS_UX)) {
            if (is_authorized_signer(app.hash)) {
                G_bolos_ux_context.app_auto_started = 1;
                screen_stack_pop();
                io_seproxyhal_disable_io();
                os_sched_exec(i); // no return
            }
        }
        i++;
    }
}

// Main function for the bootloader. If mode == BOOTLOADER_MODE_ONBOARD,
// commands are not accepted after the onboard is performed.
static void bootloader_main(bootloader_mode_t mode) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;
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
        volatile unsigned short sw = 0;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

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
                if (mode == BOOTLOADER_MODE_ONBOARD && onboard_performed) {
                    THROW(ERR_INS_NOT_SUPPORTED);
                }

                // unauthenticated instruction
                switch (APDU_CMD()) {
                case RSK_SEED_CMD: // Send wordlist
                    reset_if_starting(RSK_META_CMD_UIOP);
                    tx = set_host_seed(rx, &onboard_ctx);
                    THROW(APDU_OK);
                    break;
                case RSK_PIN_CMD: // Send pin_buffer
                    reset_if_starting(RSK_META_CMD_UIOP);
                    tx = update_pin_buffer(rx);
                    THROW(APDU_OK);
                    break;
                case RSK_IS_ONBOARD: // Wheter it's onboarded or not
                    reset_if_starting(RSK_IS_ONBOARD);
                    tx = is_onboarded();
                    THROW(APDU_OK);
                    break;
                case RSK_WIPE: //--- wipe and onboard device ---
                    reset_if_starting(RSK_META_CMD_UIOP);
                    tx = onboard_device(&onboard_ctx);
                    clear_pin();
                    if (mode == BOOTLOADER_MODE_ONBOARD) {
                        onboard_performed = 1;
                    }
                    THROW(APDU_OK);
                    break;
                case RSK_NEWPIN:
                    reset_if_starting(RSK_META_CMD_UIOP);
                    tx = set_pin();
                    clear_pin();
                    THROW(APDU_OK);
                    break;
                case RSK_ECHO_CMD: // echo
                    reset_if_starting(RSK_ECHO_CMD);
                    tx = echo(rx);
                    THROW(APDU_OK);
                    break;
                case RSK_MODE_CMD: // print mode
                    reset_if_starting(RSK_MODE_CMD);
                    tx = get_mode();
                    THROW(APDU_OK);
                    break;
                case INS_ATTESTATION:
                    reset_if_starting(INS_ATTESTATION);
                    tx = get_attestation(rx, &attestation_ctx);
                    THROW(APDU_OK);
                    break;
                case INS_SIGNER_AUTHORIZATION:
                    reset_if_starting(INS_SIGNER_AUTHORIZATION);
                    tx = do_authorize_signer(rx, &sigaut_ctx);
                    THROW(APDU_OK);
                    break;
                case RSK_RETRIES:
                    reset_if_starting(RSK_RETRIES);
                    tx = get_retries();
                    THROW(APDU_OK);
                    break;
                case RSK_UNLOCK_CMD: // Unlock
                    reset_if_starting(RSK_META_CMD_UIOP);
                    tx = unlock();
                    // The pin value will also be used in
                    // BOLOS_UX_CONSENT_APP_ADD command, so we can't wipe the
                    // pin buffer here
                    THROW(APDU_OK);
                    break;
                case RSK_END_CMD: // return to dashboard
                    reset_if_starting(RSK_END_CMD);
                    autoexec = 1;
                    return;
                case RSK_END_CMD_NOSIG: // return to dashboard
                    reset_if_starting(RSK_END_CMD_NOSIG);
                    autoexec = 0;
                    return;
                default:
                    THROW(ERR_INS_NOT_SUPPORTED);
                    break;
                }
            }
            CATCH_OTHER(e) {
                // Reset the state in case of an error
                if (e != APDU_OK) {
                    reset_if_starting(0);
                }

                switch (e & 0xF000) {
                case 0x6000:
                case 0x9000:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
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
            }
            FINALLY {
            }
        }
        END_TRY;
    }
}

/**
 * BOLOS_UX_BOOT_ONBOARDING handler
 *
 * Shows onboarding screen and waits for commands if device is not onboarded,
 * does nothing otherwise.
 *
 * @ret BOLOS_UX_OK if device is already onboarded, never returns if an actual
 *      onboarding was performed
 */
unsigned int handle_bolos_ux_boot_onboarding() {
    // re apply settings in the L4 (ble, brightness, etc) after exiting
    // application in case of wipe
    screen_settings_apply();

    // request animation when dashboard has finished displaying all the
    // elements (after onboarding OR the first time displayed)
    G_bolos_ux_context.dashboard_redisplayed = 1;

    // avoid reperso is already onboarded to avoid leaking data through
    // parameters due to user land call
    if (os_perso_isonboarded()) {
        return BOLOS_UX_OK;
    }

    io_seproxyhal_init();
    USB_power(1);
    screen_settings_apply();
    screen_not_personalized_init();
    bootloader_main(BOOTLOADER_MODE_ONBOARD);
    // bootloader_main() actually never returns when onboarding mode is active,
    // so this value is never actually returned to the caller
    return BOLOS_UX_CANCEL;
}

/**
 * BOLOS_UX_DASHBOARD handler
 *
 * Shows dashboard screen when autoexec == 0, or loads signer app when
 * autoexec == 1
 */
void handle_bolos_ux_boot_dashboard() {
    // apply settings when redisplaying dashboard
    screen_settings_apply();

    // when returning from application, the ticker could have been
    // disabled
    io_seproxyhal_setup_ticker(100);
    // Run signer application once
    if (autoexec) {
        autoexec = 0;
        run_signer_app();
    }
    screen_dashboard_init();
}

/**
 * BOLOS_UX_VALIDATE_PIN handler
 *
 * Runs the bootloader_main function
 *
 * @ret BOLOS_UX_OK if bootloader_main runs successfully
 */
unsigned int handle_bolos_ux_boot_validate_pin() {
    io_seproxyhal_init();
    USB_power(1);
    autoexec = 0;
    bootloader_main(BOOTLOADER_MODE_DEFAULT);
    return BOLOS_UX_OK;
}

/**
 * BOLOS_UX_CONSENT_APP_ADD handler
 *
 * Unlocks the device only if the signer app is authorized
 *
 * @ret BOLOS_UX_OK if the signer app is authorized and the device was unlocked,
 *      BOLOS_UX_CANCEL otherwise
 */
unsigned int handle_bolos_ux_boot_consent_app_add(unsigned char *app_hash) {
    if (is_authorized_signer(app_hash)) {
        // PIN is invalidated so we must check it again. The pin value
        // used here is the same as in RSK_UNLOCK_CMD, so we also
        // don't have a prepended length byte
        unlock_with_pin(false);
        clear_pin();
        return BOLOS_UX_OK;
    } else {
        return BOLOS_UX_CANCEL;
    }
}

/**
 * BOLOS_UX_CONSENT_FOREIGN_KEY handler
 *
 * Returns BOLOS_UX_OK to the caller
 *
 * @ret BOLOS_UX_OK
 */
unsigned int handle_bolos_ux_boot_consent_foreing_key() {
    return BOLOS_UX_OK;
}

/**
 * BOLOS_UX_CONSENT_APP_DEL handler
 *
 * Returns BOLOS_UX_OK to the caller
 *
 * @ret BOLOS_UX_OK
 */
unsigned int handle_bolos_ux_boot_consent_app_del() {
    return BOLOS_UX_OK;
}

/**
 * BOLOS_UX_PROCESSING handler
 *
 * Shows processing screen
 */
void handle_bolos_ux_boot_processing() {
    screen_processing_init();
}
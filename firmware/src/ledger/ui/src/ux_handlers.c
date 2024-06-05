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
#include <bolos_ux_common.h>
#include "ux_handlers.h"
#include "bootloader.h"
#include "ui_heartbeat.h"

dashboard_action_t dashboard_action;

void set_dashboard_action(dashboard_action_t action) {
    dashboard_action = action;
}

/**
 * Run the signer application
 *
 * @returns bool whether the application was scheduled to run
 */
static bool run_signer_app(void) {
    unsigned int i = 0;
    while (i < os_registry_count()) {
        application_t app;
        os_registry_get(i, &app);
        if (!(app.flags & APPLICATION_FLAG_BOLOS_UX)) {
            if (is_authorized_signer(app.hash)) {
                G_bolos_ux_context.app_auto_started = 1;
                set_dashboard_action(DASHBOARD_ACTION_UI_HEARTBEAT);
                screen_stack_pop();
                io_seproxyhal_disable_io();
                os_sched_exec(i); // no return
                return true;
            }
        }
        i++;
    }
    return false;
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
 * Different ways of handling this depending
 * on the value of dashboard_action
 * Can run the heartbeat frontend, the app or
 * the dashboard itself.
 */
void handle_bolos_ux_boot_dashboard() {
    if (dashboard_action == DASHBOARD_ACTION_UI_HEARTBEAT) {
        USB_power(0);
        io_seproxyhal_disable_io();
        USB_power(1);
        io_seproxyhal_init();

        // Run the heartbeat frontend and then
        // run the app (i.e., signer) upon exit
        ui_heartbeat_main(&G_bolos_ux_context.ui_heartbeat);
        if (run_signer_app())
            return;
    }

    // apply settings when redisplaying dashboard
    screen_settings_apply();

    // when returning from application, the ticker could have been
    // disabled
    io_seproxyhal_setup_ticker(100);

    // Run application (i.e., signer)
    if (dashboard_action == DASHBOARD_ACTION_APP) {
        if (run_signer_app())
            return;
    }

    // If we're here, then the dashboard action
    // is dashboard itself. Init the dashboard screen.
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

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

#ifndef __BOOTLOADER
#define __BOOTLOADER

#include "os.h"

// Handlers for bootloader-related bolos UX ux_ids

/**
 * BOLOS_UX_BOOT_ONBOARDING handler
 *
 * Shows onboarding screen and waits for commands if device is not onboarded,
 * does nothing otherwise.
 *
 * @ret BOLOS_UX_OK if device is already onboarded, never returns if an actual
 *      onboarding was performed
 */
unsigned int handle_bolos_ux_boot_onboarding();

/**
 * BOLOS_UX_DASHBOARD handler
 *
 * Shows dashboard screen when autoexec == 0, or loads signer app when
 * autoexec == 1
 */
void handle_bolos_ux_boot_dashboard();

/**
 * BOLOS_UX_VALIDATE_PIN handler
 *
 * Runs the bootloader_main function
 *
 * @ret BOLOS_UX_OK if bootloader_main runs successfully
 */
unsigned int handle_bolos_ux_boot_validate_pin();

/**
 * BOLOS_UX_CONSENT_APP_ADD handler
 *
 * Unlocks the device only if the signer app is authorized
 *
 * @ret BOLOS_UX_OK if the signer app is authorized and the device was unlocked,
 *      BOLOS_UX_CANCEL otherwise
 */
unsigned int handle_bolos_ux_boot_consent_app_add(application_t *app);

/**
 * BOLOS_UX_CONSENT_APP_DEL handler
 *
 * Returns BOLOS_UX_OK to the caller
 *
 * @ret BOLOS_UX_OK
 */
unsigned int handle_bolos_ux_boot_consent_app_del();

/**
 * BOLOS_UX_CONSENT_FOREIGN_KEY handler
 *
 * Returns BOLOS_UX_OK to the caller
 *
 * @ret BOLOS_UX_OK
 */
unsigned int handle_bolos_ux_boot_consent_foreing_key();

/**
 * BOLOS_UX_PROCESSING handler
 *
 * Shows processing screen
 */
void handle_bolos_ux_boot_processing();

#endif

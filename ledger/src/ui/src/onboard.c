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

#include <string.h>

#include "apdu.h"
#include "bolos_ux_onboarding_seed_bip39.h"
#include "defs.h"
#include "ui_err.h"
#include "os.h"
#include "onboard.h"
#include "runtime.h"

// Global onboarding flag
NON_VOLATILE unsigned char N_onboarded_ui[1];

/*
 * Reset the given onboard context
 *
 * @arg[out] onboard_ctx onboard context
 */
void reset_onboard_ctx(onboard_t *onboard_ctx) {
    explicit_bzero(onboard_ctx, sizeof(onboard_t));
}

/*
 * Implement the RSK WIPE command.
 *
 * Wipes and onboards the device.
 *
 * @arg[out] onboard_ctx onboard context
 * @ret                  number of transmited bytes to the host
 */
unsigned int onboard_device(onboard_t *onboard_ctx) {
    volatile unsigned char onboarded_flag = 0;

    // Reset the onboarding flag to mark onboarding
    // hasn't been done just in case something fails
    nvm_write((void *)PIC(N_onboarded_ui),
              (void *)&onboarded_flag,
              sizeof(onboarded_flag));

#ifndef DEBUG_BUILD
    if (!is_pin_valid()) {
        THROW(ERR_UI_INVALID_PIN);
    }
#endif

    // Wipe device
    os_global_pin_invalidate();
    os_perso_wipe();
    // Generate 32 bytes of random with onboard rng
    cx_rng((unsigned char *)onboard_ctx->seed, sizeof(onboard_ctx->seed));
    // XOR with host-generated 32 bytes random
    for (unsigned int i = 0; i < sizeof(onboard_ctx->seed); i++) {
        onboard_ctx->seed[i] ^= onboard_ctx->host_seed[i];
    }
    // The seed is now in onboard_ctx->seed, generate the mnemonic
    explicit_bzero(onboard_ctx->words_buffer,
                   sizeof(onboard_ctx->words_buffer));
    onboard_ctx->words_buffer_length =
        bolos_ux_mnemonic_from_data((unsigned char *)onboard_ctx->seed,
                                    sizeof(onboard_ctx->seed),
                                    (unsigned char *)onboard_ctx->words_buffer,
                                    sizeof(onboard_ctx->words_buffer));
    // Clear the seed
    explicit_bzero(onboard_ctx->seed, sizeof(onboard_ctx->seed));

    // Set seed from mnemonic
    os_perso_derive_and_set_seed(0,
                                 NULL,
                                 0,
                                 NULL,
                                 0,
                                 (const char *)onboard_ctx->words_buffer,
                                 onboard_ctx->words_buffer_length);

    // Clear the mnemonic
    explicit_bzero(onboard_ctx->words_buffer,
                   sizeof(onboard_ctx->words_buffer));
    onboard_ctx->words_buffer_length = 0;

    // Set PIN
    set_device_pin();
    // Finalize onboarding
    os_perso_finalize();
    os_global_pin_invalidate();
    unsigned char output_index = CMDPOS;
    SET_APDU_AT(output_index++, 2);
    SET_APDU_AT(output_index++, unlock_with_pin(true));

    // Turn the onboarding flag on to mark onboarding
    // has been done using the UI
    onboarded_flag = 1;
    nvm_write((void *)PIC(N_onboarded_ui),
              (void *)&onboarded_flag,
              sizeof(onboarded_flag));

    return output_index;
}

/*
 * Implement the RSK SEED command.
 *
 * Receives one byte at a time and fills host_seed with the host-generated
 * seed.
 *
 * @arg[in]  rx          number of received bytes from the Host
 * @arg[out] onboard_ctx onboard context
 * @ret                  number of transmited bytes to the host
 */
unsigned int set_host_seed(volatile unsigned int rx, onboard_t *onboard_ctx) {
    // Should receive 1 byte per call
    if (APDU_DATA_SIZE(rx) != 1) {
        THROW(ERR_UI_PROT_INVALID);
    }

    unsigned char index = APDU_OP();
    if ((index >= 0) && ((size_t)index < sizeof(onboard_ctx->host_seed))) {
        onboard_ctx->host_seed[index] = APDU_AT(3);
    }

    // No bytes transmited to host
    return 0;
}

/*
 * Implement the RSK IS_ONBOARD command.
 *
 * Returns onboard status to host
 *
 * @ret number of transmited bytes to the host
 */
unsigned int is_onboarded() {
    uint8_t output_index = CMDPOS;
    SET_APDU_AT(output_index++, os_perso_isonboarded());
    SET_APDU_AT(output_index++, VERSION_MAJOR);
    SET_APDU_AT(output_index++, VERSION_MINOR);
    SET_APDU_AT(output_index++, VERSION_PATCH);
    return output_index;
}

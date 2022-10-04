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

#include "string.h"

#include "defs.h"
#include "err.h"
#include "os.h"
#include "pin.h"
#include "wipe.h"

// Global onboarding flag
extern const unsigned char *N_onboarded_ui[1];

unsigned char do_rsk_wipe(wipe_t *wipe_ctx, unsigned int *words_buffer_len) {
    // Reset the onboarding flag to mark onboarding
    // hasn't been done just in case something fails
    unsigned char onboarded = 0;
    nvm_write(
        (void *)PIC(N_onboarded_ui), (void *)&onboarded, sizeof(onboarded));
#ifndef DEBUG_BUILD
    if (!is_pin_valid(wipe_ctx->pin_buffer)) {
        THROW(ERR_INVALID_PIN);
    }
#endif
    // Wipe device
    os_global_pin_invalidate();
    os_perso_wipe();
    *(wipe_ctx->onboarding_kind) = 24; // BOLOS_UX_ONBOARDING_NEW_24
    // Generate 32 bytes of random with onboard rng
    cx_rng((unsigned char *)wipe_ctx->string_buffer, HASHSIZE);
    // XOR with host-generated 32 bytes random
    for (int i = 0; i < HASHSIZE; i++) {
        wipe_ctx->string_buffer[i] ^= wipe_ctx->words_buffer[i];
    }
    // The seed is now in string_buffer, generate the mnemonic
    os_memset(wipe_ctx->words_buffer, 0, wipe_ctx->words_buffer_len);
    *words_buffer_len = wipe_ctx->mnemonic_from_data_cb(
        (unsigned char *)wipe_ctx->string_buffer,
        SEEDSIZE,
        (unsigned char *)wipe_ctx->words_buffer,
        wipe_ctx->words_buffer_len);
    // Clear the seed
    explicit_bzero((void *)wipe_ctx->string_buffer,
                   wipe_ctx->string_buffer_len);
    // Set seed from mnemonic
    os_perso_derive_and_set_seed(0,
                                 NULL,
                                 0,
                                 NULL,
                                 0,
                                 wipe_ctx->words_buffer,
                                 strlen(wipe_ctx->words_buffer));
    // Clear the mnemonic
    explicit_bzero(wipe_ctx->words_buffer, wipe_ctx->words_buffer_len);
    // Set PIN
    os_perso_set_pin(
        0, wipe_ctx->pin_buffer, strlen((const char *)wipe_ctx->pin_buffer));
    // Finalize onboarding
    os_perso_finalize();
    os_global_pin_invalidate();

    unsigned char output_index = CMDPOS;
    SET_APDU_AT(output_index++, 2);
    SET_APDU_AT(
        output_index++,
        os_global_pin_check(wipe_ctx->pin_buffer,
                            strlen((const char *)wipe_ctx->pin_buffer)));
    // Turn the onboarding flag on to mark onboarding
    // has been done using the UI
    onboarded = 1;
    nvm_write(
        (void *)PIC(N_onboarded_ui), (void *)&onboarded, sizeof(onboarded));
    // Output
    return output_index;
}
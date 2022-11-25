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
#include "defs.h"
#include "os.h"
#include "string.h"
#include "onboard.h"

/**
 * Mock context used to assert current state
 */
static mock_ctx_t mock_ctx;

void init_mock_ctx() {
    memset(&mock_ctx, 0, sizeof(mock_ctx));
}

void get_mock_ctx(mock_ctx_t *ctx) {
    memcpy(ctx, &mock_ctx, sizeof(mock_ctx));
}

/**
 * APDU buffer
 */
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

void explicit_bzero(void *s, size_t len) {
    memset(s, '\0', len);
    /* Compiler barrier.  */
    asm volatile("" ::: "memory");
}

unsigned int os_global_pin_check(unsigned char *pin_buffer,
                                 unsigned char pin_length) {
    bool pin_matches = !strncmp((const char *)pin_buffer,
                                (const char *)mock_ctx.global_pin,
                                pin_length);

    // Assert that unlock was performed while the device was locked
    if (pin_matches && !mock_ctx.device_unlocked) {
        mock_ctx.successful_unlock_while_locked_count++;
    }
    // Update mock state
    mock_ctx.device_unlocked = pin_matches;

    return (int)pin_matches;
}

void os_perso_set_pin(unsigned int identity,
                      unsigned char *pin,
                      unsigned int length) {
    strncpy((char *)mock_ctx.global_pin, (char *)pin, length);
}

void os_global_pin_invalidate(void) {
    mock_ctx.device_unlocked = false;
}

void os_memset(void *dst, unsigned char c, unsigned int length) {
    memset(dst, c, length);
}

void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len) {
    if (src_adr == NULL) {
        // Treat as memory reset
        memset(dst_adr, 0, src_len);
    } else {
        // Treat as normal copy
        memmove(dst_adr, src_adr, src_len);
    }
}

void os_perso_wipe() {
    if (!mock_ctx.device_unlocked) {
        mock_ctx.wipe_while_locked_count++;
    }
    // wipe global pin, seed and state
    memset(mock_ctx.global_pin, 0x0, sizeof(mock_ctx.global_pin));
    memset(mock_ctx.global_seed, 0x0, sizeof(mock_ctx.global_seed));
    mock_ctx.device_unlocked = false;
    mock_ctx.device_onboarded = false;
}

void os_perso_finalize(void) {
    mock_ctx.device_onboarded = true;
}

unsigned int os_perso_isonboarded(void) {
    return mock_ctx.device_onboarded;
}

unsigned int os_global_pin_retries(void) {
    return (unsigned int)MOCK_INTERNAL_RETRIES_COUNTER;
}

// Generated mnemonics buffer will be "mnemonics-generated-from:<in>"
unsigned int bolos_ux_mnemonic_from_data(unsigned char *in,
                                         unsigned int inLength,
                                         unsigned char *out,
                                         unsigned int outLength) {
    sprintf((char *)out, "mnemonics-generated-from-%s", in);
    return strlen((const char *)out);
}

void os_perso_derive_and_set_seed(unsigned char identity,
                                  const char *prefix,
                                  unsigned int prefix_length,
                                  const char *passphrase,
                                  unsigned int passphrase_length,
                                  const char *words,
                                  unsigned int words_length) {
    sprintf((char *)mock_ctx.global_seed, "seed-generated-from-%s", words);
}

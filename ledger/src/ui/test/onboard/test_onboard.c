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
#include <assert.h>
#include <string.h>

#include "cx.h"
#include "defs.h"
#include "ui_err.h"
#include "onboard.h"
#include "os.h"
#include "pin.h"
#include "assert_utils.h"
#include "apdu_utils.h"
#include "ui_instructions.h"

/**
 * Mock variables used to assert function calls
 */
static unsigned char G_mock_seed[32];
static unsigned char G_pin_buffer[10];
static unsigned char G_device_pin[10];
static unsigned char G_global_seed[257];
static bool G_is_pin_valid;
static bool G_device_unlocked;
static bool G_device_onboarded;
static bool G_wiped_while_locked;

static void setup() {
    memset(G_mock_seed, 0, sizeof(G_mock_seed));
    memset(G_pin_buffer, 0, sizeof(G_pin_buffer));
    memset(G_device_pin, 0, sizeof(G_device_pin));
    G_is_pin_valid = false;
    G_device_unlocked = false;
    G_device_onboarded = false;
    G_wiped_while_locked = false;
}

void mock_cx_rng(const unsigned char *data, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        G_mock_seed[i] = data[i];
    }
}

unsigned char *cx_rng(unsigned char *buffer, unsigned int len) {
    // Mock 32 random bytes
    for (int i = 0; i < len; i++) {
        buffer[i] = G_mock_seed[i];
    }
    return 0;
}

unsigned int bolos_ux_mnemonic_from_data(unsigned char *in,
                                         unsigned int inLength,
                                         unsigned char *out,
                                         unsigned int outLength) {
    const char mnemonics_prefix[] = "mnemonics-generated-from-";
    int len = sizeof(mnemonics_prefix) - 1;
    assert(outLength >= len + inLength);
    memcpy(out, mnemonics_prefix, len);
    memcpy(out + len, in, inLength);
    return len + inLength;
}

/**
 * Mock calls to other modules
 */
bool is_pin_valid() {
    return G_is_pin_valid;
}

void set_device_pin() {
    // NOTE: set_device_pin skips the prepended length
    memcpy(G_device_pin, G_pin_buffer + 1, sizeof(G_pin_buffer) - 1);
}

unsigned int unlock_with_pin(bool prepended_length) {
    const char *pin_buffer;
    if (prepended_length) {
        pin_buffer = (const char *)(G_pin_buffer + 1);
    } else {
        pin_buffer = (const char *)G_pin_buffer;
    }

    G_device_unlocked = (0 == strcmp((const char *)G_device_pin, pin_buffer));
    return G_device_unlocked;
}

unsigned int update_pin_buffer(volatile unsigned int rx) {
    unsigned char index = APDU_AT(2);
    unsigned char val = APDU_AT(3);
    G_pin_buffer[index] = val;
    G_pin_buffer[index + 1] = 0;
    return 3;
}

/**
 * Mock OS calls
 */
void os_global_pin_invalidate(void) {
    G_device_unlocked = false;
}

void os_perso_derive_and_set_seed(unsigned char identity,
                                  const char *prefix,
                                  unsigned int prefix_length,
                                  const char *passphrase,
                                  unsigned int passphrase_length,
                                  const char *words,
                                  unsigned int words_length) {
    sprintf((char *)G_global_seed, "seed-generated-from-%s", words);
}

void os_perso_finalize(void) {
    G_device_onboarded = true;
}

unsigned int os_perso_isonboarded(void) {
    return G_device_onboarded;
}

void os_perso_wipe() {
    if (!G_device_unlocked) {
        G_wiped_while_locked = true;
    }
    // wipe global pin, seed and state
    memset(G_device_pin, 0x0, sizeof(G_device_pin));
    memset(G_global_seed, 0x0, sizeof(G_global_seed));
    G_device_unlocked = false;
    G_device_onboarded = false;
}

// Helpers for RSK commands
static void send_rsk_pin_cmd(const char *pin) {
    unsigned int rx = 4;
    for (int i = 0; i < strlen(pin); i++) {
        SET_APDU_AT(0, CLA);
        SET_APDU_AT(1, RSK_PIN_CMD);
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, pin[i]);
        assert(3 == update_pin_buffer(rx));
    }
}

static void send_rsk_seed_cmd(onboard_t *ctx, const unsigned char *host_seed) {
    unsigned int rx = 4;
    for (int i = 0; i < SEED_LENGTH; i++) {
        SET_APDU_AT(0, CLA);
        SET_APDU_AT(1, RSK_SEED_CMD);
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, host_seed[i]);
        assert(0 == set_host_seed(rx, ctx));
    }
}

char words_buffer[] = "words_buffer";
char seed[] = "seed_buffer";

void test_reset_onboard_ctx() {
    printf("Test reset onboard context...\n");

    setup();
    onboard_t onboard_ctx;
    memcpy(onboard_ctx.words_buffer, words_buffer, sizeof(words_buffer));
    memcpy(onboard_ctx.seed, seed, sizeof(seed));

    reset_onboard_ctx(&onboard_ctx);

    ASSERT_ARRAY_CLEARED(onboard_ctx.words_buffer);
    ASSERT_ARRAY_CLEARED(onboard_ctx.seed);
    assert(0 == onboard_ctx.words_buffer_length);
}

void test_set_host_seed() {
    printf("Test set host seed...\n");

    setup();
    onboard_t onboard_ctx;
    reset_onboard_ctx(&onboard_ctx);
    // mock 32 bytes random host seed
    const char host_seed[] = {0x9c, 0xc9, 0x8b, 0xde, 0x40, 0xb3, 0x33, 0xbc,
                              0x34, 0xf2, 0xae, 0x6f, 0xe6, 0x09, 0x1f, 0x57,
                              0xfd, 0x4b, 0x6d, 0xcd, 0xc0, 0x62, 0x61, 0x53,
                              0x03, 0xf0, 0xef, 0x03, 0xce, 0x84, 0x15, 0xd3};
    unsigned int rx = 4;
    for (int i = 0; i < strlen(host_seed); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, host_seed[i]);
        assert(0 == set_host_seed(rx, &onboard_ctx));
    }
    ASSERT_MEMCMP(host_seed, onboard_ctx.host_seed, SEED_LENGTH);
}

void test_onboard_device() {
    printf("Test onboard device...\n");

    setup();
    onboard_t onboard_ctx;
    reset_onboard_ctx(&onboard_ctx);
    // mock 32 bytes random host seed
    const unsigned char host_seed[] = {
        0x9c, 0xc9, 0x8b, 0xde, 0x40, 0xb3, 0x33, 0xbc, 0x34, 0xf2, 0xae,
        0x6f, 0xe6, 0x09, 0x1f, 0x57, 0xfd, 0x4b, 0x6d, 0xcd, 0xc0, 0x62,
        0x61, 0x53, 0x03, 0xf0, 0xef, 0x03, 0xce, 0x84, 0x15, 0xd3};
    // mock 32 bytes handom seed
    const unsigned char seed[] = {
        0x21, 0x9f, 0x24, 0x3a, 0xf4, 0x23, 0x2e, 0x26, 0x0b, 0x37, 0xfe,
        0xf4, 0xd8, 0xc8, 0xf4, 0x88, 0xa5, 0x3a, 0x36, 0xd7, 0xa8, 0xa2,
        0xd5, 0x42, 0x8f, 0x57, 0xb8, 0x92, 0x79, 0x7f, 0xb0, 0xd3};

    // Set device pin (with prepended length)
    send_rsk_pin_cmd("X1234567a");
    // Set host seed
    send_rsk_seed_cmd(&onboard_ctx, host_seed);

    G_is_pin_valid = true;
    mock_cx_rng(seed, SEED_LENGTH);
    assert(3 == onboard_device(&onboard_ctx));
    ASSERT_APDU("\x80\x02\x01");
    assert(G_device_unlocked);
    assert(G_device_onboarded);
    assert(G_wiped_while_locked);

    ASSERT_STR_EQUALS("1234567a", G_device_pin);
    // "seed-generated-from-" + "mnemonics-generated-from-" + host_seed XOR seed
    ASSERT_MEMCMP(
        "seed-generated-from-mnemonics-generated-from-"
        "\xbd\x56\xaf\xe4\xb4\x90\x1d\x9a\x3f\xc5\x50\x9b\x3e\xc1\xeb\xdf\x58"
        "\x71\x5b\x1a\x68\xc0\xb4\x11\x8c\xa7\x57\x91\xb7\xfb\xa5\x00",
        G_global_seed,
        77);

    // Make sure all mnemonic and seed information is wiped after onboard_device
    ASSERT_ARRAY_CLEARED(onboard_ctx.words_buffer);
    ASSERT_ARRAY_CLEARED(onboard_ctx.seed);
    assert(0 == onboard_ctx.words_buffer_length);
}

void test_onboard_device_invalid_pin() {
    printf("Test onboard device (invalid pin)...\n");

    setup();
    onboard_t onboard_ctx;
    reset_onboard_ctx(&onboard_ctx);
    // mock 32 bytes random host seed
    const unsigned char host_seed[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // wrong device pin (without prepended length)
    send_rsk_pin_cmd("1234567a");
    // Set host seed
    send_rsk_seed_cmd(&onboard_ctx, host_seed);

    BEGIN_TRY {
        TRY {
            G_is_pin_valid = false;
            onboard_device(&onboard_ctx);
            // onboard_device should throw ERR_UI_INVALID_PIN
            ASSERT_FAIL();
        }
        CATCH(ERR_UI_INVALID_PIN) {

            return;
            assert(!G_device_onboarded);
            assert(!G_device_unlocked);
            ASSERT_ARRAY_CLEARED(G_device_pin);
            ASSERT_ARRAY_CLEARED(G_global_seed);
        }
        CATCH_OTHER(e) {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_is_onboarded() {
    printf("Test is onboarded...\n");

    setup();
    onboard_t onboard_ctx;
    reset_onboard_ctx(&onboard_ctx);
    // mock 32 bytes random host seed
    const unsigned char host_seed[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // Set device pin (with prepended length)
    send_rsk_pin_cmd("X1234567a");
    // Set host seed
    send_rsk_seed_cmd(&onboard_ctx, host_seed);

    G_device_onboarded = true;
    assert(5 == is_onboarded());
    ASSERT_APDU("\x80\x01\x04\x00\x00");

    G_device_onboarded = false;
    assert(5 == is_onboarded());
    ASSERT_APDU("\x80\x00\x04\x00\x00");
}

int main() {
    test_reset_onboard_ctx();
    test_set_host_seed();
    test_onboard_device();
    test_onboard_device_invalid_pin();
    test_is_onboarded();

    return 0;
}

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
#include "onboard.h"
#include "os.h"
#include "pin.h"

char words_buffer[] = "words_buffer";
char seed[] = "seed_buffer";

void test_reset_onboard_ctx() {
    printf("Test reset onboard context...\n");
    onboard_t onboard_ctx;
    memcpy(onboard_ctx.words_buffer, words_buffer, sizeof(words_buffer));
    memcpy(onboard_ctx.seed, seed, sizeof(seed));

    reset_onboard_ctx(&onboard_ctx);

    char expected_words_buffer[sizeof(words_buffer)];
    char expected_seed[sizeof(seed)];
    memset(expected_words_buffer, 0, sizeof(expected_words_buffer));
    memset(expected_seed, 0, sizeof(expected_seed));
    assert(memcmp(expected_words_buffer,
                  onboard_ctx.words_buffer,
                  sizeof(expected_words_buffer)) == 0);
    assert(memcmp(expected_seed, onboard_ctx.seed, sizeof(expected_seed)) == 0);
    assert(onboard_ctx.words_buffer_length == 0);
}

void test_set_host_seed() {
    printf("Test set host seed...\n");
    onboard_t onboard_ctx;
    reset_onboard_ctx(&onboard_ctx);
    // mock 32 bytes random host seed
    const char host_seed[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    unsigned int rx = 4;
    for (int i = 0; i < strlen(host_seed); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, host_seed[i]);
        assert(0 == set_host_seed(rx, &onboard_ctx));
    }
    assert(0 == strncmp((char *)onboard_ctx.host_seed, host_seed, SEEDSIZE));
}

void test_onboard_device() {
    printf("Test onboard device...\n");
    onboard_t onboard_ctx;
    reset_onboard_ctx(&onboard_ctx);
    // mock 32 bytes random host seed
    const unsigned char host_seed[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    // mock 32 bytes handom seed
    const unsigned char seed[] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    // device pin (with prepended length)
    const unsigned char valid_pin[] = "X1234567a";
    unsigned int rx;

    // Mock RSK_PIN_CMD
    rx = 4;
    for (int i = 0; i < sizeof(valid_pin); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, valid_pin[i]);
        assert(3 == update_pin_buffer(rx));
    }

    // Mock RSK_SEED_CMD
    rx = 4;
    for (int i = 0; i < strlen((const char *)host_seed); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, host_seed[i]);
        assert(0 == set_host_seed(rx, &onboard_ctx));
    }

    char generated_seed[SEEDSIZE];
    for (int i = 0; i < SEEDSIZE; i++) {
        generated_seed[i] = host_seed[i] ^ seed[i];
    }
    char expected_global_seed[257];
    memset(expected_global_seed, 0, sizeof(expected_global_seed));
    char *seed_str = stpcpy(expected_global_seed,
                            "seed-generated-from-mnemonics-generated-from-");
    for (int i = 0; i < SEEDSIZE; i++) {
        seed_str[i] = generated_seed[i];
    }

    init_mock_ctx();
    mock_cx_rng(seed, SEEDSIZE);
    assert(3 == onboard_device(&onboard_ctx));
    assert(2 == APDU_AT(1));
    assert(1 == APDU_AT(2));

    mock_ctx_t mock_ctx;
    get_mock_ctx(&mock_ctx);
    assert(true == mock_ctx.device_unlocked);
    assert(true == mock_ctx.device_onboarded);
    assert(1 == mock_ctx.wipe_while_locked_count);
    assert(!strcmp((const char *)(valid_pin + 1),
                   (const char *)mock_ctx.global_pin));
    assert(!strcmp((const char *)expected_global_seed,
                   (const char *)mock_ctx.global_seed));

    // Make sure all mnemonic and seed information is wiped after onboard_device
    char expected_words_buffer[sizeof(words_buffer)];
    char expected_seed[sizeof(seed)];
    memset(expected_words_buffer, 0, sizeof(expected_words_buffer));
    memset(expected_seed, 0, sizeof(expected_seed));
    assert(memcmp(expected_words_buffer,
                  onboard_ctx.words_buffer,
                  sizeof(expected_words_buffer)) == 0);
    assert(memcmp(expected_seed, onboard_ctx.seed, sizeof(expected_seed)) == 0);
    assert(0 == onboard_ctx.words_buffer_length);
}

void test_onboard_device_invalid_pin() {
    printf("Test onboard device (invalid pin)...\n");
    onboard_t onboard_ctx;
    reset_onboard_ctx(&onboard_ctx);
    // mock 32 bytes random host seed
    const char host_seed[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    // wrong device pin (without prepended length)
    const unsigned char invalid_pin[] = "1234567a";
    unsigned int rx;

    // Mock RSK_PIN_CMD
    rx = 4;
    for (int i = 0; i < sizeof(invalid_pin); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, invalid_pin[i]);
        assert(3 == update_pin_buffer(rx));
    }

    // Mock RSK_SEED_CMD
    rx = 4;
    for (int i = 0; i < strlen(host_seed); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, host_seed[i]);
        assert(0 == set_host_seed(rx, &onboard_ctx));
    }

    init_mock_ctx();
    // ERR_INVALID_PIN
    assert(0x69A0 == onboard_device(&onboard_ctx));
    mock_ctx_t mock_ctx;
    get_mock_ctx(&mock_ctx);

    // assert internal state was not affected
    unsigned char expected_global_pin[sizeof(mock_ctx.global_pin)];
    memset(expected_global_pin, 0, sizeof(expected_global_pin));
    unsigned char expected_global_seed[sizeof(mock_ctx.global_seed)];
    memset(expected_global_seed, 0, sizeof(expected_global_seed));

    assert(false == mock_ctx.device_onboarded);
    assert(false == mock_ctx.device_unlocked);
    assert(0 == memcmp(expected_global_pin,
                       mock_ctx.global_pin,
                       sizeof(expected_global_pin)));
    assert(0 == memcmp(expected_global_seed,
                       mock_ctx.global_seed,
                       sizeof(expected_global_seed)));
}

void test_is_onboarded() {
    printf("Test is onboarded...\n");

    onboard_t onboard_ctx;
    reset_onboard_ctx(&onboard_ctx);
    // mock 32 bytes random host seed
    const unsigned char host_seed[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    // device pin (with prepended length)
    const unsigned char valid_pin[] = "X1234567a";
    unsigned int rx;

    // Mock RSK_PIN_CMD
    rx = 4;
    for (int i = 0; i < sizeof(valid_pin); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, valid_pin[i]);
        assert(3 == update_pin_buffer(rx));
    }

    // Mock RSK_SEED_CMD
    rx = 4;
    for (int i = 0; i < strlen((const char *)host_seed); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, host_seed[i]);
        assert(0 == set_host_seed(rx, &onboard_ctx));
    }

    assert(5 == is_onboarded());
    assert(0 == APDU_AT(1));
    assert(VERSION_MAJOR == APDU_AT(2));
    assert(VERSION_MINOR == APDU_AT(3));
    assert(VERSION_PATCH == APDU_AT(4));

    onboard_device(&onboard_ctx);

    assert(5 == is_onboarded());
    assert(1 == APDU_AT(1));
    assert(VERSION_MAJOR == APDU_AT(2));
    assert(VERSION_MINOR == APDU_AT(3));
    assert(VERSION_PATCH == APDU_AT(4));
}

int main() {
    test_reset_onboard_ctx();
    test_set_host_seed();
    test_onboard_device();
    test_onboard_device_invalid_pin();
    test_is_onboarded();

    return 0;
}

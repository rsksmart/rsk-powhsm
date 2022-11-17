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
    assert(0 == strncmp((char*)onboard_ctx.host_seed, host_seed, SEEDSIZE));
}

void test_onboard_device() {
    printf("Test onboard device...\n");
    onboard_t onboard_ctx;
    reset_onboard_ctx(&onboard_ctx);
    // mock 32 bytes random host seed
    const char host_seed[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
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
    for (int i = 0; i < strlen(host_seed); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, host_seed[i]);
        assert(0 == set_host_seed(rx, &onboard_ctx));
    }

    reset_mock_func_call_list();
    assert(3 == onboard_device(&onboard_ctx));
    assert(2 == APDU_AT(1));
    assert(1 == APDU_AT(2));
    assert(get_mock_func_call(0) == MOCK_FUNC_NVM_WRITE);
    assert(get_mock_func_call(1) == MOCK_FUNC_OS_GLOBAL_PIN_INVALIDATE);
    assert(get_mock_func_call(2) == MOCK_FUNC_OS_PERSO_WIPE);
    assert(get_mock_func_call(3) == MOCK_FUNC_BOLOS_UX_MNEMONIC_FROM_DATA);
    assert(get_mock_func_call(4) == MOCK_FUNC_OS_PERSO_DERIVE_AND_SET_SEED);
    assert(get_mock_func_call(5) == MOCK_FUNC_OS_PERSO_SET_PIN);
    assert(get_mock_func_call(6) == MOCK_FUNC_OS_PERSO_FINALIZE);
    assert(get_mock_func_call(7) == MOCK_FUNC_OS_GLOBAL_PIN_INVALIDATE);
    assert(get_mock_func_call(8) == MOCK_FUNC_OS_GLOBAL_PIN_CHECK);
    assert(get_mock_func_call(9) == MOCK_FUNC_NVM_WRITE);
    assert(get_mock_func_call_count() == 10);

    // Make sure all mnemonic and seed information is wiped after onboard_device
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

    reset_mock_func_call_list();
    // ERR_INVALID_PIN
    assert(0x69A0 == onboard_device(&onboard_ctx));
    assert(get_mock_func_call(0) == MOCK_FUNC_NVM_WRITE);
    assert(get_mock_func_call_count() == 1);
}

void test_is_onboarded() {
    printf("Test is onboarded...\n");
    reset_mock_func_call_list();
    assert(5 == is_onboarded());
    assert(1 == APDU_AT(1));
    assert(VERSION_MAJOR == APDU_AT(2));
    assert(VERSION_MINOR == APDU_AT(3));
    assert(VERSION_PATCH == APDU_AT(4));
    assert(get_mock_func_call(0) == MOCK_FUNC_OS_PERSO_ISONBOARDED);
    assert(get_mock_func_call_count() == 1);
}

int main() {
    test_reset_onboard_ctx();
    test_set_host_seed();
    test_onboard_device();
    test_onboard_device_invalid_pin();
    test_is_onboarded();

    return 0;
}

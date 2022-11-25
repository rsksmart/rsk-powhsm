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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "apdu.h"
#include "os.h"
#include "pin.h"

#define IS_VALID true
#define IS_NOT_VALID false

void assert_pin(char *pin, bool expected) {
    unsigned char pin_length = (char)strlen(pin);
    unsigned char pin_buffer[16];
    memset(pin_buffer, 0, sizeof(pin_buffer));
    pin_buffer[0] = pin_length;
    strcpy((char *)pin_buffer + 1, pin);

    // Mock RSK_PIN_CMD
    unsigned int rx = 4;
    for (int i = 0; i < strlen((const char *)pin_buffer); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, pin_buffer[i]);
        assert(3 == update_pin_buffer(rx));
    }

    assert(is_pin_valid() == expected);
}

void test_validate_ok() {
    printf("Test validate pin OK...\n");

    assert_pin("abcdefgh", IS_VALID);
    assert_pin("8b23ef1s", IS_VALID);
    assert_pin("MN22P3S9", IS_VALID);
    assert_pin("MN22p3s9", IS_VALID);
}

void test_validate_numeric_pin() {
    printf("Test validate pin with only numbers...\n");

    assert_pin("1234", IS_NOT_VALID);
    assert_pin("123456", IS_NOT_VALID);
    assert_pin("12345678", IS_NOT_VALID);
    assert_pin("1234567890", IS_NOT_VALID);
}

void test_validate_pin_too_long() {
    printf("Test validate pin buffer too long...\n");

    // Long pins are accepted, but internally capped to PIN_LENGTH
    assert_pin("abcdefghi", IS_VALID);
    assert_pin("8b23ef1s85", IS_VALID);
    assert_pin("MN22P3S9P20", IS_VALID);
    assert_pin("MNOPQRSTQDAS", IS_VALID);
}

void test_validate_pin_too_short() {
    printf("Test validate pin buffer too short...\n");

    assert_pin("abcdefg", IS_NOT_VALID);
    assert_pin("8b23ef", IS_NOT_VALID);
    assert_pin("MN22P", IS_NOT_VALID);
    assert_pin("MNOP", IS_NOT_VALID);
}

void test_validate_pin_non_alpha() {
    printf("Test validate pin non alpha chars...\n");

    assert_pin("a1-@.;", IS_NOT_VALID);
    assert_pin("!@#$^&*", IS_NOT_VALID);
    assert_pin("(),./;']", IS_NOT_VALID);
    assert_pin("abcdefg", IS_NOT_VALID);
}

void test_update_pin_buffer() {
    printf("Test update pin buffer...\n");

    unsigned char pin_buffer[] = "X1234567a";
    unsigned int rx = 4;
    init_mock_ctx();
    for (int i = 0; i < strlen((const char *)pin_buffer); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, pin_buffer[i]);
        assert(3 == update_pin_buffer(rx));
    }
    mock_ctx_t mock_ctx;
    get_mock_ctx(&mock_ctx);
    const char *expected_global_pin[sizeof(mock_ctx.global_pin)];
    memset(expected_global_pin, 0, sizeof(expected_global_pin));
    assert(!strcmp((const char *)expected_global_pin,
                   (const char *)mock_ctx.global_pin));
}

void test_set_pin() {
    printf("Test set pin ok...\n");

    unsigned char pin_buffer[] = "X1234567a";
    unsigned int rx = 4;
    init_mock_ctx();
    for (int i = 0; i < strlen((const char *)pin_buffer); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, pin_buffer[i]);
        assert(3 == update_pin_buffer(rx));
    }

    assert(3 == set_pin());
    mock_ctx_t mock_ctx;
    get_mock_ctx(&mock_ctx);
    assert(true == mock_ctx.device_unlocked);
    assert(1 == mock_ctx.successful_unlock_while_locked_count);
}

void test_set_pin_invalid() {
    printf("Test set pin invalid...\n");

    unsigned char pin_buffer[] = "X12345678";
    unsigned int rx = 4;
    init_mock_ctx();
    for (int i = 0; i < strlen((const char *)pin_buffer); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, pin_buffer[i]);
        assert(3 == update_pin_buffer(rx));
    }

    assert(0x69A0 == set_pin()); // ERR_INVALID_PIN
    mock_ctx_t mock_ctx;
    get_mock_ctx(&mock_ctx);
    assert(false == mock_ctx.device_unlocked);
}

void test_unlock_with_pin() {
    printf("Test unlock with pin...\n");

    unsigned char pin_buffer[] = "X1234567a";
    unsigned int rx = 4;
    init_mock_ctx();
    for (int i = 0; i < strlen((const char *)pin_buffer); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, pin_buffer[i]);
        assert(3 == update_pin_buffer(rx));
    }
    assert(3 == set_pin());
    assert(1 == unlock_with_pin(true));
    mock_ctx_t mock_ctx;
    get_mock_ctx(&mock_ctx);
    // Skip prepended length
    assert(!strcmp((const char *)(pin_buffer + 1),
                   (const char *)mock_ctx.global_pin));
    assert(true == mock_ctx.device_unlocked);
    assert(1 == mock_ctx.successful_unlock_while_locked_count);
}

void test_unlock_with_pin_capping() {
    printf("Test unlock with pin capping...\n");

    unsigned char pin_buffer[] = "X1234567abcdef";
    unsigned int rx = 4;
    init_mock_ctx();
    for (int i = 0; i < strlen((const char *)pin_buffer); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, pin_buffer[i]);
        assert(3 == update_pin_buffer(rx));
    }
    assert(3 == set_pin());
    assert(1 == unlock_with_pin(true));
    mock_ctx_t mock_ctx;
    get_mock_ctx(&mock_ctx);
    // Make sure pin capping is applied
    // (i.e. only the first 8 bytes are copied to global buffer)
    assert(!strcmp("1234567a", (const char *)mock_ctx.global_pin));
    assert(true == mock_ctx.device_unlocked);
    assert(1 == mock_ctx.successful_unlock_while_locked_count);
}

void test_unlock_with_pin_not_set() {
    printf("Test unlock with pin (pin not set)...\n");

    unsigned char pin_buffer[] = "X1234567a";
    unsigned int rx = 4;
    init_mock_ctx();
    for (int i = 0; i < strlen((const char *)pin_buffer); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, pin_buffer[i]);
        assert(3 == update_pin_buffer(rx));
    }

    mock_ctx_t mock_ctx;
    get_mock_ctx(&mock_ctx);
    assert(0 == unlock_with_pin(true));
    assert(false == mock_ctx.device_unlocked);
    assert(0 == mock_ctx.successful_unlock_while_locked_count);
    const char *expected_global_pin[sizeof(mock_ctx.global_pin)];
    memset(expected_global_pin, 0, sizeof(expected_global_pin));
    assert(!strcmp((const char *)expected_global_pin,
                   (const char *)mock_ctx.global_pin));
}

void test_set_device_pin() {
    printf("Test set device pin...\n");

    unsigned char pin_buffer[] = "X1234567a";
    unsigned int rx = 4;
    init_mock_ctx();
    for (int i = 0; i < strlen((const char *)pin_buffer); i++) {
        SET_APDU_AT(2, i);
        SET_APDU_AT(3, pin_buffer[i]);
        assert(3 == update_pin_buffer(rx));
    }

    set_device_pin();
    mock_ctx_t mock_ctx;
    get_mock_ctx(&mock_ctx);
    // Skip prepended length
    assert(!strcmp((const char *)(pin_buffer + 1),
                   (const char *)mock_ctx.global_pin));
    assert(false == mock_ctx.device_unlocked);
}

int main() {
    test_validate_numeric_pin();
    test_validate_pin_too_long();
    test_validate_pin_too_short();
    test_validate_pin_non_alpha();
    test_update_pin_buffer();
    test_set_pin();
    test_set_pin_invalid();
    test_validate_ok();
    test_unlock_with_pin();
    test_unlock_with_pin_capping();
    test_unlock_with_pin_not_set();
    test_set_device_pin();

    return 0;
}
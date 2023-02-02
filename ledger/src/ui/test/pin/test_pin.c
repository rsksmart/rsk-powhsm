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
#include "assert_utils.h"
#include "apdu_utils.h"
#include "defs.h"
#include "ui_err.h"
#include "mock.h"
#include "ui_instructions.h"
#include "pin.h"

#define IS_VALID true
#define IS_NOT_VALID false

// Reference G_pin_buffer from pin.c
extern unsigned char G_pin_buffer[10];

// Mock variables
static unsigned char G_device_pin[10];
static bool G_device_unlocked;
static bool G_os_global_pin_invalidate_called;
static bool G_successful_unlock_while_locked;

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

static void setup() {
    memset(G_device_pin, 0, sizeof(G_device_pin));
    memset(G_pin_buffer, 0, sizeof(G_pin_buffer));
    G_device_unlocked = false;
    G_successful_unlock_while_locked = false;
    G_os_global_pin_invalidate_called = false;
}

// OS function mocks
unsigned int os_global_pin_check(unsigned char *pin_buffer,
                                 unsigned char pin_length) {
    bool pin_matches = (0 == strncmp((const char *)G_device_pin,
                                     (const char *)pin_buffer,
                                     pin_length));
    if (pin_matches && !G_device_unlocked) {
        G_device_unlocked = true;
        G_successful_unlock_while_locked = true;
    }
    return pin_matches;
}

void os_global_pin_invalidate(void) {
    G_os_global_pin_invalidate_called = true;
    G_device_unlocked = false;
}

void os_perso_set_pin(unsigned int identity,
                      unsigned char *pin,
                      unsigned int length) {
    strncpy((char *)G_device_pin, (const char *)pin, length);
}

// Other helpers
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

    setup();
    send_rsk_pin_cmd("X1234567a");

    ASSERT_STR_EQUALS("X1234567a", G_pin_buffer);
}

void test_set_pin() {
    printf("Test set pin ok...\n");

    setup();
    send_rsk_pin_cmd("X1234567a");

    assert(3 == set_pin());
    ASSERT_STR_EQUALS("1234567a", G_device_pin);
    assert(G_device_unlocked);
    assert(G_os_global_pin_invalidate_called);
    assert(G_successful_unlock_while_locked);
}

void test_set_pin_invalid() {
    printf("Test set pin invalid...\n");

    setup();
    send_rsk_pin_cmd("X12345678");

    BEGIN_TRY {
        TRY {
            set_pin();
            // set_pin should throw ERR_UI_INVALID_PIN
            ASSERT_FAIL();
        }
        CATCH(ERR_UI_INVALID_PIN) {
            assert(!G_device_unlocked);
            return;
        }
        CATCH_OTHER(e) {
            ASSERT_FAIL();
        }
        FINALLY {
        }
    }
    END_TRY;
}

void test_unlock_with_pin() {
    printf("Test unlock with pin...\n");

    setup();
    send_rsk_pin_cmd("X1234567a");

    assert(3 == set_pin());
    assert(1 == unlock_with_pin(true));
    assert(3 == set_pin());
    assert(1 == unlock_with_pin(true));
    // Skip prepended length
    ASSERT_STR_EQUALS("1234567a", G_device_pin);
    assert(G_device_unlocked);
    assert(G_successful_unlock_while_locked);
}

void test_unlock_with_pin_capping() {
    printf("Test unlock with pin capping...\n");

    setup();
    send_rsk_pin_cmd("X1234567abcdef");

    assert(3 == set_pin());
    assert(1 == unlock_with_pin(true));

    // Make sure pin capping is applied
    // (i.e. only the first 8 bytes are copied to global buffer)
    ASSERT_STR_EQUALS("1234567a", G_device_pin);
    assert(G_device_unlocked);
    assert(G_successful_unlock_while_locked);
}

void test_unlock_with_pin_not_set() {
    printf("Test unlock with pin (pin not set)...\n");

    setup();
    send_rsk_pin_cmd("X1234567a");

    assert(0 == unlock_with_pin(true));

    assert(!G_device_unlocked);
    assert(!G_successful_unlock_while_locked);

    ASSERT_ARRAY_CLEARED(G_device_pin);
}

void test_set_device_pin() {
    printf("Test set device pin...\n");

    setup();
    send_rsk_pin_cmd("X1234567a");

    set_device_pin();

    // Skip prepended length
    ASSERT_STR_EQUALS("1234567a", G_device_pin);
    assert(!G_device_unlocked);
}

int main() {
    test_validate_ok();
    test_validate_numeric_pin();
    test_validate_pin_too_long();
    test_validate_pin_too_short();
    test_validate_pin_non_alpha();
    test_update_pin_buffer();
    test_set_pin();
    test_set_pin_invalid();
    test_unlock_with_pin();
    test_unlock_with_pin_capping();
    test_unlock_with_pin_not_set();
    test_set_device_pin();

    return 0;
}
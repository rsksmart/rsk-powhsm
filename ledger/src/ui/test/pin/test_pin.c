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

#include "pin.h"

#define IS_VALID true
#define IS_NOT_VALID false

void set_payload(pin_t *pin_ctx, unsigned char *payload, size_t n) {
    memcpy(GET_PIN(pin_ctx), payload, n);
}

void assert_pin(char *pin, bool expected) {
    unsigned char pin_length = (char)strlen(pin);
    unsigned char *pin_buffer = malloc(pin_length + 2);
    pin_buffer[0] = pin_length;
    strcpy((char *)pin_buffer + 1, pin);

    pin_t pin_ctx;
    init_pin_ctx(&pin_ctx, pin_buffer);
    assert(is_pin_valid(&pin_ctx) == expected);
    free(pin_buffer);
}

void test_ok() {
    printf("Test OK...\n");

    assert_pin("abcdefgh", IS_VALID);
    assert_pin("8b23ef1s", IS_VALID);
    assert_pin("MN22P3S9", IS_VALID);
    assert_pin("MN22p3s9", IS_VALID);
}

void test_numeric_pin() {
    printf("Test pin with only numbers...\n");

    assert_pin("1234", IS_NOT_VALID);
    assert_pin("123456", IS_NOT_VALID);
    assert_pin("12345678", IS_NOT_VALID);
    assert_pin("1234567890", IS_NOT_VALID);
}

void test_pin_too_long() {
    printf("Test pin buffer too long...\n");

    assert_pin("abcdefghi", IS_NOT_VALID);
    assert_pin("8b23ef1s85", IS_NOT_VALID);
    assert_pin("MN22P3S9P20", IS_NOT_VALID);
    assert_pin("MNOPQRSTQDAS", IS_NOT_VALID);
}

void test_pin_too_short() {
    printf("Test pin buffer too short...\n");

    assert_pin("abcdefg", IS_NOT_VALID);
    assert_pin("8b23ef", IS_NOT_VALID);
    assert_pin("MN22P", IS_NOT_VALID);
    assert_pin("MNOP", IS_NOT_VALID);
}

void test_pin_non_alpha() {
    printf("Test pin non alpha chars...\n");

    assert_pin("a1-@.;", IS_NOT_VALID);
    assert_pin("!@#$^&*", IS_NOT_VALID);
    assert_pin("(),./;']", IS_NOT_VALID);
    assert_pin("abcdefg", IS_NOT_VALID);
}

int main() {
    test_ok();

    test_numeric_pin();
    test_pin_too_long();
    test_pin_too_short();
    test_pin_non_alpha();

    return 0;
}
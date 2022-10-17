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

void set_payload(pin_t *pin_ctx, unsigned char *payload, size_t n) {
    memcpy(pin_ctx->pin_buffer.payload, payload, n);
}

void test_ok() {
    printf("Test OK...\n");
    pin_t pin_ctx;
    reset_pin(&pin_ctx);

    set_payload(&pin_ctx, (unsigned char *)"abcdefgh", strlen("abcdefgh"));
    assert(is_pin_valid(&pin_ctx));
    set_payload(&pin_ctx, (unsigned char *)"8b23ef1s", strlen("8b23ef1s"));
    assert(is_pin_valid(&pin_ctx));
    set_payload(&pin_ctx, (unsigned char *)"MN22P3S9", strlen("MN22P3S9"));
    assert(is_pin_valid(&pin_ctx));
    set_payload(&pin_ctx, (unsigned char *)"MN22P3S9", strlen("MN22P3S9"));
    assert(is_pin_valid(&pin_ctx));
}

void test_numeric_pin() {
    printf("Test pin with only numbers...\n");
    pin_t pin_ctx;
    reset_pin(&pin_ctx);

    set_payload(&pin_ctx, (unsigned char *)"1234", strlen("1234"));
    assert(!is_pin_valid(&pin_ctx));
    set_payload(&pin_ctx, (unsigned char *)"123456", strlen("123456"));
    assert(!is_pin_valid(&pin_ctx));
    set_payload(&pin_ctx, (unsigned char *)"12345678", strlen("12345678"));
    assert(!is_pin_valid(&pin_ctx));
    set_payload(&pin_ctx, (unsigned char *)"1234567890", strlen("1234567890"));
    assert(!is_pin_valid(&pin_ctx));
}

void test_pin_too_long() {
    printf("Test pin buffer too long...\n");
    pin_t pin_ctx;
    reset_pin(&pin_ctx);

    set_payload(&pin_ctx, (unsigned char *)"abcdefghi", strlen("abcdefghi"));
    assert(!is_pin_valid(&pin_ctx));
    set_payload(&pin_ctx, (unsigned char *)"8b23ef1s85", strlen("8b23ef1s85"));
    assert(!is_pin_valid(&pin_ctx));
    set_payload(
        &pin_ctx, (unsigned char *)"MN22P3S9P20", strlen("MN22P3S9P20"));
    assert(!is_pin_valid(&pin_ctx));
    set_payload(
        &pin_ctx, (unsigned char *)"MNOPQRSTQDAS", strlen("MNOPQRSTQDAS"));
    assert(!is_pin_valid(&pin_ctx));
}

void test_pin_too_short() {
    printf("Test pin buffer too short...\n");
    pin_t pin_ctx;
    reset_pin(&pin_ctx);

    set_payload(&pin_ctx, (unsigned char *)"abcdefg", strlen("abcdefg"));
    assert(!is_pin_valid(&pin_ctx));
    set_payload(&pin_ctx, (unsigned char *)"8b23ef", strlen("8b23ef"));
    assert(!is_pin_valid(&pin_ctx));
    set_payload(&pin_ctx, (unsigned char *)"MN22P", strlen("MN22P"));
    assert(!is_pin_valid(&pin_ctx));
    set_payload(&pin_ctx, (unsigned char *)"MNOP", strlen("MNOP"));
    assert(!is_pin_valid(&pin_ctx));
}

void test_pin_non_alpha() {
    printf("Test pin non alpha chars...\n");
    pin_t pin_ctx;
    reset_pin(&pin_ctx);

    set_payload(&pin_ctx, (unsigned char *)"a1-@.;", strlen("a1-@.;"));
    assert(!is_pin_valid(&pin_ctx));
    set_payload(&pin_ctx, (unsigned char *)"!@#$^&*", strlen("!@#$^&*"));
    assert(!is_pin_valid(&pin_ctx));
    set_payload(&pin_ctx, (unsigned char *)"(),./;']", strlen("(),./;']"));
    assert(!is_pin_valid(&pin_ctx));
}

int main() {
    test_ok();
    test_numeric_pin();
    test_pin_too_long();
    test_pin_too_short();
    test_pin_non_alpha();

    return 0;
}
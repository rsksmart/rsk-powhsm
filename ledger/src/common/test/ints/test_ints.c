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
#include <assert.h>
#include <string.h>

#include "ints.h"

void assert_uint_to_decstr(int value, char* expected) {
    char buffer[12];
    buffer[0] = 34;
    buffer[11] = 35;

    printf("Testing conversion of %d should be '%s'...\n", value, expected);

    UINT_TO_DECSTR(buffer + 1, value);

    assert(!strcmp(expected, buffer + 1));
    assert(strlen(buffer + 1) == strlen(expected));
    // Make sure we're not writing outside of the buffer
    assert(buffer[0] == 34);
    assert(buffer[11] == 35);
}

void test_uint_to_decstr() {
    assert_uint_to_decstr(1, "1");
    assert_uint_to_decstr(52, "52");
    assert_uint_to_decstr(286, "286");
    assert_uint_to_decstr(3490, "3490");
    assert_uint_to_decstr(65536, "65536");
    assert_uint_to_decstr(7203400, "7203400");
    assert_uint_to_decstr(123456789, "123456789");
}

void assert_nibble_to_hexchar(unsigned char value, char expected) {
    char converted;
    printf("Testing nibble %d should be '%c'...\n", value, expected);
    NIBBLE_TO_HEXCHAR(converted, value);
    assert(expected == converted);
}

void test_nibble_to_hexchar() {
    char c[2];
    for (int i = 0; i < 16; i++) {
        sprintf(c, "%01x", i);
        assert_nibble_to_hexchar(i, c[0]);
    }
}

void assert_byte_to_hexstr(unsigned char value, char* expected) {
    char converted[3];
    converted[2] = 0;
    printf("Testing byte %d should be '%s'...\n", value, expected);
    BYTE_TO_HEXSTR(converted, value);
    assert(!strcmp(expected, converted));
}

void test_byte_to_hexstr() {
    char s[3];
    for (int i = 0; i <= 0xff; i++) {
        sprintf(s, "%02x", i);
        assert_byte_to_hexstr(i, s);
    }
}

int main() {
    test_uint_to_decstr();
    test_nibble_to_hexchar();
    test_byte_to_hexstr();
    return 0;
}
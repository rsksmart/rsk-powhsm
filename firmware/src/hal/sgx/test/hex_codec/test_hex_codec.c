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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "hex_codec.h"

static void test_hexcd_is_valid() {
    printf("Testing hexcd_is_valid...\n");

    assert(hexcd_is_valid("00ffA1", 6));
    assert(!hexcd_is_valid("0ff", 3));
    assert(!hexcd_is_valid("00fg", 4));
    assert(!hexcd_is_valid("gg", 2));
    assert(hexcd_is_valid("aabbccddeeff", 12));
    assert(!hexcd_is_valid("aabbccddeeffgg", 14));
    assert(!hexcd_is_valid("!@#$%^&*()", 10));
    assert(!hexcd_is_valid(NULL, 2));
}

static void test_hexcd_decode() {
    printf("Testing hexcd_decode...\n");

    uint8_t out[8] = {0};
    size_t out_len = sizeof(out);

    assert(hexcd_decode("00ffA1", 6, out, &out_len));
    assert(out_len == 3);
    assert(out[0] == 0x00);
    assert(out[1] == 0xff);
    assert(out[2] == 0xa1);

    out_len = sizeof(out);
    assert(!hexcd_decode("00f", 3, out, &out_len));
    out_len = sizeof(out);
    assert(!hexcd_decode("00fg", 4, out, &out_len));
    out_len = 1;
    assert(!hexcd_decode("00ff", 4, out, &out_len));
    out_len = sizeof(out);
    assert(!hexcd_decode(NULL, 4, out, &out_len));
    out_len = sizeof(out);
    assert(!hexcd_decode("00ff", 4, NULL, &out_len));
    assert(!hexcd_decode("00ff", 4, out, NULL));
}

static void test_hexcd_encode() {
    printf("Testing hexcd_encode...\n");

    const uint8_t data[] = {0x00, 0xff, 0xa1};
    char out[16] = {0};
    size_t out_len = sizeof(out);

    assert(hexcd_encode(data, sizeof(data), out, &out_len));
    assert(out_len == 6);
    assert(memcmp(out, "00ffa1", 6) == 0);

    out_len = 5;
    assert(!hexcd_encode(data, sizeof(data), out, &out_len));
    out_len = sizeof(out);
    assert(!hexcd_encode(NULL, sizeof(data), out, &out_len));
    out_len = sizeof(out);
    assert(!hexcd_encode(data, sizeof(data), NULL, &out_len));
    assert(!hexcd_encode(data, sizeof(data), out, NULL));
}

int main() {
    test_hexcd_is_valid();
    test_hexcd_decode();
    test_hexcd_encode();
    return 0;
}

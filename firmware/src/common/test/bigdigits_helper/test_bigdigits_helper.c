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

#include "bigdigits_helper.h"

#define MAX_DIGITS 10
#define MAX_BYTES (MAX_DIGITS * sizeof(DIGIT_T))

void assert_parse_bigint_be(const uint8_t buf[],
                            const size_t buf_size,
                            const DIGIT_T exp[],
                            const size_t exp_digits) {
    DIGIT_T dest[MAX_DIGITS];

    parse_bigint_be(buf, buf_size, dest, sizeof(dest) / sizeof(dest[0]));

    for (int i = 0; i < sizeof(dest) / sizeof(dest[0]); i++) {
        assert(dest[i] == (i < exp_digits ? exp[i] : 0));
    }
}

void test_parse_bigint_be() {
    printf("Testing parse_bigint_be... ");

    assert_parse_bigint_be(
        (const uint8_t[]){0x1c,
                          0x24,
                          0xa0,
                          0xa1,
                          0xa2,
                          0xa3,
                          0xb0,
                          0xb1,
                          0xb2,
                          0xb3,
                          0xc0,
                          0xc1,
                          0xc2,
                          0xc3},
        14,
        (const DIGIT_T[]){0xc0c1c2c3, 0xb0b1b2b3, 0xa0a1a2a3, 0x1c24},
        4);

    assert_parse_bigint_be(
        (const uint8_t[]){0xa0, 0xa1, 0xa2, 0xa3, 0xb0, 0xb1, 0xb2, 0xb3},
        8,
        (const DIGIT_T[]){0xb0b1b2b3, 0xa0a1a2a3},
        2);

    assert_parse_bigint_be(
        (const uint8_t[]){0xaa}, 1, (const DIGIT_T[]){0xaa}, 1);

    assert_parse_bigint_be(
        (const uint8_t[]){0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
                          0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19,
                          0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
                          0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09,
                          0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01},
        40,
        (const DIGIT_T[]){0x04030201,
                          0x08070605,
                          0x0c0b0a09,
                          0x100f0e0d,
                          0x14131211,
                          0x18171615,
                          0x1c1b1a19,
                          0x201f1e1d,
                          0x24232221,
                          0x28272625},
        10);

    printf("OK\n");
}

void assert_dump_bigint_be(const DIGIT_T n[],
                           const size_t n_digits,
                           const uint8_t exp[],
                           const size_t exp_size) {
    uint8_t dest[MAX_BYTES];

    memset(dest, 0xff, sizeof(dest));
    dump_bigint_be(dest, n, n_digits);

    for (int i = 0; i < sizeof(dest); i++) {

        assert(dest[i] == (i < exp_size ? exp[i] : 0xff));
    }
}

void test_dump_bigint_be() {
    printf("Testing dump_bigint_be... ");

    assert_dump_bigint_be(
        (const DIGIT_T[]){0xc0c1c2c3, 0xb0b1b2b3, 0xa0a1a2a3, 0x1c24},
        4,
        (const uint8_t[]){0x0,
                          0x0,
                          0x1c,
                          0x24,
                          0xa0,
                          0xa1,
                          0xa2,
                          0xa3,
                          0xb0,
                          0xb1,
                          0xb2,
                          0xb3,
                          0xc0,
                          0xc1,
                          0xc2,
                          0xc3},
        16);

    assert_dump_bigint_be(
        (const DIGIT_T[]){0xc0c1c2c3, 0xb0b1b2b3},
        2,
        (const uint8_t[]){0xb0, 0xb1, 0xb2, 0xb3, 0xc0, 0xc1, 0xc2, 0xc3},
        8);

    assert_dump_bigint_be(
        (const DIGIT_T[]){0xaa}, 1, (const uint8_t[]){0x0, 0x0, 0x0, 0xaa}, 4);

    assert_dump_bigint_be((const DIGIT_T[]){0x04030201,
                                            0x08070605,
                                            0x0c0b0a09,
                                            0x100f0e0d,
                                            0x14131211,
                                            0x18171615,
                                            0x1c1b1a19,
                                            0x201f1e1d,
                                            0x24232221,
                                            0x28272625},
                          10,
                          (const uint8_t[]){
                              0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
                              0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19,
                              0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
                              0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09,
                              0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                          },
                          40);

    printf("OK\n");
}

int main() {
    test_parse_bigint_be();
    test_dump_bigint_be();
    return 0;
}

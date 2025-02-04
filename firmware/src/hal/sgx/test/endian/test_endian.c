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

#include "endian.h"

void assert_write_uint32_be(const uint32_t n, const uint8_t exp[]) {
    uint8_t dest[sizeof(uint32_t)];

    memset(dest, 0, sizeof(dest));
    write_uint32_be(dest, n);

    for (unsigned long i = 0; i < sizeof(dest); i++) {
        assert(dest[i] == exp[i]);
    }
}

void test_write_uint32_be() {
    printf("Testing write_uint32_be... ");

    assert_write_uint32_be(0xaabbccdd,
                           (const uint8_t[]){0xaa, 0xbb, 0xcc, 0xdd});

    assert_write_uint32_be(0x44, (const uint8_t[]){0x0, 0x0, 0x0, 0x44});

    assert_write_uint32_be(0x4455, (const uint8_t[]){0x0, 0x0, 0x44, 0x55});

    assert_write_uint32_be(0x445566, (const uint8_t[]){0x0, 0x44, 0x55, 0x66});

    printf("OK\n");
}

int main() {
    test_write_uint32_be();
    return 0;
}

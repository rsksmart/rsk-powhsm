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

#include "bigdigits_helper.h"

void parse_bigint_be(const uint8_t* buf,
                     uint16_t buf_size,
                     DIGIT_T target[],
                     uint16_t target_digits) {

    mpSetZero(target, target_digits);
    int j = 0, k = 0;
    DIGIT_T curr = 0;
    for (int i = buf_size - 1; i >= 0; i--) {
        curr = buf[i];
        target[j] |= (curr << (k * 8));
        if (++k == sizeof(DIGIT_T)) {
            ++j;
            k = 0;
        }
    }
}

void dump_bigint_be(uint8_t* buf, const DIGIT_T n[], const size_t digits) {
    int k = 0;
    for (int i = digits - 1; i >= 0; i--) {
        buf[k++] = (uint8_t)((n[i] & 0xff000000) >> 24);
        buf[k++] = (uint8_t)((n[i] & 0x00ff0000) >> 16);
        buf[k++] = (uint8_t)((n[i] & 0x0000ff00) >> 8);
        buf[k++] = (uint8_t)((n[i] & 0x000000ff) >> 0);
    }
}
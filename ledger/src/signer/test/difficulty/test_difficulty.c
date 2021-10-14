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

#include "bigdigits.h"
#include "bc_diff.h"

static const DIGIT_T _2e256[] = {
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
};

void test_conversions() {
    const uint8_t src_bytes[] = {0x02, 0x00, 0x00};

    DIGIT_T bi[BIGINT_LEN];
    bigint(src_bytes, sizeof(src_bytes), bi, BIGINT_LEN);
    uint8_t dst_bytes[sizeof(bi)];
    dump_bigint(dst_bytes, bi, BIGINT_LEN);

    int start = 0;
    for (; dst_bytes[start] == 0; start++)
        ;
    for (int i = start; i < sizeof(dst_bytes); i++) {
        printf("%02x ", dst_bytes[i]);
    }
    printf("\n");

    assert(start + sizeof(src_bytes) == sizeof(dst_bytes));
    assert(memcmp(src_bytes, dst_bytes + start, sizeof(src_bytes)) == 0);
}

void test_difficulty() {
    const uint8_t block_diff[] = {0x02, 0x00, 0x00};

    const diff_result expected[] = {DIFF_MATCH, DIFF_MATCH, DIFF_MISMATCH};

    const uint8_t mm_hdr_hash[][32] = {
        {
            0x00, 0x00, 0x15, 0x2f, 0x5f, 0x5e, 0x57, 0xbf, 0x60, 0x10, 0x34,
            0xb6, 0xfb, 0x3c, 0xda, 0x55, 0x55, 0x38, 0xf8, 0x7d, 0x06, 0x14,
            0x15, 0x7a, 0x33, 0x9a, 0xe7, 0x2f, 0x1b, 0x9e, 0x21, 0xcb,
        },
        {
            0x00, 0x00, 0x36, 0xdb, 0xe8, 0xd9, 0xfa, 0xee, 0xa6, 0x2e, 0xb3,
            0xe3, 0x6e, 0xd9, 0x42, 0x73, 0xe0, 0x01, 0x9e, 0xc0, 0x0e, 0xa5,
            0x99, 0x85, 0xb9, 0x6b, 0x3a, 0x4d, 0xe9, 0x40, 0xaf, 0xec,
        },
        {
            0x00, 0x00, 0x85, 0x2f, 0x5f, 0x5e, 0x57, 0xbf, 0x60, 0x10, 0x34,
            0xb6, 0xfb, 0x3c, 0xda, 0x55, 0x55, 0x38, 0xf8, 0x7d, 0x06, 0x14,
            0x15, 0x7a, 0x33, 0x9a, 0xe7, 0x2f, 0x1b, 0x9e, 0x21, 0xcb,
        },
    };

    DIGIT_T difficulty[BIGINT_LEN];
    bigint(block_diff, sizeof(block_diff), difficulty, BIGINT_LEN);

    size_t size = sizeof(mm_hdr_hash) / sizeof(mm_hdr_hash[0]);
    for (int i = 0; i < size; i++) {
        diff_result r = check_difficulty(difficulty, mm_hdr_hash[i]);
        assert(r == expected[i]);
    }
}

int main() {
    test_conversions();
    test_difficulty();
    return 0;
}

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
#include <stdbool.h>
#include <assert.h>

#include "memutil.h"

void os_memmove(void *dst, const void *src, unsigned int length) {
}

void test_ok() {
    printf("Test OK...\n");
    char src[15];
    char dst[10];

    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), 10, { assert(false); });
    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), 9, { assert(false); });
    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), 4, { assert(false); });
}

void test_negative() {
    printf("Test negative length...\n");
    char src[15];
    char dst[10];

    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), -1, { return; });
    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), -5, { return; });
    assert(false);
}

void test_src_outofbounds() {
    printf("Test read src out of bounds...\n");
    char src[5];
    char dst[10];

    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), 6, { return; });
    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), 7, { return; });
    assert(false);
}

void test_dst_outofbounds() {
    printf("Test read dst out of bounds...\n");
    char src[15];
    char dst[10];

    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), 11, { return; });
    SAFE_MEMMOVE(src, sizeof(src), dst, sizeof(dst), 13, { return; });
    assert(false);
}

int main() {
    test_ok();
    test_negative();
    test_src_outofbounds();
    test_dst_outofbounds();
    return 0;
}
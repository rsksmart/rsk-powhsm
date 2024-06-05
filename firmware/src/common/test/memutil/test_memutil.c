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
#include <limits.h>

#include "memutil.h"

#define TEST_MEMMOVE(                                                      \
    dst, dst_size, dst_off, src, src_size, src_off, n, ERR_EXPR)           \
    {                                                                      \
        expected_dst =                                                     \
            (unsigned char*)((unsigned char*)dst + (unsigned int)dst_off); \
        expected_src =                                                     \
            (unsigned char*)((unsigned char*)src + (unsigned int)src_off); \
        expected_length = (unsigned int)n;                                 \
        SAFE_MEMMOVE(                                                      \
            dst, dst_size, dst_off, src, src_size, src_off, n, ERR_EXPR);  \
    }

unsigned char* expected_dst;
unsigned char* expected_src;
unsigned int expected_length;
int copied;

void os_memmove_reset_mock() {
    copied = 0;
}

void os_memmove(void* dst, const void* src, unsigned int length) {
    assert(expected_dst == dst);
    assert(expected_src == src);
    assert(expected_length == length);
    copied++;
}

void test_ok() {
    printf("Test OK...\n");
    char src[15];
    char dst[10];

    os_memmove_reset_mock();
    TEST_MEMMOVE(
        dst, sizeof(dst), 0, src, sizeof(src), 0, 10, { assert(false); });
    TEST_MEMMOVE(
        dst, sizeof(dst), 0, src, sizeof(src), 0, 9, { assert(false); });
    TEST_MEMMOVE(
        dst, sizeof(dst), 0, src, sizeof(src), 0, 4, { assert(false); });
    TEST_MEMMOVE(
        dst, sizeof(dst), 1, src, sizeof(src), 2, 4, { assert(false); });
    TEST_MEMMOVE(
        dst, sizeof(dst), 4, src, sizeof(src), 9, 6, { assert(false); });
    assert(copied == 5);
}

void test_negatives() {
    printf("Test negatives...\n");
    char src[15];
    char dst[10];
    int failed = 0;

    os_memmove_reset_mock();
    TEST_MEMMOVE(dst, sizeof(dst), 0, src, sizeof(src), 0, -1, { failed++; });
    TEST_MEMMOVE(dst, sizeof(dst), 0, src, sizeof(src), 0, -5, { failed++; });
    TEST_MEMMOVE(dst, sizeof(dst), -1, src, sizeof(src), 0, 2, { failed++; });
    TEST_MEMMOVE(dst, sizeof(dst), 0, src, sizeof(src), -1, 8, { failed++; });
    assert(failed == 4);
    assert(!copied);
}

void test_src_outofbounds() {
    printf("Test read src out of bounds...\n");
    char src[5];
    char dst[10];
    int failed = 0;

    os_memmove_reset_mock();
    TEST_MEMMOVE(dst, sizeof(dst), 0, src, sizeof(src), 0, 6, { failed++; });
    TEST_MEMMOVE(dst, sizeof(dst), 0, src, sizeof(src), 0, 7, { failed++; });
    assert(failed == 2);
    assert(!copied);
}

void test_src_outofbounds_offset() {
    printf("Test read src out of bounds with offset...\n");
    char src[15];
    char dst[10];
    int failed = 0;

    os_memmove_reset_mock();
    TEST_MEMMOVE(dst, sizeof(dst), 0, src, sizeof(src), 6, 10, { failed++; });
    TEST_MEMMOVE(dst, sizeof(dst), 0, src, sizeof(src), 15, 4, { failed++; });
    assert(failed == 2);
    assert(!copied);
}

void test_dst_outofbounds() {
    printf("Test read dst out of bounds...\n");
    char src[15];
    char dst[10];
    int failed = 0;

    os_memmove_reset_mock();
    TEST_MEMMOVE(dst, sizeof(dst), 0, src, sizeof(src), 0, 11, { failed++; });
    TEST_MEMMOVE(dst, sizeof(dst), 0, src, sizeof(src), 0, 13, { failed++; });
    assert(failed == 2);
    assert(!copied);
}

void test_dst_outofbounds_offset() {
    printf("Test read dst out of bounds with offset...\n");
    char src[5];
    char dst[10];
    int failed = 0;

    os_memmove_reset_mock();
    TEST_MEMMOVE(dst, sizeof(dst), 8, src, sizeof(src), 0, 3, { failed++; });
    TEST_MEMMOVE(dst, sizeof(dst), 10, src, sizeof(src), 0, 1, { failed++; });
    assert(failed == 2);
    assert(!copied);
}

void test_overflow() {
    printf("Test overflow...\n");
    char src[5];
    char dst[10];
    int failed = 0;

    os_memmove_reset_mock();
    TEST_MEMMOVE(
        dst, sizeof(dst), 10, src, sizeof(src), 0, UINT_MAX - 5, { failed++; });
    TEST_MEMMOVE(
        dst, sizeof(dst), UINT_MAX, src, sizeof(src), 0, 5, { failed++; });
    TEST_MEMMOVE(
        dst, sizeof(dst), 0, src, sizeof(src), 10, UINT_MAX - 5, { failed++; });
    TEST_MEMMOVE(
        dst, sizeof(dst), 0, src, sizeof(src), UINT_MAX, 5, { failed++; });
    TEST_MEMMOVE((void*)__UINTPTR_MAX__ - 10, 20, 15, src, sizeof(src), 0, 5, {
        failed++;
    });
    TEST_MEMMOVE(dst, sizeof(dst), 0, (void*)__UINTPTR_MAX__ - 10, 20, 15, 5, {
        failed++;
    });
    assert(failed == 6);
    assert(!copied);
}

int main() {
    test_ok();
    test_negatives();
    test_src_outofbounds();
    test_src_outofbounds_offset();
    test_dst_outofbounds();
    test_dst_outofbounds_offset();
    test_overflow();
    return 0;
}
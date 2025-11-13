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

#include "hal/platform.h"

// Unit tests
void test_platform_memmove() {
    printf("Test platform_memmove()...\n");

    const char src[] = "this is a test string";
    char dest[sizeof(src)];

    memset(dest, 0, sizeof(dest));
    assert(memcmp(src, dest, sizeof(src)));

    platform_memmove(dest, src, sizeof(dest));

    assert(!memcmp(src, dest, sizeof(src)));
}

void test_platform_getid() {
    printf("Test platform_get_id()...\n");

    assert(!memcmp("sgx", platform_get_id(), strlen("led")));
}

void test_platform_get_timestamp() {
    printf("Test platform_get_timestamp()...\n");

    assert(platform_get_timestamp() == 0);
}

int main() {
    test_platform_memmove();
    test_platform_getid();
    test_platform_get_timestamp();

    return 0;
}

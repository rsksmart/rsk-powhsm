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
#include <string.h>
#include <assert.h>

#include "pathAuth.h"
#include "bip32_path.h"

// Mock functions
void platform_memmove(void* dst, const void* src, unsigned int length) {
    memmove(dst, src, length);
}

// Predefined values
const char btc[] = "m/44'/0'/0'/0/0";
const char tbtc[] = "m/44'/1'/0'/0/0";
const char rsk[] = "m/44'/137'/0'/0/0";
const char trsk[] = "m/44'/1'/1'/0/0";
const char mst[] = "m/44'/137'/1'/0/0";
const char tmst[] = "m/44'/1'/2'/0/0";

unsigned char tmp[SINGLE_PATH_SIZE_BYTES];

// Unit tests
void test_paths_requiring_auth() {
    printf("Testing paths that require authentication...\n");

    assert(SINGLE_PATH_SIZE_BYTES == bip32_parse_path(btc, tmp));
    assert(pathRequireAuth(tmp));
    assert(!pathDontRequireAuth(tmp));

    assert(SINGLE_PATH_SIZE_BYTES == bip32_parse_path(tbtc, tmp));
    assert(pathRequireAuth(tmp));
    assert(!pathDontRequireAuth(tmp));
}

void test_paths_not_requiring_auth() {
    printf("Testing paths that do not require authentication...\n");

    assert(SINGLE_PATH_SIZE_BYTES == bip32_parse_path(rsk, tmp));
    assert(pathDontRequireAuth(tmp));
    assert(!pathRequireAuth(tmp));
    assert(SINGLE_PATH_SIZE_BYTES == bip32_parse_path(trsk, tmp));
    assert(pathDontRequireAuth(tmp));
    assert(!pathRequireAuth(tmp));
    assert(SINGLE_PATH_SIZE_BYTES == bip32_parse_path(mst, tmp));
    assert(pathDontRequireAuth(tmp));
    assert(!pathRequireAuth(tmp));
    assert(SINGLE_PATH_SIZE_BYTES == bip32_parse_path(tmst, tmp));
    assert(pathDontRequireAuth(tmp));
    assert(!pathRequireAuth(tmp));
}

void test_path_order() {
    printf("Testing predefined path order...\n");

    assert(SINGLE_PATH_SIZE_BYTES == bip32_parse_path(btc, tmp));
    assert(!memcmp(get_ordered_path(0), tmp, sizeof(tmp)));
    assert(SINGLE_PATH_SIZE_BYTES == bip32_parse_path(tbtc, tmp));
    assert(!memcmp(get_ordered_path(1), tmp, sizeof(tmp)));
    assert(SINGLE_PATH_SIZE_BYTES == bip32_parse_path(trsk, tmp));
    assert(!memcmp(get_ordered_path(2), tmp, sizeof(tmp)));
    assert(SINGLE_PATH_SIZE_BYTES == bip32_parse_path(tmst, tmp));
    assert(!memcmp(get_ordered_path(3), tmp, sizeof(tmp)));
    assert(SINGLE_PATH_SIZE_BYTES == bip32_parse_path(rsk, tmp));
    assert(!memcmp(get_ordered_path(4), tmp, sizeof(tmp)));
    assert(SINGLE_PATH_SIZE_BYTES == bip32_parse_path(mst, tmp));
    assert(!memcmp(get_ordered_path(5), tmp, sizeof(tmp)));
    assert(!get_ordered_path(6));
    assert(!get_ordered_path(8));
    assert(!get_ordered_path(10));
    assert(!get_ordered_path(100));
    assert(!get_ordered_path(1000));
}

int main() {
    test_paths_requiring_auth();
    test_paths_not_requiring_auth();
    test_path_order();

    return 0;
}

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

#include "bip32_path.h"

void test_parses_correctly(const char* path,
                           const uint32_t expected_parts[],
                           const size_t expected_parts_count) {

    printf("\tPath \"%s\" is parsed correctly... ", path);
    fflush(stdout);

    uint8_t binpath[5 * sizeof(uint32_t) + 1];
    size_t binpathlen = bip32_parse_path(path, binpath);

    // Return value
    assert(binpathlen == expected_parts_count * sizeof(uint32_t) + 1);

    // First byte should be the number of parts
    assert(binpath[0] == (uint8_t)expected_parts_count);

    uint32_t* parts = (uint32_t*)(&binpath[1]);

    // Validate parts
    for (int i = 0; i < expected_parts_count; i++) {
        assert(parts[i] == expected_parts[i]);
    }

    printf("OK!\n");
}

void test_parsing_fails(const char* path) {
    uint8_t binpath[5 * sizeof(uint32_t) + 1];

    printf("\tPath \"%s\" parsing fails... ", path);
    fflush(stdout);

    assert(!bip32_parse_path(path, binpath));

    printf("OK!\n");
}

int main() {
    printf("Testing BIP32 path parsing...\n");
    test_parses_correctly("m/0/0/0/0/0", (const uint32_t[]){0, 0, 0, 0, 0}, 5);
    test_parses_correctly(
        "m/10/20/30/40/50", (const uint32_t[]){10, 20, 30, 40, 50}, 5);

    // PowHSM authorized paths
    test_parses_correctly(
        "m/44'/0'/0'/0/0",
        (const uint32_t[]){0x8000002c, 0x80000000, 0x80000000, 0, 0},
        5);

    test_parses_correctly(
        "m/44'/1'/0'/0/0",
        (const uint32_t[]){0x8000002c, 0x80000001, 0x80000000, 0, 0},
        5);

    test_parses_correctly(
        "m/44'/1'/1'/0/0",
        (const uint32_t[]){0x8000002c, 0x80000001, 0x80000001, 0, 0},
        5);

    test_parses_correctly(
        "m/44'/1'/2'/0/0",
        (const uint32_t[]){0x8000002c, 0x80000001, 0x80000002, 0, 0},
        5);

    test_parses_correctly(
        "m/44'/137'/0'/0/0",
        (const uint32_t[]){0x8000002c, 0x80000089, 0x80000000, 0, 0},
        5);

    test_parses_correctly(
        "m/44'/137'/1'/0/0",
        (const uint32_t[]){0x8000002c, 0x80000089, 0x80000001, 0, 0},
        5);

    // Some failure cases
    test_parsing_fails("somethingelse");
    test_parsing_fails("f/0/0/0/0/0");
    test_parsing_fails("m/0/0/0/0/0/0");
    test_parsing_fails("m/0/0/0/0/1suffix");
    test_parsing_fails("m/123/notanumber/0/0/0");

    // Part limits
    test_parses_correctly("m/2147483647/0/0/0/2147483647'",
                          (const uint32_t[]){0x7fffffff, 0, 0, 0, 0xffffffff},
                          5);
    test_parsing_fails("m/2147483648/0/0/0/0");
    test_parsing_fails("m/2147483648'/0/0/0/0");
    test_parsing_fails("m/01234567890/0/0/0/0");

    return 0;
}
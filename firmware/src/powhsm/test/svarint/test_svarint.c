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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "svarint.h"

svarint_ctx_t context;

void test_init() {
    printf("Testing context initialization...\n");

    svarint_init(&context);

    assert(context.state == SVARINT_ST_HEADER);
    assert(context.size == 0);
    assert(context.offset == 0);
    assert(context.value == 0);
    assert(!svarint_result());
    assert(svarint_notstarted());
}

void test_parsing(const uint8_t* buf,
                  const uint8_t len,
                  uint8_t expected_read,
                  uint32_t expected_value) {
    printf("Testing value for \"0x");
    for (uint8_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\" should be %u and bytes read should be %u...\n",
           expected_value,
           expected_read);
    // Test sending step bytes at a time (increasing)
    for (uint8_t step = 1; step <= len; step++) {
        printf("- with step %u\n", step);

        svarint_init(&context);
        uint8_t total_read = 0;
        for (uint8_t i = 0; i < len; i += step) {
            assert(!svarint_result());
            uint8_t remaining = i + step >= len ? len - i : step;
            uint8_t bs_read = svarint_consume(buf + i, remaining);
            assert(!svarint_notstarted());
            assert(bs_read > 0);
            total_read += (uint8_t)bs_read;
            if (svarint_result())
                break;
        }
        assert(svarint_result() == SVARINT_ST_DONE);
        assert(context.value == expected_value);
        assert(total_read == expected_read);

        // In case the buffer still has remaining bytes, attempting to
        // read an extra byte should trigger an invalid error
        if (len > total_read) {
            printf("-- reading past should yield an invalid error\n");
            assert(!svarint_consume(buf + total_read, 1));
            assert(svarint_result() == SVARINT_ERR_INVALID);
        }
    }
}

void test_unsupported(const uint8_t* buf, const uint8_t len) {
    printf("Testing parsing for \"0x");
    for (uint8_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\" should yield an unsupported error...\n");

    // Test sending step bytes at a time (increasing)
    for (uint8_t step = 1; step <= len; step++) {
        printf("- with step %u\n", step);

        svarint_init(&context);
        uint8_t total_read = 0;
        for (uint8_t i = 0; i < len; i += step) {
            uint8_t remaining = i + step >= len ? len - i : step;
            assert(!svarint_result());
            uint8_t bs_read = svarint_consume(buf + i, remaining);
            assert(!svarint_notstarted());
            assert(bs_read > 0);
            total_read += bs_read;
            if (svarint_result())
                break;
        }
        assert(svarint_result() == SVARINT_ERR_UNSUPPORTED);

        // In case the buffer still has remaining bytes, attempting to
        // read an extra byte should trigger an invalid error
        if (len > total_read) {
            printf("-- reading past should trigger an invalid error\n");
            assert(!svarint_consume(buf + total_read, 1));
            assert(svarint_result() == SVARINT_ERR_INVALID);
        }
    }
}

void test_encode(uint32_t value,
                 const uint8_t* expected,
                 const uint8_t expected_length) {
    uint8_t result[5];

    printf("Test encoding %u...\n", value);
    assert(svarint_encode(value, result, sizeof(result)) == expected_length);
    assert(!memcmp(expected, result, expected_length));
}

int main() {
    test_init();

    test_parsing((uint8_t[]){0xaa}, 1, 1, 0xaa);
    test_parsing((uint8_t[]){0xaa, 0xbb}, 2, 1, 0xaa);
    test_parsing((uint8_t[]){0xfc}, 1, 1, 0xfc);
    test_parsing((uint8_t[]){0xfc, 0xbb}, 2, 1, 0xfc);

    test_parsing((uint8_t[]){0xfd, 0xaa, 0xbb}, 3, 3, 0xbbaa);
    test_parsing((uint8_t[]){0xfd, 0xaa, 0xbb, 0xcc, 0xdd}, 5, 3, 0xbbaa);

    test_parsing((uint8_t[]){0xfe, 0xcc, 0xdd, 0xee, 0xff}, 5, 5, 0xffeeddcc);
    test_parsing((uint8_t[]){0xfe, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03},
                 8,
                 5,
                 0xffeeddcc);

    test_parsing((uint8_t[]){0xff, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0},
                 9,
                 9,
                 0x44332211);
    test_parsing(
        (uint8_t[]){0xff, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, 1, 2, 3, 4},
        13,
        9,
        0x44332211);

    test_unsupported((uint8_t[]){0xff, 0x11, 0x22, 0x33, 0x44, 1, 0, 0, 0}, 9);
    test_unsupported(
        (uint8_t[]){0xff, 0x11, 0x22, 0x33, 0x44, 1, 0, 0, 0, 1, 2}, 11);

    test_encode(0x00, (uint8_t[]){0x00}, 1);
    test_encode(0xab, (uint8_t[]){0xab}, 1);
    test_encode(0xfc, (uint8_t[]){0xfc}, 1);

    test_encode(0xfd, (uint8_t[]){0xfd, 0xfd, 0x00}, 3);
    test_encode(0xaabb, (uint8_t[]){0xfd, 0xbb, 0xaa}, 3);
    test_encode(0xffff, (uint8_t[]){0xfd, 0xff, 0xff}, 3);

    test_encode(0x010000, (uint8_t[]){0xfe, 0x00, 0x00, 0x01, 0x00}, 5);
    test_encode(0xaabbccdd, (uint8_t[]){0xfe, 0xdd, 0xcc, 0xbb, 0xaa}, 5);
    test_encode(0xffffffff, (uint8_t[]){0xfe, 0xff, 0xff, 0xff, 0xff}, 5);

    return 0;
}

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
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "hex_reader.h"

/* Decode a single hex digit */
static uint8_t decode_hex_digit(char digit) {
    if (digit >= '0' && digit <= '9') {
        return (uint8_t)(digit - '0');
    }
    if (digit >= 'a' && digit <= 'f') {
        return (uint8_t)(digit - 'a' + 10);
    }
    if (digit >= 'A' && digit <= 'F') {
        return (uint8_t)(digit - 'A' + 10);
    }
    // Invalid hex char
    return 16;
}

/* Decode a single hex char */
static uint8_t decode_hex(const char* chars) {
    return 16 * decode_hex_digit(chars[0]) + decode_hex_digit(chars[1]);
}

/* Tell whether a char is a hex char */
static inline bool is_hex_char(char c) {
    return ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F'));
}

/*
 * Read src_length hex bytes from the src string
 * Return the number of bytes actually read or
 * -1 in case of error
 */
int read_hex(const char* src, size_t src_length, void* dest) {
    if ((src_length % 2) != 0)
        return -1;

    size_t bytes_read = 0;
    for (int i = 0; i < src_length; i += 2) {
        if (!is_hex_char(src[i]) || !is_hex_char(src[i + 1]))
            return -1;
        ((uint8_t*)dest)[bytes_read++] = decode_hex(src + i);
    }
    return bytes_read;
}
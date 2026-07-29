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

#include "hex_codec.h"

static int hex_to_nibble(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    return -1;
}

bool hexcd_is_valid(const char* hex, size_t hex_length) {
    if (!hex)
        return false;

    if ((hex_length % 2) != 0)
        return false;

    for (size_t i = 0; i < hex_length; i++) {
        if (hex_to_nibble(hex[i]) < 0)
            return false;
    }

    return true;
}

bool hexcd_decode(const char* hex,
                  size_t hex_length,
                  uint8_t* out,
                  size_t* out_size) {
    if (!hex || !out || !out_size)
        return false;

    size_t out_capacity = *out_size;
    *out_size = 0;

    if (!hexcd_is_valid(hex, hex_length))
        return false;

    size_t needed = hex_length / 2;
    if (needed > out_capacity)
        return false;

    for (size_t i = 0; i < needed; i++) {
        int high = hex_to_nibble(hex[i * 2]);
        int low = hex_to_nibble(hex[i * 2 + 1]);
        if (high < 0 || low < 0)
            return false;
        out[i] = (uint8_t)((high << 4) | low);
    }

    *out_size = needed;
    return true;
}

bool hexcd_encode(const uint8_t* data,
                  size_t data_length,
                  char* out,
                  size_t* out_size) {
    static const char* hex_digits = "0123456789abcdef";

    if (!data || !out || !out_size)
        return false;

    size_t out_capacity = *out_size;
    *out_size = 0;

    if (data_length > (SIZE_MAX / 2))
        return false;

    size_t needed = data_length * 2;
    if (needed > out_capacity)
        return false;

    for (size_t i = 0; i < data_length; i++) {
        out[i * 2] = hex_digits[(data[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex_digits[data[i] & 0x0f];
    }

    *out_size = needed;
    return true;
}

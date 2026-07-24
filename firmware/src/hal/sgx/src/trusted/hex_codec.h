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

#ifndef __TRUSTED_HEX_CODEC_H
#define __TRUSTED_HEX_CODEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Tell whether a given input is valid hexadecimal data
 *
 * @param hex the input hex buffer
 * @param hex_length the input hex buffer size in bytes
 *
 * @returns whether the input is valid hexadecimal data
 */
bool hexcd_is_valid(const char* hex, size_t hex_length);

/**
 * @brief Decode hexadecimal data into binary data
 *
 * @param hex the input hex buffer
 * @param hex_length the input hex buffer size in bytes
 * @param out the output binary buffer
 * @param out_size input/output output buffer capacity/resulting size in bytes
 *
 * @returns whether decoding was successful
 */
bool hexcd_decode(const char* hex,
                  size_t hex_length,
                  uint8_t* out,
                  size_t* out_size);

/**
 * @brief Encode binary data into hexadecimal data
 *
 * @param data the input binary buffer
 * @param data_length the input binary buffer size in bytes
 * @param out the output hex buffer
 * @param out_size input/output output buffer capacity/resulting size in bytes
 *
 * @returns whether encoding was successful
 */
bool hexcd_encode(const uint8_t* data,
                  size_t data_length,
                  char* out,
                  size_t* out_size);

#endif // __TRUSTED_HEX_CODEC_H

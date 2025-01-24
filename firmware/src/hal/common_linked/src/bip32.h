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

#ifndef __HAL_BIP32_H
#define __HAL_BIP32_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "hal/constants.h"

#define BIP32_PATH_PART_LENGTH (sizeof(uint32_t))
#define BIP32_PATH_LENGTH (1 + BIP32_PATH_NUMPARTS * BIP32_PATH_PART_LENGTH)

/**
 * @brief Parse the given string representation of a bip32 path
 *        into binary format
 *
 * @param path the bip32 path as string
 * @param out the destination buffer for the parsed path
 *
 * @returns the size of the parsed path in bytes, or zero in case of error
 */
size_t bip32_parse_path(const char* path, uint8_t* out);

/**
 * @brief Derive a private key from the given seed and bip32 path
 *
 * @param out the destination buffer for the derived key
 * @param seed the seed to use for derivation
 * @param seed_length the seed length in bytes
 * @param path the bip32 path
 * @param path_length the bip32 path length in derivation steps
 *
 * @returns whether derivation succeeded
 */
bool bip32_derive_private(uint8_t* out,
                          const uint8_t* seed,
                          const unsigned int seed_length,
                          const uint32_t* path,
                          const unsigned int path_length);

#endif // __HAL_BIP32_H

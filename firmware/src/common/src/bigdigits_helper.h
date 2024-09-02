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

#ifndef __BIGDIGITS_HELPER_H
#define __BIGDIGITS_HELPER_H

#include "bigdigits.h"

/*
 * Initialize a big integer. This is kind of tricky because the way big
 * integers are modeled in memory. Here goes an example:
 *
 * For the number:
 *
 *    [1c, 24, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3]
 *
 * (that is, 0x1c24a0a1a2a3b0b1b2b3c0c1c2c3), we must build the following
 * array of uin32_t numbers:
 *
 *   [0xc0c1c2c3, 0xb0b1b2b3, 0xa0a1a2a3, 0x00001c24]
 *
 * This function implements exactly the conversion exemplified above.
 *
 * @arg[in] buf         buffer holding big integer bytes in big-endian order
 * @arg[in] buf_size    buffer size in bytes
 * @arg[out] target     big integer to initialize
 * @arg[in] target_digits number of 32-byte integers comprising the big integer
 */
void parse_bigint_be(const uint8_t* buf,
                     uint16_t buf_size,
                     DIGIT_T target[],
                     uint16_t target_digits);

/*
 * Dump a bigint to given buffer (big-endian).
 *
 * @arg[in] buf  pointer to destination buffer
 * @arg[in] n    big integer to dump
 * @arg[in] size number of 32-byte integers comprising n
 */
void dump_bigint_be(uint8_t* buf, const DIGIT_T n[], const size_t digits);

#endif // __BIGDIGITS_HELPER_H
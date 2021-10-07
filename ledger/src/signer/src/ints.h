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

#ifndef __INTS
#define __INTS

// -----------------------------------------------------------------------
// Utility macros for integer manipulation.
// -----------------------------------------------------------------------

// Read an integer in big endian order from memory.
// Initializes the number to set to zero before reading.
//
// @arg buf buffer to read
// @arg n integer to be assigned with extracted number
//
// NOTE: Avoid buffer overflow: buffer length must be >= sizeof(n)
#define BIGENDIAN_FROM(buf, n) VAR_BIGENDIAN_FROM(buf, n, sizeof(n))

// Read an variable size integer in big endian order from memory.
// Initializes the number to set to zero before reading.
//
// @arg buf buffer to read
// @arg n integer to be assigned with extracted number
// @arg size number of bytes to read
//
// NOTE 1: Avoid lossy conversions: sizeof(n) must be >= size
// NOTE 2: Avoid buffer overflow: buffer length must be >= size
#define VAR_BIGENDIAN_FROM(buf, n, size)                \
    {                                                   \
        n = 0;                                          \
        for (unsigned int __i = 0; __i < size; __i++) { \
            n = (n << 8) | (buf)[__i];                  \
        }                                               \
    }

// Write a variable size integer in big endian order to memory.
//
// @arg buf buffer to write
// @arg n integer to be assigned with extracted number
// @arg size number of bytes to write
//
// NOTE 1: Avoid lossy conversions: sizeof(n) must be <= size
// NOTE 2: Avoid buffer overflow: buffer length must be >= size
#define VAR_BIGENDIAN_TO(buf, n, size)                         \
    {                                                          \
        memset(buf, 0, size);                                  \
        for (unsigned int __i = 0; __i < size; __i++) {        \
            (buf)[__i] = (n >> (8 * (size - __i - 1))) & 0xFF; \
        }                                                      \
    }

#endif

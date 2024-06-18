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

#ifndef __LOG_H
#define __LOG_H

#if defined(HSM_PLATFORM_X86)

#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Works just like printf
 */
void LOG(const char *format, ...);

/**
 * @brief Print buffer in hex format with prefix
 *
 * @param prefix the log prefix (the general log prefix will be prepended too)
 * @param buffer the buffer containing the bytes to output as hex chars
 * @param size the size of buffer in bytes
 */
void LOG_HEX(const char *prefix, void *buffer, size_t size);

#elif defined(HSM_PLATFORM_LEDGER)

#define LOG(...)
#define LOG_HEX(...)

#else
#error "HSM Platform undefined"
#endif

#endif // __LOG_H

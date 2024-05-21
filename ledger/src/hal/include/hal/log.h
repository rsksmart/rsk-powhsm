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

#include "bigdigits.h"
#include "srlp.h"

/** Set a prefix for all logs */
void LOG_SET_PREFIX(char* prefix);

/** Works just like printf */
void LOG(const char *format, ...);

/** Print buffer in hex format with prefix */
void LOG_HEX(const char *prefix, void *buffer, size_t size);

/** Print big integer in hex format with optional prefix and suffix strings */
void LOG_BIGD_HEX(const char *prefix,
                  const DIGIT_T *a,
                  size_t len,
                  const char *suffix);

#elif defined(HSM_PLATFORM_LEDGER)

#define LOG(...)
#define LOG_HEX(...)
#define LOG_BIGD_HEX(...)

#else
    #error "HSM Platform undefined"
#endif

#endif // __LOG_H

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

#ifndef __DBG_H
#define __DBG_H

#ifdef HSM_SIMULATOR

#include <stdio.h>
#include <stdlib.h>

#include "bigdigits.h"
#include "srlp.h"

#define LOG(...) printf(__VA_ARGS__);

/** Print buffer in hex format with prefix */
void LOG_HEX(const char *prefix, void *buffer, size_t size);

/** Print big integer in hex format with optional prefix and suffix strings */
void LOG_BIGD_HEX(const char *prefix,
                  const DIGIT_T *a,
                  size_t len,
                  const char *suffix);

/** Print N copies of a given char */
void LOG_N_CHARS(const char c, unsigned int times);

/** Print the given SRLP context (see srlp.h) */
void LOG_SRLP_CTX(uint8_t v, rlp_ctx_t ctx[], uint8_t ptr);

#else

#define LOG(...)
#define LOG_HEX(...)
#define LOG_BIGD_HEX(...)
#define LOG_N_CHARS(...)
#define LOG_SRLP_CTX(...)

#endif

#endif // __DBG_H

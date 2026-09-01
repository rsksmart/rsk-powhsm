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

#include <stdlib.h>

#ifdef LOGLEVEL_DEBUG
#define DEBUG(...) INFO(__VA_ARGS__)
#define DEBUG_HEX(...) INFO_HEX(__VA_ARGS__)
#else
#define DEBUG(...)
#define DEBUG_HEX(...)
#endif

/**
 * @brief Works just like printf
 */
void INFO(const char *format, ...);

/**
 * @brief Print buffer in hex format with prefix
 *
 * @param prefix the log prefix (the general log prefix will be prepended too)
 * @param buffer the buffer containing the bytes to output as hex chars
 * @param size the size of buffer in bytes
 */
void INFO_HEX(const char *prefix, const void *buffer, const size_t size);

/**
 * @brief Set a prefix for all logs
 *
 * @param prefix the prefix to use for logs
 */
void log_set_prefix(const char *prefix);

/**
 * @brief Clear any prefix set for logs
 */
void log_clear_prefix();

#endif // __LOG_H

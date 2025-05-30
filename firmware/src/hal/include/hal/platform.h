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

#ifndef __HAL_PLATFORM_H
#define __HAL_PLATFORM_H

#include <stdint.h>
#include <stdbool.h>

// Size in bytes of a platform id
#define PLATFORM_ID_LENGTH 3

/**
 * @brief Perform the platform-specific version of memmove
 *
 * @param dst destination buffer
 * @param src source buffer
 * @param length number of bytes to copy
 */
void platform_memmove(void *dst, const void *src, unsigned int length);

/**
 * @brief Request exiting/closing to the underlying platform
 */
void platform_request_exit();

/**
 * @brief Get the current platform id
 */
const char *platform_get_id();

/**
 * @brief Get the current timestamp
 */
uint64_t platform_get_timestamp();

/**
 * X86 specific headers
 */
#if defined(HSM_PLATFORM_X86)

#include "explicit_bzero.h"

#endif // HSM_PLATFORM_X86

#endif // __HAL_PLATFORM_H

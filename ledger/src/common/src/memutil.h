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

#ifndef __MEMUTIL_H
#define __MEMUTIL_H

#include <stdint.h>
#include <stdbool.h>

#include "os.h"

#define MEMMOVE_ZERO_OFFSET 0

#define SAFE_MEMMOVE(                                                       \
    dst, dst_size, dst_off, src, src_size, src_off, n, ERR_EXPR)            \
    if (!safe_memmove(dst, dst_size, dst_off, src, src_size, src_off, n)) { \
        ERR_EXPR;                                                           \
    }

__attribute__((always_inline)) static inline int safe_memmove(
    const void *dst,
    unsigned int dst_size,
    unsigned int dst_off,
    const void *src,
    unsigned int src_size,
    unsigned int src_off,
    unsigned int n) {

    if (n + dst_off < n || n + src_off < n ||
        (uintptr_t)dst + (uintptr_t)dst_off < (uintptr_t)dst ||
        (uintptr_t)src + (uintptr_t)src_off < (uintptr_t)src ||
        n + dst_off > dst_size || n + src_off > src_size) {

        return false;
    } else {
        os_memmove(
            (unsigned char *)dst + dst_off, (unsigned char *)src + src_off, n);
        return true;
    }
}

#endif // __MEMUTIL_H

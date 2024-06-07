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

#include <string.h>
#include "mock.h"

// APDU buffer
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

// Mock variables used by os_exception.h
static try_context_t G_try_last_open_context_var;
try_context_t *G_try_last_open_context = &G_try_last_open_context_var;

void explicit_bzero(void *s, size_t len) {
    memset(s, '\0', len);
    /* Compiler barrier.  */
    asm volatile("" ::: "memory");
}

void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len) {
    if (src_adr == NULL) {
        // Treat as memory reset
        memset(dst_adr, 0, src_len);
    } else {
        // Treat as normal copy
        memmove(dst_adr, src_adr, src_len);
    }
}

void os_memmove(void *dst, const void *src, unsigned int length) {
    memmove(dst, src, length);
}

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

#include <assert.h>
#include <stddef.h>
#include <string.h>

#ifndef __APDU_UTILS_H
#define __APDU_UTILS_H

#define CHANNEL_APDU 0

#define IO_APDU_BUFFER_SIZE (5 + 80)
extern unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

#define ASSERT_APDU(str_literal) \
    assert(0 == memcmp(G_io_apdu_buffer, str_literal, sizeof(str_literal) - 1))

#define SET_APDU(str_literal, rx)                                   \
    memcpy(G_io_apdu_buffer, str_literal, sizeof(str_literal) - 1); \
    rx = (sizeof(str_literal) - 1)

#define CLEAR_APDU() memset(G_io_apdu_buffer, 0, sizeof(G_io_apdu_buffer))

#endif // __APDU_UTILS_H

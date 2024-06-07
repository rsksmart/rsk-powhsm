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

#ifndef __AUTH_CONSTANTS_H
#define __AUTH_CONSTANTS_H

#include <stdint.h>

const uint8_t EVENT_EMITTER[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x01, 0x00, 0x00, 0x06};

const uint8_t EVENT_SIGNATURE[] = {
    0x7a, 0x7c, 0x29, 0x48, 0x15, 0x28, 0xac, 0x8c, 0x2b, 0x2e, 0x93,
    0xae, 0xe6, 0x58, 0xfd, 0xdd, 0x4d, 0xc1, 0x53, 0x04, 0xfa, 0x72,
    0x3a, 0x5c, 0x2b, 0x88, 0x51, 0x45, 0x57, 0xbc, 0xc7, 0x90};
#define EVENT_SIGNATURE_SIZE (32)

#endif // __AUTH_CONSTANTS_H
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

// Varint decoder
// Returns true if the buffer is big enough to decode the containing varint
#include "varint.h"

bool varintCanDecode(uint8_t *buffer, uint32_t bufferLength) {
    unsigned char firstByte;
    firstByte = buffer[0];
    if (firstByte < 0xFD) {
        return true;
    } else if (firstByte == 0xFD) {
        if (bufferLength >= 3)
            return true;
        else
            return false;
    } else if (firstByte == 0xFE) {
        if (bufferLength >= 5)
            return true;
        else
            return false;
    } else
        return false;
}

// Returns length in bytes of the body, given a hdr value
int varintLen(uint8_t firstByte) {
    if (firstByte < 0xFD)
        return 1;
    else
        return (1 << (firstByte - 0xFC));
}

// Encode number 'value' into 'buffer', returns lenght in 'len'
void createVarint(unsigned int value,
                  unsigned char *buffer,
                  unsigned char *len) {
    if (value < 0xFD) {
        buffer[0] = (unsigned char)(value);
        *len = 1;
        return;
    }
    buffer[1] = (unsigned char)(value & 0xFF);
    buffer[2] = (unsigned char)((value >> 8) & 0xFF);
    if (value < 0xffff) {
        buffer[0] = 0xFD;
        *len = 3;
        return;
    }
    buffer[3] = (unsigned char)((value >> 16) & 0xFF);
    if (value < 0xffffff) {
        buffer[0] = 0xFE;
        *len = 4;
        return;
    }
    buffer[4] = (unsigned char)((value >> 24) & 0xFF);
    buffer[0] = 0xFF;
    *len = 5;
}

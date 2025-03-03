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

#include "der_utils.h"
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

// Helper function to encode a len-byte unsigned integer (R or S) in DER format
static size_t der_encode_uint(uint8_t* dest, uint8_t* src, size_t len) {
    // Check if we need a leading zero byte
    bool lz = src[0] & 0x80;
    // Start of source: remove leading zeroes
    size_t trim = 0;
    while (!src[trim] && trim < (len - 1))
        trim++;
    // Output
    size_t off = 0;
    dest[off++] = 0x02;                      // Integer tag
    dest[off++] = len - trim + (lz ? 1 : 0); // Length byte
    if (lz)
        dest[off++] = 0x00;                     // Leading zero
    memcpy(dest + off, src + trim, len - trim); // Actual integer
    return (size_t)dest[1] + 2;
}

uint8_t der_encode_signature(uint8_t* dest, sgx_ecdsa256_signature_t* sig) {
    // Temporary buffers for R and S with
    // space for TLV with potential leading zero
    uint8_t r_encoded[sizeof(sig->r) + 3];
    uint8_t s_encoded[sizeof(sig->r) + 3];
    uint8_t r_len = (uint8_t)der_encode_uint(r_encoded, sig->r, sizeof(sig->r));
    uint8_t s_len = (uint8_t)der_encode_uint(s_encoded, sig->s, sizeof(sig->s));

    // Start the sequence
    dest[0] = 0x30;                             // Sequence tag
    dest[1] = r_len + s_len;                    // Length of the sequence
    memcpy(dest + 2, r_encoded, r_len);         // Copy encoded R
    memcpy(dest + 2 + r_len, s_encoded, s_len); // Copy encoded S

    // Return total length of DER encoded signature
    return (uint8_t)(2 + r_len + s_len);
}

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

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "hal/constants.h"
#include "sig_utils.h"

#define DER_SEQUENCE_TAG 0x30
#define DER_SEQUENCE_TAG_PARITY_BIT 0x01
#define DER_INTEGER_TAG 0x02
#define DER_NEGATIVE_BIT 0x80

// 30 L 02 01 r 02 01 s
#define SIG_MIN_LENGTH 8
#define SIG_COMPONENT_LENGTH 32
// Allow for a leading zero
#define SIG_COMPONENT_MAX_ENCODED_LENGTH (SIG_COMPONENT_LENGTH + 1)

// Taken from the secp256k1 curve parameters
// https://github.com/bitcoin-core/secp256k1/blob/master/src/scalar_4x64_impl.h#L15
static const uint8_t secp256k1_order[SIG_COMPONENT_LENGTH] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
    0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

// Is the given big-endian value within [1, n-1]?
static bool component_in_range(const uint8_t* value, size_t length) {
    // Skip leading zeroes
    while (length > 0 && *value == 0) {
        value++;
        length--;
    }

    if (length == 0 || length > SIG_COMPONENT_LENGTH) {
        return false;
    }

    if (length < SIG_COMPONENT_LENGTH) {
        return true;
    }

    for (size_t i = 0; i < SIG_COMPONENT_LENGTH; i++) {
        if (value[i] != secp256k1_order[i]) {
            return value[i] < secp256k1_order[i];
        }
    }

    // Value equals the curve order
    return false;
}

// Read a DER-encoded signature component (r or s) and check its value,
// advancing the given pointer past it
static bool read_component(const uint8_t** p, const uint8_t* end) {
    if (end - *p < 2 || (*p)[0] != DER_INTEGER_TAG) {
        return false;
    }

    size_t length = (*p)[1];
    *p += 2;

    if (length == 0 || length > SIG_COMPONENT_MAX_ENCODED_LENGTH ||
        (size_t)(end - *p) < length) {
        return false;
    }

    // Components are never negative
    if ((*p)[0] & DER_NEGATIVE_BIT) {
        return false;
    }

    bool in_range = component_in_range(*p, length);
    *p += length;
    return in_range;
}

bool sig_der_is_sound(const uint8_t* sig, size_t sig_length) {
    if (sig == NULL || sig_length < SIG_MIN_LENGTH ||
        sig_length > MAX_SIGNATURE_LENGTH) {
        return false;
    }

    if ((sig[0] & ~DER_SEQUENCE_TAG_PARITY_BIT) != DER_SEQUENCE_TAG) {
        return false;
    }

    if (sig[1] != sig_length - 2) {
        return false;
    }

    const uint8_t* p = sig + 2;
    const uint8_t* end = sig + sig_length;

    if (!read_component(&p, end) || !read_component(&p, end)) {
        return false;
    }

    // No trailing data allowed
    return p == end;
}

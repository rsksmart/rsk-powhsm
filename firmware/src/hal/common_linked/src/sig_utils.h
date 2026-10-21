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

#ifndef __SIG_UTILS_H
#define __SIG_UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/**
 * @brief Sanity check a DER-encoded secp256k1 ECDSA signature
 * before releasing it.
 *
 * Checks that the signature is well formed (30 L 02 Lr r 02 Ls s, with
 * no trailing data) and that both r and s are within [1, n-1], where n
 * is the secp256k1 curve order. Some Ledger firmware versions set the
 * lowest bit of the sequence tag to signal the parity of R's Y
 * coordinate, so both 0x30 and 0x31 are accepted as the sequence tag.
 * Superfluous leading zeroes on r and s are tolerated.
 *
 * @param sig        the DER-encoded signature
 * @param sig_length the signature length
 *
 * @returns whether the signature is sound
 */
bool sig_der_is_sound(const uint8_t* sig, size_t sig_length);

#endif // __SIG_UTILS_H

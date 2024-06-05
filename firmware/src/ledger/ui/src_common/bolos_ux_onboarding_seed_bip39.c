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

/*******************************************************************************
 *   Ledger Blue - Secure firmware
 *   (c) 2016, 2017 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include "os.h"
#include "cx.h"

#include "bolos_ux_common.h"
#include "bolos_ux_onboarding_seed_bip39.h"

unsigned int bolos_ux_mnemonic_from_data(unsigned char *in,
                                         unsigned int inLength,
                                         unsigned char *out,
                                         unsigned int outLength) {
    unsigned char bits[32 + 1];
    unsigned int mlen = inLength * 3 / 4;
    unsigned int i, j, idx, offset;

    if ((inLength % 4) || (inLength < 16) || (inLength > 32)) {
        THROW(INVALID_PARAMETER);
    }
    cx_hash_sha256(in, inLength, bits);

    bits[inLength] = bits[0];
    os_memmove(bits, in, inLength);
    offset = 0;
    for (i = 0; i < mlen; i++) {
        unsigned char wordLength;
        idx = 0;
        for (j = 0; j < 11; j++) {
            idx <<= 1;
            idx +=
                (bits[(i * 11 + j) / 8] & (1 << (7 - ((i * 11 + j) % 8)))) > 0;
        }
        wordLength =
            BIP39_WORDLIST_OFFSETS[idx + 1] - BIP39_WORDLIST_OFFSETS[idx];
        if ((offset + wordLength) > outLength) {
            THROW(INVALID_PARAMETER);
        }
        os_memmove(out + offset,
                   BIP39_WORDLIST + BIP39_WORDLIST_OFFSETS[idx],
                   wordLength);
        offset += wordLength;
        if (i < mlen - 1) {
            if (offset > outLength) {
                THROW(INVALID_PARAMETER);
            }
            out[offset++] = ' ';
        }
    }
    return offset;
}

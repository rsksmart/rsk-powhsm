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

/**
 * Third party library taken from:
 * https://github.com/firefly/wallet/blob/29adeaf7029142063b7a6878e049efd4c6534982/source/libs/ethers/src/keccak256.h
 */

/* sha3 - an implementation of Secure Hash Algorithm 3 (Keccak).
 * based on the
 * The Keccak SHA-3 submission. Submission to NIST (Round 3), 2011
 * by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche
 *
 * Copyright: 2013 Aleksey Kravchenko <rhash.admin@gmail.com>
 *
 * Permission is hereby granted,  free of charge,  to any person  obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction,  including without limitation
 * the rights to  use, copy, modify,  merge, publish, distribute, sublicense,
 * and/or sell copies  of  the Software,  and to permit  persons  to whom the
 * Software is furnished to do so.
 *
 * This program  is  distributed  in  the  hope  that it will be useful,  but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  Use this program  at  your own risk!
 */

#ifndef __KECCAK256_H_
#define __KECCAK256_H_

#include <stdint.h>

#define sha3_max_permutation_size 25
#define sha3_max_rate_in_qwords 24

typedef struct SHA3_CTX {
    /* 1600 bits algorithm hashing state */
    uint64_t hash[sha3_max_permutation_size];
    /* 1536-bit buffer for leftovers */
    uint64_t message[sha3_max_rate_in_qwords];
    /* count of bytes in the message[] buffer */
    uint16_t rest;
} SHA3_CTX;


#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */


void keccak_init(SHA3_CTX *ctx);
void keccak_update(SHA3_CTX *ctx, const unsigned char *msg, uint16_t size);
void keccak_final(SHA3_CTX *ctx, unsigned char* result);


#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif  /* __KECCAK256_H_ */

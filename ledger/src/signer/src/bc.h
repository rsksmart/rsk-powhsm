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

#ifndef __BC_H
#define __BC_H

// -----------------------------------------------------------------------
// Constants referenced all around the code
// -----------------------------------------------------------------------

// Difficulty and BigInts
#define BIGINT_LEN 9
#define MAX_DIFFICULTY_SIZE 32

// Hashing
#define HASH_SIZE 32
#define KECCAK256_HASH_SIZE HASH_SIZE

// Merge mining constants
#define MM_HASH_PREFIX_SIZE 20
#define MM_HASH_SUFFIX_SIZE 4

// Brothers
#define MAX_BROTHERS 10

// Coinbase transaction constants
#define CB_MAX_RSK_TAG_POSITION 64
#define CB_MAX_AFTER_MM_HASH 128
#define CB_MIN_TX_SIZE 64
#define CB_MIDSTATE_PREFIX 8
#define CB_MIDSTATE_DATA 40
#define CB_MIDSTATE_SUFFIX 4

// Field sizes and offsets
#define UMM_ROOT_SIZE 20
#define MAX_MERKLE_PROOF_SIZE 960
#define MAX_CB_TXN_SIZE 273
#define BTC_HEADER_SIZE 80
#define BTC_HEADER_RLP_LEN 82
#define MERKLE_ROOT_OFFSET 36

#endif // __BC_H

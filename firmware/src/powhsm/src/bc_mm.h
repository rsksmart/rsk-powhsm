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

#ifndef __BC_MM_H
#define __BC_MM_H

#include <stdint.h>

#include "ints.h"

#include "bc.h"
#include "bc_hash.h"
#include "bc_nu.h"

// Max RLP prefix encoding size
#define MAX_RLP_PREFIX_SIZE 9

// List encoding constants
#define RLP_SHORT_LIST_BASE 0xC0
#define RLP_LONG_LIST_BASE 0xF7

// String encoding constants
#define RLP_MAX_SINGLE_BYTE 0x7F
#define RLP_SHORT_STRING_BASE 0x80
#define RLP_LONG_STRING_BASE 0xB7

/*
 * Hash a RLP prefix for a list of the given size.
 *
 * @arg[out] kctx     Keccak context for hashing
 * @arg[in] list_size list size in bytes
 */
void mm_hash_rlp_list_prefix(keccak_ctx_t* kctx, uint16_t list_size);

/*
 * Hash a RLP prefix for a "good" string of the given size.
 * A string is "good" if the RLP prefix can be determined
 * from the string length alone. This will be the case
 * any string with lenght greater than one.
 *
 * @arg[out] kctx     Keccak context for hashing
 * @arg[in] str_size  string size in bytes, must be greater than one
 */
void mm_hash_good_rlp_str_prefix(keccak_ctx_t* kctx, uint16_t str_size);

/*
 * Hash a RLP prefix for a "bad" string. Bad strings are one byte
 * long, and the prefix length is determined by the contexts of
 * the string's single byte.
 *
 * @arg[out] kctx Keccak context for hashing
 * @arg[in]  str  pointer to the bad string's single byte
 */
void mm_hash_bad_rlp_str_prefix(keccak_ctx_t* kctx, const uint8_t* str);

#endif // __BC_MM_H

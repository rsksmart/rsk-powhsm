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

#ifndef __BC_DIFF_H
#define __BC_DIFF_H

#include <stdint.h>

#include "bigdigits.h"
#include "bigdigits_helper.h"
#include "bc.h"

// Block difficulty caps for each network
#define BCDIFF_MBD_MAINNET \
    {0x16600000, 0x7883c069, 0x17b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}; // 7 ZH

#define BCDIFF_MBD_TESTNET \
    { 0xa4c68000, 0x38d7e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 } // 1 PH

#define BCDIFF_MBD_REGTEST {0x14, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}; // 20

#ifdef HSM_PLATFORM_X86
extern DIGIT_T MAX_BLOCK_DIFFICULTY[BIGINT_LEN];
#endif

// Errors
#define BCDIFF_ERR_INVALID (2)
#define BCDIFF_ERR_CAPPING (3)

/*
 * Store the given difficulty in the given big integer.
 *
 * @arg[in] diff_bytes bytes comprising difficulty
 * @arg[in] diff_size  number of bytes cmprising difficulty
 * @arg[in] difficulty big integer where difficulty will be store
 */
void store_difficulty(uint8_t* diff_bytes,
                      uint8_t diff_size,
                      DIGIT_T difficulty[]);

typedef enum { DIFF_MATCH = 1, DIFF_MISMATCH, DIFF_ZERO } diff_result;

/*
 * Check if BTC merge mining header matches block's difficulty.
 *
 * @arg[in] difficulty block difficulty
 * @arg[in] mm_hdr_hash BTC merge mining block hash
 *
 * @return
 *   DIFF_MATCH if BTC merge mining header matches block difficulty,
 *   DIFF_MISMATCH otherwise
 */
diff_result check_difficulty(DIGIT_T difficulty[], const uint8_t* mm_hdr_hash);

/*
 * Cap block difficulty.
 *
 * @arg[in/out] difficulty the block difficulty to cap
 * @ret
 * 0 if capping ok (regardless of capping result)
 * BCDIFF_ERR_CAPPING if an error occurs
 */
int cap_block_difficulty(DIGIT_T difficulty[]);

/*
 * Accumulate difficulty.
 *
 * @arg[in] difficulty difficulty to accumulate
 * @arg[in/out] total_difficulty difficulty accumulator
 * @ret
 *   1 if there's carry
 *   0 if there's no carry
 *   BCDIFF_ERR_INVALID if an error occurs
 */
DIGIT_T accum_difficulty(DIGIT_T difficulty[], DIGIT_T total_difficulty[]);

#endif // __BC_DIFF_H

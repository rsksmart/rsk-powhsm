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

#include <string.h>

#include "bc_diff.h"
#include "hal/log.h"
#include "memutil.h"

// Maximum difficulty for block difficulty capping (network dependent)
#ifdef TESTNET
static const DIGIT_T MAX_BLOCK_DIFFICULTY[BIGINT_LEN] = BCDIFF_MBD_TESTNET;
#elif defined(REGTEST)
static const DIGIT_T MAX_BLOCK_DIFFICULTY[BIGINT_LEN] = BCDIFF_MBD_REGTEST;
#elif defined(HSM_PLATFORM_X86)
DIGIT_T MAX_BLOCK_DIFFICULTY[BIGINT_LEN];
#else
static const DIGIT_T MAX_BLOCK_DIFFICULTY[BIGINT_LEN] = BCDIFF_MBD_MAINNET;
#endif

/*
 * Store the given difficulty in the given big integer.
 *
 * @arg[in] diff_bytes bytes comprising difficulty
 * @arg[in] diff_size  number of bytes cmprising difficulty
 * @arg[in] difficulty big integer where difficulty will be store
 */
void store_difficulty(uint8_t* diff_bytes,
                      uint8_t diff_size,
                      DIGIT_T difficulty[]) {
    parse_bigint_be(diff_bytes, diff_size, difficulty, BIGINT_LEN);
}

static const DIGIT_T _2e256[] = {
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
};

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
diff_result check_difficulty(DIGIT_T difficulty[], const uint8_t* mm_hdr_hash) {
    DIGIT_T target[BIGINT_LEN];
    DIGIT_T aux[BIGINT_LEN];

    // Taken from rskj:
    // minDifficulty is 3 because target needs to be of length 256
    // and not have 1 in the position 255 (count start from 0)
    // Implementation detail: to save memory we just remember
    // the first digit (least significant digit) of the original block
    // difficulty and then use the block difficulty to do the division
    DIGIT_T first_difficulty_digit = difficulty[0];
    mpSetDigit(aux, 3, BIGINT_LEN);
    int cmp = mpCompare_ct(difficulty, aux, BIGINT_LEN);
    if (cmp != 1) {
        mpSetDigit(difficulty, 3, BIGINT_LEN);
    }

    int r = mpDivide(target, aux, _2e256, BIGINT_LEN, difficulty, BIGINT_LEN);

    if (cmp != 1) {
        mpSetDigit(difficulty, first_difficulty_digit, BIGINT_LEN);
    }

    // Target = top/block_difficulty
    // int r = mpDivide(target, aux, _2e256, BIGINT_LEN, resultDifficulty,
    // BIGINT_LEN);
    if (r == -1) {
        // Divison by zero, report error
        return DIFF_ZERO;
    }

    // Turn BTC MM block hash into a big int
    parse_bigint_be(mm_hdr_hash, HASH_SIZE, aux, BIGINT_LEN);

    // Block difficulty is invalid iif BTC MM block hash > target
    // BTC merge mining header (aux) matches block difficulty if
    // aux <= target. That is, if cmp != 1.
    cmp = mpCompare_ct(aux, target, BIGINT_LEN);

    LOG_BIGD_HEX("2^256 = ", _2e256, BIGINT_LEN, "\n");
    LOG_BIGD_HEX("Block difficulty = ", difficulty, BIGINT_LEN, "\n");
    LOG_BIGD_HEX("Target = ", target, BIGINT_LEN, "\n");
    LOG_BIGD_HEX("BTC MM block hash = ", aux, BIGINT_LEN, "\n");
    LOG("Difficulty is %s\n", cmp == 1 ? "not valid" : "valid");

    return cmp != 1 ? DIFF_MATCH : DIFF_MISMATCH;
}

/*
 * Cap block difficulty.
 *
 * @arg[in/out] difficulty the block difficulty to cap
 * @ret
 * 0 if capping ok (regardless of capping result)
 * BCDIFF_ERR_CAPPING if an error occurs
 */
int cap_block_difficulty(DIGIT_T difficulty[]) {
    int cmp = mpCompare_ct(difficulty, MAX_BLOCK_DIFFICULTY, BIGINT_LEN);

    LOG_BIGD_HEX("Block difficulty = ", difficulty, BIGINT_LEN, "\n");
    LOG_BIGD_HEX("Cap = ", MAX_BLOCK_DIFFICULTY, BIGINT_LEN, "\n");
    LOG("Block difficulty %s been capped\n", cmp == 1 ? "has" : "has NOT");

    // Block difficulty > Cap => Set block difficulty to cap
    if (cmp == 1) {
        SAFE_MEMMOVE(difficulty,
                     sizeof(DIGIT_T) * BIGINT_LEN,
                     MEMMOVE_ZERO_OFFSET,
                     MAX_BLOCK_DIFFICULTY,
                     sizeof(MAX_BLOCK_DIFFICULTY),
                     MEMMOVE_ZERO_OFFSET,
                     sizeof(MAX_BLOCK_DIFFICULTY),
                     { return BCDIFF_ERR_CAPPING; });
    }

    return 0;
}

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
DIGIT_T accum_difficulty(DIGIT_T difficulty[], DIGIT_T total_difficulty[]) {
    DIGIT_T aux[BIGINT_LEN];
    DIGIT_T carry = mpAdd(aux, difficulty, total_difficulty, BIGINT_LEN);

    // This condition should never happen in the current implementation. This is
    // just a double-check to ensure that aux holds a valid value before
    // updating total_difficulty.
    if (carry == MAX_DIGIT)
        return BCDIFF_ERR_INVALID;

    SAFE_MEMMOVE(total_difficulty,
                 sizeof(DIGIT_T) * BIGINT_LEN,
                 MEMMOVE_ZERO_OFFSET,
                 aux,
                 sizeof(aux),
                 MEMMOVE_ZERO_OFFSET,
                 sizeof(DIGIT_T) * BIGINT_LEN,
                 { return BCDIFF_ERR_INVALID; });

    return carry;
}

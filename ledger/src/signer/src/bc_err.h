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

#ifndef __BC_ERR_H
#define __BC_ERR_H

// Error codes returned by blockchain protocols
typedef enum {
    UNKNOWN = 0,
    PROT_INVALID = 0x6b87, // Ledger got invalid or unexpected message
    RLP_INVALID,           // Ledger got RLP that is not a valid block
    BLOCK_TOO_OLD,         // Block is too old to be validated
    BLOCK_TOO_SHORT,       // Block doesn't has expected number of fields
    PARENT_HASH_INVALID,   // Invalid parent hash
    RECEIPT_ROOT_INVALID,  // Invalid receipt root
    BLOCK_NUM_INVALID,     // Invalid block num (size > 4 bytes)
    BLOCK_DIFF_INVALID,    // Invalid bock difficulty (zero or size > 32 bytes)
    UMM_ROOT_INVALID,      // Invalid UMM root (if present, size > 20 bytes)
    BTC_HEADER_INVALID,    // Invalid BTC merge mining header (size != 80 bytes)
    MERKLE_PROOF_INVALID,  // Invalid Merkle proof (size % 32 != 0)
    BTC_CB_TXN_INVALID,    // Invalid cb txn
    MM_RLP_LEN_MISMATCH,   // Merge mining RLP lengths don't match
    BTC_DIFF_MISMATCH,     // BTC merge mining header doesn't match block diff
    MERKLE_PROOF_MISMATCH, // Merkle proof doesn't match merkle root
    MM_HASH_MISMATCH,      // Merge mining hashes don't match
    MERKLE_PROOF_OVERFLOW, // Merkle proof exceeds maximum size
    CB_TXN_OVERFLOW,       // Coinbase transaction exceeds maximum size
    BUFFER_OVERFLOW,       // Work area buffer overflow

    CHAIN_MISMATCH,      // Block is not parent of previous block
    TOTAL_DIFF_OVERFLOW, // Total difficulty overflow

    ANCESTOR_TIP_MISMATCH, // Ancestor tip mismatch
    CB_TXN_HASH_MISMATCH,  // Coinbase transaction mismatch

    BROTHERS_TOO_MANY,       // Too many brothers
    BROTHER_PARENT_MISMATCH, // Brother parent hash mismatch
    BROTHER_SAME_AS_BLOCK,   // Brother cannot be same as block
    BROTHER_ORDER_INVALID,   // Invalid ordering of brothers
} err_code_t;

/*
 * If running in simulator mode, display to stderr an error message for the
 * given error code.
 *
 * @arg [in] errcode error code
 */
void show_error(err_code_t errcode);

// Abort current app with suitable error code
#define FAIL(errcode)        \
    {                        \
        show_error(errcode); \
        THROW(errcode);      \
    }

#endif // __BC_ERR_H

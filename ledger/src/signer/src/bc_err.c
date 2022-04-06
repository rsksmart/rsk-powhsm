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

#include "bc_err.h"

#ifdef HSM_SIMULATOR

#include <stdio.h>

static struct err_entry {
    err_code_t errcode;
    char errmsg[128];
} err_table[] = {
    {UNKNOWN, "Unknown error"},
    {PROT_INVALID, "Invalid or unexpected message"},
    {RLP_INVALID, "Invalid RLP"},
    {BLOCK_TOO_OLD, "Block too old"},
    {BLOCK_TOO_SHORT, "Block too short"},
    {PARENT_HASH_INVALID, "Invalid parent hash"},
    {RECEIPT_ROOT_INVALID, "Invalid receipt root"},
    {BLOCK_NUM_INVALID, "Block number > 4 bytes"},
    {BLOCK_DIFF_INVALID, "Block difficulty zero or > 32 bytes"},
    {UMM_ROOT_INVALID, "Invalid UMM root"},
    {BTC_HEADER_INVALID, "Invalid BTC merge mining header"},
    {MERKLE_PROOF_INVALID, "Invalid Merkle proof"},
    {BTC_CB_TXN_INVALID, "Invalid coinbase transaction"},
    {MM_RLP_LEN_MISMATCH, "Merge mining RLP lengths don't match"},
    {BTC_DIFF_MISMATCH, "BTC merge mining header doesn't match block diff"},
    {MERKLE_PROOF_MISMATCH, "Merkle proof doesn't match merkle root"},
    {MM_HASH_MISMATCH, "Merge mining hashes don't match"},
    {MERKLE_PROOF_OVERFLOW, "Merkle proof exceeds maximum size"},
    {CB_TXN_OVERFLOW, "Coinbase transaction exceeds maximum size"},
    {BUFFER_OVERFLOW, "Work area buffer overflow"},

    {CHAIN_MISMATCH, "Block is not parent of previous block"},
    {TOTAL_DIFF_OVERFLOW, "Total difficulty overflow"},

    {ANCESTOR_TIP_MISMATCH, "Ancestor tip mismatch"},
    {CB_TXN_HASH_MISMATCH, "Coinbase transaction hash mismatch"},

    {BROTHERS_TOO_MANY, "Too many brothers"},
    {BROTHER_PARENT_MISMATCH, "Brother parent hash mismatch"},
    {BROTHER_SAME_AS_BLOCK, "Brother cannot be same as block"},
    {BROTHER_ORDER_INVALID, "Invalid ordering of brothers"},
};

void show_error(err_code_t errcode) {
    char *msg = err_table[0].errmsg;
    for (unsigned int i = 1; i < sizeof(err_table) / sizeof(struct err_entry);
         i++) {
        if (err_table[i].errcode == errcode) {
            msg = err_table[i].errmsg;
            break;
        }
    }
    fprintf(stderr, "*** ERROR: %s\n", msg);
}
#else
void show_error(err_code_t errcode) {
}
#endif

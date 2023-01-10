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

#ifndef __BC_BLOCKUTILS_H
#define __BC_BLOCKUTILS_H

// -----------------------------------------------------------------------
// Convenience macros and functions for operating on block_t
// -----------------------------------------------------------------------

#include "bc_block.h"
#include "bc_nu.h"
#include "mem.h"
#include "flags.h"

// Bit flags
#define HAS_UMM_ROOT 0x01   // Is umm_root present in the current block?
#define BAD_STR 0x02        // Are we processing a bad (single byte) string?
#define HEADER_VALID 0x04   // We know the current header is valid
#define MM_HEADER_RECV 0x08 // We received the BTC merge mining header
#define CB_TXN_RECV 0x10    // We received the coinbase transaction

// Macros for field offsets, 1-based
#define F_PARENT_HASH 1
#define F_RECEIPT_ROOT 6
#define F_BLOCK_DIFF 8
#define F_BLOCK_NUM 9
#define F_UMM_ROOT 17
#define F_MM_HEADER (block.network_upgrade >= NU_PAPYRUS ? 18 : 17)
#define F_MERKLE_PROOF (block.network_upgrade >= NU_PAPYRUS ? 19 : 18)
#define F_COINBASE_TXN (block.network_upgrade >= NU_PAPYRUS ? 20 : 19)

// Field contributes to block hash if before Merkle proof
#define SHOULD_COMPUTE_BLOCK_HASH \
    (block.network_upgrade == NU_UNKNOWN || block.field < F_MERKLE_PROOF)

// Execute cmd when inside a field contributing to merge mining hash
#define WHEN_MM(cmd)                                                        \
    if (block.network_upgrade == NU_UNKNOWN || block.field < F_MM_HEADER) { \
        (cmd);                                                              \
    }

#define PROCESSING_BLOCK()                   \
    (APDU_OP() == OP_ADVANCE_HEADER_CHUNK || \
     APDU_OP() == OP_ADVANCE_HEADER_META)

#define BLOCK_ALREADY_VALID()                                       \
    (!PROCESSING_BLOCK() && (HAS_FLAG(block.flags, HEADER_VALID) || \
                             bc_st_updating.already_validated))

// Convenience macro for last field contributing to merge mining hash
#define MM_HASH_LAST_FIELD \
    (block.network_upgrade >= NU_PAPYRUS ? F_UMM_ROOT : F_UMM_ROOT - 1)

#endif // __BC_BLOCKUTILS_H

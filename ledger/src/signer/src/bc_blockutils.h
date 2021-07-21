#ifndef _BLOCK_COMMONS
#define _BLOCK_COMMONS

// -----------------------------------------------------------------------
// Convenience macros and functions for operating on block_t
// -----------------------------------------------------------------------

#include "bc_block.h"
#include "bc_nu.h"
#include "mem.h"

// Bit flags
#define HAS_UMM_ROOT 0x01   // Is umm_root present in the current block?
#define BAD_STR 0x02        // Are we processing a bad (single byte) string?
#define HEADER_VALID 0x04   // We know the current header is valid
#define MM_HEADER_RECV 0x08 // We received the BTC merge mining header
#define CB_TXN_RECV 0x10    // We received the coinbase transaction

// Operate on bit flags
#define SET_FLAG(flags, f) ((flags) |= (f))
#define CLR_FLAG(flags, f) ((flags) &= ~(f))
#define HAS_FLAG(flags, f) ((flags) & (f))

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

// Convenience macro for last field contributing to merge mining hash
#define MM_HASH_LAST_FIELD \
    (block.network_upgrade >= NU_PAPYRUS ? F_UMM_ROOT : F_UMM_ROOT - 1)

#endif
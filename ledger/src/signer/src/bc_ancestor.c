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

#include "os.h"

#include "bc.h"
#include "dbg.h"
#include "defs.h"
#include "ints.h"
#include "mem.h"
#include "srlp.h"
#include "memutil.h"

#include "bc_block.h"
#include "bc_blockutils.h"
#include "bc_ancestor.h"
#include "bc_err.h"
#include "bc_hash.h"
#include "bc_mm.h"
#include "bc_state.h"
#include "util.h"

// We'll be asking for block header chunks of at most this size
#define MAX_CHUNK_SIZE 80

// Number of blocks to validate
static uint32_t expected_blocks;

// Count of validated blocks
static uint32_t curr_block;

// Expected OP for next message
static uint8_t expected_state;

/*
 * Store the given buffer in the block's work area.
 *
 * @arg[in] buf  buffer to store
 * @arg[in] size buffer size in bytes
 */
static void wa_store(const uint8_t* buf, uint16_t size) {
    SAFE_MEMMOVE(block.wa_buf,
                 sizeof(block.wa_buf),
                 block.wa_off,
                 buf,
                 size,
                 MEMMOVE_ZERO_OFFSET,
                 size,
                 FAIL(BUFFER_OVERFLOW));

    block.wa_off += size;
}

// -----------------------------------------------------------------------
// Update ancestor validations
// -----------------------------------------------------------------------

/*
 * Update ancestor prologue: call once we have the first block's hash.
 */
static void bc_upd_ancestor_prologue() {
    if (HNEQ(block.block_hash, N_bc_state.ancestor_block) &&
        HNEQ(block.block_hash, N_bc_state.best_block)) {
        FAIL(ANCESTOR_TIP_MISMATCH);
    }
}

/*
 * State updates to perform when successfully updated ancestor.
 */
static void bc_upd_ancestor_success() {
    NVM_WRITE(N_bc_state.ancestor_block, block.block_hash, HASH_SIZE);
    NVM_WRITE(N_bc_state.ancestor_receipt_root, block.receipt_root, HASH_SIZE);
}

// -----------------------------------------------------------------------
// RLP parser callbacks
// -----------------------------------------------------------------------

/*
 * Block starts: nesting level must not exceed one.
 *
 * @arg[in] size: size of list payload in bytes
 */
static void list_start(const uint16_t size) {
    ++block.depth;
    if (block.depth != 1) {
        FAIL(RLP_INVALID);
    }

    block.size = size;
    block.recv = 0;
}

/*
 * List finishes: we must be closing the top level list, and received
 * bytes must match block size. In addition, we must have seen the
 * expected number of fields.
 */
static void list_end() {
    --block.depth;
    if (block.depth != 0 || block.size != block.recv) {
        FAIL(RLP_INVALID);
    }

    // Block can end at the BTC mm header or anywhere past it
    if (block.field < F_MM_HEADER) {
        FAIL(BLOCK_TOO_SHORT);
    }
}

/*
 * Block field starts: field must be inside top level list.
 *
 * @arg[in] field size in bytes
 */
static void str_start(const uint16_t size) {
    if (block.depth != 1) {
        FAIL(RLP_INVALID);
    }

    block.wa_off = 0;

    // NOTE: This will return 1 even for a single byte "bad" string
    // where str[0] <= 0x7f (it should return 0). That's ok because
    // in that case we actually received a single byte. But we must
    // not add 1 to block.recv in str_chunk.
    block.recv += guess_rlp_str_prefix_size(size);

    // Signal bad string
    if (size == 1) {
        SET_FLAG(block.flags, BAD_STR);
    }

    ++block.field;

    if (block.field == F_PARENT_HASH && size != HASH_SIZE) {
        FAIL(PARENT_HASH_INVALID);
    }

    if (block.field == F_RECEIPT_ROOT && size != HASH_SIZE) {
        FAIL(RECEIPT_ROOT_INVALID);
    }

    if (SHOULD_COMPUTE_BLOCK_HASH) {
        // The starting str contributes to the block (and possibly mm) hash
        //   - Good string: we can hash RLP prefix right now.
        //   - Bad string: RLP prefix will depend on str contents.
        if (!HAS_FLAG(block.flags, BAD_STR)) {
            mm_hash_good_rlp_str_prefix(&block.block_ctx, size);
        }
    }

    if (block.field == F_MM_HEADER && size != BTC_HEADER_SIZE) {
        FAIL(BTC_HEADER_INVALID);
    }
}

/*
 * Block chunk arrived.
 *
 * @arg[in] chunk  pointer to arrived chunk
 * @arg[in] size   size in bytes of arrived chunk
 */
static void str_chunk(const uint8_t* chunk, const size_t size) {
    // Count chunk length as received bytes only if:
    //  - Chunk doesn't belong to a bad string, or
    //  - Bad string actually has RLP prefix
    if (!HAS_FLAG(block.flags, BAD_STR) || HAS_RLP_PREFIX(chunk[0])) {
        block.recv += size;
    }

    if (block.field == F_PARENT_HASH) {
        wa_store(chunk, size);
    }

    // Store receipt only for last block
    if (block.field == F_RECEIPT_ROOT && curr_block + 1 == expected_blocks) {
        wa_store(chunk, size);
    }

    if (block.field == F_BLOCK_NUM) {
        wa_store(chunk, size);
    }

    if (block.field == F_MM_HEADER) {
        wa_store(chunk, size);
    }

    if (SHOULD_COMPUTE_BLOCK_HASH) {
        // Chunk corresponds to a bad str, so we couldn't hash its RLP prefix
        // until now, when str contents are available. Hash prefix now.
        if (HAS_FLAG(block.flags, BAD_STR)) {
            mm_hash_bad_rlp_str_prefix(&block.block_ctx, chunk);
        }

        // And then hash the str chunk itself
        KECCAK_UPDATE(&block.block_ctx, chunk, size);
    }
}

/* Current block chunk finished */
static void str_end() {
    if (block.field == F_PARENT_HASH) {
        HSTORE(block.parent_hash, block.wa_buf);
    }

    // Store receipt root only for last block
    if (block.field == F_RECEIPT_ROOT && curr_block + 1 == expected_blocks) {
        HSTORE(block.receipt_root, block.wa_buf);
    }

    // Block number in wa_buf:
    // Store for computing mm_hash and determine network upgrade
    if (block.field == F_BLOCK_NUM) {
        if (block.wa_off > sizeof(block.number)) {
            FAIL(BLOCK_NUM_INVALID);
        }
        VAR_BIGENDIAN_FROM(block.wa_buf, block.number, block.wa_off);
        SET_NETWORK_UPGRADE(block.number, &block.network_upgrade);
        if (block.network_upgrade == NU_ANCIENT) {
            FAIL(BLOCK_TOO_OLD);
        }
    }

    // Verify that we got valid mm_rlp_len in OP_UPD_ANCESTOR_HEADER_META
    if (block.field == MM_HASH_LAST_FIELD) {
        if (block.recv != block.mm_rlp_len) {
            FAIL(MM_RLP_LEN_MISMATCH);
        }
    }

    // We have the complete merge mining header in wa_buf. We must:
    //  - Finalize the block hash computation
    //  - Signal the merge mining header was received
    if (block.field == F_MM_HEADER) {
        KECCAK_FINAL(&block.block_ctx, block.block_hash);
        SET_FLAG(block.flags, MM_HEADER_RECV);
    }

    // Done with this chunk, clear BAD_STR flag if set
    if (HAS_FLAG(block.flags, BAD_STR)) {
        CLR_FLAG(block.flags, BAD_STR);
    }
}

static const rlp_callbacks_t callbacks = {
    str_start,
    str_chunk,
    str_end,
    list_start,
    list_end,
};

// -----------------------------------------------------------------------
// Blockchain update ancestor implementation
// -----------------------------------------------------------------------

/*
 * Initialize Blockchain update ancestor protocol state.
 */
void bc_init_upd_ancestor() {
    expected_blocks = 0;
    curr_block = 0;
    expected_state = OP_UPD_ANCESTOR_INIT;
}

/*
 * Update blockchain ancestor.
 *
 * @arg[in] rx number of received bytes from the Host
 * @ret     number of transmited bytes to the host
 */
unsigned int bc_upd_ancestor(volatile unsigned int rx) {
    uint8_t op = APDU_OP();

    // Check we are getting expected OP
    if (op != OP_UPD_ANCESTOR_INIT && op != expected_state) {
        FAIL(PROT_INVALID);
    }

    // Check we are getting the expected amount of data
    if (op == OP_UPD_ANCESTOR_INIT && APDU_DATA_SIZE(rx) != sizeof(uint32_t)) {
        FAIL(PROT_INVALID);
    }
    if (op == OP_UPD_ANCESTOR_HEADER_META &&
        APDU_DATA_SIZE(rx) != sizeof(block.mm_rlp_len)) {
        FAIL(PROT_INVALID);
    }
    if (op == OP_UPD_ANCESTOR_HEADER_CHUNK) {
        uint16_t expected_txlen =
            block.size > 0 ? MIN(block.size - block.recv, MAX_CHUNK_SIZE)
                           : MAX_CHUNK_SIZE;
        if (APDU_DATA_SIZE(rx) != expected_txlen) {
            FAIL(PROT_INVALID);
        }
    }

    // -------------------------------------------------------------------
    // OP_INIT
    // -------------------------------------------------------------------
    if (op == OP_UPD_ANCESTOR_INIT) {
        expected_state = OP_UPD_ANCESTOR_HEADER_META;

        memset(aux_bc_st.prev_parent_hash, 0, HASH_SIZE);

        curr_block = 0;
        BIGENDIAN_FROM(APDU_DATA_PTR, expected_blocks);
        if (expected_blocks == 0) {
            FAIL(PROT_INVALID);
        }

        SET_APDU_OP(OP_UPD_ANCESTOR_HEADER_META);
        return TX_NO_DATA();
    }

    // -------------------------------------------------------------------
    // OP_HEADER_META
    // -------------------------------------------------------------------
    if (op == OP_UPD_ANCESTOR_HEADER_META) {
        LOG("---- Block %u of %u\n", curr_block + 1, expected_blocks);

        // Clear block data
        memset(&block, 0, sizeof(block));
        rlp_start(&callbacks);

        // Read the RLP payload length
        BIGENDIAN_FROM(APDU_DATA_PTR, block.mm_rlp_len);

        // Block hash computation: encode and hash payload len

        // Sanity check: make sure given mm_rlp_len plus BTC_HEADER_RLP_LEN does
        // not overflow
        if ((uint16_t)(block.mm_rlp_len + BTC_HEADER_RLP_LEN) <
            block.mm_rlp_len) {
            LOG("Given MM RLP list length too large, would overflow: %u\n",
                block.mm_rlp_len);
            FAIL(PROT_INVALID);
        }

        KECCAK_INIT(&block.block_ctx);
        mm_hash_rlp_list_prefix(&block.block_ctx,
                                block.mm_rlp_len + BTC_HEADER_RLP_LEN);

        // Now waiting for block data
        expected_state = OP_UPD_ANCESTOR_HEADER_CHUNK;
        SET_APDU_OP(OP_UPD_ANCESTOR_HEADER_CHUNK);
        SET_APDU_TXLEN(MAX_CHUNK_SIZE);

        return TX_FOR_DATA_SIZE(1);
    }

    // -------------------------------------------------------------------
    // OP_HEADER_CHUNK
    // -------------------------------------------------------------------
    if (op == OP_UPD_ANCESTOR_HEADER_CHUNK) {
        if (rlp_consume(APDU_DATA_PTR, APDU_DATA_SIZE(rx)) < 0) {
            FAIL(RLP_INVALID);
        }

        // We have received the whole BTC merge mining header.
        // So we have the block hash. Since we aren't validating
        // blocks here, after validating parent chaining we can
        // ask for next block or leave.
        if (HAS_FLAG(block.flags, MM_HEADER_RECV)) {

            LOG_HEX("Block hash", block.block_hash, HASH_SIZE);
            LOG_HEX("Parent hash", block.parent_hash, HASH_SIZE);

            // First block: perform update ancestor prologue
            // Otherwise: verify block chains to parent
            if (curr_block == 0) {
                bc_upd_ancestor_prologue();
            } else if (HNEQ(aux_bc_st.prev_parent_hash, block.block_hash)) {
                FAIL(CHAIN_MISMATCH);
            }
            // Store parent hash to validate chaining for next block
            // (next block hash must match this block's parent hash)
            HSTORE(aux_bc_st.prev_parent_hash, block.parent_hash);

            ++curr_block;

            // More blocks? Ask for next block metadata
            if (curr_block < expected_blocks) {
                expected_state = OP_UPD_ANCESTOR_HEADER_META;
                SET_APDU_OP(OP_UPD_ANCESTOR_HEADER_META);
                return TX_NO_DATA();
            }

            // Blocks exhausted? Leave
            bc_upd_ancestor_success();
            expected_state = OP_UPD_ANCESTOR_INIT;
            SET_APDU_OP(OP_UPD_ANCESTOR_SUCCESS);
            return TX_NO_DATA();
        }

        // Current block not fully consumed? Ask for next chunk
        if (block.recv < block.size) {
            SET_APDU_OP(OP_UPD_ANCESTOR_HEADER_CHUNK);
            SET_APDU_TXLEN(MIN(block.size - block.recv, MAX_CHUNK_SIZE));
            return TX_FOR_DATA_SIZE(1);
        }

        // Reached end of block and haven't seen BTC mm header? That's bad!
        FAIL(RLP_INVALID);
    }

    // You shouldn't be here
    FAIL(PROT_INVALID);
    return 0;
}

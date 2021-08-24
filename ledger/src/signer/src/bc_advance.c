#include <string.h>

#ifdef FEDHM_EMULATOR
#include "usb.h"
#else
#include "os.h"
#endif

#include "bc.h"
#include "dbg.h"
#include "defs.h"
#include "ints.h"
#include "mem.h"
#include "srlp.h"
#include "bigdigits.h"

#include "bc_block.h"
#include "bc_blockutils.h"
#include "bc_advance.h"
#include "bc_diff.h"
#include "bc_err.h"
#include "bc_hash.h"
#include "bc_mm.h"
#include "bc_nu.h"
#include "bc_state.h"

#define min(x, y) ((x) <= (y) ? (x) : (y))

// We'll be asking for block header chunks of at most this size
#define MAX_CHUNK_SIZE 80

// Threshold difficulty to achieve when advancing the blockchain
// NOTE: for example, to specify 0x 000001d5 bcab6123 1c92f6c6, use
// const DIGIT_T MIN_REQUIRED_DIFFICULTY[BIGINT_LEN] = { 0x1c92f6c6, 0xbcab6123, 0x000001d5, 0, 0, 0, 0, 0, 0 };

// Here we take it from an external definition (see Makefile for details)
#ifdef PARAM_MIN_REQUIRED_DIFFICULTY
static const DIGIT_T MIN_REQUIRED_DIFFICULTY[BIGINT_LEN] = PARAM_MIN_REQUIRED_DIFFICULTY;
#endif

// -----------------------------------------------------------------------
// Blockchain advance validation state
// -----------------------------------------------------------------------

// Number of blocks to validate
static uint32_t expected_blocks;

// Count of validated blocks
static uint32_t curr_block;

// Expected OP for next message
static uint8_t expected_state;

#define ABORT(errcode)                    \
    {                                     \
        expected_state = OP_ADVANCE_INIT; \
        RESET_BC_STATE();                 \
        FAIL(errcode);                    \
    }

// -----------------------------------------------------------------------
// Storage utilities
// -----------------------------------------------------------------------

/*
 * Store the given buffer in the block's work area.
 *
 * @arg[in] buf  buffer to store
 * @arg[in] size buffer size in bytes
 */
static void wa_store(const uint8_t* buf, uint16_t size) {
    if (block.wa_off + size > WA_SIZE) {
        ABORT(BUFFER_OVERFLOW);
    }
    memcpy(block.wa_buf + block.wa_off, buf, size);
    block.wa_off += size;
}

/*
 * Store Merkle proof chunk in block.merkle_proof.
 *
 * @arg[in] chunk pointer to chunk to store
 * @arg[in] size  chunk size in bytes
 */
static void store_merkle_bytes(const uint8_t* chunk, uint16_t size) {
    if (block.merkle_off + size > MAX_MERKLE_PROOF_SIZE) {
        ABORT(MERKLE_PROOF_OVERFLOW);
    }
    memcpy(block.merkle_proof + block.merkle_off, chunk, size);
    block.merkle_off += size;
}

/*
 * Store coinbase transaction chunk in block.cb_txn.
 *
 * @arg[in] chunk pointer to chunk to store
 * @arg[in] size  chunk size in bytes
 */
static void store_cb_txn_bytes(const uint8_t* chunk, uint16_t size) {
    if (block.cb_off > MAX_CB_TXN_SIZE) {
        ABORT(CB_TXN_OVERFLOW);
    }
    memcpy(block.cb_txn + block.cb_off, chunk, size);
    block.cb_off += size;
}

// -----------------------------------------------------------------------
// Blockchain advance actions and validations
// -----------------------------------------------------------------------

/*
 * Patch the current block's hash_for_mm.
 *
 * @arg[in] has_umm_root whether the current block has a umm root
 */
static void patch_hash_for_mm(bool has_umm_root) {
    if (has_umm_root) {
        KECCAK_INIT(&block.mm_ctx);
        KECCAK_UPDATE(&block.mm_ctx, block.hash_for_mm, UMM_ROOT_SIZE);
        KECCAK_UPDATE(&block.mm_ctx, block.umm_root, UMM_ROOT_SIZE);
        KECCAK_FINAL(&block.mm_ctx, block.hash_for_mm);
    }

    VAR_BIGENDIAN_TO(
        &block.hash_for_mm[KECCAK256_HASH_SIZE - sizeof(block.number)],
        block.number,
        sizeof(block.number));

    uint8_t size =
        KECCAK256_HASH_SIZE - MM_HASH_PREFIX_SIZE - MM_HASH_SUFFIX_SIZE;
    memset(&block.hash_for_mm[MM_HASH_PREFIX_SIZE], 0, size);
}

/*
 * Validate the current block's merkle proof. This function assumes
 * that the cb_txn_hash is stored in the block's work area.
 */
static void validate_merkle_proof() {
    for (uint16_t i = 0; i < block.merkle_off; i += HASH_SIZE) {
        fold_left(&block.ctx, block.wa_buf, block.merkle_proof + i);
    }
    REV_HASH(block.wa_buf);
    if (HNEQ(block.merkle_root, block.wa_buf)) {
        ABORT(MERKLE_PROOF_MISMATCH);
    }
}

/*
 * Compute the cb_txn_hash for the current block. It stores
 * the cb_txn_hash in the block's work area, so this method
 * MUST be called before validate_merkle_proof().
 */
static void compute_cb_txn_hash() {
    memset(block.wa_buf, 0, CB_MIDSTATE_PREFIX);
    memcpy(block.wa_buf + CB_MIDSTATE_PREFIX, block.cb_txn, CB_MIDSTATE_DATA);
    memset(block.wa_buf + CB_MIDSTATE_PREFIX + CB_MIDSTATE_DATA,
           0,
           CB_MIDSTATE_SUFFIX);
    sha256_init(&block.mid_ctx);
    sha256_midstate(&block.mid_ctx, block.wa_buf);
    sha256_update(&block.mid_ctx,
                  block.cb_txn + CB_MIDSTATE_DATA,
                  block.cb_off - CB_MIDSTATE_DATA);
    sha256_final(&block.mid_ctx, block.wa_buf);
    sha256_init(&block.mid_ctx);
    sha256_update(&block.mid_ctx, block.wa_buf, HASH_SIZE);
    sha256_final(&block.mid_ctx, block.wa_buf);
    REV_HASH(block.wa_buf);
}

const char rsk_tag[] = "RSKBLOCK:";
#define RSK_TAG_LEN 9 // Length of "RSKBLOCK:"

/*
 * Extract mm_hash from the coinbase transaction, and compare
 * it with the current block's hash_for_mm.
 */
static void validate_mm_hash() {
    uint8_t* tail = block.cb_txn + CB_MIDSTATE_DATA;
    uint8_t* last = block.cb_txn + block.cb_off - 1;

    // If present, ptr will point to the rightmost rsk_tag occurrence.
    // Otherwise, ptr will be 1 less than tail.
    uint8_t* ptr = last;
    for (; ptr >= tail; ptr--) {
        if (last - ptr + 1U >= RSK_TAG_LEN &&
            memcmp(ptr, rsk_tag, RSK_TAG_LEN) == 0) {
            break;
        }
    }

    if (ptr < tail) {
        ABORT(BTC_CB_TXN_INVALID);
    }

    if (ptr - tail > CB_MAX_RSK_TAG_POSITION) {
        ABORT(BTC_CB_TXN_INVALID);
    }

    if (ptr + RSK_TAG_LEN + HASH_SIZE > last) {
        ABORT(BTC_CB_TXN_INVALID);
    }

    if (last - (ptr + RSK_TAG_LEN + HASH_SIZE) + 1 > CB_MAX_AFTER_MM_HASH) {
        ABORT(BTC_CB_TXN_INVALID);
    }

    uint64_t n;
    BIGENDIAN_FROM(block.cb_txn, n);
    if (n + (last - tail) + 1 <= CB_MIN_TX_SIZE) {
        ABORT(BTC_CB_TXN_INVALID);
    }

    uint8_t size =
        KECCAK256_HASH_SIZE - MM_HASH_PREFIX_SIZE - MM_HASH_SUFFIX_SIZE;
    if (block.network_upgrade >= NU_WASABI) {
        memset(&(ptr + RSK_TAG_LEN)[MM_HASH_PREFIX_SIZE], 0, size);
    }

    if (HNEQ(ptr + RSK_TAG_LEN, block.hash_for_mm)) {
        ABORT(MM_HASH_MISMATCH);
    }
}

/*
 * Blockchain advance prologue: call once we have the firt block's hash.
 */
static void bc_adv_prologue() {
    if (N_bc_state.updating.in_progress &&
        HNEQ(block.block_hash, N_bc_state.updating.next_expected_block)) {
        ABORT(CHAIN_MISMATCH);
    }

    if (!N_bc_state.updating.in_progress) {
        set_bc_state_flag(&N_bc_state.updating.in_progress);
        NVM_WRITE(&N_bc_state.updating.newest_valid_block,
                  block.block_hash,
                  HASH_SIZE);
    }
}

/*
 * Accumulate total blockchain difficulty. Only call this once you
 * know that the current block is valid. If there is enough difficulty
 * accumulated, record in the state that we found our new best block.
 */
static void bc_adv_accum_diff() {
    // Nothing to do it we already have a best block
    if (N_bc_state.updating.found_best_block) {
        return;
    }

#if defined(FEDHM_EMULATOR)
    mpPrintHex("Total difficulty before = ",
               aux_bc_st.total_difficulty,
               BIGINT_LEN,
               "\n");
    mpPrintHex("Block difficulty = ", block.difficulty, BIGINT_LEN, "\n");
#endif

    // Otherwise accumulate total difficulty
    DIGIT_T carry =
        accum_difficulty(block.difficulty, aux_bc_st.total_difficulty);
    if (carry) {
        ABORT(TOTAL_DIFF_OVERFLOW);
    }

#ifdef FEDHM_EMULATOR
    mpPrintHex("Min required difficulty = ",
               MIN_REQUIRED_DIFFICULTY,
               BIGINT_LEN,
               "\n");
    mpPrintHex(
        "Total difficulty = ", aux_bc_st.total_difficulty, BIGINT_LEN, "\n");
    LOG("Comparison: %d\n",
        mpCompare_ct(
            aux_bc_st.total_difficulty, MIN_REQUIRED_DIFFICULTY, BIGINT_LEN));
#endif

    // Not enough difficulty yet: we are done
    if (mpCompare_ct(aux_bc_st.total_difficulty,
                     MIN_REQUIRED_DIFFICULTY,
                     BIGINT_LEN) < 0) {
        return;
    }

    // Enough difficulty accumulated? We found our best block!
    set_bc_state_flag(&N_bc_state.updating.found_best_block);
    NVM_WRITE(N_bc_state.updating.best_block, block.block_hash, HASH_SIZE);
}

/*
 * State updates to perform when successfully advanced blockchain.
 */
static void bc_adv_success() {
    NVM_WRITE(N_bc_state.best_block, N_bc_state.updating.best_block, HASH_SIZE);
    NVM_WRITE(N_bc_state.newest_valid_block,
              N_bc_state.updating.newest_valid_block,
              HASH_SIZE);
    RESET_BC_STATE();
}

/*
 * State updates to perform on partial sucess.
 */
static void bc_adv_partial_success() {
    NVM_WRITE(N_bc_state_var.updating.next_expected_block,
              block.parent_hash,
              HASH_SIZE);
    NVM_WRITE(N_bc_state.updating.total_difficulty,
              aux_bc_st.total_difficulty,
              sizeof(aux_bc_st.total_difficulty));
}

// -----------------------------------------------------------------------
// RLP parser callbacks
// -----------------------------------------------------------------------

// Valid blocks have the form [field_1, ..., field_n]. That is, a single
// top level list with bytearrays inside. Anything not having this shape
// is an invalid block.

/*
 * Block starts: nesting level must not exceed one.
 *
 * @arg[in] size: size of list payload in bytes
 */
static void list_start(const uint16_t size) {
    ++block.depth;
    if (block.depth != 1) {
        ABORT(RLP_INVALID);
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
        ABORT(RLP_INVALID);
    }

    if (block.field != F_COINBASE_TXN) {
        ABORT(BLOCK_TOO_SHORT);
    }
}

/*
 * Block field starts: field must be inside top level list.
 *
 * @arg[in] field size in bytes
 */
static void str_start(const uint16_t size) {
    if (block.depth != 1) {
        ABORT(RLP_INVALID);
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
        ABORT(PARENT_HASH_INVALID);
    }

    // UMM root field and papyrus active?
    // Validate length of UMM root (either zero or expected length) and
    // mark whether it's present so that we save it when we get the data.
    if (block.network_upgrade >= NU_PAPYRUS && block.field == F_UMM_ROOT) {
        if (size != 0 && size != UMM_ROOT_SIZE) {
            ABORT(UMM_ROOT_INVALID);
        }
        if (size != 0) {
            SET_FLAG(block.flags, HAS_UMM_ROOT);
        }
    }

    if (SHOULD_COMPUTE_BLOCK_HASH) {
        // The starting str contributes to the block (and possibly mm) hash
        //   - Good string: we can hash RLP prefix right now.
        //   - Bad string: RLP prefix will depend on str contents.
        if (!HAS_FLAG(block.flags, BAD_STR)) {
            mm_hash_good_rlp_str_prefix(&block.block_ctx, size);
            WHEN_MM(mm_hash_good_rlp_str_prefix(&block.mm_ctx, size));
        }
    }

    if (block.field == F_MM_HEADER && size != BTC_HEADER_SIZE) {
        ABORT(BTC_HEADER_INVALID);
    }

    if (block.field == F_MERKLE_PROOF) {
        if (size % HASH_SIZE != 0) {
            ABORT(MERKLE_PROOF_INVALID);
        }
        block.merkle_off = 0;
    }

    if (block.field == F_COINBASE_TXN) {
        // size <= CB_MIDSTATE_DATA: txn has no tail
        if (size <= CB_MIDSTATE_DATA || size > MAX_CB_TXN_SIZE) {
            ABORT(BTC_CB_TXN_INVALID);
        }
        block.cb_off = 0;
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

    if (block.field == F_BLOCK_DIFF) {
        wa_store(chunk, size);
    }

    if (block.field == F_BLOCK_NUM) {
        wa_store(chunk, size);
    }

    if (block.field == F_MM_HEADER) {
        wa_store(chunk, size);
    }

    if (block.field == F_UMM_ROOT && HAS_FLAG(block.flags, HAS_UMM_ROOT)) {
        wa_store(chunk, size);
    }

    if (block.field == F_MERKLE_PROOF) {
        store_merkle_bytes(chunk, size);
    }

    if (block.field == F_COINBASE_TXN) {
        store_cb_txn_bytes(chunk, size);
    }

    if (SHOULD_COMPUTE_BLOCK_HASH) {
        // Chunk corresponds to a bad str, so we couldn't hash its RLP prefix
        // until now, when str contents are available. Hash prefix now.
        if (HAS_FLAG(block.flags, BAD_STR)) {
            mm_hash_bad_rlp_str_prefix(&block.block_ctx, chunk);
            WHEN_MM(mm_hash_bad_rlp_str_prefix(&block.mm_ctx, chunk));
        }

        // And then hash the str chunk itself
        KECCAK_UPDATE(&block.block_ctx, chunk, size);
        WHEN_MM(KECCAK_UPDATE(&block.mm_ctx, chunk, size));
    }
}

/* Current block chunk finished */
static void str_end() {
    if (block.field == F_PARENT_HASH) {
        HSTORE(block.parent_hash, block.wa_buf);
    }

    if (block.field == F_BLOCK_DIFF) {
        if (block.wa_off > MAX_DIFFICULTY_SIZE) {
            ABORT(BLOCK_DIFF_INVALID);
        }
        store_difficulty(block.wa_buf, block.wa_off, block.difficulty);
    }

    // Block number in wa_buf:
    // Store for computing mm_hash and determine network upgrade
    if (block.field == F_BLOCK_NUM) {
        if (block.wa_off > sizeof(block.number)) {
            ABORT(BLOCK_NUM_INVALID);
        }
        VAR_BIGENDIAN_FROM(block.wa_buf, block.number, block.wa_off);
        SET_NETWORK_UPGRADE(block.number, block.network_upgrade);
        if (block.network_upgrade == NU_ANCIENT) {
            ABORT(BLOCK_TOO_OLD);
        }
    }

    if (block.field == MM_HASH_LAST_FIELD) {
        if (block.recv != block.mm_rlp_len) {
            ABORT(MM_RLP_LEN_MISMATCH);
        }

        // If there's a umm_root, we now have it in block.wa_buf. Store it.
        if (HAS_FLAG(block.flags, HAS_UMM_ROOT)) {
            if (block.wa_off != UMM_ROOT_SIZE) {
                ABORT(UMM_ROOT_INVALID);
            }
            memcpy(block.umm_root, block.wa_buf, block.wa_off);
        }
    }

    // We have the complete merge mining header in wa_buf. We must:
    //   - Finalize block and hash_for_mm computation
    //   - Store the Merkle root in block.merkle_root
    //   - Signal the merge mining header was received
    if (block.field == F_MM_HEADER) {
        KECCAK_FINAL(&block.block_ctx, block.block_hash);
        KECCAK_FINAL(&block.mm_ctx, block.hash_for_mm);
        HSTORE(block.merkle_root, block.wa_buf + MERKLE_ROOT_OFFSET);
        SET_FLAG(block.flags, MM_HEADER_RECV);
    }

    if (block.field == F_COINBASE_TXN) {
        SET_FLAG(block.flags, CB_TXN_RECV);
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
// Blockchain advance protocol implementation
// -----------------------------------------------------------------------

/*
 * Initialize Blockchain advance protocol state.
 */
void bc_init_advance() {
    expected_state = OP_ADVANCE_INIT;
}

/*
 * Advance blockchain state.
 *
 * @arg[in] rx number of received bytes from the Host
 * @ret     number of transmited bytes to the host
 */
unsigned int bc_advance(volatile unsigned int rx) {
    uint8_t op = APDU_OP();

    // Check we are getting expected OP
    if (op != OP_ADVANCE_INIT && op != expected_state) {
        ABORT(PROT_INVALID);
    }

    // Check we are getting the expected amount of data
    if (op == OP_ADVANCE_INIT && APDU_DATA_SIZE(rx) != sizeof(uint32_t)) {
        ABORT(PROT_INVALID);
    }
    if (op == OP_ADVANCE_HEADER_META &&
        APDU_DATA_SIZE(rx) != sizeof(block.mm_rlp_len)) {
        ABORT(PROT_INVALID);
    }
    if (op == OP_ADVANCE_HEADER_CHUNK) {
        uint16_t expected_txlen =
            block.size > 0 ? min(block.size - block.recv, MAX_CHUNK_SIZE)
                           : MAX_CHUNK_SIZE;
        if (APDU_DATA_SIZE(rx) != expected_txlen) {
            ABORT(PROT_INVALID);
        }
    }

    // -------------------------------------------------------------------
    // OP_INIT
    // -------------------------------------------------------------------
    if (op == OP_ADVANCE_INIT) {
        expected_state = OP_ADVANCE_HEADER_META;

        memset(aux_bc_st.prev_parent_hash, 0, HASH_SIZE);
        memcpy(aux_bc_st.total_difficulty,
               N_bc_state.updating.total_difficulty,
               sizeof(aux_bc_st.total_difficulty));

        curr_block = 0;
        BIGENDIAN_FROM(APDU_DATA_PTR, expected_blocks);
        if (expected_blocks == 0) {
            ABORT(PROT_INVALID);
        }

        SET_APDU_OP(OP_ADVANCE_HEADER_META);
        return TX_NO_DATA();
    }

    // -------------------------------------------------------------------
    // OP_HEADER_META
    // -------------------------------------------------------------------
    if (op == OP_ADVANCE_HEADER_META) {
        LOG("---- Block %u of %u\n", curr_block + 1, expected_blocks);

        // Clear block data
        memset(&block, 0, sizeof(block));
        rlp_start(&callbacks);

        // Network upgrade unknown until we get to the block number
        block.network_upgrade = NU_UNKNOWN;

        // Read the RLP payload length
        BIGENDIAN_FROM(APDU_DATA_PTR, block.mm_rlp_len);

        // Block hash computation: encode and hash payload len
        KECCAK_INIT(&block.block_ctx);
        mm_hash_rlp_list_prefix(&block.block_ctx,
                                block.mm_rlp_len + BTC_HEADER_RLP_LEN);

        // Merge mining hash computation: encode and hash mm_rlp_payload_len
        KECCAK_INIT(&block.mm_ctx);
        mm_hash_rlp_list_prefix(&block.mm_ctx, block.mm_rlp_len);

        // Now waiting for block data
        expected_state = OP_ADVANCE_HEADER_CHUNK;
        SET_APDU_OP(OP_ADVANCE_HEADER_CHUNK);
        SET_APDU_TXLEN(MAX_CHUNK_SIZE);

        return TX_FOR_DATA_SIZE(1);
    }

    // -------------------------------------------------------------------
    // OP_HEADER_CHUNK
    // -------------------------------------------------------------------
    if (op == OP_ADVANCE_HEADER_CHUNK) {
        if (rlp_consume(APDU_DATA_PTR, APDU_DATA_SIZE(rx)) < 0) {
            ABORT(RLP_INVALID);
        }

        // Check flags. Don't forget to reset them, or they
        // will activated on successive chunks!

        // We have received the whole BTC merge mining header. We can:
        //  - Perform advance blockchain validations
        //  - Check that merge mining header matches block's difficulty
        //  - Finish block.hash_for_mm computation
        if (HAS_FLAG(block.flags, MM_HEADER_RECV)) {
            CLR_FLAG(block.flags, MM_HEADER_RECV);

            // First block: perform blockchain advance prologue
            // Otherwise: verify block chains to parent
            if (curr_block == 0) {
                bc_adv_prologue();
            } else if (HNEQ(aux_bc_st.prev_parent_hash, block.block_hash)) {
                ABORT(CHAIN_MISMATCH);
            }
            // Store parent hash to validate chaining for next block
            // (next block hash must match this block's parent hash)
            HSTORE(aux_bc_st.prev_parent_hash, block.parent_hash);

            // If we already validated the current block, signal that.
            if (HEQ(block.block_hash, N_bc_state.newest_valid_block)) {
                set_bc_state_flag(&N_bc_state.updating.already_validated);
            }

            // If block is known to be valid, set HEADER_VALID flag.
            // Otherwise perform valdiations enabled by having the mm header.
            if (N_bc_state.updating.already_validated) {
                SET_FLAG(block.flags, HEADER_VALID);
            } else {
                // Compute merge mining header hash
                double_sha256_rev(&block.ctx,
                                  block.wa_buf,
                                  BTC_HEADER_SIZE,
                                  block.mm_hdr_hash);

                // Check difficulty
                diff_result r =
                    check_difficulty(block.difficulty, block.mm_hdr_hash);
                if (r == DIFF_ZERO) {
                    ABORT(BLOCK_DIFF_INVALID);
                }
                if (r == DIFF_MISMATCH) {
                    ABORT(BTC_DIFF_MISMATCH);
                }

                // Finish hash for merge mining computation
                patch_hash_for_mm(HAS_FLAG(block.flags, HAS_UMM_ROOT));
            }
        }

        // We have received the whole coinbase transaction.
        // Provided the block is not valid, we can:
        //  - Extract the cb_txn_hash
        //  - Use it to validate the merkle proof
        //  - Extract mm_hash and compare it with hash_for_mm
        //
        // This completes the current block's validation
        if (HAS_FLAG(block.flags, CB_TXN_RECV) &&
            !HAS_FLAG(block.flags, HEADER_VALID)) {

            CLR_FLAG(block.flags, CB_TXN_RECV);
            compute_cb_txn_hash();
            validate_merkle_proof();
            validate_mm_hash();
            SET_FLAG(block.flags, HEADER_VALID);
        }

        // We know this block is valid
        if (HAS_FLAG(block.flags, HEADER_VALID)) {

            // Since we have a valid block, we can accumulate difficulty.
            // This will set updating.found_best_block if we accumulated
            // enough difficulty.
            bc_adv_accum_diff();

            // Successfully advanced the blockchain: leave with success
            if (N_bc_state.updating.found_best_block &&
                HEQ(N_bc_state.best_block, block.parent_hash)) {
                bc_adv_success();
                expected_state = OP_ADVANCE_INIT;
                SET_APDU_OP(OP_ADVANCE_SUCCESS);
                return TX_NO_DATA();
            }

            // Current block valid, yet no success.
            // If no more blocks available, leave with partial success
            ++curr_block;
            if (curr_block == expected_blocks) {
                bc_adv_partial_success();
                expected_state = OP_ADVANCE_INIT;
                SET_APDU_OP(OP_ADVANCE_PARTIAL);
                return TX_NO_DATA();
            }

            // Current block valid, yet no success.
            // More blocks available, ask for them and continue.
            expected_state = OP_ADVANCE_HEADER_META;
            SET_APDU_OP(OP_ADVANCE_HEADER_META);
            return TX_NO_DATA();
        }

        // Current block header not exhausted, ask for next chunk
        SET_APDU_OP(OP_ADVANCE_HEADER_CHUNK);
        SET_APDU_TXLEN(min(block.size - block.recv, MAX_CHUNK_SIZE));
        return TX_FOR_DATA_SIZE(1);
    }

    // You shouldn't be here
    ABORT(PROT_INVALID);
    return 0;
}

// -----------------------------------------------------------------------
// Blockchain advance protocol precompiled parameters dumping
// -----------------------------------------------------------------------

/*
 * Dump minimum required difficulty to the specified APDU buffer data offset.
 * This function will copy to the the buffer the bytes comprising the
 * precompiled minimum cumulative difficulty in big endian order,
 * including leading zeroes.
 *
 * @arg[in] offset APDU buffer data dump offset
 * @ret number of bytes dumped to APDU buffer
 */
static uint8_t dump_min_req_difficulty(int offset) {
    uint8_t buf[sizeof(MIN_REQUIRED_DIFFICULTY)];
    dump_bigint(buf, MIN_REQUIRED_DIFFICULTY, BIGINT_LEN);
    memcpy(APDU_DATA_PTR + offset, buf, sizeof(buf));
    return sizeof(MIN_REQUIRED_DIFFICULTY);
}

/*
 * Get advance blockchain protocol precompiled parameters.
 *
 * Dump format:
 * Bytes 0-31: initial block hash
 * Bytes 32-67: minimum required difficulty (big endian)
 * Byte 68: network identifier (see bc_nu.h for the definition)
 *
 * @ret number of transmited bytes to the host
 */
unsigned int bc_advance_get_params() {
    int dump_size = 0;
    dump_size += bc_dump_initial_block_hash(0);
    dump_size += dump_min_req_difficulty(dump_size);
    APDU_DATA_PTR[dump_size++] = NETWORK_IDENTIFIER;

    return TX_FOR_DATA_SIZE(dump_size);
}

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

#include "auth.h"
#include "auth_constants.h"
#include "mem.h"
#include "memutil.h"
#include "srlp.h"
#include "flags.h"
#include "util.h"

#include "dbg.h"

// -----------------------------------------------------------------------
// RLP parser callbacks
// -----------------------------------------------------------------------

// Valid RSK receipts have the form [field_0, ..., field_5]
// (six fields in the top-level list).
//
// In particular, field_3 (the fourth top level field) has the form
// [log_0, ..., log_n], with n >= 0. This is the log list.
//
// Each log_m with 0 <= m <= n is of the form
// [address, topics, data] (exactly three elements)
// with:
// - address being the emitter address
// - topics: [topic_0, ..., topic_p] with p >=0 the list of topics
// - data being the unindexed data associated with the event (not used)
//
// In particular, we're interested in finding a log with:
// - a specific address (hardcoded, predefined) - the bridge address
// - exactly three topics, topic_0, topic_1 and topic_2, of which:
//   - topic_0 (aka the event signature) must match a specific
//     value (harcoded, predefined)
//   - topic_2 must match the current BTC tx hash

// RSK receipt constants
// All indexes and levels are 1-based

#define LIST_ELEMENTS (6)
#define LOG_ELEMENTS (3)

#define TOP_LEVEL (1)
#define LOG_LEVEL (3)
#define TOPIC_LEVEL (4)

#define LOGS_INDEX (4)
#define EVENT_EMITTER_INDEX (1)
#define TOPICS_INDEX (2)
#define TOPIC_SIGNATURE_INDEX (1)
#define TOPIC_TXHASH_INDEX (3)

// Flags
#define IS_INIT (0x01)
#define IS_VALID_EMITTER (0x02)
#define IS_VALID_SIGNATURE (0x04)
#define IS_VALID_TXHASH (0x08)
#define IS_MATCH (0x10)

__attribute__((always_inline)) static inline void update_indexes() {
    if (auth.receipt.level > 0)
        auth.receipt.index[auth.receipt.level - 1]++;
    for (uint8_t i = auth.receipt.level;
         i < MIN(auth.receipt.level, RECEIPT_MAX_DEPTH) - 1;
         i++)
        auth.receipt.index[i] = 0;
}

static void list_start(const uint16_t size) {
    update_indexes();

    ++auth.receipt.level;

    // About to start parsing a log? => clear the flags and counters
    if (auth.receipt.index[TOP_LEVEL - 1] == LOGS_INDEX &&
        auth.receipt.level == LOG_LEVEL) {
        CLR_FLAG(auth.receipt.flags, IS_VALID_EMITTER);
        CLR_FLAG(auth.receipt.flags, IS_VALID_SIGNATURE);
        CLR_FLAG(auth.receipt.flags, IS_VALID_TXHASH);
    }

    // Count total number of bytes remaining for the entire receipt
    if (auth.receipt.level == TOP_LEVEL) {
        auth.receipt.remaining_bytes = size + rlp_list_prefix_size(size);
    }
}

static void list_end() {
    // Have we just finished parsing a log? =>
    // set the match bit only if we found a match
    if (auth.receipt.index[TOP_LEVEL - 1] == LOGS_INDEX &&
        auth.receipt.level == LOG_LEVEL) {
        // Validate the parsed log had the exact number of elements
        if (auth.receipt.index[LOG_LEVEL - 1] != LOG_ELEMENTS) {
            LOG("[E] Found log with %u elements\n",
                auth.receipt.index[LOG_LEVEL - 1]);
            THROW(ERR_AUTH_RECEIPT_INVALID);
        }

        if (HAS_FLAG(auth.receipt.flags, IS_VALID_EMITTER) &&
            HAS_FLAG(auth.receipt.flags, IS_VALID_SIGNATURE) &&
            HAS_FLAG(auth.receipt.flags, IS_VALID_TXHASH)) {
            SET_FLAG(auth.receipt.flags, IS_MATCH);
        }
    }

    // Validate the parsed receipt had the exact number of
    // top level elements
    if (auth.receipt.level == TOP_LEVEL &&
        auth.receipt.index[TOP_LEVEL - 1] != LIST_ELEMENTS) {
        LOG("[E] Receipt had %u elements\n", auth.receipt.index[TOP_LEVEL - 1]);
        THROW(ERR_AUTH_RECEIPT_INVALID);
    }

    --auth.receipt.level;

    // Reset indexes of lower levels
    for (uint8_t i = auth.receipt.level; i < RECEIPT_MAX_DEPTH; i++)
        auth.receipt.index[i] = 0;
}

static void str_start(const uint16_t size) {
    // Top level must be a list
    if (auth.receipt.level == 0) {
        LOG("[E] Receipt not a list\n");
        THROW(ERR_AUTH_RECEIPT_INVALID);
    }

    update_indexes();

    // Save strings only for desired fields
    if (auth.receipt.index[TOP_LEVEL - 1] == LOGS_INDEX &&
        auth.receipt.level >= LOG_LEVEL) {
        auth.receipt.aux_offset = 0;
    }
}

static void str_chunk(const uint8_t* chunk, const size_t size) {
    // Save strings only for desired fields
    // Also prevent erroring while saving
    // undesired fields that could be too big
    if (auth.receipt.index[TOP_LEVEL - 1] == LOGS_INDEX &&
        auth.receipt.level >= LOG_LEVEL &&
        auth.receipt.aux_offset + size <= sizeof(auth.receipt.aux)) {
        SAFE_MEMMOVE(auth.receipt.aux,
                     sizeof(auth.receipt.aux),
                     auth.receipt.aux_offset,
                     chunk,
                     size,
                     MEMMOVE_ZERO_OFFSET,
                     size,
                     THROW(ERR_AUTH_INVALID_DATA_SIZE));
        auth.receipt.aux_offset += size;
    }
}

static void str_end() {
    // Compare values with expected values
    if (auth.receipt.index[TOP_LEVEL - 1] == LOGS_INDEX &&
        auth.receipt.level >= LOG_LEVEL) {
        switch (auth.receipt.level) {
        case LOG_LEVEL:
            if (auth.receipt.index[LOG_LEVEL - 1] == EVENT_EMITTER_INDEX &&
                auth.receipt.aux_offset == sizeof(EVENT_EMITTER) &&
                !memcmp(auth.receipt.aux,
                        (void*)PIC(EVENT_EMITTER),
                        sizeof(EVENT_EMITTER)))
                SET_FLAG(auth.receipt.flags, IS_VALID_EMITTER);
            break;
        case TOPIC_LEVEL:
            if (auth.receipt.index[LOG_LEVEL - 1] == TOPICS_INDEX) {
                if (auth.receipt.index[TOPIC_LEVEL - 1] ==
                        TOPIC_SIGNATURE_INDEX &&
                    auth.receipt.aux_offset == sizeof(EVENT_SIGNATURE) &&
                    !memcmp(auth.receipt.aux,
                            (void*)PIC(EVENT_SIGNATURE),
                            sizeof(EVENT_SIGNATURE)))
                    SET_FLAG(auth.receipt.flags, IS_VALID_SIGNATURE);
                else if (auth.receipt.index[TOPIC_LEVEL - 1] ==
                             TOPIC_TXHASH_INDEX &&
                         auth.receipt.aux_offset == sizeof(auth.tx_hash) &&
                         !memcmp(auth.receipt.aux,
                                 auth.tx_hash,
                                 sizeof(auth.tx_hash)))
                    SET_FLAG(auth.receipt.flags, IS_VALID_TXHASH);
            }
            break;
        }
    }
}

static const rlp_callbacks_t callbacks = {
    str_start,
    str_chunk,
    str_end,
    list_start,
    list_end,
};

/*
 * Implement the RSK receipt parsing and validation portion of the signing
 * authorization protocol.
 *
 * @arg[in] rx      number of received bytes from the host
 * @ret             number of transmited bytes to the host
 */
unsigned int auth_sign_handle_receipt(volatile unsigned int rx) {
    if (auth.state != STATE_AUTH_RECEIPT) {
        LOG("[E] Expected to be in the receipt state\n");
        THROW(ERR_AUTH_INVALID_STATE);
    }

    if (!HAS_FLAG(auth.receipt.flags, IS_INIT)) {
        rlp_start(&callbacks);
        keccak_init(&auth.receipt.hash_ctx);
        SET_FLAG(auth.receipt.flags, IS_INIT);
    }

    int res = rlp_consume(APDU_DATA_PTR, APDU_DATA_SIZE(rx));
    if (res < 0) {
        LOG("[E] RLP parser returned error %d\n", res);
        THROW(ERR_AUTH_RECEIPT_RLP);
    }
    auth.receipt.remaining_bytes -= APDU_DATA_SIZE(rx);

    keccak_update(&auth.receipt.hash_ctx, APDU_DATA_PTR, APDU_DATA_SIZE(rx));

    if (auth.receipt.remaining_bytes == 0) {
        if (HAS_FLAG(auth.receipt.flags, IS_MATCH)) {
            // Finalize the hash calculation
            keccak_final(&auth.receipt.hash_ctx, auth.receipt_hash);

            // Log hash for debugging purposes
            LOG_HEX(
                "Receipt hash: ", auth.receipt_hash, sizeof(auth.receipt_hash));

            // Request RSK transaction receipt
            SET_APDU_OP(P1_MERKLEPROOF);
            SET_APDU_TXLEN(AUTH_MAX_EXCHANGE_SIZE);
            auth.expected_bytes = APDU_TXLEN();
            auth_transition_to(STATE_AUTH_MERKLEPROOF);
            return TX_FOR_TXLEN();
        }

        // No match
        LOG("[E] No log match found in the receipt\n");
        // To comply with the legacy implementation
        THROW(ERR_AUTH_INVALID_DATA_SIZE);
    }

    SET_APDU_TXLEN(MIN(auth.receipt.remaining_bytes, AUTH_MAX_EXCHANGE_SIZE));
    auth.expected_bytes = APDU_TXLEN();
    return TX_FOR_TXLEN();
}
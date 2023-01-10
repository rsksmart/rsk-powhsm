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
#include "mem.h"
#include "memutil.h"
#include "bc_state.h"

#include "dbg.h"

#define REQUEST_MORE_IF_NEED()                      \
    {                                               \
        if (apdu_offset >= APDU_DATA_SIZE(rx)) {    \
            SET_APDU_TXLEN(AUTH_MAX_EXCHANGE_SIZE); \
            return TX_FOR_TXLEN();                  \
        }                                           \
    }

#define FAIL_IF_LEAF()                             \
    {                                              \
        if (auth.trie.current_node == 0) {         \
            LOG("[E] Leaf node not a leaf\n");     \
            THROW(ERR_AUTH_RECEIPT_HASH_MISMATCH); \
        }                                          \
    }

#define IGNORE_IF_INTERNAL()            \
    {                                   \
        if (auth.trie.current_node > 0) \
            break;                      \
    }

static void trie_cb(const trie_cb_event_t event) {
    // Update node hash
    keccak_update(
        &auth.trie.hash_ctx, auth.trie.ctx.raw, auth.trie.ctx.raw_size);

    switch (event) {
    case TRIE_EV_FLAGS:
        if (TRIE_FG_VERSION(auth.trie.ctx.flags) != AUTH_TRIE_NODE_VERSION) {
            LOG("[E] Invalid node version: %u\n",
                TRIE_FG_VERSION(auth.trie.ctx.flags));
            THROW(ERR_AUTH_NODE_INVALID_VERSION);
        }

        if (auth.trie.current_node == 0 &&
            (TRIE_FG_NODE_PRESENT_LEFT(auth.trie.ctx.flags) ||
             TRIE_FG_NODE_PRESENT_RIGHT(auth.trie.ctx.flags))) {
            LOG("[E] Leaf node not a leaf\n");
            THROW(ERR_AUTH_RECEIPT_HASH_MISMATCH);
        }

        // In a valid proof, the first node of the partial merkle proof
        // MUST be the leaf and contain the receipt as a value.
        // Any receipt is by definition more than 32 bytes
        // in size, and therefore a merkle proof node that contains it should
        // encode it as a long value (i.e., containing hash and length only)
        // Hence, getting here indicates the given proof is INVALID.
        // Fail indicating a receipt hash mismatch.
        if (auth.trie.current_node == 0 &&
            !TRIE_FG_HAS_LONG_VALUE(auth.trie.ctx.flags)) {
            LOG("[E] Leaf node must have a long value\n");
            THROW(ERR_AUTH_RECEIPT_HASH_MISMATCH);
        }
        break;
    case TRIE_EV_VALUE_START:
    case TRIE_EV_VALUE_DATA:
    case TRIE_EV_VALUE_END:
        IGNORE_IF_INTERNAL();
        LOG("[E] Leaf node must have a long value\n");
        THROW(ERR_AUTH_RECEIPT_HASH_MISMATCH);
        break;
    case TRIE_EV_VALUE_HASH_START:
        IGNORE_IF_INTERNAL();
        auth.trie.offset = 0;
        break;
    case TRIE_EV_VALUE_HASH_DATA:
        IGNORE_IF_INTERNAL();
        SAFE_MEMMOVE(auth.trie.value_hash,
                     sizeof(auth.trie.value_hash),
                     auth.trie.offset,
                     auth.trie.ctx.raw,
                     sizeof(auth.trie.ctx.raw),
                     MEMMOVE_ZERO_OFFSET,
                     auth.trie.ctx.raw_size,
                     THROW(ERR_AUTH_INVALID_DATA_SIZE));
        auth.trie.offset += auth.trie.ctx.raw_size;
        break;
    case TRIE_EV_VALUE_HASH_END:
        IGNORE_IF_INTERNAL();
        if (memcmp(auth.receipt_hash,
                   auth.trie.value_hash,
                   sizeof(auth.trie.value_hash))) {
            LOG("[E] Receipt hash mismatch\n");
            THROW(ERR_AUTH_RECEIPT_HASH_MISMATCH);
        }
        break;
    case TRIE_EV_LEFT_NODE_START:
    case TRIE_EV_RIGHT_NODE_START:
        FAIL_IF_LEAF();
        auth.trie.offset = 0;
        break;
    case TRIE_EV_LEFT_NODE_DATA:
    case TRIE_EV_RIGHT_NODE_DATA:
        FAIL_IF_LEAF();
        SAFE_MEMMOVE(auth.trie.child_hash,
                     sizeof(auth.trie.child_hash),
                     auth.trie.offset,
                     auth.trie.ctx.raw,
                     sizeof(auth.trie.ctx.raw),
                     MEMMOVE_ZERO_OFFSET,
                     auth.trie.ctx.raw_size,
                     THROW(ERR_AUTH_INVALID_DATA_SIZE));
        auth.trie.offset += auth.trie.ctx.raw_size;
        break;
    case TRIE_EV_LEFT_NODE_EMBEDDED_START:
    case TRIE_EV_RIGHT_NODE_EMBEDDED_START:
        FAIL_IF_LEAF();
        keccak_init(&auth.trie.aux_hash_ctx);
        break;
    case TRIE_EV_LEFT_NODE_EMBEDDED_DATA:
    case TRIE_EV_RIGHT_NODE_EMBEDDED_DATA:
        FAIL_IF_LEAF();
        keccak_update(
            &auth.trie.aux_hash_ctx, auth.trie.ctx.raw, auth.trie.ctx.raw_size);
        break;
    case TRIE_EV_LEFT_NODE_END:
    case TRIE_EV_RIGHT_NODE_END:
    case TRIE_EV_LEFT_NODE_EMBEDDED_END:
    case TRIE_EV_RIGHT_NODE_EMBEDDED_END:
        FAIL_IF_LEAF();
        if (event == TRIE_EV_LEFT_NODE_EMBEDDED_END ||
            event == TRIE_EV_RIGHT_NODE_EMBEDDED_END)
            keccak_final(&auth.trie.aux_hash_ctx, auth.trie.child_hash);
        if (!memcmp(auth.trie.node_hash,
                    auth.trie.child_hash,
                    sizeof(auth.trie.node_hash)))
            auth.trie.num_linked++;
        break;
    }
}

/*
 * Implement the partial merkle trie parsing portion
 * of the signing authorization protocol.
 *
 * @arg[in] rx      number of received bytes from the host
 * @ret             number of transmited bytes to the host
 */
unsigned int auth_sign_handle_merkleproof(volatile unsigned int rx) {
    uint8_t apdu_offset = 0;

    if (auth.state != STATE_AUTH_MERKLEPROOF) {
        LOG("[E] Expected to be in the MP state\n");
        THROW(ERR_AUTH_INVALID_STATE);
    }

    while (true) {
        // Read number of nodes (single byte)
        if (auth.trie.total_nodes == 0) {
            auth.trie.total_nodes = APDU_DATA_PTR[apdu_offset++];
            auth.trie.current_node = 0;
            auth.trie.state = AUTH_TRIE_STATE_NODE_LENGTH;

            REQUEST_MORE_IF_NEED();
        }

        if (auth.trie.state == AUTH_TRIE_STATE_NODE_LENGTH) {
            // Verify node is at least one byte long
            if (APDU_DATA_PTR[apdu_offset] == 0) {
                LOG("[E] Got MP node length zero\n");
                THROW(ERR_AUTH_INVALID_DATA_SIZE);
            }
            trie_init(&auth.trie.ctx, &trie_cb, APDU_DATA_PTR[apdu_offset++]);
            keccak_init(&auth.trie.hash_ctx);
            auth.trie.state = AUTH_TRIE_STATE_NODE;
            auth.trie.num_linked = 0;

            REQUEST_MORE_IF_NEED();
        }

        if (auth.trie.state == AUTH_TRIE_STATE_NODE) {
            apdu_offset += trie_consume(APDU_DATA_PTR + apdu_offset,
                                        APDU_DATA_SIZE(rx) - apdu_offset);

            if (trie_result() < 0) {
                LOG("[E] Error parsing MP node: %u\n", trie_result());
                // Reusing an existing error code due to legacy protocol
                THROW(ERR_AUTH_RECEIPT_ROOT_MISMATCH);
            } else if (trie_result() == TRIE_ST_DONE) {
                keccak_final(&auth.trie.hash_ctx, auth.trie.node_hash);
                LOG("MP@%u ", auth.trie.current_node);
                LOG_HEX(
                    "hash: ", auth.trie.node_hash, sizeof(auth.trie.node_hash));

                if (auth.trie.current_node > 0) {
                    // If this is an internal node, check
                    // it was successfully linked with exactly
                    // one child
                    if (auth.trie.num_linked != 1) {
                        LOG("[E] Node chaining mismatch\n");
                        THROW(ERR_AUTH_NODE_CHAINING_MISMATCH);
                    }
                }

                auth.trie.current_node++;

                // If this is the root, check it matches the current
                // bc state's ancestor receipts root
                if (auth.trie.current_node == auth.trie.total_nodes) {
                    if (!memcmp(N_bc_state.ancestor_receipt_root,
                                auth.trie.node_hash,
                                sizeof(N_bc_state.ancestor_receipt_root))) {
                        auth_transition_to(STATE_AUTH_SIGN);
                        return 0;
                    }

                    LOG("[E] Receipt root mismatch\n");
                    THROW(ERR_AUTH_RECEIPT_ROOT_MISMATCH);
                }

                auth.trie.state = AUTH_TRIE_STATE_NODE_LENGTH;
            }

            REQUEST_MORE_IF_NEED();
        }
    }
}
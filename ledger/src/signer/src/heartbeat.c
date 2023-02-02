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
#include "heartbeat.h"
#include "apdu.h"
#include "defs.h"
#include "memutil.h"
#include "bc_state.h"
#include "compiletime.h"

/*
 * Reset the given heartbeat context
 */
static void reset_heartbeat(heartbeat_t* heartbeat_ctx) {
    explicit_bzero(heartbeat_ctx, sizeof(heartbeat_t));
    heartbeat_ctx->state = STATE_HEARTBEAT_WAIT_UD_VALUE;
}

/*
 * Check that the SM for the heartbeat generation
 * matches the expected state.
 *
 * Reset the state and throw a protocol error
 * otherwise.
 */
static void check_state(heartbeat_t* heartbeat_ctx,
                        state_heartbeat_t expected) {
    if (heartbeat_ctx->state != expected) {
        reset_heartbeat(heartbeat_ctx);
        THROW(ERR_HBT_PROT_INVALID);
    }
}

// -----------------------------------------------------------------------
// Protocol implementation
// -----------------------------------------------------------------------

/*
 * Implement the heartbeat protocol.
 *
 * @arg[in] rx      number of received bytes from the Host
 * @arg[in] heartbeat_ctx heartbeat context
 * @ret             number of transmited bytes to the host
 */
unsigned int get_heartbeat(volatile unsigned int rx,
                           heartbeat_t* heartbeat_ctx) {
    // Build should fail when more bytes than available are tried to be copied
    // from the last signed BTC tx hash
    COMPILE_TIME_ASSERT(LAST_SIGNED_TX_BYTES <=
                        sizeof(N_bc_state.last_auth_signed_btc_tx_hash));

    COMPILE_TIME_ASSERT(MAX_HEARTBEAT_MESSAGE_SIZE <= APDU_TOTAL_DATA_SIZE_OUT);

    switch (APDU_OP()) {
    case OP_HBT_UD_VALUE:
        // Should receive a user-defined value
        if (APDU_DATA_SIZE(rx) != UD_VALUE_SIZE) {
            reset_heartbeat(heartbeat_ctx);
            THROW(ERR_HBT_PROT_INVALID);
        }

        // Initialize message
        explicit_bzero(heartbeat_ctx->msg, sizeof(heartbeat_ctx->msg));
        heartbeat_ctx->msg_offset = 0;

        // Copy the message prefix
        SAFE_MEMMOVE(heartbeat_ctx->msg,
                     sizeof(heartbeat_ctx->msg),
                     heartbeat_ctx->msg_offset,
                     (void*)PIC(HEARTBEAT_MSG_PREFIX),
                     HEARTBEAT_MSG_PREFIX_LENGTH,
                     MEMMOVE_ZERO_OFFSET,
                     HEARTBEAT_MSG_PREFIX_LENGTH,
                     THROW(ERR_HBT_INTERNAL));
        heartbeat_ctx->msg_offset += HEARTBEAT_MSG_PREFIX_LENGTH;

        // Copy the current best block
        SAFE_MEMMOVE(heartbeat_ctx->msg,
                     sizeof(heartbeat_ctx->msg),
                     heartbeat_ctx->msg_offset,
                     N_bc_state.best_block,
                     sizeof(N_bc_state.best_block),
                     MEMMOVE_ZERO_OFFSET,
                     sizeof(N_bc_state.best_block),
                     THROW(ERR_HBT_INTERNAL));
        heartbeat_ctx->msg_offset += sizeof(N_bc_state.best_block);

        // Copy the last LAST_SIGNED_TX_BYTES bytes of the last auth signed tx
        SAFE_MEMMOVE(heartbeat_ctx->msg,
                     sizeof(heartbeat_ctx->msg),
                     heartbeat_ctx->msg_offset,
                     N_bc_state.last_auth_signed_btc_tx_hash,
                     sizeof(N_bc_state.last_auth_signed_btc_tx_hash),
                     MEMMOVE_ZERO_OFFSET,
                     LAST_SIGNED_TX_BYTES,
                     THROW(ERR_HBT_INTERNAL));
        heartbeat_ctx->msg_offset += LAST_SIGNED_TX_BYTES;

        // Copy the UD value from the APDU
        SAFE_MEMMOVE(heartbeat_ctx->msg,
                     sizeof(heartbeat_ctx->msg),
                     heartbeat_ctx->msg_offset,
                     APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE,
                     MEMMOVE_ZERO_OFFSET,
                     UD_VALUE_SIZE,
                     THROW(ERR_HBT_INTERNAL));
        heartbeat_ctx->msg_offset += UD_VALUE_SIZE;

        heartbeat_ctx->state = STATE_HEARTBEAT_READY;

        return TX_FOR_DATA_SIZE(0);
    case OP_HBT_GET:
        check_state(heartbeat_ctx, STATE_HEARTBEAT_READY);

        // Sign message
        int endorsement_size = os_endorsement_key2_derive_sign_data(
            heartbeat_ctx->msg, heartbeat_ctx->msg_offset, APDU_DATA_PTR);

        return TX_FOR_DATA_SIZE(endorsement_size);
    case OP_HBT_GET_MESSAGE:
        check_state(heartbeat_ctx, STATE_HEARTBEAT_READY);

        SAFE_MEMMOVE(APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE,
                     MEMMOVE_ZERO_OFFSET,
                     heartbeat_ctx->msg,
                     sizeof(heartbeat_ctx->msg),
                     MEMMOVE_ZERO_OFFSET,
                     heartbeat_ctx->msg_offset,
                     THROW(ERR_HBT_INTERNAL));

        return TX_FOR_DATA_SIZE(heartbeat_ctx->msg_offset);
    case OP_HBT_APP_HASH:
        return TX_FOR_DATA_SIZE(os_endorsement_get_code_hash(APDU_DATA_PTR));
    case OP_HBT_PUBKEY:
        return TX_FOR_DATA_SIZE(os_endorsement_get_public_key(
            ENDORSEMENT_SCHEME_INDEX, APDU_DATA_PTR));
    default:
        reset_heartbeat(heartbeat_ctx);
        THROW(ERR_HBT_PROT_INVALID);
        break;
    }
}

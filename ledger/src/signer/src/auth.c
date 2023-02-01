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
#include "err.h"
#include "sign.h"
#include "mem.h"
#include "compiletime.h"

#include "dbg.h"

/*
 * Transition to the given state, performing corresponding
 * initializations.
 *
 * @arg[in] state   the state to transition to
 */
void auth_transition_to(uint8_t state) {
    if (state == STATE_AUTH_START)
        memset(&auth, 0, sizeof(auth));

    auth.state = state;

    // Init shared state
    memset(&auth.tx, 0, sizeof(auth.tx));
    memset(&auth.receipt, 0, sizeof(auth.receipt));
    memset(&auth.trie, 0, sizeof(auth.trie));
}

/*
 * Implement the signing authorization protocol.
 *
 * @arg[in] rx      number of received bytes from the host
 * @ret             number of transmited bytes to the host
 */
unsigned int auth_sign(volatile unsigned int rx) {
    unsigned int tx;

    // Sanity check: tx hash size and
    // last auth signed tx hash size
    // must match
    COMPILE_TIME_ASSERT(sizeof(N_bc_state.last_auth_signed_btc_tx_hash) ==
                        sizeof(auth.tx_hash));

    // Check we receive the amount of bytes we requested
    // (this is an extra check on the legacy protocol, not
    // really adding much validation)
    if (auth.state != STATE_AUTH_START &&
        auth.state != STATE_AUTH_MERKLEPROOF &&
        APDU_DATA_SIZE(rx) != auth.expected_bytes)
        THROW(ERR_AUTH_INVALID_DATA_SIZE);

    switch (APDU_OP() & 0xF) {
    case P1_PATH:
        if ((tx = auth_sign_handle_path(rx)) == 0)
            break;
        return tx;
    case P1_BTC:
        return auth_sign_handle_btctx(rx);
    case P1_RECEIPT:
        return auth_sign_handle_receipt(rx);
    case P1_MERKLEPROOF:
        if ((tx = auth_sign_handle_merkleproof(rx)) == 0)
            break;
        return tx;
    default:
        // Invalid OP
        THROW(ERR_AUTH_INVALID_DATA_SIZE);
    }

    if (auth.state != STATE_AUTH_SIGN)
        THROW(ERR_AUTH_INVALID_STATE); // Invalid state

    tx = do_sign(auth.path,
                 DERIVATION_PATH_PARTS,
                 auth.sig_hash,
                 sizeof(auth.sig_hash),
                 APDU_DATA_PTR,
                 APDU_TOTAL_DATA_SIZE_OUT);

    // Save the BTC tx hash to NVM if this signature required authorization
    if (auth.auth_required) {
        // Avoid rewriting the same value to NVM multiple times
        if (memcmp(N_bc_state.last_auth_signed_btc_tx_hash,
                   auth.tx_hash,
                   sizeof(auth.tx_hash))) {
            NVM_WRITE(N_bc_state.last_auth_signed_btc_tx_hash,
                      auth.tx_hash,
                      sizeof(N_bc_state.last_auth_signed_btc_tx_hash));

            // Log hash for debugging purposes
            LOG_HEX("Saved BTC tx hash: ", auth.tx_hash, sizeof(auth.tx_hash));
        } else {
            // Log (already saved) hash for debugging purposes
            LOG_HEX("Did not rewrite already saved BTC tx hash: ",
                    auth.tx_hash,
                    sizeof(auth.tx_hash));
        }
    }

    // Error signing?
    if (tx == DO_SIGN_ERROR) {
        THROW(ERR_INTERNAL);
    }

    SET_APDU_OP(P1_SUCCESS);
    auth_transition_to(STATE_AUTH_START);
    return TX_FOR_DATA_SIZE(tx);
}

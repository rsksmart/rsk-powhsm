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

#include "os.h"

#include "auth.h"
#include "pathAuth.h"

#include "mem.h"
#include "memutil.h"

/*
 * Implement the path parsing and validation portion of the signing
 * authorization protocol.
 *
 * @arg[in] rx      number of received bytes from the host
 * @ret             number of transmited bytes to the host
 */
unsigned int auth_sign_handle_path(volatile unsigned int rx) {
    if (auth.state != STATE_AUTH_PATH)
        THROW(ERR_AUTH_INVALID_STATE);

    if ((rx != DATA + PATH_LEN + INPUT_INDEX_LEN) &&
        (rx != DATA + PATH_LEN + HASH_LENGTH))
        THROW(ERR_AUTH_INVALID_DATA_SIZE); // Wrong buffer size,
                                           // has to be either 28
                                           // (DATA+PATH_LEN+INPUT_INDEX_LEN) or
                                           // 56 (DATA+PATH_LEN+HASHEN)

    // Read derivation path
    SAFE_MEMMOVE(auth.path,
                 sizeof(auth.path),
                 MEMMOVE_ZERO_OFFSET,
                 APDU_DATA_PTR,
                 APDU_TOTAL_DATA_SIZE,
                 1, // Skip path length (first byte)
                 sizeof(auth.path),
                 THROW(ERR_AUTH_INVALID_DATA_SIZE));

    if (pathRequireAuth(APDU_DATA_PTR)) {
        // If path requires authorization, continue with authorization
        auth.auth_required = true;

        if (rx != DATA + PATH_LEN + INPUT_INDEX_LEN)
            THROW(ERR_AUTH_INVALID_DATA_SIZE_AUTH_SIGN);

        // Read input index to sign
        SAFE_MEMMOVE(&auth.input_index_to_sign,
                     sizeof(auth.input_index_to_sign),
                     MEMMOVE_ZERO_OFFSET,
                     APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE,
                     PATH_LEN,
                     INPUT_INDEX_LEN,
                     THROW(ERR_AUTH_INVALID_DATA_SIZE));

        // Request BTC transaction
        SET_APDU_OP(P1_BTC);
        SET_APDU_TXLEN(APDU_TOTAL_DATA_SIZE);
        auth.expected_bytes = APDU_TXLEN();
        auth_transition_to(STATE_AUTH_BTCTX);
        return TX_FOR_TXLEN();
    } else if (pathDontRequireAuth(APDU_DATA_PTR)) {
        // If path doesn't require authorization,
        // go directly to signing
        auth.auth_required = false;

        if (rx != DATA + PATH_LEN + HASH_LENGTH)
            THROW(ERR_AUTH_INVALID_DATA_SIZE_UNAUTH_SIGN);

        // Read hash to sign
        SAFE_MEMMOVE(auth.sig_hash,
                     sizeof(auth.sig_hash),
                     MEMMOVE_ZERO_OFFSET,
                     APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE,
                     PATH_LEN,
                     sizeof(auth.sig_hash),
                     THROW(ERR_AUTH_INVALID_DATA_SIZE));

        auth_transition_to(STATE_AUTH_SIGN);
        return 0;
    }

    // If no path match, then bail out
    // signalling invalid path
    THROW(ERR_AUTH_INVALID_PATH);
}

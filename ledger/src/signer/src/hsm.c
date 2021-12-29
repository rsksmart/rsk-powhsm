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

#include "hsm.h"
#include "os.h"

#include "defs.h"
#include "mem.h"
#include "memutil.h"

#include "pathAuth.h"
#include "auth.h"
#include "sign.h"

#include "bc_state.h"
#include "bc_advance.h"
#include "bc_ancestor.h"

#include "attestation.h"

#include "dbg.h"

// Operation being currently executed
static unsigned char curr_cmd;

/*
 * Reset shared memory state.
 */
static void reset_shared_state() {
    explicit_bzero(&mem, sizeof(mem));
}

/*
 * Reset all reseteable operations, only if the given operation is starting.
 *
 * @arg[in] cmd operation code
 */
static void reset_if_starting(unsigned char cmd) {
    // Reset only if starting new operation (cmd != curr_cmd).
    // Otherwise we already reset when curr_cmd started.
    if (cmd != curr_cmd) {
        reset_shared_state();
        bc_init_advance();
        bc_init_upd_ancestor();
        curr_cmd = cmd;
    }
}

unsigned int hsm_process_apdu(volatile unsigned int rx) {
    unsigned int tx = 0;

    // No apdu received
    if (rx == 0) {
        THROW(0x6982);
    }

    // Zero out commonly read APDU buffer offsets,
    // to avoid reading uninitialized memory
    if (rx < MIN_APDU_BYTES) {
        explicit_bzero(G_io_apdu_buffer + rx, MIN_APDU_BYTES - rx);
    }

    // Invalid CLA
    if (APDU_CLA() != CLA) {
        THROW(0x6E11);
    }

    switch (APDU_CMD()) {
    // Reports the current mode (i.e., always reports app aka signer mode)
    case RSK_MODE_CMD:
        reset_if_starting(RSK_MODE_CMD);
        SET_APDU_CMD(RSK_MODE_APP);
        tx = 2;
        break;

    // Reports wheter the device is onboarded and the current signer version
    case RSK_IS_ONBOARD:
        reset_if_starting(RSK_IS_ONBOARD);
        uint8_t output_index = CMDPOS;
        SET_APDU_AT(output_index++, os_perso_isonboarded());
        SET_APDU_AT(output_index++, VERSION_MAJOR);
        SET_APDU_AT(output_index++, VERSION_MINOR);
        SET_APDU_AT(output_index++, VERSION_PATCH);
        tx = 5;
        break;

    // Derives and returns the corresponding public key for the given path
    case INS_GET_PUBLIC_KEY:
        reset_if_starting(INS_GET_PUBLIC_KEY);

        // Check the received data size
        if (rx != DATA + sizeof(uint32_t) * RSK_PATH_LEN)
            THROW(0x6A87); // Wrong buffer size

        // Check for path validity before returning the public key
        // Actual path starts at normal data pointer, but
        // is prepended by a single byte indicating the path length
        // (all paths have the same length in practice, so this should
        // be refactored in the future)
        if (!(pathRequireAuth(APDU_DATA_PTR - 1) ||
              pathDontRequireAuth(APDU_DATA_PTR - 1))) {
            // If no path match, then bail out
            THROW(0x6A8F); // Invalid Key Path
        }

        // Derive the public key
        SAFE_MEMMOVE(auth.path,
                     sizeof(auth.path),
                     0,
                     APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE,
                     0,
                     RSK_PATH_LEN * sizeof(uint32_t),
                     THROW(0x6A8F));
        tx = do_pubkey(auth.path,
                       RSK_PATH_LEN,
                       G_io_apdu_buffer,
                       sizeof(G_io_apdu_buffer));

        // Error deriving?
        if (tx == DO_PUBKEY_ERROR) {
            THROW(0x6A99);
        }

        break;

    case INS_SIGN:
        reset_if_starting(INS_SIGN);
        tx = auth_sign(rx);
        break;

    case INS_ATTESTATION:
        reset_if_starting(INS_ATTESTATION);
        tx = get_attestation(rx, &attestation);
        break;

    // Get blockchain state
    case INS_GET_STATE:
        reset_if_starting(INS_GET_STATE);
        tx = bc_get_state(rx);
        break;

    // Reset blockchain state
    case INS_RESET_STATE:
        reset_if_starting(INS_RESET_STATE);
        tx = bc_reset_state(rx);
        break;

    // Advance blockchain
    case INS_ADVANCE:
        reset_if_starting(INS_ADVANCE);
        tx = bc_advance(rx);
        break;

    // Advance blockchain precompiled parameters
    case INS_ADVANCE_PARAMS:
        reset_if_starting(INS_ADVANCE_PARAMS);
        tx = bc_advance_get_params();
        break;

    // Update ancestor
    case INS_UPD_ANCESTOR:
        reset_if_starting(INS_UPD_ANCESTOR);
        tx = bc_upd_ancestor(rx);
        break;

    default: // Unknown command
        THROW(0x6D00);
        break;
    }

    return tx;
}

unsigned int hsm_process_exception(unsigned short code, unsigned int tx) {
    unsigned short sw = 0;

    // Always reset the full state when an error occurs
    if (code != 0x9000) {
        RESET_BC_STATE();
        reset_if_starting(0);
    }

    // Apply code transformations
    switch (code & 0xF000) {
    case 0x6000:
    case 0x9000:
        sw = code;
        break;
    default:
        sw = 0x6800 | (code & 0x7FF);
        break;
    }

    // Append resulting code to APDU
    SET_APDU_AT(tx++, sw >> 8);
    SET_APDU_AT(tx++, sw);

    return tx;
}

void hsm_init() {
    // Initialize current operation
    // (0 = no operation being executed)
    curr_cmd = 0;

    // Blockchain state initialization
    bc_init_state();
}

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
#include "os_io_seproxyhal.h"

#include "defs.h"
#include "instructions.h"
#include "modes.h"
#include "err.h"
#include "mem.h"
#include "memutil.h"

#include "pathAuth.h"
#include "auth.h"
#include "sign.h"

#include "bc_state.h"
#include "bc_advance.h"
#include "bc_ancestor.h"

#include "attestation.h"
#include "heartbeat.h"

#include "dbg.h"

// Macro that throws an error unless
// the device is onboarded
#define REQUIRE_ONBOARDED()          \
    if (os_perso_isonboarded() != 1) \
        THROW(ERR_DEVICE_NOT_ONBOARDED);

// Operation being currently executed
static unsigned char curr_cmd;

// Whether exit has been requested
static bool _hsm_exit_requested;

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

// Exit the application
static void app_exit(void) {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
            _hsm_exit_requested = true;
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

unsigned int hsm_process_apdu(volatile unsigned int rx) {
    unsigned int tx = 0;

    // No apdu received
    if (rx == 0) {
        THROW(ERR_EMPTY_BUFFER);
    }

    // Zero out commonly read APDU buffer offsets,
    // to avoid reading uninitialized memory
    if (rx < MIN_APDU_BYTES) {
        explicit_bzero(G_io_apdu_buffer + rx, MIN_APDU_BYTES - rx);
    }

    // Invalid CLA
    if (APDU_CLA() != CLA) {
        THROW(ERR_INVALID_CLA);
    }

    switch (APDU_CMD()) {
    // Reports the current mode (i.e., always reports signer mode)
    case RSK_MODE_CMD:
        reset_if_starting(RSK_MODE_CMD);
        SET_APDU_CMD(APP_MODE_SIGNER);
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
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_GET_PUBLIC_KEY);

        // Check the received data size
        if (rx != DATA + sizeof(uint32_t) * DERIVATION_PATH_PARTS)
            THROW(ERR_INVALID_DATA_SIZE); // Wrong buffer size

        // Check for path validity before returning the public key
        // Actual path starts at normal data pointer, but
        // is prepended by a single byte indicating the path length
        // (all paths have the same length in practice, so this should
        // be refactored in the future)
        if (!(pathRequireAuth(APDU_DATA_PTR - 1) ||
              pathDontRequireAuth(APDU_DATA_PTR - 1))) {
            // If no path match, then bail out
            THROW(ERR_INVALID_PATH); // Invalid Key Path
        }

        // Derive the public key
        SAFE_MEMMOVE(auth.path,
                     sizeof(auth.path),
                     MEMMOVE_ZERO_OFFSET,
                     APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE_OUT,
                     MEMMOVE_ZERO_OFFSET,
                     sizeof(auth.path),
                     THROW(ERR_INVALID_PATH));
        tx = do_pubkey(auth.path,
                       DERIVATION_PATH_PARTS,
                       G_io_apdu_buffer,
                       sizeof(G_io_apdu_buffer));

        // Error deriving?
        if (tx == DO_PUBKEY_ERROR) {
            THROW(ERR_INTERNAL);
        }

        break;

    case INS_SIGN:
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_SIGN);
        tx = auth_sign(rx);
        break;

    case INS_ATTESTATION:
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_ATTESTATION);
        tx = get_attestation(rx, &attestation);
        break;

    case INS_HEARTBEAT:
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_HEARTBEAT);
        tx = get_heartbeat(rx, &heartbeat);
        break;

    // Get blockchain state
    case INS_GET_STATE:
        REQUIRE_ONBOARDED();

        // Get blockchain state is considered part of the
        // advance blockchain operation
        reset_if_starting(INS_ADVANCE);
        tx = bc_get_state(rx);
        break;

    // Reset blockchain state
    case INS_RESET_STATE:
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_RESET_STATE);
        tx = bc_reset_state(rx);
        break;

    // Advance blockchain
    case INS_ADVANCE:
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_ADVANCE);
        tx = bc_advance(rx);
        break;

    // Advance blockchain precompiled parameters
    case INS_ADVANCE_PARAMS:
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_ADVANCE_PARAMS);
        tx = bc_advance_get_params();
        break;

    // Update ancestor
    case INS_UPD_ANCESTOR:
        REQUIRE_ONBOARDED();

        reset_if_starting(INS_UPD_ANCESTOR);
        tx = bc_upd_ancestor(rx);
        break;

    case INS_EXIT:
        bc_backup_partial_state();
        app_exit();
        tx = TX_FOR_DATA_SIZE(0);
        break;

    default: // Unknown command
        THROW(ERR_INS_NOT_SUPPORTED);
        break;
    }

    return tx;
}

unsigned int hsm_process_exception(unsigned short code, unsigned int tx) {
    unsigned short sw = 0;

    // Always reset the full state when an error occurs
    if (code != APDU_OK) {
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
    // (check for a potential overflow first)
    if (tx + 2 > sizeof(G_io_apdu_buffer)) {
        tx = 0;
        sw = 0x6983;
    }
    SET_APDU_AT(tx++, sw >> 8);
    SET_APDU_AT(tx++, sw);

    return tx;
}

void hsm_init() {
    // Initialize current operation
    // (0 = no operation being executed)
    curr_cmd = 0;

    // No exit requested
    _hsm_exit_requested = false;

    // Blockchain state initialization
    bc_init_state();
}

bool hsm_exit_requested() {
    return _hsm_exit_requested;
}

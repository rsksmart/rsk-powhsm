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

#include "upgrade.h"
#include "hal/exceptions.h"
#include "hal/log.h"
#include "hal/seed.h"
#include "defs.h"
#include "apdu.h"
#include "hsm.h"

// Operation selectors
typedef enum {
    OP_UPGRADE_START_EXPORT = 0x01,
    OP_UPGRADE_START_IMPORT = 0x02,
    OP_UPGRADE_IDENTIFY_PEER = 0x03,
    OP_UPGRADE_PROCESS_DATA = 0x04,
} op_code_upgrade_t;

// Error codes
typedef enum {
    ERR_UPGRADE_PROTOCOL = 0x6A00,
    ERR_UPGRADE_SPEC = 0x6A01,
    ERR_UPGRADE_AUTH = 0x6A02,
    ERR_UPGRADE_DATA_PROCESSING = 0x6A03,
    ERR_UPGRADE_INTERNAL = 0x6A99,
} err_code_upgrade_t;

// MRENCLAVE size
#define UPGRADE_MRENCLAVE_SIZE HASH_LENGTH

// SGX upgrade spec
typedef struct {
    uint8_t mrenclave_from[UPGRADE_MRENCLAVE_SIZE];
    uint8_t mrenclave_to[UPGRADE_MRENCLAVE_SIZE];
} upgrade_spec_t;

// SGX upgrade operations
typedef enum {
    upgrade_operation_none = 0,
    upgrade_operation_export = 1,
    upgrade_operation_import = 2,
} upgrade_operation_t;

// SGX upgrade SM states
typedef enum {
    upgrade_state_await_spec = 0,
    upgrade_state_await_peer_id = 1,
    upgrade_state_ready_for_xchg = 2,
} upgrade_state_t;

// SGX upgrade context
typedef struct {
    upgrade_operation_t operation;
    upgrade_state_t state;
    upgrade_spec_t spec;
} upgrade_ctx_t;

// SGX upgrade ctx
static upgrade_ctx_t upgrade_ctx;

/*
 * Reset the upgrade context
 */
static void reset_upgrade() {
    explicit_bzero(&upgrade_ctx, sizeof(upgrade_ctx));
}

/*
 * Check that the context for the SGX upgrade
 * matches the expected state and is in a
 * consistent state.
 *
 * Reset the state and throw a protocol error
 * otherwise.
 */
static void check_state(upgrade_state_t expected) {
    // Consistency check
    if (upgrade_ctx.state == upgrade_state_await_spec &&
        upgrade_ctx.operation != upgrade_operation_none) {
        reset_upgrade();
        THROW(ERR_UPGRADE_PROTOCOL);
    } else if (upgrade_ctx.state != upgrade_state_await_spec &&
               upgrade_ctx.operation == upgrade_operation_none) {
        reset_upgrade();
        THROW(ERR_UPGRADE_PROTOCOL);
    }
    // Expectation check
    if (upgrade_ctx.state != expected) {
        reset_upgrade();
        THROW(ERR_UPGRADE_PROTOCOL);
    }
}

// -----------------------------------------------------------------------
// Protocol implementation
// -----------------------------------------------------------------------

void upgrade_init() {
    reset_upgrade();
    LOG("Upgrade module initialized\n");
}

#define DUMMY_PEER_ID "peer-id:"
#define DUMMY_PEER_ID_LEN (sizeof(DUMMY_PEER_ID) - 1)

#define DUMMY_DATA "data_export_result"
#define DUMMY_DATA_LEN (sizeof("data_export_result") - 1)

unsigned int do_upgrade(volatile unsigned int rx) {
    uint8_t* expected_mre = NULL;

    switch (APDU_OP()) {
    case OP_UPGRADE_START_EXPORT:
    case OP_UPGRADE_START_IMPORT:
        check_state(upgrade_state_await_spec);
        if (APDU_OP() == OP_UPGRADE_START_EXPORT) {
            // Exporting requirements
            REQUIRE_ONBOARDED();
            REQUIRE_UNLOCKED();
        } else {
            // Importing requirements
            REQUIRE_NOT_ONBOARDED();
        }
        // We expect a from/to upgrade spec
        if (APDU_DATA_SIZE(rx) != UPGRADE_MRENCLAVE_SIZE * 2) {
            reset_upgrade();
            THROW(ERR_UPGRADE_SPEC);
        }
        memcpy(upgrade_ctx.spec.mrenclave_from,
               APDU_DATA_PTR,
               UPGRADE_MRENCLAVE_SIZE);
        memcpy(upgrade_ctx.spec.mrenclave_to,
               APDU_DATA_PTR + UPGRADE_MRENCLAVE_SIZE,
               UPGRADE_MRENCLAVE_SIZE);
        LOG("Spec received\n");
        LOG_HEX(
            "From:", upgrade_ctx.spec.mrenclave_from, UPGRADE_MRENCLAVE_SIZE);
        LOG_HEX("To:", upgrade_ctx.spec.mrenclave_to, UPGRADE_MRENCLAVE_SIZE);
        upgrade_ctx.state = upgrade_state_await_peer_id;
        upgrade_ctx.operation = APDU_OP() == OP_UPGRADE_START_EXPORT
                                    ? upgrade_operation_export
                                    : upgrade_operation_import;
        LOG("Role: %s\n",
            upgrade_ctx.operation == upgrade_operation_export ? "exporter"
                                                              : "importer");
        return TX_NO_DATA();
    case OP_UPGRADE_IDENTIFY_PEER:
        check_state(upgrade_state_await_peer_id);
        expected_mre = upgrade_ctx.operation == upgrade_operation_export
                           ? upgrade_ctx.spec.mrenclave_to
                           : upgrade_ctx.spec.mrenclave_from;
        if (APDU_DATA_SIZE(rx) != DUMMY_PEER_ID_LEN + UPGRADE_MRENCLAVE_SIZE ||
            memcmp(APDU_DATA_PTR, DUMMY_PEER_ID, DUMMY_PEER_ID_LEN) ||
            memcmp(APDU_DATA_PTR + DUMMY_PEER_ID_LEN,
                   expected_mre,
                   UPGRADE_MRENCLAVE_SIZE)) {
            reset_upgrade();
            THROW(ERR_UPGRADE_AUTH);
        }
        upgrade_ctx.state = upgrade_state_ready_for_xchg;
        return TX_NO_DATA();
    case OP_UPGRADE_PROCESS_DATA:
        check_state(upgrade_state_ready_for_xchg);
        switch (upgrade_ctx.operation) {
        case upgrade_operation_export:
            memcpy(APDU_DATA_PTR, DUMMY_DATA, DUMMY_DATA_LEN);
            LOG("Data export complete\n");
            reset_upgrade();
            return TX_FOR_DATA_SIZE(DUMMY_DATA_LEN);
        case upgrade_operation_import:
            if (APDU_DATA_SIZE(rx) != DUMMY_DATA_LEN) {
                reset_upgrade();
                THROW(ERR_UPGRADE_DATA_PROCESSING);
            }
            LOG("Importing data\n");
            LOG_HEX("From:",
                    upgrade_ctx.spec.mrenclave_from,
                    UPGRADE_MRENCLAVE_SIZE);
            LOG_HEX(
                "To:", upgrade_ctx.spec.mrenclave_to, UPGRADE_MRENCLAVE_SIZE);
            LOG_HEX("Imported data:", APDU_DATA_PTR, APDU_DATA_SIZE(rx));
            reset_upgrade();
            return TX_NO_DATA();
        default:
            // We should never reach this point
            THROW(ERR_UPGRADE_INTERNAL);
        }
    default:
        reset_upgrade();
        THROW(ERR_UPGRADE_PROTOCOL);
        break;
    }
}

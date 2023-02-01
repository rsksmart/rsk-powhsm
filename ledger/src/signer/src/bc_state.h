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

#ifndef __BC_STATE_H
#define __BC_STATE_H

// -----------------------------------------------------------------------
// Non-volatile blockchain state
// -----------------------------------------------------------------------

#include <stdbool.h>
#include <stdint.h>

#include "os.h"

#include "bigdigits.h"
#include "nvm.h"

#include "bc.h"
#include "bc_diff.h"
#include "runtime.h"

typedef struct {
    uint8_t best_block[HASH_SIZE];
    uint8_t newest_valid_block[HASH_SIZE];
    uint8_t ancestor_block[HASH_SIZE];
    uint8_t ancestor_receipt_root[HASH_SIZE];
    uint8_t last_auth_signed_btc_tx_hash[HASH_SIZE];

    uint8_t initialized;
} bc_state_t;

typedef struct {
    uint8_t next_expected_block[HASH_SIZE];
    uint8_t best_block[HASH_SIZE];
    uint8_t newest_valid_block[HASH_SIZE];
    bool in_progress;
    bool already_validated;
    bool found_best_block;
    DIGIT_T total_difficulty[BIGINT_LEN];
} bc_state_updating_t;

typedef struct {
    uint8_t valid;
    bc_state_updating_t data;
} bc_state_updating_backup_t;

extern NON_VOLATILE bc_state_t N_bc_state_var;
#define N_bc_state (*(bc_state_t*)PIC(&N_bc_state_var))

extern NON_VOLATILE bc_state_updating_backup_t N_bc_state_updating_backup_var;
#define N_bc_state_updating_backup \
    (*(bc_state_updating_backup_t*)PIC(&N_bc_state_updating_backup_var))

#ifndef PARAM_INITIAL_BLOCK_HASH
#include "defs.h"
extern uint8_t INITIAL_BLOCK_HASH[HASH_LENGTH];
#endif

// -----------------------------------------------------------------------
// Get/Reset blockchain state protocol
// -----------------------------------------------------------------------

// Operation selectors
typedef enum {
    OP_STATE_GET_HASH = 0x01,
    OP_STATE_GET_DIFF = 0x02,
    OP_STATE_GET_FLAGS = 0x03,

    OP_STATE_RESET_INIT = 0x01,
    OP_STATE_RESET_DONE = 0x02,
} op_code_state_t;

// Hash descriptors
#define BEST_BLOCK 0x01
#define NEWEST_VALID_BLOCK 0x02
#define ANCESTOR_BLOCK 0x03
#define ANCESTOR_RECEIPT_ROOT 0x05
#define U_BEST_BLOCK 0x81
#define U_NEWEST_VALID_BLOCK 0x82
#define U_NEXT_EXPECTED_BLOCK 0x84

/*
 * Initialize blockchain state.
 */
void bc_init_state();

/**
 * Backup the current partial advance blockchain state
 * to NVM
 */
void bc_backup_partial_state();

/*
 * Implement the get blockchain state procotol.
 *
 * @arg[in] rx number of received bytes from the Host
 * @ret        number of transmited bytes to the host
 */
unsigned int bc_get_state(volatile unsigned int rx);

// Actual state reset as a macro, so we can call it from other places
#define RESET_BC_STATE()                                    \
    if (bc_st_updating.in_progress) {                       \
        memset(&bc_st_updating, 0, sizeof(bc_st_updating)); \
    }

/*
 * Implement the reset blockchain state protocol.
 *
 * @arg[in] rx number of received bytes from the Host
 * @ret        number of transmited bytes to the host
 */
unsigned int bc_reset_state(volatile unsigned int rx);

/*
 * Dump initial block hash to the specified APDU buffer data offset.
 *
 * @arg[in] offset APDU buffer data dump offset
 * @ret number of bytes dumped to APDU buffer
 */
uint8_t bc_dump_initial_block_hash(int offset);

#endif // __BC_STATE_H

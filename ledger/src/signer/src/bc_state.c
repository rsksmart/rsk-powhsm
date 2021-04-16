#include <stdbool.h>
#include <string.h>

#include "defs.h"
#include "dbg.h"
#include "nvm.h"

#include "bc_state.h"
#include "bc_err.h"

// -----------------------------------------------------------------------
// Convenience routines to set state boolean flags
// -----------------------------------------------------------------------

static const bool __true = true;
static const bool __false = false;

void set_bc_state_flag(const bool* flag) {
    NVM_WRITE(flag, &__true, sizeof(bool));
}

void clr_bc_state_flag(const bool* flag) {
    NVM_WRITE(flag, &__false, sizeof(bool));
}

// -----------------------------------------------------------------------
// Blockchain state initialization
// -----------------------------------------------------------------------

// Here we take it from an external definition (see Makefile for details)
#ifdef PARAM_INITIAL_BLOCK_HASH
static const uint8_t INITIAL_BLOCK_HASH[] = PARAM_INITIAL_BLOCK_HASH;
#else
#ifdef FEDHM_EMULATOR
// This hash works for the test data (parent hash of
// last block in ledger/src/tests/resources/splits-09.json).
static const uint8_t INITIAL_BLOCK_HASH[] = {
    0x69, 0x87, 0x80, 0x41, 0xd1, 0xb7, 0x8d, 0x61, 0x05, 0x86, 0x2e,
    0xb9, 0xef, 0xa5, 0xe6, 0xda, 0x85, 0x13, 0x30, 0xf2, 0xc0, 0x0f,
    0xb9, 0x2f, 0x3a, 0xb4, 0xa0, 0x4b, 0xbe, 0xa1, 0x33, 0x7c,
};
#endif
#endif

// Non-volatile initialization flag.
// Linker rules are different in emulator and Ledger mode.
// When running in emulator mode we must avoid the const.
#ifdef FEDHM_EMULATOR
static bool N_bc_initialized;
#else
static const bool N_bc_initialized = 0;
#endif

/*
 * Initialize blockchain state.
 */
void bc_init_state() {
    if (!N_bc_initialized) {
        NVM_RESET(&N_bc_state, sizeof(N_bc_state));
        NVM_WRITE(N_bc_state.best_block, INITIAL_BLOCK_HASH, HASH_SIZE);
        NVM_WRITE(N_bc_state.newest_valid_block, INITIAL_BLOCK_HASH, HASH_SIZE);

        bool b = true;
        NVM_WRITE(&N_bc_initialized, &b, sizeof(b));
    }
}

// -----------------------------------------------------------------------
// Blockchain state operations
// -----------------------------------------------------------------------

// Non-volatile blockchain validaton state
const bc_state_t N_bc_state_var;

/*
 * Dump hash corresponding to hash_codes[hash_ix] to APDU.
 * @ret size of data dumped to APDU buffer
 */
uint8_t dump_hash(uint8_t hash_code) {
    const uint8_t* h;
    switch (hash_code) {
    case BEST_BLOCK:
        h = N_bc_state.best_block;
        break;
    case NEWEST_VALID_BLOCK:
        h = N_bc_state.newest_valid_block;
        break;
    case ANCESTOR_BLOCK:
        h = N_bc_state.ancestor_block;
        break;
    case ANCESTOR_RECEIPT_ROOT:
        h = N_bc_state.ancestor_receipt_root;
        break;
    case U_BEST_BLOCK:
        h = N_bc_state.updating.best_block;
        break;
    case U_NEWEST_VALID_BLOCK:
        h = N_bc_state.updating.newest_valid_block;
        break;
    case U_NEXT_EXPECTED_BLOCK:
        h = N_bc_state.updating.next_expected_block;
        break;
    default:
        FAIL(PROT_INVALID);
    }
    APDU_DATA_PTR[0] = hash_code;
    memcpy(APDU_DATA_PTR + 1, h, HASH_SIZE);
    return 1 + HASH_SIZE;
}

/*
 * Dump difficulty to the APDU buffer. This function will copy to the
 * the buffer the bytes comprising the state's cumulative difficulty
 * in big endian order, with no leading zeroes.
 *
 * @ret number of bytes dumped to APDU buffer
 */
uint8_t dump_difficulty() {
    uint8_t buf[sizeof(N_bc_state.updating.total_difficulty)];
    dump_bigint(buf, N_bc_state.updating.total_difficulty, BIGINT_LEN);
    unsigned int start = 0;
    for (; start < sizeof(buf) && buf[start] == 0; start++)
        ;
    memcpy(APDU_DATA_PTR, buf + start, sizeof(buf) - start);
    return sizeof(buf) - start;
}

/*
 * Dump initial block hash to the specified APDU buffer data offset.
 *
 * @arg[in] offset APDU buffer data dump offset
 * @ret number of bytes dumped to APDU buffer
 */
uint8_t bc_dump_initial_block_hash(int offset) {
    memcpy(APDU_DATA_PTR + offset, INITIAL_BLOCK_HASH, sizeof(INITIAL_BLOCK_HASH));
    return sizeof(INITIAL_BLOCK_HASH);
}

/*
 * Dump blockchain state flags to APDU buffer.
 * @ret number of bytes dumped to buffer
 */
uint8_t dump_flags() {
    APDU_DATA_PTR[0] = N_bc_state.updating.in_progress;
    APDU_DATA_PTR[1] = N_bc_state.updating.already_validated;
    APDU_DATA_PTR[2] = N_bc_state.updating.found_best_block;
    return 3;
}

/*
 * Implement the get blockchain state procotol.
 *
 * @arg[in] rx number of received bytes from the Host
 * @ret        number of transmited bytes to the host
 */
unsigned int bc_get_state(volatile unsigned int rx) {
    uint8_t op = APDU_OP();

    uint8_t expected_data_size = op == OP_GET_HASH ? 1 : 0;
    if (APDU_DATA_SIZE(rx) != expected_data_size) {
        FAIL(PROT_INVALID);
    }

    if (op == OP_GET_HASH) {
        return TX_FOR_DATA_SIZE(dump_hash(APDU_DATA_PTR[0]));
    }

    if (op == OP_GET_DIFF) {
        return TX_FOR_DATA_SIZE(dump_difficulty());
    }

    if (op == OP_GET_FLAGS) {
        return TX_FOR_DATA_SIZE(dump_flags());
    }

    FAIL(PROT_INVALID);
}

/*
 * Implement the reset blockchain state protocol.
 *
 * @arg[in] rx number of received bytes from the Host
 * @ret        number of transmited bytes to the host
 */
unsigned int bc_reset_state(volatile unsigned int rx) {
    if (APDU_OP() != OP_RESET_INIT) {
        FAIL(PROT_INVALID);
    }
    if (APDU_DATA_SIZE(rx) != 0) {
        FAIL(PROT_INVALID);
    }
    RESET_BC_STATE();
    SET_APDU_OP(OP_RESET_DONE);
    return TX_NO_DATA();
}

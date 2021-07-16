#ifndef __BC_STATE
#define __BC_STATE

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

typedef struct {
    uint8_t best_block[HASH_SIZE];
    uint8_t newest_valid_block[HASH_SIZE];
    uint8_t ancestor_block[HASH_SIZE];
    uint8_t ancestor_receipt_root[HASH_SIZE];
    struct {
        uint8_t next_expected_block[HASH_SIZE];
        uint8_t best_block[HASH_SIZE];
        uint8_t newest_valid_block[HASH_SIZE];
        bool in_progress;
        bool already_validated;
        bool found_best_block;
        DIGIT_T total_difficulty[BIGINT_LEN];
    } updating;
} bc_state_t;

extern const bc_state_t N_bc_state_var;
#define N_bc_state (*(bc_state_t*)PIC(&N_bc_state_var))

#ifndef PARAM_INITIAL_BLOCK_HASH
#include "defs.h"
extern uint8_t INITIAL_BLOCK_HASH[HASHLEN];
#endif

// #ifdef FEDHM_EMULATOR
// #define N_bc_state N_bc_state_var
// #else
// #endif

// -----------------------------------------------------------------------
// Get/Reset blockchain state protocol
// -----------------------------------------------------------------------

#define INS_GET_STATE 0x20
#define OP_GET_HASH 0x01
#define OP_GET_DIFF 0x02
#define OP_GET_FLAGS 0x03

// Hash descriptors
#define BEST_BLOCK 0x01
#define NEWEST_VALID_BLOCK 0x02
#define ANCESTOR_BLOCK 0x03
#define ANCESTOR_RECEIPT_ROOT 0x05
#define U_BEST_BLOCK 0x81
#define U_NEWEST_VALID_BLOCK 0x82
#define U_NEXT_EXPECTED_BLOCK 0x84

#define INS_RESET_STATE 0x21
#define OP_RESET_INIT 0x01
#define OP_RESET_DONE 0x02

/*
 * Convenience macros to set state boolean flags
 */
void set_bc_state_flag(const bool* flag);

/*
 * Initialize blockchain state.
 */
void bc_init_state();

/*
 * Implement the get blockchain state procotol.
 *
 * @arg[in] rx number of received bytes from the Host
 * @ret        number of transmited bytes to the host
 */
unsigned int bc_get_state(volatile unsigned int rx);

// Actual state reset as a macro, so we can call it from other places
#define RESET_BC_STATE() \
    NVM_RESET(&N_bc_state.updating, sizeof(N_bc_state.updating))

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

#endif

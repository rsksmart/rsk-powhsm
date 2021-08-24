#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "defs.h"
#include "nvm.h"

#include "bc_state.h"
#include "bc_state_host.h"
#include "bc_diff.h"

static void dump_hash(const uint8_t* header, const uint8_t* buf);

#define HASH_SIZE 32

const uint8_t hash_codes[] = {
    BEST_BLOCK,
    NEWEST_VALID_BLOCK,
    ANCESTOR_BLOCK,
    ANCESTOR_RECEIPT_ROOT,
    U_BEST_BLOCK,
    U_NEWEST_VALID_BLOCK,
    U_NEXT_EXPECTED_BLOCK,
};

static uint8_t hash_code_ix = 0;

/*
 * Emulate a host interacting with a ledger via the
 * get blockchain state protocol.
 *
 * @arg[in] tx number of transmitted bytes
 * @ret number of bytes written to APDU buffer
 */
uint16_t bc_get_state_host(uint8_t tx) {
    SET_APDU_CLA(CLA);
    SET_APDU_CMD(INS_GET_STATE);

    uint8_t op = APDU_OP();

    if (op == OP_GET_IDLE) {
        hash_code_ix = 0;
        SET_APDU_OP(OP_GET_HASH);
        APDU_DATA_PTR[0] = hash_codes[hash_code_ix];
        return TX_FOR_DATA_SIZE(1);
    }

    if (op == OP_GET_HASH) {
        if (APDU_DATA_PTR[0] != hash_codes[hash_code_ix]) {
            fprintf(stderr, "Invalid hash received\n");
            THROW(0x6a00);
        }

        fprintf(stderr, "Hash code = %u", APDU_DATA_PTR[0]);
        dump_hash("", APDU_DATA_PTR + 1);

        ++hash_code_ix;
        if (hash_code_ix < sizeof(hash_codes)) {
            APDU_DATA_PTR[0] = hash_codes[hash_code_ix];
            return TX_FOR_DATA_SIZE(1);
        } else {
            SET_APDU_OP(OP_GET_DIFF);
            return TX_NO_DATA();
        }
    }

    if (op == OP_GET_DIFF) {
        fprintf(stderr, "Diff: bytes = %u\n", tx - DATA);
        for (unsigned int i = 0; i < tx - DATA; i++) {
            fprintf(stderr, "%02x", APDU_DATA_PTR[i]);
        }
        fputc('\n', stderr);
        SET_APDU_OP(OP_GET_FLAGS);
        return TX_NO_DATA();
    }

    if (op == OP_GET_FLAGS) {
        fprintf(stderr,
                "Got flags: %u - %u - %u\n",
                APDU_DATA_PTR[0],
                APDU_DATA_PTR[1],
                APDU_DATA_PTR[2]);
        THROW(0x9000);
    }

    return 0;
}

/*
 * Emulate a host interacting with a ledger via the
 * reset blockchain state protocol.
 *
 * @arg[in] tx number of transmitted bytes
 * @ret number of bytes written to APDU buffer
 */
uint16_t bc_reset_state_host(uint8_t tx) {
    SET_APDU_CLA(CLA);
    SET_APDU_CMD(INS_RESET_STATE);

    uint8_t op = APDU_OP();

    if (op == OP_RESET_IDLE) {
        SET_APDU_OP(OP_RESET_INIT);
        return TX_NO_DATA();
    }

    if (op == OP_RESET_DONE) {
        fprintf(stderr, "Blockchain state reset:\n");
        dump_bc_state();
        THROW(0x9000);
    }

    return 0;
}

static void dump_hash(const uint8_t* header, const uint8_t* buf) {
    fprintf(stderr, "%s: ", header);
    for (unsigned int i = 0; i < HASH_SIZE; i++) {
        fprintf(stderr, "%02x", buf[i]);
    }
    fputc('\n', stderr);
}

void dump_bc_state() {
    dump_hash("Best block", N_bc_state.best_block);
    dump_hash("Newest valid block", N_bc_state.newest_valid_block);
    dump_hash("Ancestor block", N_bc_state.ancestor_block);
    dump_hash("Ancestor receipt root", N_bc_state.ancestor_receipt_root);

    fprintf(stderr, "  In progress: %u\n", N_bc_state.updating.in_progress);
    fprintf(stderr,
            "  Already validated: %u\n",
            N_bc_state.updating.already_validated);
    fprintf(stderr,
            "  Found best block: %u\n",
            N_bc_state.updating.found_best_block);

    fprintf(stderr, "  Total difficulty: ");
    uint8_t buf[sizeof(N_bc_state.updating.total_difficulty)];
    dump_bigint(buf, N_bc_state.updating.total_difficulty, BIGINT_LEN);
    bool dump_digit = false;
    for (unsigned int i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0) {
            dump_digit = true;
        }
        if (dump_digit) {
            fprintf(stderr, "%02x", buf[i]);
        }
    }
    fputc('\n', stderr);

    dump_hash("  Updating -> Best block", N_bc_state.updating.best_block);
    dump_hash("  Updating -> Next expected block",
              N_bc_state.updating.next_expected_block);
    dump_hash("  Updating -> Newest valid block",
              N_bc_state.updating.newest_valid_block);
}
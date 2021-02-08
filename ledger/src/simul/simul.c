/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   Main simulator source file
 ********************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "mem.h"

// Simulation of cx_hash()
#include "sha256.h"

// local definitions
#include "defs.h"

// BTC TX-parsing code
#include "txparser.h"

// Trie MP parsing code
#include "merkleProof.h"

// rlp-parsing code
#include "rlp.h"

// Path auth definitions
#include "pathAuth.h"

// usb emulation code
#include "usb.h"

#include "bc_state.h"
#include "bc_advance.h"
#include "bc_ancestor.h"
#include "bc_adv_upd_host.h"
#include "bc_single_block.h"

// Hardcoded check values
#include "contractValues.h"

// Constants
#include "const.h"

// Missing 'main.c' definitions (these should be moved elsewhere)
unsigned int path[5];

const char ARG_SIGN[] = "--sign";
const char ARG_ADVANCE[] = "--adv";
const char ARG_UPD_ANCESTOR[] = "--upd";
const char ARG_GET_STATE[] = "--get";
const char ARG_RESET_STATE[] = "--reset";
const char ARG_FUZZ[] = "--fuzz";
const char ARG_SINGLE_BLOCK[] = "--block";

// Activate fuzzer
bool fuzzer = false;
int SEED = 0;

// Receipt keccak256 hash
unsigned char ReceiptHashBuf[HASHLEN];
// Receipts trie root (from block headers)
unsigned char ReceiptsRootBuf[HASHLEN];

// Which advance host to use
int advance_host;

static void setup_bc_adv_upd(int num_splits, char* arg) {
    if (strcmp(ARG_ADVANCE, arg) == 0) {
        setup_bc_advance_host(num_splits, false);
    } else {
        setup_bc_advance_host(num_splits, true);
    }
    SET_APDU_CMD(INS_ADVANCE);
    SET_APDU_OP(OP_ADVANCE_IDLE);
}

void main(int argc, char** argv) {
    // Initialize blockchain state
    bc_init_state();

    // State machine=parsing header
    PARSE_STM state = S_CMD_START;

    int rx = 0;
    int tx = 1;

    SET_APDU_CLA(CLA);

    // Parse options
    printf("[I] Usage: %s <--sign|--pow> [--fuzz N]\n", argv[0]);
    printf("[I] Context sizes: (rlp_ctx: %lu tx_ctx: %lu) mp_ctx: %lu\n",
           sizeof(rlp_ctx),
           sizeof(tx_ctx),
           sizeof(MP_CTX));

    // Activate fuzzing
    if (argc > 1)
        for (int i = 1; i < argc; i++)
            if (strcmp(argv[i], ARG_FUZZ) == 0) {
                fuzzer = true;
                SEED = atoi(argv[i + 1]);
                printf("[F] Activating built-in fuzzer\n");
            }
    // Parse mode
    if (argc == 1 || strcmp(argv[1], ARG_SIGN) == 0) {
        SET_APDU_CMD(INS_SIGN);
        SET_APDU_OP(P1_PATH);
    } else if (strcmp(argv[1], ARG_ADVANCE) == 0 ||
               strcmp(argv[1], ARG_UPD_ANCESTOR) == 0) {
        int i = 1;
        if (argc == 3) {
            i = atoi(argv[2]);
        }
        advance_host = ADV_UPD_HOST;
        setup_bc_adv_upd(i, argv[1]);
    } else if (strcmp(argv[1], ARG_SINGLE_BLOCK) == 0 && argc == 3) {
        advance_host = SINGLE_BLOCK_HOST;
        setup_bc_single_block(argv[2]);
    } else if (strcmp(argv[1], ARG_GET_STATE) == 0) {
        SET_APDU_CMD(INS_GET_STATE);
        SET_APDU_OP(OP_GET_IDLE);
    } else if (strcmp(argv[1], ARG_RESET_STATE) == 0) {
        SET_APDU_CMD(INS_RESET_STATE);
        SET_APDU_OP(OP_RESET_IDLE);
    } else {
        fprintf(stderr, "Invalid action: %s\n", argv[1]);
        exit(1);
    }

    if (fuzzer) {
        fprintf(stderr, "[I] Fuzzer: using seed %i\n", SEED);
        srandom(SEED);
    }

    while (true) {
        rx = io_exchange(0, tx);
        if (fuzzer) {
            // Do mutations
            int mutPos = random() % rx;
            int mutType = random() % 100;
            switch (mutType) {
            case 0:
                G_io_apdu_buffer[mutPos]++;
                break;
            case 1:
                G_io_apdu_buffer[mutPos]--;
                break;
            case 2:
                G_io_apdu_buffer[mutPos] = 0;
                break;
            case 3:
                G_io_apdu_buffer[mutPos] = 0xff;
                break;
            case 4:
                G_io_apdu_buffer[mutPos] = random() % 255;
                break;
            }
        }

        if (G_io_apdu_buffer[OP] == P1_SUCCESS) {
            if (fuzzer) {
                // Reset transfer
                G_io_apdu_buffer[0] = CLA;
                G_io_apdu_buffer[1] = INS_SIGN;
                G_io_apdu_buffer[OP] = P1_PATH; // REQUEST PATH to host
                rx = 0;
                tx = 1;
                state = S_CMD_START;
                memset(&rlp_ctx, 0, sizeof(rlp_ctx));
                memset(&tx_ctx, 0, sizeof(tx_ctx));
                resetTransfer();
                continue;
            } else
                exit(0);
        }
        if (rx == 0) {
            THROW(0x6982);
        }
        if (APDU_CLA() != CLA) {
            THROW(0x6E11);
        }
        switch (G_io_apdu_buffer[1]) {
#include "hsmCommands.h"
        case INS_GET_STATE:
            tx = bc_get_state(rx);
            break;
        case INS_RESET_STATE:
            tx = bc_reset_state(rx);
            break;
        case INS_ADVANCE:
            tx = bc_advance(rx);
            break;
        case INS_UPD_ANCESTOR:
            tx = bc_upd_ancestor(rx);
            break;
        }
    }
}

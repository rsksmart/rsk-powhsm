#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "defs.h"
#include "usb.h"

#include "bc_util.h"
#include "bc_state.h"
#include "bc_advance.h"
#include "bc_single_block.h"
#include "bc_state_host.h"
#include "hex_reader.h"

// Constants
#include "const.h"

static FILE* block_stream = NULL;

static bool upd_init = false;

/*
 * Setup single block validation host.
 *
 * @arg[in] block_file file that contains the block information
 */
void setup_bc_single_block(char* block_file) {
    block_stream = fopen(block_file, "r");

    printf("Processing block file: %s\n", block_file);

    SET_APDU_CMD(INS_ADVANCE);
    SET_APDU_OP(OP_ADVANCE_IDLE);
}

/*
 * Emulate a host interacting w/a ledger via the advance blockchain protocol
 * sending a single block.
 *
 * @ret number of bytes written to APDU buffer
 */
uint16_t bc_single_block() {
    SET_APDU_CLA(CLA);
    SET_APDU_CMD(INS_ADVANCE);

    uint8_t op = APDU_OP();

    if (op == OP_ADVANCE_IDLE) {
        // Dump the blockchain state before starting
        printf("Blockchain state - Start\n");
        dump_bc_state();

        SET_APDU_OP(OP_ADVANCE_INIT);
        dump_bigendian(APDU_DATA_PTR, sizeof(uint32_t), 1 /*always one block*/);
        return TX_FOR_DATA_SIZE(sizeof(uint32_t));
    }

    if (op == OP_ADVANCE_HEADER_META) {
        // First two bytes (4 hex chars) of the block file should be
        // the merge mining rlp payload length in big endian

        // Following byte is meant as a human-readable separator, should be skipped

        // Following 32 bytes (64 hex chars) of the block file should be
        // the coinbase transaction hash

        // Following byte is meant as a human-readable separator, should be skipped
        read_hex(block_stream, APDU_DATA_PTR, 2);
        fseek(block_stream, 1, SEEK_CUR);
        read_hex(block_stream, APDU_DATA_PTR + 2, 32);
        fseek(block_stream, 1, SEEK_CUR);
        SET_APDU_OP(OP_ADVANCE_HEADER_META);
        return TX_FOR_DATA_SIZE(34);
    }

    if (op == OP_ADVANCE_HEADER_CHUNK) {
        uint8_t requested = APDU_TXLEN();
        size_t read = read_hex(block_stream, APDU_DATA_PTR, requested);
        return TX_FOR_DATA_SIZE(read);
    }

    if (op == OP_ADVANCE_PARTIAL || op == OP_ADVANCE_SUCCESS) {
        // Dump the blockchain state at the end
        printf("Success processing block - result: %s\n", (op == OP_ADVANCE_PARTIAL ? "PARTIAL" : "FULL"));
        printf("Blockchain state - End\n");
        dump_bc_state();
        THROW(0x9000);
    }

    return 0;
}

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "defs.h"
#include "usb.h"

#include "bc_state.h"
#include "bc_advance.h"
#include "bc_ancestor.h"
#include "bc_adv_upd_host.h"
#include "bc_state_host.h"

typedef struct {
    char* split_file_name;
    uint32_t num_blocks;
    uint16_t* block_offsets;
    uint16_t* mm_rlp_sizes;
} split_meta_t;

static uint16_t block_offsets[][11] = {
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 1046, 2184, 3200, 4223, 5318, 6406, 7398, 8557, 9629, 10669},
    {0, 1168, 2248, 3415, 4574, 5698, 6868, 8036, 9123, 10290, 0},
    {0, 1168, 2246, 3324, 4483, 5642, 6775, 7855, 9014, 10182, 0},
    {0, 1080, 2248, 3372, 4460, 5627, 6707, 7874, 9033, 10166, 0},
    {0, 1133, 2211, 3379, 4538, 5706, 6874, 8042, 9130, 10263, 0},
    {0, 1166, 2313, 3455, 4622, 5780, 6857, 8012, 9182, 10324, 0},
    {0, 1157, 2315, 3394, 4552, 5719, 6877, 8035, 9190, 10360, 0},
    {0, 1167, 2325, 3483, 4606, 5764, 6931, 8089, 9255, 10378, 0},
    {0, 1138, 2226, 3357, 4515, 5594, 6761, 7920, 9089, 10247, 0},
    {0, 1158, 2281, 3448, 4606, 5744, 6902, 7979, 9111, 10199, 0},
};

static uint16_t mm_rlp_sizes[][11] = {
    {482, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {496, 505, 496, 505, 496, 506, 504, 504, 505, 505, 504},
    {505, 496, 504, 496, 496, 505, 505, 505, 504, 496, 0},
    {505, 496, 496, 496, 496, 505, 496, 496, 505, 505, 0},
    {496, 505, 496, 504, 504, 496, 504, 496, 505, 497, 0},
    {505, 496, 505, 496, 505, 505, 505, 504, 505, 505, 0},
    {503, 505, 496, 504, 495, 495, 495, 504, 496, 504, 0},
    {495, 495, 495, 495, 504, 495, 495, 495, 504, 495, 0},
    {504, 495, 495, 495, 495, 504, 495, 503, 495, 504, 0},
    {496, 504, 503, 495, 495, 504, 495, 504, 495, 504, 0},
    {495, 495, 504, 495, 496, 495, 495, 504, 504, 495, 0},
};

static split_meta_t splits[] = {
    {"resources/single-block-regtest.rlp",
     1,
     block_offsets[0],
     mm_rlp_sizes[0]},
    {"resources/split-00.rlp", 11, block_offsets[1], mm_rlp_sizes[1]},
    {"resources/split-01.rlp", 10, block_offsets[2], mm_rlp_sizes[2]},
    {"resources/split-02.rlp", 10, block_offsets[3], mm_rlp_sizes[3]},
    {"resources/split-03.rlp", 10, block_offsets[4], mm_rlp_sizes[4]},
    {"resources/split-04.rlp", 10, block_offsets[5], mm_rlp_sizes[5]},
    {"resources/split-05.rlp", 10, block_offsets[6], mm_rlp_sizes[6]},
    {"resources/split-06.rlp", 10, block_offsets[7], mm_rlp_sizes[7]},
    {"resources/split-07.rlp", 10, block_offsets[8], mm_rlp_sizes[8]},
    {"resources/split-08.rlp", 10, block_offsets[9], mm_rlp_sizes[9]},
    {"resources/split-09.rlp", 10, block_offsets[10], mm_rlp_sizes[10]},
};

static uint32_t split_index = 0;
static uint32_t split_limit = 0;
static uint32_t block_index = 0;
static FILE* split_stream = NULL;

static bool upd_ancestor = false;
static bool upd_init = false;
static uint32_t upd_split_index = 0;
static uint32_t upd_block_index = 0;

/*
 * Setup blockchain advance protocol host.
 *
 * @arg[in] num_splits number of block splits to process
 * @arg[in] should_upd_ancestor whether to update ancestor after advancing
 */
void setup_bc_advance_host(int num_splits, bool should_upd_ancestor) {
    if (num_splits == 0) {
        printf("No splits to process, leaving\n");
        THROW(0x9000);
    }

    block_index = 0;
    if (num_splits == -1) {
        // Only process the first split
        split_index = 0;
        split_limit = 1;
    } else {
        // Process n splits
        split_limit = sizeof(splits) / sizeof(split_meta_t);
        split_index = split_limit - num_splits;
    }
    split_stream = fopen(splits[split_index].split_file_name, "rb");
    upd_ancestor = should_upd_ancestor;

    printf("Processing split file: %s\n", splits[split_index].split_file_name);
}

static void dump_bigendian(uint8_t* buffer, size_t bytes, uint64_t n) {
    for (int i = 0; i < bytes; i++) {
        buffer[bytes - i - 1] = (uint8_t)(n & 0xff);
        n >>= 8;
    }
}

// Check if we found the best block
static void check_best_block_found() {
    if (N_bc_state.updating.found_best_block && !upd_init) {
        upd_init = true;
        upd_split_index = split_index;
        upd_block_index = block_index - 1;

        printf("**** Best block found at split = %u, block index = %u\n",
               upd_split_index,
               upd_block_index);
    }
}

/*
 * Emulate a host interacting w/ a ledger via the advance blockchain protocol.
 *
 * @ret number of bytes written to APDU buffer
 */
uint16_t bc_advance_host() {
    split_meta_t curr_split = splits[split_index];

    SET_APDU_CLA(CLA);
    SET_APDU_CMD(INS_ADVANCE);

    uint8_t op = APDU_OP();

    if (op == OP_ADVANCE_IDLE) {
        SET_APDU_OP(OP_ADVANCE_INIT);
        dump_bigendian(APDU_DATA_PTR, sizeof(uint32_t), curr_split.num_blocks);
        return TX_FOR_DATA_SIZE(sizeof(uint32_t));
    }

    if (op == OP_ADVANCE_HEADER_META) {
        check_best_block_found();
        fseek(split_stream, curr_split.block_offsets[block_index], SEEK_SET);
        SET_APDU_OP(OP_ADVANCE_HEADER_META);
        dump_bigendian(APDU_DATA_PTR,
                       sizeof(uint16_t),
                       curr_split.mm_rlp_sizes[block_index++]);
        return TX_FOR_DATA_SIZE(sizeof(uint16_t));
    }

    if (op == OP_ADVANCE_HEADER_CHUNK) {
        check_best_block_found();
        uint8_t requested = APDU_TXLEN();
        size_t read = fread(APDU_DATA_PTR, 1, requested, split_stream);
        return TX_FOR_DATA_SIZE(read);
    }

    if (op == OP_ADVANCE_PARTIAL) {
        check_best_block_found();
        printf("Partial success - state:\n");
        dump_bc_state();

        split_index++;
        if (split_index == split_limit) {
            printf("No more splits, leaving with partial success\n");
            THROW(0x9000);
        }

        block_index = 0;
        curr_split = splits[split_index];
        fclose(split_stream);
        split_stream = fopen(curr_split.split_file_name, "rb");
        printf("Processing split file: %s\n", curr_split.split_file_name);

        SET_APDU_OP(OP_ADVANCE_INIT);
        dump_bigendian(APDU_DATA_PTR, sizeof(uint32_t), curr_split.num_blocks);
        return TX_FOR_DATA_SIZE(sizeof(uint32_t));
    }

    if (op == OP_ADVANCE_SUCCESS) {
        check_best_block_found();
        printf("Successfully advanced blockchain - state:\n");
        dump_bc_state();

        if (upd_ancestor) {
            SET_APDU_CMD(INS_UPD_ANCESTOR);
            SET_APDU_OP(OP_UPD_ANCESTOR_IDLE);
            return bc_upd_ancestor_host();
        } else {
            THROW(0x9000);
        }
    }

    return 0;
}

/*
 * Emulate a host interacting w/ a ledger via the update ancestor protocol.
 *
 * @ret number of bytes written to APDU buffer
 */
uint16_t bc_upd_ancestor_host() {
    split_meta_t split = splits[upd_split_index];

    SET_APDU_CLA(CLA);
    SET_APDU_CMD(INS_UPD_ANCESTOR);

    uint8_t op = APDU_OP();

    if (op == OP_UPD_ANCESTOR_IDLE) {
        if (split.num_blocks - upd_block_index < 1) {
            printf("No blocks in split, aborting\n");
            THROW(0x9000);
        }

        putchar('\n');
        printf("**** Updating ancestor\n");
        printf("**** Starting split index = %u\n", upd_split_index);
        printf("**** Starting block index = %u\n", upd_block_index);
        putchar('\n');

        split_stream = fopen(split.split_file_name, "rb");

        SET_APDU_OP(OP_UPD_ANCESTOR_INIT);
        dump_bigendian(APDU_DATA_PTR,
                       sizeof(uint32_t),
                       split.num_blocks - upd_block_index);
        return TX_FOR_DATA_SIZE(sizeof(uint32_t));
    }

    if (op == OP_UPD_ANCESTOR_HEADER_META) {
        fseek(split_stream, split.block_offsets[upd_block_index], SEEK_SET);
        SET_APDU_OP(OP_UPD_ANCESTOR_HEADER_META);
        dump_bigendian(APDU_DATA_PTR,
                       sizeof(uint16_t),
                       split.mm_rlp_sizes[upd_block_index++]);
        return TX_FOR_DATA_SIZE(sizeof(uint16_t));
    }

    if (op == OP_UPD_ANCESTOR_HEADER_CHUNK) {
        uint8_t requested = APDU_TXLEN();
        size_t read = fread(APDU_DATA_PTR, 1, requested, split_stream);
        return TX_FOR_DATA_SIZE(read);
    }

    if (op == OP_UPD_ANCESTOR_SUCCESS) {
        printf("Successfully updated ancestor - state:\n");
        dump_bc_state();
        THROW(0x9000);
    }

    return 0;
}

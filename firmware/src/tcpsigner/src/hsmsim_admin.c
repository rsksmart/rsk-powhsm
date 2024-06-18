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

#include "hal/seed.h"
#include "hal/log.h"
#include "hsmsim_admin.h"
#include "apdu.h"
#include "bc_state.h"
#include "ints.h"

static hsmsim_admin_data_t hsmsim_admin_data;

void hsmsim_admin_init() {
    memset(&hsmsim_admin_data, 0, sizeof(hsmsim_admin_data));
    LOG("ADMIN: Init OK.\n");
}

bool hsmsim_admin_need_process(unsigned int rx) {
    return APDU_CLA() == HSMSIM_ADMIN_CLA;
}

static unsigned int hsmsim_admin_error(uint16_t code) {
    unsigned int tx = 0;
    SET_APDU_AT(tx++, HSMSIM_ADMIN_CLA);
    SET_APDU_AT(tx++, code >> 8);
    SET_APDU_AT(tx++, code);
    return tx;
}

static unsigned int hsmsim_admin_ok(unsigned int tx) {
    if ((tx + 2 * APDU_ELEMENT_SIZE) > APDU_TOTAL_SIZE) {
        LOG("ADMIN: Buffer overflow on I/O when trying to reply "
            "to the host.\n");
        return hsmsim_admin_error(HSMSIM_ADMIN_ERROR_BUFFER_OVERFLOW);
    }

    SET_APDU_AT(tx++, 0x90);
    SET_APDU_AT(tx++, 0x00);
    return tx;
}

unsigned int hsmsim_admin_process_apdu(unsigned int rx) {
    unsigned int tx;
    unsigned int offset;
    nvmmem_stats_t nvmmem_stats;

    if (APDU_CLA() != HSMSIM_ADMIN_CLA) {
        LOG("ADMIN: Invalid CLA: %d.\n", APDU_CLA());
        return hsmsim_admin_error(HSMSIM_ADMIN_ERROR_INVALID_PROTOCOL);
    }

    if (rx < MIN_ADMIN_BYTES) {
        LOG("ADMIN: Too few bytes in operation: %d.\n", rx);
        return hsmsim_admin_error(HSMSIM_ADMIN_ERROR_INVALID_PROTOCOL);
    }

    switch (APDU_CMD()) {
    case HSMSIM_ADMIN_CMD_SET_ANCESTOR_RCPT_ROOT:
        if (APDU_DATA_SIZE(rx) != HASH_LENGTH) {
            LOG("ADMIN: Invalid ancestor receipts root size. Expected %d "
                "bytes, got %d.\n",
                HASH_LENGTH,
                APDU_DATA_SIZE(rx));
            return hsmsim_admin_error(HSMSIM_ADMIN_ERROR_DATA_SIZE);
        }
        memcpy(hsmsim_admin_data.old_ancestor_receipts_root,
               N_bc_state.ancestor_receipt_root,
               HASH_LENGTH);
        memcpy(N_bc_state.ancestor_receipt_root, APDU_DATA_PTR, HASH_LENGTH);
        hsmsim_admin_data.ancestor_receipts_root_set = true;
        LOG_HEX("ADMIN: Ancestor receipts root set to",
                N_bc_state.ancestor_receipt_root,
                HASH_LENGTH);
        tx = TX_FOR_DATA_SIZE(0);
        break;
    case HSMSIM_ADMIN_CMD_RESET_ANCESTOR_RCPT_ROOT:
        if (!hsmsim_admin_data.ancestor_receipts_root_set) {
            LOG("ADMIN: Cannot reset ancestor receipts root: not set.\n");
            return hsmsim_admin_error(HSMSIM_ADMIN_ERROR_INVALID_STATE);
        }
        memcpy(N_bc_state.ancestor_receipt_root,
               hsmsim_admin_data.old_ancestor_receipts_root,
               HASH_LENGTH);
        hsmsim_admin_data.ancestor_receipts_root_set = false;
        LOG_HEX("ADMIN: Ancestor receipts root reset to",
                N_bc_state.ancestor_receipt_root,
                HASH_LENGTH);
        tx = TX_FOR_DATA_SIZE(0);
        break;
    case HSMSIM_ADMIN_CMD_RESET_NVM_STATS:
        nvmem_stats_reset();
        tx = TX_FOR_DATA_SIZE(0);
        break;
    case HSMSIM_ADMIN_CMD_GET_NVM_STATS:
        offset = 0;
        nvmmem_stats = nvmem_get_stats();
        APDU_DATA_PTR[offset++] =
            (unsigned char)sizeof(nvmmem_stats.write_count);
        VAR_BIGENDIAN_TO(APDU_DATA_PTR + offset,
                         nvmmem_stats.write_count,
                         sizeof(nvmmem_stats.write_count));
        offset += sizeof(nvmmem_stats.write_count);
        tx = TX_FOR_DATA_SIZE(offset);
        LOG("ADMIN: got NVM stats - %u writes.\n", nvmmem_stats.write_count);
        break;
    case HSMSIM_ADMIN_CMD_GET_IS_ONBOARDED:
        APDU_DATA_PTR[0] = (unsigned char)seed_available();
        tx = TX_FOR_DATA_SIZE(1);
        LOG("ADMIN: got is_onboarded status.\n");
        break;
    case HSMSIM_ADMIN_CMD_SET_IS_ONBOARDED:
        if (APDU_DATA_SIZE(rx) != 1) {
            LOG("ADMIN: Invalid is_onboarded value size. Expected 1 "
                "byte, got %d.\n",
                APDU_DATA_SIZE(rx));
            return hsmsim_admin_error(HSMSIM_ADMIN_ERROR_DATA_SIZE);
        }
        seed_set_is_onboarded((bool)APDU_DATA_PTR[0]);
        LOG("ADMIN: is_onboarded set to %d.\n",
            (unsigned char)seed_available());
        tx = TX_FOR_DATA_SIZE(0);
        break;
    default:
        LOG("ADMIN: Invalid CMD: %d.\n", APDU_CMD());
        return hsmsim_admin_error(HSMSIM_ADMIN_ERROR_INVALID_PROTOCOL);
    }

    return hsmsim_admin_ok(tx);
}

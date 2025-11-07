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

#ifndef __TRUSTED_META_BC_H
#define __TRUSTED_META_BC_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "meta_bc.h"

#include "hal/exceptions.h"
#include "hal/log.h"

#include "apdu.h"
#include "instructions.h"
#include "err.h"

#include "bc_advance.h"
#include "bc_ancestor.h"
#include "bc_err.h"

#define MAX_CHUNK_SIZE 80
#define CHUNK_OVERHEAD 5

unsigned int do_meta_advupd(unsigned int rx) {
    uint8_t cmd;
    uint8_t internal_buffer[MAX_CHUNK_SIZE + CHUNK_OVERHEAD];
    uint8_t* old_buffer;
    size_t old_buffer_size;

    cmd = APDU_CMD();

    // Backup message buffer spec
    old_buffer = communication_get_msg_buffer();
    old_buffer_size = communication_get_msg_buffer_size();

    // Set new buffer
    communication_set_msg_buffer(internal_buffer, sizeof(internal_buffer));

    // Send data in chunks
    unsigned int total_data = APDU_DATA_SIZE(rx);
    unsigned int data_offset = 0;
    unsigned int chunk_size =
        total_data < MAX_CHUNK_SIZE ? total_data : MAX_CHUNK_SIZE;
    unsigned int irx = 0;

    BEGIN_TRY {
        TRY {
            // Initialize internal buffer for soundness
            memcpy(internal_buffer, old_buffer, rx < DATA ? rx : DATA);
            if (rx < DATA)
                SET_APDU_OP(0);

            while (data_offset < total_data) {
                SET_APDU_CLA();
                SET_APDU_CMD(cmd);
                SET_APDU_OP(old_buffer[OP]);
                if (chunk_size > APDU_TOTAL_DATA_SIZE) {
                    // This shouldn't happen
                    THROW(ERR_INTERNAL);
                }
                if (chunk_size > total_data - data_offset) {
                    // Not enough data
                    THROW(PROT_INVALID);
                }
                memcpy(
                    APDU_DATA_PTR, &old_buffer[DATA + data_offset], chunk_size);
                irx = TX_FOR_DATA_SIZE(chunk_size);
                LOG_HEX("ITX >", internal_buffer, irx);
                switch (cmd) {
                case INS_ADVANCE:
                    irx = bc_advance(irx);
                    break;
                case INS_UPD_ANCESTOR:
                    irx = bc_upd_ancestor(irx);
                    break;
                default:
                    // We should never reach this point
                    THROW(ERR_INTERNAL);
                }
                LOG_HEX("ITX <", internal_buffer, irx);
                // Validate response
                if (irx != TX_FOR_TXLEN() && irx != TX_NO_DATA()) {
                    LOG("Unexpected response size\n");
                    THROW(ERR_INTERNAL);
                }
                if (APDU_CLA() != CLA || APDU_CMD() != cmd) {
                    LOG("Unexpected response command\n");
                    THROW(ERR_INTERNAL);
                }
                // Done?
                if (APDU_OP() != old_buffer[OP]) {
                    break;
                }
                data_offset += chunk_size;
                chunk_size = APDU_TXLEN();
            }

            // Restore message buffer
            communication_set_msg_buffer(old_buffer, old_buffer_size);

            // Response
            SET_APDU_OP(internal_buffer[OP]);
            if (irx == TX_FOR_DATA_SIZE(1)) {
                SET_APDU_TXLEN(internal_buffer[DATA]);
                return TX_FOR_TXLEN();
            } else {
                return TX_NO_DATA();
            }
        }
        CATCH_OTHER(e) {
            // Restore message buffer
            communication_set_msg_buffer(old_buffer, old_buffer_size);
            // Forward
            THROW(e);
        }
        FINALLY {
        }
    }
    END_TRY;
}

#endif // __TRUSTED_META_BC_H

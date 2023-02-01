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

#ifndef __HSMSIM_ADMIN_H
#define __HSMSIM_ADMIN_H

#include <stdbool.h>
#include <stdint.h>

#include "constants.h"

// Admin APDU constants
#define MIN_ADMIN_BYTES 2
#define HSMSIM_ADMIN_CLA 0x99

#define HSMSIM_ADMIN_CMD_SET_ANCESTOR_RCPT_ROOT 0x01
#define HSMSIM_ADMIN_CMD_RESET_ANCESTOR_RCPT_ROOT 0x02
#define HSMSIM_ADMIN_CMD_RESET_NVM_STATS 0x03
#define HSMSIM_ADMIN_CMD_GET_NVM_STATS 0x04
#define HSMSIM_ADMIN_CMD_GET_IS_ONBOARDED 0x05
#define HSMSIM_ADMIN_CMD_SET_IS_ONBOARDED 0x06

#define HSMSIM_ADMIN_ERROR_INVALID_PROTOCOL 0x6f00
#define HSMSIM_ADMIN_ERROR_DATA_SIZE 0x6f01
#define HSMSIM_ADMIN_ERROR_INVALID_STATE 0x6f02
#define HSMSIM_ADMIN_ERROR_BUFFER_OVERFLOW 0x6f03

// Misc constants
#define HSMSIM_ADMIN_DEFAULT_IS_ONBOARDED (true)

#define HSMSIM_ADMIN_IS_ONBOARDED_YES (1)
#define HSMSIM_ADMIN_IS_ONBOARDED_NO (0)

#define HSMSIM_RETRIES (3)

typedef struct hsmsim_admin_nvm_info_s {
    unsigned int write_count;
} hsmsim_admin_nvm_info_t;

typedef struct hsmsim_admin_data_s {
    bool ancestor_receipts_root_set;
    uint8_t old_ancestor_receipts_root[HASH_LENGTH];

    hsmsim_admin_nvm_info_t nvm_stats;

    bool is_onboarded;
} hsmsim_admin_data_t;

void hsmsim_admin_init();

bool hsmsim_admin_need_process(unsigned int rx);

unsigned int hsmsim_admin_process_apdu(unsigned int rx);

void hsmsim_admin_nvm_record_write();

unsigned int hsmsim_admin_get_is_onboarded();

#endif // __HSMSIM_ADMIN_H

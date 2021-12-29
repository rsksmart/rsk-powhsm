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

#ifndef __HSMSIM_ADMIN
#define __HSMSIM_ADMIN

#include <stdbool.h>
#include <stdint.h>

#include "defs.h"

// Admin APDU constants
#define MIN_ADMIN_BYTES 2
#define HSMSIM_ADMIN_CLA 0x99

#define HSMSIM_ADMIN_CMD_SET_ANCESTOR_RCPT_ROOT 0x01
#define HSMSIM_ADMIN_CMD_RESET_ANCESTOR_RCPT_ROOT 0x02

#define HSMSIM_ADMIN_ERROR_INVALID_PROTOCOL 0x6f00
#define HSMSIM_ADMIN_ERROR_DATA_SIZE 0x6f01
#define HSMSIM_ADMIN_ERROR_INVALID_STATE 0x6f02

typedef struct hsmsim_admin_data_s {
    bool ancestor_receipts_root_set;
    uint8_t old_ancestor_receipts_root[HASH_LEN];
} hsmsim_admin_data_t;

void hsmsim_admin_init();

bool hsmsim_admin_need_process(unsigned int rx);

unsigned int hsmsim_admin_process_apdu(unsigned int rx);

#endif

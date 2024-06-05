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

#ifndef __BOOTLOADER_MOCK_H
#define __BOOTLOADER_MOCK_H

// Needed for signer_authorization.h
#define PARAM_SIGNERS_FILE testing

#include <assert.h>
#include <stdint.h>
#include "attestation.h"
#include "os_exceptions.h"
#include "apdu_utils.h"
#include "mock.h"

// Mock types
typedef struct mock_struct onboard_t;

typedef struct mock_bolos_ux_context {
    unsigned int app_auto_started;
    unsigned int dashboard_redisplayed;

    union {
        att_t attestation;
        sigaut_t sigaut;
        onboard_t onboard;
    };
} bolos_ux_context_t;

extern bolos_ux_context_t G_bolos_ux_context;

// Mock function declarations
void reset_onboard_ctx(onboard_t* onboard_ctx);
unsigned int set_host_seed(volatile unsigned int rx, onboard_t* onboard_ctx);
unsigned int is_onboarded();
unsigned int onboard_device(onboard_t* onboard_ctx);
unsigned short io_exchange(unsigned char channel, unsigned short tx_len);

#endif // __BOOTLOADER_MOCK_H

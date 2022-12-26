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

#ifndef _MOCK_H
#define _MOCK_H

#include <assert.h>
#include <stdint.h>
#include "os_exceptions.h"

#define CHANNEL_APDU 0
#define INS_ATTESTATION 0x50
#define INS_SIGNER_AUTHORIZATION 0x51

#define IO_APDU_BUFFER_SIZE (5 + 255)
extern unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

// Assert helpers
#define ASSERT_EQUALS(a, b) assert((a) == (b))
#define ASSERT_NOT_NULL(obj) assert(NULL != obj)
#define ASSERT_APDU(str) \
    assert(0 == strncmp((const char*)G_io_apdu_buffer, str, strlen(str)))
#define ASSERT_FAIL() assert(false)

#define APDU_RETURN(offset) \
    ((uint16_t)(G_io_apdu_buffer[offset] << 8) | (G_io_apdu_buffer[offset + 1]))

// Empty struct used to mock data types
struct mock_struct {
    void* mock_data;
};

// Mock types
typedef struct mock_struct att_t;
typedef struct mock_struct sigaut_t;
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

typedef uint8_t cx_curve_t;
typedef struct mock_struct cx_sha3_t;
typedef struct mock_struct cx_ecfp_public_key_t;
typedef struct mock_struct cx_ecfp_private_key_t;

// Mock function declarations
void reset_attestation(att_t* att_ctx);
void reset_signer_authorization(sigaut_t* sigaut_ctx);
void reset_onboard_ctx(onboard_t* onboard_ctx);
unsigned int set_host_seed(volatile unsigned int rx, onboard_t* onboard_ctx);
unsigned int is_onboarded();
unsigned int onboard_device(onboard_t* onboard_ctx);
unsigned int get_attestation(volatile unsigned int rx, att_t* att_ctx);
void init_signer_authorization();
unsigned int do_authorize_signer(volatile unsigned int rx,
                                 sigaut_t* sigaut_ctx);
unsigned short io_exchange(unsigned char channel, unsigned short tx_len);

#endif
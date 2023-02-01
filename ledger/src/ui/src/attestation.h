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

#ifndef __ATTESTATION_H
#define __ATTESTATION_H

#include <stdint.h>
#include "os.h"
#include "defs.h"
#include "signer_authorization.h"

// -----------------------------------------------------------------------
// Custom CA attestation
// -----------------------------------------------------------------------

// Operation selectors
typedef enum {
    OP_ATT_UD_VALUE = 0x01,
    OP_ATT_GET_MSG = 0x02,
    OP_ATT_GET = 0x03,
    OP_ATT_APP_HASH = 0x04,
} op_code_att_t;

// Error codes
typedef enum {
    ATT_NO_ONBOARD = 0x6A02, // Device not onboarded using the UI
} err_code_att_t;

// Attestation message prefix
#define ATT_MSG_PREFIX "HSM:UI:4.0"
#define ATT_MSG_PREFIX_LENGTH (sizeof(ATT_MSG_PREFIX) - sizeof(""))

// User defined value size
#define UD_VALUE_SIZE 32

// Path of the public key to derive for the attestation (m/44'/0'/0'/0/0 - BTC)
#define PUBKEY_PATH                                                            \
    "\x2c\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00" \
    "\x00\x00"
#define PUBKEY_PATH_LENGTH (sizeof(PUBKEY_PATH) - sizeof(""))
#define PATH_PART_COUNT 5

// Attestation message to sign size (prefix + UD value + BTC compressed public
// key + authorized signer version + authorized signer iteration)
#define ATT_MESSAGE_SIZE                                         \
    (ATT_MSG_PREFIX_LENGTH + UD_VALUE_SIZE + PUBKEY_CMP_LENGTH + \
     SIGAUT_SIGNER_HASH_SIZE + SIGAUT_SIGNER_ITERATION_SIZE)

// Attestation SM states
typedef enum {
    att_state_wait_ud_value = 0,
    att_state_ready,
} att_state_t;

// Attestation context
typedef struct {
    att_state_t state;

    uint8_t msg[ATT_MESSAGE_SIZE];
    unsigned int msg_offset;

    unsigned char path[PUBKEY_PATH_LENGTH];
    unsigned char priv_key_data[SEED_LENGTH];
    cx_ecfp_private_key_t priv_key;
    cx_ecfp_public_key_t pub_key;
} att_t;

// -----------------------------------------------------------------------
// Protocol
// -----------------------------------------------------------------------

/*
 * Reset the given attestation context
 *
 * @arg[in] att_ctx attestation context
 */
void reset_attestation(att_t* att_ctx);

/*
 * Implement the attestation protocol.
 *
 * @arg[in] rx      number of received bytes from the Host
 * @arg[in] att_ctx attestation context
 * @ret             number of transmited bytes to the host
 */
unsigned int get_attestation(volatile unsigned int rx, att_t* att_ctx);

#endif // __ATTESTATION_H

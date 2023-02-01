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

#ifndef __SIGNER_AUTHORIZATION_H
#define __SIGNER_AUTHORIZATION_H

#ifndef PARAM_SIGNERS_FILE
#error "Signers header file not defined!"
#endif

// clang-format off
#define QUOTEME(x) #x
#define SIGNERS_FOR(x) QUOTEME(signer_authorization_signers/x.h)
#define SIGNERS_FILE SIGNERS_FOR(PARAM_SIGNERS_FILE)
// clang-format on

#include <stdint.h>
#include <stdbool.h>
#include "os.h"
#include "cx.h"
#include "defs.h"
#include "signer_authorization_status.h"
#include SIGNERS_FILE

// -----------------------------------------------------------------------
// Signer installation & execution authorization
// -----------------------------------------------------------------------

// Operation selectors
typedef enum {
    OP_SIGAUT_GET_CURRENT = 0x00,
    OP_SIGAUT_SIGVER = 0x01,
    OP_SIGAUT_SIGN = 0x02,
    OP_SIGAUT_GET_AUTH_COUNT = 0x03,
    OP_SIGAUT_GET_AUTH_AT = 0x04,
} op_code_sigaut_t;

// Error codes
typedef enum {
    ERR_SIGAUT_INVALID_ITERATION = 0x6A03,
    ERR_SIGAUT_INVALID_SIGNATURE = 0x6A04,
    ERR_SIGAUT_INVALID_AUTH_INVALID_INDEX = 0x6A05,
} err_code_sigaut_t;

// Return values for signer authorization
typedef enum {
    RES_SIGAUT_MORE = 0x01,
    RES_SIGAUT_SUCCESS = 0x02,
} res_code_sigaut_t;

// Ethereum message prefix
#define ETHEREUM_MSG_PREFIX \
    "\x19"                  \
    "Ethereum Signed Message:\n"
#define ETHEREUM_MSG_PREFIX_LENGTH (sizeof(ETHEREUM_MSG_PREFIX) - sizeof(""))

// RSK signer version message parts
#define RSK_SIGNER_VERSION_MSG_P1 "RSK_powHSM_signer_"
#define RSK_SIGNER_VERSION_MSG_P1_LENGTH \
    (sizeof(RSK_SIGNER_VERSION_MSG_P1) - sizeof(""))

#define RSK_SIGNER_VERSION_MSG_P2 "_iteration_"
#define RSK_SIGNER_VERSION_MSG_P2_LENGTH \
    (sizeof(RSK_SIGNER_VERSION_MSG_P2) - sizeof(""))

// Authorizers' public keys length (uncompressed format)
#define AUTHORIZED_SIGNER_PUBKEY_LENGTH 65

// Maximum number of authorizers (increase this if using a greater number)
#define MAX_AUTHORIZERS 10

// Hash and iteration sizes
#define SIGAUT_SIGNER_HASH_SIZE HASH_LENGTH
#define SIGAUT_SIGNER_ITERATION_SIZE sizeof(uint16_t)

#define AUX_BUFFER_SIZE 10

// Signer authorization SM states
typedef enum {
    sigaut_state_wait_signer_version = 0,
    sigaut_state_wait_signature,
} sigaut_state_t;

// Signer authorization context
typedef struct {
    sigaut_state_t state;

    sigaut_signer_t signer;

    bool authorized_signer_verified[MAX_AUTHORIZERS];

    union {
        cx_sha3_t auth_hash_ctx;
        cx_ecfp_public_key_t pubkey;
    };

    union {
        uint8_t buf[AUX_BUFFER_SIZE];
        uint8_t auth_hash[HASH_LENGTH];
    };
} sigaut_t;

// -----------------------------------------------------------------------
// Protocol
// -----------------------------------------------------------------------

/*
 * Initialize the signer authorization
 */
void init_signer_authorization();

/*
 * Reset the given signer authorization context
 *
 * @arg[in] sigaut_ctx signer authorization context
 */
void reset_signer_authorization(sigaut_t* sigaut_ctx);

/*
 * Implement the signer authorization protocol.
 *
 * @arg[in] rx                      number of received bytes from the Host
 * @arg[in] sigaut_ctx              signer authorization context
 * @ret                             number of transmited bytes to the host
 */
unsigned int do_authorize_signer(volatile unsigned int rx,
                                 sigaut_t* sigaut_ctx);

/*
 * Tell whether the given signer hash is authorized to run
 * as per the current signer authorization status.
 *
 * @arg[in] signer_hash     the signer hash
 */
bool is_authorized_signer(unsigned char* signer_hash);

/*
 * Get the current authorized signer information
 */
sigaut_signer_t* get_authorized_signer_info();

#endif // __SIGNER_AUTHORIZATION_H

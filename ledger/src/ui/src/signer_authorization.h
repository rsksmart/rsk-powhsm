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

#ifndef __SIGNER_AUTHORIZATION
#define __SIGNER_AUTHORIZATION

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
#include SIGNERS_FILE

// -----------------------------------------------------------------------
// Signer installation & execution authorization
// -----------------------------------------------------------------------

// Command and sub-operations
#define INS_SIGNER_AUTHORIZATION 0x51

#define SIG_AUT_OP_GET_CURRENT 0x00
#define SIG_AUT_OP_SIGVER 0x01
#define SIG_AUT_OP_SIGN 0x02
#define SIG_AUT_OP_GET_AUTH_COUNT 0x03
#define SIG_AUT_OP_GET_AUTH_AT 0x04

// Signature providing possible return values
#define SIG_AUT_OP_SIGN_RES_MORE 0x01
#define SIG_AUT_OP_SIGN_RES_SUCCESS 0x02

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
#define SIGAUT_SIGNER_HASH_SIZE HASHSIZE
#define SIGAUT_SIGNER_ITERATION_SIZE sizeof(uint16_t)

#define AUX_BUFFER_SIZE 10

// Signer version
typedef struct {
    uint8_t hash[HASHSIZE];
    uint16_t iteration;
} sigaut_signer_t;

// Signer status
typedef struct {
    bool initialized;
    sigaut_signer_t signer;
} sigaut_signer_status_t;

// Signer authorization SM stages
typedef enum {
    sigaut_stage_wait_signer_version = 0,
    sigaut_stage_wait_signature,
} sigaut_stage_t;

// Signer authorization context
typedef struct {
    sigaut_stage_t stage;

    sigaut_signer_t signer;

    bool authorized_signer_verified[MAX_AUTHORIZERS];

    union {
        cx_sha3_t auth_hash_ctx;
        cx_ecfp_public_key_t pubkey;
    };

    union {
        uint8_t buf[AUX_BUFFER_SIZE];
        uint8_t auth_hash[HASHSIZE];
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

#endif

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

#include "hal/hash.h"

// Attestation message prefix
#define ATT_MSG_PREFIX "POWHSM:5.5::"
#define ATT_MSG_PREFIX_LENGTH (sizeof(ATT_MSG_PREFIX) - sizeof(""))

// Attestation UD value size
#define ATT_UD_VALUE_SIZE 32

// Number of leading bytes of the last signed BTC tx
// to include in the message
#define ATT_LAST_SIGNED_TX_BYTES 8

// Maximum attestation message to sign size
// Prefix: 12 bytes
// Platform: 3 bytes
// UD value: 32 bytes
// Public keys hash: 32 bytes
// Current best block hash: 32 bytes
// Head of latest authorised signed BTC transaction hash: 8 bytes
// Timestamp: 8 bytes
// TOTAL: 127 bytes
#define MAX_ATT_MESSAGE_SIZE 130

// Attestation SM states
typedef enum {
    STATE_ATTESTATION_WAIT_SIGN = 0,
    STATE_ATTESTATION_READY,
} state_attestation_t;

typedef struct att_s {
    state_attestation_t state;

    hash_sha256_ctx_t hash_ctx; // Attestation public keys hashing context
    uint8_t msg[MAX_ATT_MESSAGE_SIZE]; // Attestation message
    uint8_t msg_length;

    uint32_t path[BIP32_PATH_NUMPARTS];
    uint8_t pubkey[PUBKEY_UNCMP_LENGTH];
    uint8_t pubkey_length;
} att_t;

// -----------------------------------------------------------------------
// Protocol
// -----------------------------------------------------------------------

// Operation selectors
typedef enum {
    OP_ATT_GET = 0x01,
    OP_ATT_GET_MESSAGE = 0x02,
    OP_ATT_APP_HASH = 0x03,
    OP_ATT_GET_ENVELOPE = 0x04,
} op_code_attestation_t;

// Error codes
typedef enum {
    ERR_ATT_PROT_INVALID = 0x6b00, // Host not respecting protocol
    ERR_ATT_INTERNAL = 0x6b01, // Internal error while generating attestation
} err_code_attestation_t;

/*
 * Implement the attestation protocol.
 *
 * @arg[in] rx      number of received bytes from the Host
 * @arg[in] att_ctx attestation context
 * @ret             number of transmited bytes to the host
 */
unsigned int get_attestation(volatile unsigned int rx, att_t* att_ctx);

#endif // __ATTESTATION_H

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

#ifndef __HEARTBEAT_H
#define __HEARTBEAT_H

// -----------------------------------------------------------------------
// Signer heartbeat
// -----------------------------------------------------------------------

// Operation selectors
typedef enum {
    OP_HBT_UD_VALUE = 0x01,
    OP_HBT_GET = 0x02,
    OP_HBT_GET_MESSAGE = 0x03,
    OP_HBT_APP_HASH = 0x04,
    OP_HBT_PUBKEY = 0x05,
} op_code_heartbeat_t;

// Error codes
typedef enum {
    ERR_HBT_PROT_INVALID = 0x6b10, // Host not respecting protocol
    ERR_HBT_INTERNAL = 0x6b11,     // Internal error while generating heartbeat
} err_code_heartbeat_t;

// Heartbeat message prefix
#define HEARTBEAT_MSG_PREFIX "HSM:SIGNER:HB:4.0:"
#define HEARTBEAT_MSG_PREFIX_LENGTH (sizeof(HEARTBEAT_MSG_PREFIX) - sizeof(""))

// User-defined value size
#define UD_VALUE_SIZE 16 // bytes

// Number of trailing bytes of the last signed BTC tx
// to include in the message
#define LAST_SIGNED_TX_BYTES 8 // bytes

// Index of the endorsement scheme
#define ENDORSEMENT_SCHEME_INDEX 2

// Maximum heartbeat message to sign size
#define MAX_HEARTBEAT_MESSAGE_SIZE 80

// Heartbeat SM states
typedef enum {
    STATE_HEARTBEAT_WAIT_UD_VALUE = 0,
    STATE_HEARTBEAT_READY,
} state_heartbeat_t;

typedef struct heartbeat_s {
    state_heartbeat_t state;

    uint8_t msg[MAX_HEARTBEAT_MESSAGE_SIZE]; // Heartbeat message
    unsigned int msg_offset;
} heartbeat_t;

/*
 * Implement the heartbeat protocol.
 *
 * @arg[in] rx      number of received bytes from the Host
 * @arg[in] heartbeat_ctx heartbeat context
 * @ret             number of transmited bytes to the host
 */
unsigned int get_heartbeat(volatile unsigned int rx,
                           heartbeat_t* heartbeat_ctx);

#endif // __HEARTBEAT_H

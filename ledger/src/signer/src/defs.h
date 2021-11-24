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

#ifndef DEFS_H
#define DEFS_H

#include "apdu.h"

// Version and patchlevel
#define VERSION_MAJOR 0x02
#define VERSION_MINOR 0x03
#define VERSION_PATCH 0x02

// Instructions
#define INS_SIGN 0x02
#define INS_GET_PUBLIC_KEY 0x04
#define RSK_IS_ONBOARD 0x06
#define RSK_MODE_CMD 0x43

// Operations within instructions
#define P1_PATH 0x01
#define P1_BTC 0x02
#define P1_RECEIPT 0x04
#define P1_MERKLEPROOF 0x08
#define P1_LAST 0x80
#define P1_SUCCESS 0x81

// App mode response for the mode command
#define RSK_MODE_APP 0x03

// Max USB transfer size
#define MAX_USB_TRANSFER 50

// Size constants
#define HASHLEN 32
#define KEYLEN 32
#define PATHLEN 21
#define INPUTINDEXLEN 4
#define RSK_PATH_LEN 5
#define MAX_SIGNATURE_LENGTH 72

// Parser state machine:
typedef enum {
    S_CMD_START,
    S_TX_HDR,
    S_TX_VARINT,
    S_TX_INPUT_START,
    S_TX_INPUT_READ,
    S_TX_SCRIPT_READ,
    S_TX_INPUT_REMAINING,
    S_TX_REMAINING,
    S_TX_END,
    S_RLP_HDR,
    S_RLP_FIELD,
    S_RLP_FINISH,
    S_MP_START,
    S_MP_NODE_HDR,
    S_MP_NODE_SHARED_PREFIX_HDR,
    S_MP_NODE_SHARED_PREFIX_BODY,
    S_MP_NODE_SHARED_PREFIX_VARINT_HDR,
    S_MP_NODE_SHARED_PREFIX_VARINT_BODY,
    S_MP_NODE_HDR2,
    S_MP_NODE_LEFT,
    S_MP_NODE_LEFT_BYTES,
    S_MP_NODE_RIGHT,
    S_MP_NODE_RIGHT_BYTES,
    S_MP_NODE_CHILDRENSIZE,
    S_MP_NODE_VARINT_HDR,
    S_MP_NODE_VARINT_BODY,
    S_MP_NODE_VALUE,
    S_MP_NODE_VALUE_LEN,
    S_MP_NODE_REMAINING,
    S_SIGN_MESSAGE,
    S_CMD_FINISHED
} PARSE_STM;

// Topic Offsets
#define EXPECTED_TOPIC_BTC_TX_INDEX 2
#define EXPECTED_TOPIC_SIGNATURE_INDEX 1

#endif // DEFS_H

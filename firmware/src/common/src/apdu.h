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

/**
 * APDU buffer related constants and macros
 */

#ifndef __APDU_H
#define __APDU_H

#include "common_requirements.h"

// CLA for the entire protocol
#define CLA 0x80

// Offsets within APDU buffer
#define TXLEN 3
#define DATA 3
#define OP 2
#define CMDPOS 1
#define CLAPOS 0

// APDU buffer getters
#define APDU_CLA() (communication_get_msg_buffer()[CLAPOS])
#define APDU_CMD() (communication_get_msg_buffer()[CMDPOS])
#define APDU_OP() (communication_get_msg_buffer()[OP])
#define APDU_TXLEN() (communication_get_msg_buffer()[TXLEN])
#define APDU_AT(pos) (communication_get_msg_buffer()[pos])

// APDU buffer setters
#define SET_APDU_CLA() (communication_get_msg_buffer()[CLAPOS] = CLA)
#define SET_APDU_CMD(cmd) (communication_get_msg_buffer()[CMDPOS] = (cmd))
#define SET_APDU_OP(op) (communication_get_msg_buffer()[OP] = (op))
#define SET_APDU_TXLEN(len) (communication_get_msg_buffer()[TXLEN] = (len))
#define SET_APDU_AT(pos, value) (communication_get_msg_buffer()[pos] = (value))

// Get pointer to payload within APDU buffer.
// No args, so it can be treated like an array pointer.
#define APDU_DATA_PTR (communication_get_msg_buffer() + DATA)

// Total size of APDU
#define APDU_TOTAL_SIZE (communication_get_msg_buffer_size())
// Size of APDU elements
#define APDU_ELEMENT_SIZE (sizeof(communication_get_msg_buffer()[0]))
// Total size of APDU data part
#define APDU_TOTAL_DATA_SIZE (communication_get_msg_buffer_size() - DATA)
// Total size of APDU data part for outputting
// (need to leave space for result code)
#define APDU_RESULT_CODE_SIZE 2
#define APDU_TOTAL_DATA_SIZE_OUT (APDU_TOTAL_DATA_SIZE - APDU_RESULT_CODE_SIZE)

// Size of payload in APDU
#define APDU_DATA_SIZE(rx) ((rx) >= DATA ? (rx)-DATA : 0)

// Minimum arbitrarily readable APDU bytes
#define MIN_APDU_BYTES 4

// Number of bytes to transmit for data payload with size s
#define TX_FOR_DATA_SIZE(s) (DATA + (s))

// Number of bytes to transmit when sending no data payload
#define TX_NO_DATA() (DATA)

// Number of bytes to transmit when sending only the number of
// bytes to receive in the subsequent tx
#define TX_FOR_TXLEN() (DATA + 1)

// Generic error codes used by both Signer and UI
typedef enum {
    ERR_INVALID_BUFFER = 0x6982,
    ERR_INS_NOT_SUPPORTED = 0x6D00,
    APDU_OK = 0x9000,
} err_code_generic_t;

#endif // __APDU_H

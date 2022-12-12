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

#ifndef __HEARTBEAT
#define __HEARTBEAT

// -----------------------------------------------------------------------
// Signer heartbeat
// -----------------------------------------------------------------------

// APDU instruction
#define INS_HEARTBEAT 0x60

// Maximum heartbeat message to sign size
#define MAX_HEARTBEAT_MESSAGE_SIZE 100

// Heartbeat SM stages
typedef enum {
    heartbeat_stage_wait_ud_value = 0,
    heartbeat_stage_ready,
} heartbeat_stage_t;

typedef struct heartbeat_s {
    heartbeat_stage_t stage;

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

#endif

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

#ifndef __UI_HEARTBEAT_H
#define __UI_HEARTBEAT_H

#include <stdint.h>

// -----------------------------------------------------------------------
// UI heartbeat
// -----------------------------------------------------------------------

// Operation selectors
typedef enum {
    OP_UI_HBT_UD_VALUE = 0x01,
    OP_UI_HBT_GET = 0x02,
    OP_UI_HBT_GET_MESSAGE = 0x03,
    OP_UI_HBT_APP_HASH = 0x04,
    OP_UI_HBT_PUBKEY = 0x05,
} op_code_ui_heartbeat_t;

// Error codes
typedef enum {
    ERR_UI_HBT_PROT_INVALID = 0x6b10, // Host not respecting protocol
} err_code_ui_heartbeat_t;

// Heartbeat message prefix
#define UI_HEARTBEAT_MSG_PREFIX "HSM:UI:HB:4.0:"
#define UI_HEARTBEAT_MSG_PREFIX_LENGTH \
    (sizeof(UI_HEARTBEAT_MSG_PREFIX) - sizeof(""))

// User-defined value size
#define UD_VALUE_SIZE 32 // bytes

// Index of the endorsement scheme
#define ENDORSEMENT_SCHEME_INDEX 2

// Maximum heartbeat message to sign size
#define MAX_UI_HEARTBEAT_MESSAGE_SIZE 80

// Heartbeat SM states
typedef enum {
    STATE_UI_HEARTBEAT_WAIT_UD_VALUE = 0,
    STATE_UI_HEARTBEAT_READY,
} state_ui_heartbeat_t;

typedef struct heartbeat_s {
    state_ui_heartbeat_t state;

    uint8_t msg[MAX_UI_HEARTBEAT_MESSAGE_SIZE]; // Heartbeat message
    unsigned int msg_offset;
} ui_heartbeat_t;

/**
 * Initialize the heartbeat context
 *
 * @arg[in] ui_heartbeat_ctx the UI heartbeat context
 */
void ui_heartbeat_init(ui_heartbeat_t *ui_heartbeat_ctx);

/**
 * Implement the heartbeat protocol.
 *
 * @arg[in] rx               number of received bytes from the Host
 * @arg[in] ui_heartbeat_ctx the UI heartbeat context
 * @ret                      number of transmited bytes to the host
 */
unsigned int get_ui_heartbeat(ui_heartbeat_t *ui_heartbeat_ctx,
                              volatile unsigned int rx);

/**
 * Process an APDU message
 *
 * @arg[in] ui_heartbeat_ctx the UI heartbeat context
 * @arg[in] rx number of received bytes from the host
 * @ret        number of transmited bytes to the host
 */
unsigned int ui_heartbeat_process_apdu(ui_heartbeat_t *ui_heartbeat_ctx,
                                       volatile unsigned int rx);

/**
 * Main function for the heartbeat frontend.
 * It basically only allows for gathering the heartbeat
 * and re-executing the authorized app
 * (i.e., the signer).
 *
 * @arg[in] ui_heartbeat_ctx the UI heartbeat context
 */
void ui_heartbeat_main(ui_heartbeat_t *ui_heartbeat_ctx);

#endif // __UI_HEARTBEAT_H

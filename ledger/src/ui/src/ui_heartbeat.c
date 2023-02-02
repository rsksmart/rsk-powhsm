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

#include <string.h>

#include "ui_heartbeat.h"
#include "apdu.h"
#include "ui_instructions.h"
#include "ints.h"
#include "ui_err.h"
#include "communication.h"
#include "memutil.h"
#include "compiletime.h"
#include "signer_authorization_status.h"

// Heartbeat init alias
#define reset_ui_heartbeat(ctx) ui_heartbeat_init(ctx)

/**
 * Initialize the heartbeat context
 *
 * @arg[in] ui_heartbeat_ctx the UI heartbeat context
 */
void ui_heartbeat_init(ui_heartbeat_t *ui_heartbeat_ctx) {
    COMPILE_TIME_ASSERT(MAX_UI_HEARTBEAT_MESSAGE_SIZE <=
                        APDU_TOTAL_DATA_SIZE_OUT);

    explicit_bzero(ui_heartbeat_ctx, sizeof(ui_heartbeat_t));
    ui_heartbeat_ctx->state = STATE_UI_HEARTBEAT_WAIT_UD_VALUE;
}

static ui_heartbeat_t *current_context;

static void reset_state() {
    reset_ui_heartbeat(current_context);
}

/*
 * Check that the SM for the heartbeat generation
 * matches the expected state.
 *
 * Reset the state and throw a protocol error
 * otherwise.
 *
 * @arg[in] ui_heartbeat_ctx the UI heartbeat context
 */
static void check_state(ui_heartbeat_t *ui_heartbeat_ctx,
                        state_ui_heartbeat_t expected) {
    if (ui_heartbeat_ctx->state != expected) {
        reset_ui_heartbeat(ui_heartbeat_ctx);
        THROW(ERR_UI_HBT_PROT_INVALID);
    }
}

// -----------------------------------------------------------------------
// Protocol implementation
// -----------------------------------------------------------------------

/**
 * Implement the heartbeat protocol.
 *
 * @arg[in] rx               number of received bytes from the Host
 * @arg[in] ui_heartbeat_ctx the UI heartbeat context
 * @ret                      number of transmited bytes to the host
 */
unsigned int get_ui_heartbeat(ui_heartbeat_t *ui_heartbeat_ctx,
                              volatile unsigned int rx) {
    switch (APDU_OP()) {
    case OP_UI_HBT_UD_VALUE:
        // Should receive a user-defined value
        if (APDU_DATA_SIZE(rx) != UD_VALUE_SIZE) {
            reset_ui_heartbeat(ui_heartbeat_ctx);
            THROW(ERR_UI_HBT_PROT_INVALID);
        }

        sigaut_signer_t *current_signer_info = get_authorized_signer_info();

        // Initialize message
        explicit_bzero(ui_heartbeat_ctx->msg, sizeof(ui_heartbeat_ctx->msg));
        ui_heartbeat_ctx->msg_offset = 0;

        // Copy the message prefix
        SAFE_MEMMOVE(ui_heartbeat_ctx->msg,
                     sizeof(ui_heartbeat_ctx->msg),
                     ui_heartbeat_ctx->msg_offset,
                     (void *)PIC(UI_HEARTBEAT_MSG_PREFIX),
                     UI_HEARTBEAT_MSG_PREFIX_LENGTH,
                     MEMMOVE_ZERO_OFFSET,
                     UI_HEARTBEAT_MSG_PREFIX_LENGTH,
                     THROW(ERR_UI_INTERNAL));
        ui_heartbeat_ctx->msg_offset += UI_HEARTBEAT_MSG_PREFIX_LENGTH;

        // Copy the UD value from the APDU
        SAFE_MEMMOVE(ui_heartbeat_ctx->msg,
                     sizeof(ui_heartbeat_ctx->msg),
                     ui_heartbeat_ctx->msg_offset,
                     APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE,
                     MEMMOVE_ZERO_OFFSET,
                     UD_VALUE_SIZE,
                     THROW(ERR_UI_INTERNAL));
        ui_heartbeat_ctx->msg_offset += UD_VALUE_SIZE;

        // Copy signer hash and iteration into the message space
        SAFE_MEMMOVE(ui_heartbeat_ctx->msg,
                     sizeof(ui_heartbeat_ctx->msg),
                     ui_heartbeat_ctx->msg_offset,
                     current_signer_info->hash,
                     sizeof(current_signer_info->hash),
                     MEMMOVE_ZERO_OFFSET,
                     sizeof(current_signer_info->hash),
                     THROW(ERR_UI_INTERNAL));
        ui_heartbeat_ctx->msg_offset += sizeof(current_signer_info->hash);

        // Make sure iteration fits
        if (ui_heartbeat_ctx->msg_offset +
                sizeof(current_signer_info->iteration) >
            sizeof(ui_heartbeat_ctx->msg))
            THROW(ERR_UI_INTERNAL);

        VAR_BIGENDIAN_TO(ui_heartbeat_ctx->msg + ui_heartbeat_ctx->msg_offset,
                         current_signer_info->iteration,
                         sizeof(current_signer_info->iteration));
        ui_heartbeat_ctx->msg_offset += sizeof(current_signer_info->iteration);

        ui_heartbeat_ctx->state = STATE_UI_HEARTBEAT_READY;

        return TX_FOR_DATA_SIZE(0);
    case OP_UI_HBT_GET:
        check_state(ui_heartbeat_ctx, STATE_UI_HEARTBEAT_READY);

        // Sign message
        int endorsement_size = os_endorsement_key2_derive_sign_data(
            ui_heartbeat_ctx->msg, ui_heartbeat_ctx->msg_offset, APDU_DATA_PTR);

        return TX_FOR_DATA_SIZE(endorsement_size);
    case OP_UI_HBT_GET_MESSAGE:
        check_state(ui_heartbeat_ctx, STATE_UI_HEARTBEAT_READY);

        SAFE_MEMMOVE(APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE,
                     MEMMOVE_ZERO_OFFSET,
                     ui_heartbeat_ctx->msg,
                     sizeof(ui_heartbeat_ctx->msg),
                     MEMMOVE_ZERO_OFFSET,
                     ui_heartbeat_ctx->msg_offset,
                     THROW(ERR_UI_INTERNAL));

        return TX_FOR_DATA_SIZE(ui_heartbeat_ctx->msg_offset);
    case OP_UI_HBT_APP_HASH:
        return TX_FOR_DATA_SIZE(os_endorsement_get_code_hash(APDU_DATA_PTR));
    case OP_UI_HBT_PUBKEY:
        return TX_FOR_DATA_SIZE(os_endorsement_get_public_key(
            ENDORSEMENT_SCHEME_INDEX, APDU_DATA_PTR));
    default:
        reset_ui_heartbeat(ui_heartbeat_ctx);
        THROW(ERR_UI_HBT_PROT_INVALID);
        break;
    }
}

/**
 * Process an APDU message
 *
 * @arg[in] ui_heartbeat_ctx the UI heartbeat context
 * @arg[in] rx number of received bytes from the host
 * @ret        number of transmited bytes to the host
 */
unsigned int ui_heartbeat_process_apdu(ui_heartbeat_t *ui_heartbeat_ctx,
                                       volatile unsigned int rx) {
    unsigned int tx = 0;

    // no apdu received, well, reset the session, and reset the
    // bootloader configuration
    if (rx == 0) {
        THROW(ERR_EMPTY_BUFFER);
    }

    if (APDU_CLA() != CLA) {
        THROW(ERR_UI_INVALID_CLA);
    }

    // unauthenticated instruction
    switch (APDU_CMD()) {
    case RSK_MODE_CMD:
        tx = get_mode_heartbeat();
        break;
    case INS_UI_HEARTBEAT:
        tx = get_ui_heartbeat(ui_heartbeat_ctx, rx);
        break;
    case RSK_END_CMD: // return to app
        THROW(EX_BOOTLOADER_RSK_END);
    default:
        THROW(ERR_INS_NOT_SUPPORTED);
        break;
    }

    return tx;
}

/**
 * Main function for the heartbeat frontend.
 * It basically only allows for gathering the heartbeat
 * and re-executing the authorized app
 * (i.e., the signer).
 *
 * @arg[in] ui_heartbeat_ctx the UI heartbeat context
 */
void ui_heartbeat_main(ui_heartbeat_t *ui_heartbeat_ctx) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU, rx);

                tx = ui_heartbeat_process_apdu(ui_heartbeat_ctx, rx);
                THROW(APDU_OK);
            }
            CATCH(EX_BOOTLOADER_RSK_END) {
                break;
            }
            CATCH_OTHER(e) {
                current_context = ui_heartbeat_ctx;
                tx = comm_process_exception(e, tx, &reset_state);
            }
            FINALLY {
            }
        }
        END_TRY;
    }
}

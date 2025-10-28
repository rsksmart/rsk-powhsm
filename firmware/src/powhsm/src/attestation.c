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

#include "hal/seed.h"
#include "hal/endorsement.h"
#include "hal/platform.h"
#include "hal/exceptions.h"

#include "attestation.h"
#include "apdu.h"
#include "defs.h"
#include "pathAuth.h"
#include "bc_state.h"
#include "bc_hash.h"
#include "mem.h"
#include "memutil.h"
#include "util.h"

// Attestation message prefix
const char att_msg_prefix[ATT_MSG_PREFIX_LENGTH] = ATT_MSG_PREFIX;

// Utility macros for message gathering paging
// Maximum page size is APDU data part size minus one
// byte (first byte of the response), which is used to indicate
// whether there is a next page or not.
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX_PAGESIZE (APDU_TOTAL_DATA_SIZE_OUT - 1)
#define PAGECOUNT(itemcount) (((itemcount) + MAX_PAGESIZE - 1) / MAX_PAGESIZE)
#define CURPAGESIZE(itemcount, page) \
    (MIN(MAX_PAGESIZE, (itemcount) - ((page)*MAX_PAGESIZE)))

static void reset_attestation(att_t* att_ctx) {
    explicit_bzero(att_ctx, sizeof(att_t));
    att_ctx->state = STATE_ATTESTATION_WAIT_SIGN;
}

static void check_state(att_t* att_ctx, state_attestation_t expected) {
    if (att_ctx->state != expected) {
        reset_attestation(att_ctx);
        THROW(ERR_ATT_PROT_INVALID);
    }
}

static void hash_public_key(const char* path,
                            size_t path_size,
                            att_t* att_ctx) {
    // Derive public key

    // Skip first byte of path when copying (path size byte)
    SAFE_MEMMOVE(att_ctx->path,
                 sizeof(att_ctx->path),
                 MEMMOVE_ZERO_OFFSET,
                 (unsigned int*)path,
                 path_size,
                 1,
                 sizeof(att_ctx->path),
                 { goto hash_public_key_error; });

    att_ctx->pubkey_length = sizeof(att_ctx->pubkey);
    if (!seed_derive_pubkey(att_ctx->path,
                            sizeof(att_ctx->path) / sizeof(att_ctx->path[0]),
                            att_ctx->pubkey,
                            &att_ctx->pubkey_length)) {
        goto hash_public_key_error;
    }

    // Hash
    SHA256_UPDATE(&att_ctx->hash_ctx, att_ctx->pubkey, att_ctx->pubkey_length);

    // Cleanup public key
    explicit_bzero(&att_ctx->pubkey, sizeof(att_ctx->pubkey));
    att_ctx->pubkey_length = 0;

    return;

hash_public_key_error:
    // Cleanup public key
    explicit_bzero(&att_ctx->pubkey, sizeof(att_ctx->pubkey));
    att_ctx->pubkey_length = 0;
    THROW(ERR_ATT_INTERNAL);
}

static void write_uint64_be(uint8_t* out, uint64_t in) {
    out[0] = (uint8_t)(in >> 56);
    out[1] = (uint8_t)(in >> 48);
    out[2] = (uint8_t)(in >> 40);
    out[3] = (uint8_t)(in >> 32);
    out[4] = (uint8_t)(in >> 24);
    out[5] = (uint8_t)(in >> 16);
    out[6] = (uint8_t)(in >> 8);
    out[7] = (uint8_t)in;
}

/*
 * Generate the attestation message.
 *
 * @arg[in] att_ctx attestation context
 * @arg[in] ud_value pointer to the user-defined value
 */
static void generate_message_to_sign(att_t* att_ctx, unsigned char* ud_value) {

    // Initialize message
    explicit_bzero(att_ctx->msg, sizeof(att_ctx->msg));
    att_ctx->msg_length = 0;

    // Copy the message prefix
    SAFE_MEMMOVE(att_ctx->msg,
                 sizeof(att_ctx->msg),
                 att_ctx->msg_length,
                 (void*)PIC(ATT_MSG_PREFIX),
                 ATT_MSG_PREFIX_LENGTH,
                 MEMMOVE_ZERO_OFFSET,
                 ATT_MSG_PREFIX_LENGTH,
                 THROW(ERR_ATT_INTERNAL));
    att_ctx->msg_length += ATT_MSG_PREFIX_LENGTH;

    // Copy the platform id
    SAFE_MEMMOVE(att_ctx->msg,
                 sizeof(att_ctx->msg),
                 att_ctx->msg_length,
                 (void*)PIC(platform_get_id()),
                 PLATFORM_ID_LENGTH,
                 MEMMOVE_ZERO_OFFSET,
                 PLATFORM_ID_LENGTH,
                 THROW(ERR_ATT_INTERNAL));
    att_ctx->msg_length += PLATFORM_ID_LENGTH;

    // Copy the UD value
    SAFE_MEMMOVE(att_ctx->msg,
                 sizeof(att_ctx->msg),
                 att_ctx->msg_length,
                 (void*)PIC(ud_value),
                 ATT_UD_VALUE_SIZE,
                 MEMMOVE_ZERO_OFFSET,
                 ATT_UD_VALUE_SIZE,
                 THROW(ERR_ATT_INTERNAL));
    att_ctx->msg_length += ATT_UD_VALUE_SIZE;

    // Prepare the digest
    SHA256_INIT(&att_ctx->hash_ctx);

    // Retrieve and hash the public keys in order
    for (unsigned int i = 0; i < KEY_PATH_COUNT(); i++) {
        hash_public_key(get_ordered_path(i), SINGLE_PATH_SIZE_BYTES, att_ctx);
    }

    // Finalise the public keys hash straight into the message
    SHA256_FINAL(&att_ctx->hash_ctx, &att_ctx->msg[att_ctx->msg_length]);
    att_ctx->msg_length += HASH_LENGTH;

    // Copy the current best block
    SAFE_MEMMOVE(att_ctx->msg,
                 sizeof(att_ctx->msg),
                 att_ctx->msg_length,
                 N_bc_state.best_block,
                 sizeof(N_bc_state.best_block),
                 MEMMOVE_ZERO_OFFSET,
                 sizeof(N_bc_state.best_block),
                 THROW(ERR_ATT_INTERNAL));
    att_ctx->msg_length += sizeof(N_bc_state.best_block);

    // Copy the leading bytes of the last authorised signed tx
    SAFE_MEMMOVE(att_ctx->msg,
                 sizeof(att_ctx->msg),
                 att_ctx->msg_length,
                 N_bc_state.last_auth_signed_btc_tx_hash,
                 sizeof(N_bc_state.last_auth_signed_btc_tx_hash),
                 MEMMOVE_ZERO_OFFSET,
                 ATT_LAST_SIGNED_TX_BYTES,
                 THROW(ERR_ATT_INTERNAL));
    att_ctx->msg_length += ATT_LAST_SIGNED_TX_BYTES;

    // Copy the current timestamp
    write_uint64_be(&att_ctx->msg[att_ctx->msg_length],
                    platform_get_timestamp());
    att_ctx->msg_length += sizeof(uint64_t);
}

// -----------------------------------------------------------------------
// Protocol implementation
// -----------------------------------------------------------------------

/*
 * Implement the attestation protocol.
 *
 * @arg[in] rx      number of received bytes from the Host
 * @arg[in] att_ctx attestation context
 * @ret             number of transmited bytes to the host
 */
unsigned int get_attestation(volatile unsigned int rx, att_t* att_ctx) {
    size_t buf_length;
    uint8_t* buf;

    switch (APDU_OP()) {
    case OP_ATT_GET:
        // Should receive a user-defined value
        if (APDU_DATA_SIZE(rx) != ATT_UD_VALUE_SIZE) {
            reset_attestation(att_ctx);
            THROW(ERR_ATT_PROT_INVALID);
        }

        // Generate the message to attest
        generate_message_to_sign(att_ctx, APDU_DATA_PTR);

        // Attest message
        uint8_t endorsement_size = (uint8_t)MIN(APDU_TOTAL_DATA_SIZE_OUT, 0xFF);
        if (!endorsement_sign(att_ctx->msg,
                              att_ctx->msg_length,
                              APDU_DATA_PTR,
                              &endorsement_size)) {
            THROW(ERR_ATT_INTERNAL);
        }

        // Ready
        att_ctx->state = STATE_ATTESTATION_READY;

        return TX_FOR_DATA_SIZE(endorsement_size);
    case OP_ATT_GET_ENVELOPE:
    case OP_ATT_GET_MESSAGE:
        check_state(att_ctx, STATE_ATTESTATION_READY);

        // Should receive a page index
        if (APDU_DATA_SIZE(rx) != 1)
            THROW(ERR_ATT_PROT_INVALID);

        // Get the envelope or message
        buf = endorsement_get_envelope();
        buf_length = endorsement_get_envelope_length();
        if (!buf || APDU_OP() == OP_ATT_GET_MESSAGE) {
            buf = att_ctx->msg;
            buf_length = att_ctx->msg_length;
        }

        // Check page index within range (page index is zero based)
        if (APDU_DATA_PTR[0] >= PAGECOUNT(buf_length)) {
            THROW(ERR_ATT_PROT_INVALID);
        }
        uint8_t page = APDU_DATA_PTR[0];

        // Copy the page into the APDU buffer (no need to check for limits since
        // the chunk size is based directly on the APDU size)
        SAFE_MEMMOVE(APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE_OUT,
                     1,
                     buf,
                     buf_length,
                     APDU_DATA_PTR[0] * MAX_PAGESIZE,
                     CURPAGESIZE(buf_length, page),
                     THROW(ERR_ATT_INTERNAL));
        APDU_DATA_PTR[0] = page < (PAGECOUNT(buf_length) - 1);

        return TX_FOR_DATA_SIZE(CURPAGESIZE(buf_length, page) + 1);
    case OP_ATT_APP_HASH:
        check_state(att_ctx, STATE_ATTESTATION_READY);

        buf_length = MIN(APDU_TOTAL_DATA_SIZE_OUT, 0xFF);
        if (!endorsement_get_code_hash(APDU_DATA_PTR, (uint8_t*)&buf_length)) {
            THROW(ERR_ATT_INTERNAL);
        }
        return TX_FOR_DATA_SIZE(buf_length);
    default:
        THROW(ERR_ATT_PROT_INVALID);
        break;
    }
    return 0;
}

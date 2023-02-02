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
#include <stdlib.h>
#include "os.h"
#include "cx.h"
#include "signer_authorization.h"
#include "defs.h"
#include "ui_err.h"
#include "memutil.h"
#include "ints.h"
#include "compiletime.h"
#include "runtime.h"

// Initial signer hash taken from an external definition (see Makefile for
// details)
#ifdef PARAM_INITIAL_SIGNER_HASH
static const uint8_t INITIAL_SIGNER_HASH[] = PARAM_INITIAL_SIGNER_HASH;
#else
#error "Initial signer hash not defined!"
#endif

// Initial signer iteration taken from an external definition (see Makefile for
// details)
#ifdef PARAM_INITIAL_SIGNER_ITERATION
static const uint16_t INITIAL_SIGNER_ITERATION = PARAM_INITIAL_SIGNER_ITERATION;
#else
#error "Initial signer iteration not defined!"
#endif

// Authorized signers
static const uint8_t authorizers_pubkeys[][AUTHORIZED_SIGNER_PUBKEY_LENGTH] =
    AUTHORIZERS_PUBKEYS;

// Total number of authorizers
#define TOTAL_AUTHORIZERS \
    (sizeof(authorizers_pubkeys) / sizeof(authorizers_pubkeys[0]))

// Minimum number of authorizers required to authorize a signer
#define THRESHOLD_AUTHORIZERS (TOTAL_AUTHORIZERS / 2 + 1)

/*
 * Sanity check the status of the signer authorization
 * component
 */
static void sanity_check() {
    if (!N_current_signer_status.initialized)
        THROW(ERR_UI_INTERNAL);
}

/*
 * Check that the SM for the signer authorization
 * matches the expected state.
 *
 * Reset the state and throw a protocol error
 * otherwise.
 */
static void check_state(sigaut_t* sigaut_ctx, sigaut_state_t expected) {
    sanity_check();

    if (sigaut_ctx->state != expected) {
        reset_signer_authorization(sigaut_ctx);
        THROW(ERR_UI_PROT_INVALID);
    }
}

static void generate_message_to_sign(sigaut_t* sigaut_ctx) {
    uint8_t message_size;

    cx_keccak_init(&sigaut_ctx->auth_hash_ctx, 256);

    // Hash eth prefix
    cx_hash((cx_hash_t*)&sigaut_ctx->auth_hash_ctx,
            0,
            (unsigned char*)ETHEREUM_MSG_PREFIX,
            ETHEREUM_MSG_PREFIX_LENGTH,
            0);

    // Compute total message size
    UINT_TO_DECSTR(sigaut_ctx->buf, sigaut_ctx->signer.iteration);
    message_size = RSK_SIGNER_VERSION_MSG_P1_LENGTH +
                   sizeof(sigaut_ctx->signer.hash) * 2 + // Hexa
                   RSK_SIGNER_VERSION_MSG_P2_LENGTH +
                   strlen((const char*)sigaut_ctx->buf);

    // Hash message size
    UINT_TO_DECSTR(sigaut_ctx->buf, message_size);
    cx_hash((cx_hash_t*)&sigaut_ctx->auth_hash_ctx,
            0,
            sigaut_ctx->buf,
            strlen((const char*)sigaut_ctx->buf),
            0);

    // Hash message
    cx_hash((cx_hash_t*)&sigaut_ctx->auth_hash_ctx,
            0,
            (unsigned char*)RSK_SIGNER_VERSION_MSG_P1,
            RSK_SIGNER_VERSION_MSG_P1_LENGTH,
            0);
    for (unsigned int i = 0; i < sizeof(sigaut_ctx->signer.hash); i++) {
        BYTE_TO_HEXSTR(sigaut_ctx->buf, sigaut_ctx->signer.hash[i]);
        cx_hash(
            (cx_hash_t*)&sigaut_ctx->auth_hash_ctx, 0, sigaut_ctx->buf, 2, 0);
    }
    cx_hash((cx_hash_t*)&sigaut_ctx->auth_hash_ctx,
            0,
            (unsigned char*)RSK_SIGNER_VERSION_MSG_P2,
            RSK_SIGNER_VERSION_MSG_P2_LENGTH,
            0);
    UINT_TO_DECSTR(sigaut_ctx->buf, sigaut_ctx->signer.iteration);
    cx_hash((cx_hash_t*)&sigaut_ctx->auth_hash_ctx,
            CX_LAST,
            sigaut_ctx->buf,
            strlen((const char*)sigaut_ctx->buf),
            sigaut_ctx->auth_hash);
}

// -----------------------------------------------------------------------
// Protocol implementation
// -----------------------------------------------------------------------

/*
 * Initialize the signer authorization
 */
void init_signer_authorization() {
    // Build should fail when more authorizers than supported are provided
    COMPILE_TIME_ASSERT(TOTAL_AUTHORIZERS <= MAX_AUTHORIZERS);

    const bool t = true;
    // Make sure NVM signer status is initialized
    if (!N_current_signer_status.initialized) {
        nvm_write(N_current_signer_status.signer.hash,
                  (void*)INITIAL_SIGNER_HASH,
                  sizeof(N_current_signer_status.signer.hash));
        nvm_write(&N_current_signer_status.signer.iteration,
                  (void*)&INITIAL_SIGNER_ITERATION,
                  sizeof(N_current_signer_status.signer.iteration));
        nvm_write(&N_current_signer_status.initialized,
                  (void*)&t,
                  sizeof(N_current_signer_status.initialized));
    }
}

/*
 * Reset the given signer authorization context
 *
 * @arg[in] sigaut_ctx signer authorization context
 */
void reset_signer_authorization(sigaut_t* sigaut_ctx) {
    explicit_bzero(sigaut_ctx, sizeof(sigaut_t));
    sigaut_ctx->state = sigaut_state_wait_signer_version;
}

/*
 * Implement the signer authorization protocol.
 *
 * @arg[in] rx                      number of received bytes from the Host
 * @arg[in] sigaut_ctx signer    authorization context
 * @ret                             number of transmited bytes to the host
 */
unsigned int do_authorize_signer(volatile unsigned int rx,
                                 sigaut_t* sigaut_ctx) {
    uint8_t signature_valid, valid_count, auth_index;

    switch (APDU_OP()) {
    case OP_SIGAUT_GET_CURRENT:
        sanity_check();

        SAFE_MEMMOVE(APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE_OUT,
                     MEMMOVE_ZERO_OFFSET,
                     N_current_signer_status.signer.hash,
                     sizeof(N_current_signer_status.signer.hash),
                     MEMMOVE_ZERO_OFFSET,
                     sizeof(N_current_signer_status.signer.hash),
                     THROW(ERR_UI_INTERNAL));

        if (APDU_TOTAL_DATA_SIZE_OUT <
            sizeof(N_current_signer_status.signer.hash) +
                sizeof(N_current_signer_status.signer.iteration))
            THROW(ERR_UI_INTERNAL);

        VAR_BIGENDIAN_TO(APDU_DATA_PTR +
                             sizeof(N_current_signer_status.signer.hash),
                         N_current_signer_status.signer.iteration,
                         sizeof(N_current_signer_status.signer.iteration));

        return TX_FOR_DATA_SIZE(
            sizeof(N_current_signer_status.signer.hash) +
            sizeof(N_current_signer_status.signer.iteration));
    case OP_SIGAUT_SIGVER:
        check_state(sigaut_ctx, sigaut_state_wait_signer_version);

        // Should receive a signer hash followed by a signer iteration
        if (APDU_DATA_SIZE(rx) != (sizeof(sigaut_ctx->signer.hash) +
                                   sizeof(sigaut_ctx->signer.iteration)))
            THROW(ERR_UI_PROT_INVALID);

        // Set the signer version
        SAFE_MEMMOVE(sigaut_ctx->signer.hash,
                     sizeof(sigaut_ctx->signer.hash),
                     MEMMOVE_ZERO_OFFSET,
                     APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE,
                     MEMMOVE_ZERO_OFFSET,
                     sizeof(sigaut_ctx->signer.hash),
                     THROW(ERR_UI_INTERNAL));

        BIGENDIAN_FROM(APDU_DATA_PTR + sizeof(sigaut_ctx->signer.hash),
                       sigaut_ctx->signer.iteration);

        // Make sure the intended iteration is strictly greater than the current
        // iteration
        if (sigaut_ctx->signer.iteration <=
            N_current_signer_status.signer.iteration) {
            reset_signer_authorization(sigaut_ctx);
            THROW(ERR_SIGAUT_INVALID_ITERATION);
        }

        // Compute the hash that should be signed for this signer version
        // to be authorized
        generate_message_to_sign(sigaut_ctx);

        sigaut_ctx->state = sigaut_state_wait_signature;

        return TX_FOR_DATA_SIZE(0);
    case OP_SIGAUT_SIGN:
        check_state(sigaut_ctx, sigaut_state_wait_signature);

        // Check to see whether we find a matching authorized signer
        signature_valid = 0;
        for (unsigned int i = 0; i < TOTAL_AUTHORIZERS && !signature_valid;
             i++) {
            // Clear public key memory region first just in case initialization
            // fails
            explicit_bzero(&sigaut_ctx->pubkey, sizeof(sigaut_ctx->pubkey));
            // Init public key
            cx_ecfp_init_public_key(CX_CURVE_256K1,
                                    (unsigned char*)authorizers_pubkeys[i],
                                    sizeof(authorizers_pubkeys[i]),
                                    &sigaut_ctx->pubkey);
            signature_valid = cx_ecdsa_verify(&sigaut_ctx->pubkey,
                                              0,
                                              CX_NONE,
                                              sigaut_ctx->auth_hash,
                                              HASH_LENGTH,
                                              APDU_DATA_PTR,
                                              APDU_DATA_SIZE(rx));
            // Cleanup
            explicit_bzero(&sigaut_ctx->pubkey, sizeof(sigaut_ctx->pubkey));

            // Found a valid signature?
            if (signature_valid) {
                sigaut_ctx->authorized_signer_verified[i] = true;
            }
        }

        // Reached the threshold?
        valid_count = 0;
        for (unsigned int i = 0; i < TOTAL_AUTHORIZERS; i++)
            if (sigaut_ctx->authorized_signer_verified[i])
                valid_count++;

        if (valid_count >= THRESHOLD_AUTHORIZERS) {
            // Write the new authorized signer version and iteration to NVM,
            // reset the operation and signal success
            nvm_write(N_current_signer_status.signer.hash,
                      sigaut_ctx->signer.hash,
                      sizeof(N_current_signer_status.signer.hash));
            nvm_write(&N_current_signer_status.signer.iteration,
                      &sigaut_ctx->signer.iteration,
                      sizeof(N_current_signer_status.signer.iteration));
            reset_signer_authorization(sigaut_ctx);
            APDU_DATA_PTR[0] = RES_SIGAUT_SUCCESS;
        } else {
            APDU_DATA_PTR[0] = RES_SIGAUT_MORE;
        }
        return TX_FOR_DATA_SIZE(1);
    case OP_SIGAUT_GET_AUTH_COUNT:
        APDU_DATA_PTR[0] = (unsigned char)TOTAL_AUTHORIZERS;
        return TX_FOR_DATA_SIZE(1);
    case OP_SIGAUT_GET_AUTH_AT:
        if (APDU_DATA_SIZE(rx) != 1)
            THROW(ERR_UI_PROT_INVALID);

        auth_index = APDU_DATA_PTR[0];
        if (auth_index >= (uint8_t)TOTAL_AUTHORIZERS)
            THROW(ERR_SIGAUT_INVALID_AUTH_INVALID_INDEX);

        SAFE_MEMMOVE(APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE_OUT,
                     MEMMOVE_ZERO_OFFSET,
                     authorizers_pubkeys[auth_index],
                     sizeof(authorizers_pubkeys[auth_index]),
                     MEMMOVE_ZERO_OFFSET,
                     sizeof(authorizers_pubkeys[auth_index]),
                     THROW(ERR_UI_INTERNAL));

        return TX_FOR_DATA_SIZE(sizeof(authorizers_pubkeys[auth_index]));
    default:
        reset_signer_authorization(sigaut_ctx);
        THROW(ERR_UI_PROT_INVALID);
        break;
    }
}

/*
 * Tell whether the given signer hash is authorized to run
 * as per the current signer authorization status.
 *
 * @arg[in] signer_hash     the signer hash
 */
bool is_authorized_signer(unsigned char* signer_hash) {
#ifdef DEBUG_BUILD
    return true;
#else
    return !memcmp(N_current_signer_status.signer.hash,
                   signer_hash,
                   sizeof(N_current_signer_status.signer.hash));
#endif
}

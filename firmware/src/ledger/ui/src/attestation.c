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
#include "os.h"
#include "cx.h"
#include "attestation.h"
#include "defs.h"
#include "ui_err.h"
#include "memutil.h"
#include "ints.h"
#include "runtime.h"

// Utility macros to save memory
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define PAGESIZE (APDU_TOTAL_DATA_SIZE_OUT - 1)
#define PAGECOUNT(itemcount) (((itemcount) + PAGESIZE - 1) / PAGESIZE)

// Global onboarding flag
extern NON_VOLATILE unsigned char* N_onboarded_ui[1];

// Attestation message prefix
const char att_msg_prefix[ATT_MSG_PREFIX_LENGTH] = ATT_MSG_PREFIX;

// Path of the public key to derive
const char key_derivation_path[PUBKEY_PATH_LENGTH] = PUBKEY_PATH;

/*
 * Check the SM for the attestation generation
 * matches the expected state.
 *
 * Reset the state and throw a protocol error
 * otherwise.
 */
static void check_state(att_t* att_ctx, att_state_t expected) {
    if (att_ctx->state != expected) {
        reset_attestation(att_ctx);
        THROW(ERR_UI_PROT_INVALID);
    }
}

/*
 * Throw an internal error unless the APDU
 * buffer data part is large enough to fit
 * the given number of bytes
 *
 * The reason this is treated as an internal
 * error is that all operations checking this
 * already know that the buffer *should* be
 * large enough and are just sanity checking
 */
static void check_apdu_buffer_holds(size_t size) {
    if (APDU_TOTAL_DATA_SIZE_OUT < size) {
        THROW(ERR_UI_INTERNAL);
    }
}

/*
 * Given an uncompressed secp256k1 public key,
 * compress it to the given destination, returning
 * the size.
 *
 * @arg[in] pub_key public key
 * @arg[in] dst destination
 * @arg[in] dst_size destination size
 * @arg[in] dst_offset destination offset
 * @ret     size of the compressed public key
 */
static size_t compress_pubkey_into(cx_ecfp_public_key_t* pub_key,
                                   uint8_t* dst,
                                   size_t dst_size,
                                   size_t dst_offset) {
    SAFE_MEMMOVE(dst,
                 dst_size,
                 dst_offset,
                 pub_key->W,
                 sizeof(pub_key->W),
                 MEMMOVE_ZERO_OFFSET,
                 PUBKEY_CMP_LENGTH,
                 THROW(ERR_UI_INTERNAL));
    dst[dst_offset] = pub_key->W[pub_key->W_len - 1] & 0x01 ? 0x03 : 0x02;
    return PUBKEY_CMP_LENGTH;
}

/*
 * Reset the given attestation context
 *
 * @arg[in] att_ctx attestation context
 */
void reset_attestation(att_t* att_ctx) {
    explicit_bzero(att_ctx, sizeof(att_t));
    att_ctx->state = att_state_wait_ud_value;
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
    uint8_t message_size;

    // Verify that the device has been onboarded
    unsigned char onboarded = *((unsigned char*)PIC(N_onboarded_ui));
    if (!onboarded) {
        THROW(ATT_NO_ONBOARD);
        return 0;
    }

    switch (APDU_OP()) {
    case OP_ATT_UD_VALUE:
        check_state(att_ctx, att_state_wait_ud_value);

        // Should receive a user-defined value
        if (APDU_DATA_SIZE(rx) != UD_VALUE_SIZE)
            THROW(ERR_UI_PROT_INVALID);

        sigaut_signer_t* current_signer_info = get_authorized_signer_info();

        // Initialize message
        explicit_bzero(att_ctx->msg, sizeof(att_ctx->msg));
        att_ctx->msg_offset = 0;

        // Copy prefix and user defined value into the message space
        SAFE_MEMMOVE(att_ctx->msg,
                     sizeof(att_ctx->msg),
                     att_ctx->msg_offset,
                     (const void*)PIC(att_msg_prefix),
                     sizeof(att_msg_prefix),
                     MEMMOVE_ZERO_OFFSET,
                     sizeof(att_msg_prefix),
                     THROW(ERR_UI_INTERNAL));
        att_ctx->msg_offset += sizeof(att_msg_prefix);
        SAFE_MEMMOVE(att_ctx->msg,
                     sizeof(att_ctx->msg),
                     att_ctx->msg_offset,
                     APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE,
                     MEMMOVE_ZERO_OFFSET,
                     UD_VALUE_SIZE,
                     THROW(ERR_UI_INTERNAL));
        att_ctx->msg_offset += UD_VALUE_SIZE;

        // Derive, compress and copy the public key into the message space
        BEGIN_TRY {
            TRY {
                SAFE_MEMMOVE(att_ctx->path,
                             sizeof(att_ctx->path),
                             MEMMOVE_ZERO_OFFSET,
                             (const void*)PIC(key_derivation_path),
                             sizeof(key_derivation_path),
                             MEMMOVE_ZERO_OFFSET,
                             sizeof(key_derivation_path),
                             THROW(ERR_UI_INTERNAL));
                // Derive private key
                os_perso_derive_node_bip32(CX_CURVE_256K1,
                                           (unsigned int*)att_ctx->path,
                                           PATH_PART_COUNT,
                                           att_ctx->priv_key_data,
                                           NULL);
                cx_ecdsa_init_private_key(CX_CURVE_256K1,
                                          att_ctx->priv_key_data,
                                          PRIVATE_KEY_LENGTH,
                                          &att_ctx->priv_key);
                // Cleanup private key data
                explicit_bzero(att_ctx->priv_key_data,
                               sizeof(att_ctx->priv_key_data));
                // Derive public key
                cx_ecfp_generate_pair(
                    CX_CURVE_256K1, &att_ctx->pub_key, &att_ctx->priv_key, 1);
                // Cleanup private key
                explicit_bzero(&att_ctx->priv_key, sizeof(att_ctx->priv_key));
                // Compress public key into message space
                att_ctx->msg_offset +=
                    compress_pubkey_into(&att_ctx->pub_key,
                                         att_ctx->msg,
                                         sizeof(att_ctx->msg),
                                         att_ctx->msg_offset);
                // Cleanup public key
                explicit_bzero(&att_ctx->pub_key, sizeof(att_ctx->pub_key));
            }
            CATCH_OTHER(e) {
                // Cleanup key data and fail
                explicit_bzero(att_ctx->priv_key_data,
                               sizeof(att_ctx->priv_key_data));
                explicit_bzero(&att_ctx->priv_key, sizeof(att_ctx->priv_key));
                explicit_bzero(&att_ctx->pub_key, sizeof(att_ctx->pub_key));
                THROW(ERR_UI_INTERNAL);
            }
            FINALLY {
            }
        }
        END_TRY;

        // Copy signer hash and iteration into the message space
        SAFE_MEMMOVE(att_ctx->msg,
                     sizeof(att_ctx->msg),
                     att_ctx->msg_offset,
                     current_signer_info->hash,
                     sizeof(current_signer_info->hash),
                     MEMMOVE_ZERO_OFFSET,
                     sizeof(current_signer_info->hash),
                     THROW(ERR_UI_INTERNAL));
        att_ctx->msg_offset += sizeof(current_signer_info->hash);

        // Make sure iteration fits
        if (att_ctx->msg_offset + sizeof(current_signer_info->iteration) >
            sizeof(att_ctx->msg))
            THROW(ERR_UI_INTERNAL);

        VAR_BIGENDIAN_TO(att_ctx->msg + att_ctx->msg_offset,
                         current_signer_info->iteration,
                         sizeof(current_signer_info->iteration));
        att_ctx->msg_offset += sizeof(current_signer_info->iteration);

        att_ctx->state = att_state_ready;

        return TX_FOR_DATA_SIZE(0);
    case OP_ATT_GET_MSG:
        // Retrieve message to sign page
        check_state(att_ctx, att_state_ready);

        // Should receive a page index
        if (APDU_DATA_SIZE(rx) != 1)
            THROW(ERR_UI_PROT_INVALID);

        // Maximum page size is APDU data part size minus one
        // byte (first byte of the response), which is used to indicate
        // whether there is a next page or not.

        // Check page index within range (page index is zero based)
        if (APDU_DATA_PTR[0] >= PAGECOUNT(att_ctx->msg_offset)) {
            THROW(ERR_UI_PROT_INVALID);
        }

        // Copy the page into the APDU buffer (no need to check for limits since
        // the chunk size is based directly on the APDU size)
        message_size =
            MIN(PAGESIZE, att_ctx->msg_offset - (APDU_DATA_PTR[0] * PAGESIZE));
        SAFE_MEMMOVE(APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE_OUT,
                     1,
                     att_ctx->msg,
                     sizeof(att_ctx->msg),
                     APDU_DATA_PTR[0] * PAGESIZE,
                     message_size,
                     THROW(ERR_UI_INTERNAL));
        APDU_DATA_PTR[0] =
            APDU_DATA_PTR[0] < (PAGECOUNT(att_ctx->msg_offset) - 1);

        return TX_FOR_DATA_SIZE(message_size + 1);
    case OP_ATT_GET:
        check_state(att_ctx, att_state_ready);

        // Reset SM
        att_ctx->state = att_state_wait_ud_value;

        // Sign and output
        check_apdu_buffer_holds(MAX_SIGNATURE_LENGTH);
        return TX_FOR_DATA_SIZE(os_endorsement_key2_derive_sign_data(
            att_ctx->msg, att_ctx->msg_offset, APDU_DATA_PTR));
    case OP_ATT_APP_HASH:
        // This can be asked for at any time
        check_apdu_buffer_holds(HASH_LENGTH);
        return TX_FOR_DATA_SIZE(os_endorsement_get_code_hash(APDU_DATA_PTR));
    default:
        // Reset SM
        att_ctx->state = att_state_wait_ud_value;
        THROW(ERR_UI_PROT_INVALID);
        break;
    }
}

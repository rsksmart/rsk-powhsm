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
#include "err.h"
#include "memutil.h"

// Utility macros to save memory
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define PAGESIZE (APDU_TOTAL_DATA_SIZE - 1)
#define PAGECOUNT(itemcount) (((itemcount) + PAGESIZE - 1) / PAGESIZE)

// Global onboarding flag
extern const unsigned char* N_onboarded_ui[1];

// Attestation message prefix
const char att_msg_prefix[ATT_MSG_PREFIX_LENGTH] = ATT_MSG_PREFIX;

// Path of the public key to derive
const char key_derivation_path[PUBKEY_PATH_LENGTH] = PUBKEY_PATH;

/*
 * Check the SM for the attestation generation
 * matches the expected stage.
 *
 * Reset the state and throw a protocol error
 * otherwise.
 */
static void check_stage(att_t* att_ctx, att_stage_t expected) {
    if (att_ctx->stage != expected) {
        reset_attestation(att_ctx);
        THROW(PROT_INVALID);
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
    if (APDU_TOTAL_DATA_SIZE < size) {
        THROW(INTERNAL);
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
 * @ret     size of the compressed public key
 */
static size_t compress_pubkey_into(cx_ecfp_public_key_t* pub_key,
                                   uint8_t* dst,
                                   size_t dst_size) {
    SAFE_MEMMOVE(dst,
                 dst_size,
                 0,
                 pub_key->W,
                 sizeof(pub_key->W),
                 0,
                 PUBKEYCOMPRESSEDSIZE,
                 THROW(INTERNAL));
    dst[0] = pub_key->W[pub_key->W_len - 1] & 0x01 ? 0x03 : 0x02;
    return PUBKEYCOMPRESSEDSIZE;
}

/*
 * Given an uncompressed secp256k1 public key,
 * compress it in place, returning the size.
 *
 * @arg[in] pub_key public key
 * @ret     size of the compressed public key
 */
static size_t compress_pubkey(cx_ecfp_public_key_t* pub_key) {
    pub_key->W_len =
        compress_pubkey_into(pub_key, pub_key->W, sizeof(pub_key->W));
    return pub_key->W_len;
}

/*
 * Given the UD value,
 * generate the initial part of the attestation message,
 * consisting of <prefix><ud value><BTC pub key>.
 *
 * @arg[in] att_ctx attestation context
 * @arg[in] ud_value user defined value
 * @arg[in] ud_value user defined value size
 */
static void generate_message_to_sign_partial(att_t* att_ctx,
                                             uint8_t* ud_value,
                                             size_t ud_value_size) {
    // Initialize message
    explicit_bzero(att_ctx->msg, sizeof(att_ctx->msg));

    // Copy prefix and user defined value into the message space
    att_ctx->msg_offset = 0;
    SAFE_MEMMOVE(att_ctx->msg,
                 sizeof(att_ctx->msg),
                 att_ctx->msg_offset,
                 PIC(att_msg_prefix),
                 sizeof(att_msg_prefix),
                 0,
                 sizeof(att_msg_prefix),
                 THROW(INTERNAL));
    att_ctx->msg_offset += sizeof(att_msg_prefix);
    SAFE_MEMMOVE(att_ctx->msg,
                 sizeof(att_ctx->msg),
                 att_ctx->msg_offset,
                 ud_value,
                 ud_value_size,
                 0,
                 ud_value_size,
                 THROW(INTERNAL));
    att_ctx->msg_offset += ud_value_size;

    // Derive, compress and copy the public key into the message space
    BEGIN_TRY {
        TRY {
            SAFE_MEMMOVE(att_ctx->path,
                         sizeof(att_ctx->path),
                         0,
                         PIC(key_derivation_path),
                         sizeof(key_derivation_path),
                         0,
                         sizeof(key_derivation_path),
                         THROW(INTERNAL));
            // Derive private key
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       att_ctx->path,
                                       PATH_PART_COUNT,
                                       att_ctx->priv_key_data,
                                       NULL);
            cx_ecdsa_init_private_key(CX_CURVE_256K1,
                                      att_ctx->priv_key_data,
                                      KEYLEN,
                                      &att_ctx->priv_key);
            // Cleanup private key data
            explicit_bzero(att_ctx->priv_key_data,
                           sizeof(att_ctx->priv_key_data));
            // Derive public key
            cx_ecfp_generate_pair(
                CX_CURVE_256K1, &att_ctx->pub_key, &att_ctx->priv_key, 1);
            // Cleanup private key
            explicit_bzero(&att_ctx->priv_key, sizeof(att_ctx->priv_key));
            // Compress public key in place
            compress_pubkey(&att_ctx->pub_key);
            // Copy into message space
            SAFE_MEMMOVE(att_ctx->msg,
                         sizeof(att_ctx->msg),
                         att_ctx->msg_offset,
                         att_ctx->pub_key.W,
                         sizeof(att_ctx->pub_key.W),
                         0,
                         att_ctx->pub_key.W_len,
                         THROW(INTERNAL));
            att_ctx->msg_offset += att_ctx->pub_key.W_len;

            // Cleanup public key
            explicit_bzero(&att_ctx->pub_key, sizeof(att_ctx->pub_key));
        }
        CATCH_OTHER(e) {
            // Cleanup key data and fail
            explicit_bzero(att_ctx->priv_key_data,
                           sizeof(att_ctx->priv_key_data));
            explicit_bzero(&att_ctx->priv_key, sizeof(att_ctx->priv_key));
            explicit_bzero(&att_ctx->pub_key, sizeof(att_ctx->pub_key));
            THROW(INTERNAL);
        }
        FINALLY {
        }
    }
    END_TRY;
}

/*
 * Assuming the custom CA public key is loaded in att_ctx->ca_pubkey,
 * complete the generation of the attestation message.
 *
 * @arg[in] att_ctx attestation context
 */
static void complete_message_to_sign(att_t* att_ctx) {
    // Compress and append the CA public key to the existing message
    att_ctx->msg_offset +=
        compress_pubkey_into(&att_ctx->ca_pubkey,
                             att_ctx->msg + att_ctx->msg_offset,
                             sizeof(att_ctx->msg) - att_ctx->msg_offset);
}

/*
 * Reset the given attestation context
 *
 * @arg[in] att_ctx attestation context
 */
void reset_attestation(att_t* att_ctx) {
    explicit_bzero(att_ctx, sizeof(att_ctx));
    att_ctx->stage = att_stage_wait_ud_value;
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
        THROW(NO_ONBOARD);
        return 0;
    }

    switch (APDU_OP()) {
    case ATT_OP_UD_VALUE:
        check_stage(att_ctx, att_stage_wait_ud_value);

        // Should receive a user-defined value
        if (APDU_DATA_SIZE(rx) != UD_VALUE_SIZE)
            THROW(PROT_INVALID);

        generate_message_to_sign_partial(att_ctx, APDU_DATA_PTR, UD_VALUE_SIZE);

        att_ctx->stage = att_stage_wait_ca_pubkey;

        return TX_FOR_DATA_SIZE(0);
    case ATT_OP_PUBKEY:
        check_stage(att_ctx, att_stage_wait_ca_pubkey);

        // Should receive an uncompressed public key. Store it.
        if (APDU_DATA_SIZE(rx) != PUBKEYSIZE)
            THROW(PROT_INVALID);

        // Clear public key memory region first just in case initialization
        // fails
        explicit_bzero(&att_ctx->ca_pubkey, sizeof(att_ctx->ca_pubkey));
        // Init public key
        cx_ecfp_init_public_key(
            CX_CURVE_256K1, APDU_DATA_PTR, PUBKEYSIZE, &att_ctx->ca_pubkey);

        // Finish generating the message to sign
        complete_message_to_sign(att_ctx);

        att_ctx->stage = att_stage_wait_ca_hash;

        return TX_FOR_DATA_SIZE(0);
    case ATT_OP_HASH:
        check_stage(att_ctx, att_stage_wait_ca_hash);

        // Should receive a hash. Store it.
        if (APDU_DATA_SIZE(rx) != HASHSIZE)
            THROW(PROT_INVALID);

        SAFE_MEMMOVE(att_ctx->ca_signed_hash,
                     sizeof(att_ctx->ca_signed_hash),
                     0,
                     APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE,
                     0,
                     HASHSIZE,
                     THROW(INTERNAL));

        att_ctx->stage = att_stage_wait_ca_signature;

        return TX_FOR_DATA_SIZE(0);
    case ATT_OP_SIGNATURE:
        check_stage(att_ctx, att_stage_wait_ca_signature);

        // Should receive a length and length bytes
        if (APDU_DATA_SIZE(rx) < 2 ||
            APDU_DATA_SIZE(rx) != APDU_DATA_PTR[0] + 1)
            THROW(PROT_INVALID);
        // Respect maximum signature size
        if (APDU_DATA_PTR[0] > MAX_SIGNATURE_LENGTH)
            THROW(PROT_INVALID);
        // Clear signature memory area first just in case something else fails
        att_ctx->ca_signature_length = 0;
        memset(att_ctx->ca_signature, 0, sizeof(att_ctx->ca_signature));
        // Store signature and length
        att_ctx->ca_signature_length = APDU_DATA_PTR[0];
        SAFE_MEMMOVE(att_ctx->ca_signature,
                     sizeof(att_ctx->ca_signature),
                     0,
                     APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE,
                     1,
                     att_ctx->ca_signature_length,
                     THROW(INTERNAL));

        att_ctx->stage = att_stage_ready;

        return TX_FOR_DATA_SIZE(0);
    case ATT_OP_GET_MSG:
        // Retrieve message to sign page
        check_stage(att_ctx, att_stage_ready);

        // Should receive a page index
        if (APDU_DATA_SIZE(rx) != 1)
            THROW(PROT_INVALID);

        // Maximum page size is APDU data part size minus one
        // byte (first byte of the response), which is used to indicate
        // whether there is a next page or not.

        // Check page index within range (page index is zero based)
        if (APDU_DATA_PTR[0] >= PAGECOUNT(att_ctx->msg_offset)) {
            THROW(PROT_INVALID);
        }

        // Copy the page into the APDU buffer (no need to check for limits since
        // the chunk size is based directly on the APDU size)
        message_size =
            MIN(PAGESIZE, att_ctx->msg_offset - (APDU_DATA_PTR[0] * PAGESIZE));
        SAFE_MEMMOVE(APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE,
                     1,
                     att_ctx->msg,
                     sizeof(att_ctx->msg),
                     APDU_DATA_PTR[0] * PAGESIZE,
                     message_size,
                     THROW(INTERNAL));
        APDU_DATA_PTR[0] =
            APDU_DATA_PTR[0] < (PAGECOUNT(att_ctx->msg_offset) - 1);

        return TX_FOR_DATA_SIZE(message_size + 1);
    case ATT_OP_GET:
        check_stage(att_ctx, att_stage_ready);

        // Keypoint: only generate the attestation if the given public key
        // is the same as the device's custom CA public key.
        if (!cx_ecdsa_verify(&att_ctx->ca_pubkey,
                             0,
                             CX_SHA256,
                             att_ctx->ca_signed_hash,
                             HASHSIZE,
                             att_ctx->ca_signature,
                             att_ctx->ca_signature_length) ||
            !os_customca_verify(att_ctx->ca_signed_hash,
                                att_ctx->ca_signature,
                                att_ctx->ca_signature_length))
            THROW(CA_MISMATCH);

        // Reset SM
        att_ctx->stage = att_stage_wait_ud_value;

        // Sign and output
        check_apdu_buffer_holds(MAX_SIGNATURE_LENGTH);
        return TX_FOR_DATA_SIZE(os_endorsement_key2_derive_sign_data(
            att_ctx->msg, att_ctx->msg_offset, APDU_DATA_PTR));
    case ATT_OP_APP_HASH:
        // This can be asked for at any time
        check_apdu_buffer_holds(HASHSIZE);
        return TX_FOR_DATA_SIZE(os_endorsement_get_code_hash(APDU_DATA_PTR));
    default:
        // Reset SM
        att_ctx->stage = att_stage_wait_ud_value;
        THROW(PROT_INVALID);
        break;
    }
}
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
#include "attestation.h"
#include "apdu.h"
#include "defs.h"
#include "pathAuth.h"
#include "bc_hash.h"
#include "mem.h"
#include "memutil.h"

// Attestation message prefix
const char att_msg_prefix[ATT_MSG_PREFIX_LENGTH] = ATT_MSG_PREFIX;

// -----------------------------------------------------------------------
// Protocol implementation
// -----------------------------------------------------------------------

static void hash_public_key(const char* path,
                            size_t path_size,
                            att_t* att_ctx) {
    BEGIN_TRY {
        TRY {
            // Derive public key

            // Skip first byte of path when copying (path size byte)
            SAFE_MEMMOVE(att_ctx->path,
                         sizeof(att_ctx->path),
                         MEMMOVE_ZERO_OFFSET,
                         (unsigned int*)path,
                         path_size,
                         1,
                         sizeof(att_ctx->path),
                         THROW(ERR_ATT_INTERNAL));

            // Derive and init private key
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       att_ctx->path,
                                       DERIVATION_PATH_PARTS,
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

            // Hash
            SHA256_UPDATE(
                &att_ctx->hash_ctx, att_ctx->pub_key.W, att_ctx->pub_key.W_len);

            // Cleanup public key
            explicit_bzero(&att_ctx->pub_key, sizeof(att_ctx->pub_key));
        }
        CATCH_OTHER(e) {
            // Cleanup key data and fail
            explicit_bzero(att_ctx->priv_key_data,
                           sizeof(att_ctx->priv_key_data));
            explicit_bzero(&att_ctx->priv_key, sizeof(att_ctx->priv_key));
            explicit_bzero(&att_ctx->pub_key, sizeof(att_ctx->pub_key));
            THROW(ERR_ATT_INTERNAL);
        }
        FINALLY {
        }
    }
    END_TRY;
}

/*
 * Generate the attestation message.
 *
 * @arg[in] att_ctx attestation context
 * @ret             generated message size
 */
static unsigned int generate_message_to_sign(att_t* att_ctx) {
    // Initialize message
    explicit_bzero(att_ctx->msg, sizeof(att_ctx->msg));

    // Copy the message prefix
    SAFE_MEMMOVE(att_ctx->msg,
                 sizeof(att_ctx->msg),
                 MEMMOVE_ZERO_OFFSET,
                 (void*)PIC(ATT_MSG_PREFIX),
                 ATT_MSG_PREFIX_LENGTH,
                 MEMMOVE_ZERO_OFFSET,
                 ATT_MSG_PREFIX_LENGTH,
                 THROW(ERR_ATT_INTERNAL));

    // Prepare the digest
    SHA256_INIT(&att_ctx->hash_ctx);

    // Retrieve and hash the public keys in order
    for (unsigned int i = 0; i < KEY_PATH_COUNT(); i++) {
        hash_public_key(get_ordered_path(i), SINGLE_PATH_SIZE_BYTES, att_ctx);
    }

    SHA256_FINAL(&att_ctx->hash_ctx, &att_ctx->msg[ATT_MSG_PREFIX_LENGTH]);

    return ATT_MSG_PREFIX_LENGTH + HASH_SIZE;
}

/*
 * Implement the attestation protocol.
 *
 * @arg[in] rx      number of received bytes from the Host
 * @arg[in] att_ctx attestation context
 * @ret             number of transmited bytes to the host
 */
unsigned int get_attestation(volatile unsigned int rx, att_t* att_ctx) {
    unsigned int message_size;

    switch (APDU_OP()) {
    case OP_ATT_GET:
        // Generate the message to sign
        message_size = generate_message_to_sign(att_ctx);

        // Sign message
        int endorsement_size = os_endorsement_key2_derive_sign_data(
            att_ctx->msg, message_size, APDU_DATA_PTR);

        return TX_FOR_DATA_SIZE(endorsement_size);
    case OP_ATT_GET_MESSAGE:
        // Generate and output the message to sign
        message_size = generate_message_to_sign(att_ctx);

        SAFE_MEMMOVE(APDU_DATA_PTR,
                     APDU_TOTAL_DATA_SIZE,
                     MEMMOVE_ZERO_OFFSET,
                     att_ctx->msg,
                     sizeof(att_ctx->msg),
                     MEMMOVE_ZERO_OFFSET,
                     message_size,
                     THROW(ERR_ATT_INTERNAL));

        return TX_FOR_DATA_SIZE(message_size);
    case OP_ATT_APP_HASH:
        return TX_FOR_DATA_SIZE(os_endorsement_get_code_hash(APDU_DATA_PTR));
    default:
        THROW(ERR_ATT_PROT_INVALID);
        break;
    }
}

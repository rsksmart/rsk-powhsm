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
    UNUSED(rx);

    unsigned int message_size;
    uint8_t code_hash_size;

    switch (APDU_OP()) {
    case OP_ATT_GET:
        // Generate the message to attest
        message_size = generate_message_to_sign(att_ctx);

        // Attest message
        uint8_t endorsement_size = APDU_TOTAL_DATA_SIZE_OUT;
        if (!endorsement_sign(
                att_ctx->msg, message_size, APDU_DATA_PTR, &endorsement_size)) {
            THROW(ERR_ATT_INTERNAL);
        }

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
        code_hash_size = APDU_TOTAL_DATA_SIZE_OUT;
        if (!endorsement_get_code_hash(APDU_DATA_PTR, &code_hash_size)) {
            THROW(ERR_ATT_INTERNAL);
        }
        return TX_FOR_DATA_SIZE(code_hash_size);
    default:
        THROW(ERR_ATT_PROT_INVALID);
        break;
    }
    return 0;
}

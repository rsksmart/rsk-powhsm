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

#include "os_attestation.h"
#include "hsmsim_attestation.h"
#include "hsmsim_exceptions.h"
#include "os_ecdsa.h"
#include "sha256.h"
#include "hmac_sha256.h"

unsigned int os_endorsement_key2_derive_sign_data(unsigned char *src,
                                                  unsigned int srcLength,
                                                  unsigned char *signature) {
    uint8_t pubkey[PUBKEY_UNCMP_LENGTH];
    uint8_t tweak[HMAC_SHA256_SIZE];
    uint8_t hash[HASH_LENGTH];

    sha256(src, srcLength, hash, sizeof(hash));

    if (hsmsim_helper_getpubkey(
            attestation_id.key, pubkey, sizeof(pubkey), false) !=
        sizeof(pubkey)) {
        THROW(HSMSIM_EXC_SECP_ERROR);
    }

    if (hmac_sha256(attestation_id.code_hash,
                    sizeof(attestation_id.code_hash),
                    pubkey,
                    sizeof(pubkey),
                    tweak,
                    sizeof(tweak)) != sizeof(tweak)) {
        THROW(HSMSIM_EXC_HMAC_ERROR);
    }

    return hsmsim_helper_tweak_sign(attestation_id.key, tweak, hash, signature);
}

unsigned int os_endorsement_get_code_hash(unsigned char *buffer) {
    memmove(buffer, attestation_id.code_hash, sizeof(attestation_id.code_hash));
    return sizeof(attestation_id.code_hash);
}

unsigned int os_endorsement_get_public_key(unsigned char index,
                                           unsigned char *buffer) {
    uint8_t tempbuf[PUBKEY_UNCMP_LENGTH];
    size_t tempbuf_size = hsmsim_helper_getpubkey(
        attestation_id.key, tempbuf, sizeof(tempbuf), false);
    memcpy(buffer, tempbuf, tempbuf_size);
    return tempbuf_size;
}
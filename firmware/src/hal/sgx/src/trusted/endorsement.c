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

#include <stdio.h>
#include <stddef.h>
#include <string.h>
// TODO: remove usage of secp256k1 here upon final implementation
// (only needed here for mock implementation)
#include <secp256k1.h>

#include "hal/constants.h"
#include "hal/endorsement.h"
#include "hal/seed.h"
#include "hal/exceptions.h"
#include "hal/log.h"

#include "random.h"

// TODO: remove HMAC-SHA256 entirely upon final implementation,
// (only needed for mock implementation)
#include "hmac_sha256.h"

static secp256k1_context* sp_ctx = NULL;

// Test key for mock implementation
static const uint8_t attestation_key[] = {
    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
};
// Test code hash for mock implementation
static const uint8_t attestation_code_hash[] = {
    0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
    0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
    0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
};
static uint8_t attestation_pubkey[PUBKEY_UNCMP_LENGTH];

static size_t tweak_sign(const unsigned char* key,
                         const unsigned char* tweak,
                         const unsigned char* hash,
                         unsigned char* sig) {
    unsigned char tweaked_key[PRIVATE_KEY_LENGTH];
    secp256k1_ecdsa_signature sp_sig;
    size_t sig_serialized_size = MAX_SIGNATURE_LENGTH;

    // Tweak private key
    memmove(tweaked_key, key, sizeof(tweaked_key));
    if (!secp256k1_ec_seckey_tweak_add(sp_ctx, tweaked_key, tweak))
        return 0;

    // Sign and serialize as DER
    secp256k1_ecdsa_sign(sp_ctx, &sp_sig, hash, tweaked_key, NULL, NULL);
    secp256k1_ecdsa_signature_serialize_der(
        sp_ctx, sig, &sig_serialized_size, &sp_sig);

    return (int)sig_serialized_size;
}

static uint8_t derive_pubkey_uncmp(const unsigned char* key,
                                   unsigned char* dest) {
    secp256k1_pubkey pubkey;
    size_t dest_size = PUBKEY_UNCMP_LENGTH;

    // Calculate the public key and serialize it according to
    // the compressed argument
    if (!secp256k1_ec_pubkey_create(sp_ctx, &pubkey, key)) {
        return 0;
    }

    secp256k1_ec_pubkey_serialize(
        sp_ctx, dest, &dest_size, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    return (uint8_t)dest_size;
}

bool endorsement_init() {
    // Init the secp256k1 context
    if (!sp_ctx)
        sp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    // Compute attestation public key
    if (derive_pubkey_uncmp(attestation_key, attestation_pubkey) !=
        PUBKEY_UNCMP_LENGTH) {
        LOG("Error getting uncompressed public key for mock attestation key\n");
        return false;
    }
    LOG("Loaded mock attestation key:\n");
    LOG_HEX("\tKey: ", attestation_key, sizeof(attestation_key));
    LOG_HEX("\tPublic key: ", attestation_pubkey, sizeof(attestation_pubkey));

    return true;
}

bool endorsement_sign(uint8_t* msg,
                      size_t msg_size,
                      uint8_t* signature_out,
                      uint8_t* signature_out_length) {

    uint8_t tweak[HMAC_SHA256_SIZE];
    uint8_t hash[HASH_LENGTH];

    if (*signature_out_length < MAX_SIGNATURE_LENGTH) {
        return false;
    }

    sha256(msg, msg_size, hash, sizeof(hash));

    if (hmac_sha256(attestation_code_hash,
                    sizeof(attestation_code_hash),
                    attestation_pubkey,
                    sizeof(attestation_pubkey),
                    tweak,
                    sizeof(tweak)) != sizeof(tweak)) {
        LOG("Error computing tweak for endorsement\n");
        return false;
    }

    if (*signature_out_length < MAX_SIGNATURE_LENGTH) {
        LOG("Output buffer for signature too small: %u bytes\n",
            *signature_out_length);
        return false;
    }

    *signature_out_length =
        tweak_sign(attestation_key, tweak, hash, signature_out);

    return true;
}

bool endorsement_get_code_hash(uint8_t* code_hash_out,
                               uint8_t* code_hash_out_length) {

    if (*code_hash_out_length < HASH_LENGTH) {
        LOG("Output buffer for code hash too small: %u bytes\n",
            *code_hash_out_length);
        return false;
    }

    memmove(
        code_hash_out, attestation_code_hash, sizeof(attestation_code_hash));
    *code_hash_out_length = sizeof(attestation_code_hash);

    return true;
}

bool endorsement_get_public_key(uint8_t* public_key_out,
                                uint8_t* public_key_out_length) {
    if (*public_key_out_length < PUBKEY_UNCMP_LENGTH) {
        LOG("Output buffer for public key too small: %u bytes\n",
            *public_key_out_length);
        return false;
    }

    memcpy(public_key_out, attestation_pubkey, sizeof(attestation_pubkey));
    *public_key_out_length = sizeof(attestation_pubkey);

    return true;
}
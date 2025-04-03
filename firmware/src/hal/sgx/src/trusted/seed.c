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
#include <string.h>
#include <stdint.h>
#include <secp256k1.h>
#include <openenclave/enclave.h>

#include "hal/hash.h"
#include "hal/seed.h"
#include "hal/constants.h"
#include "hal/log.h"

#include "secret_store.h"
#include "bip32.h"
#include "random.h"

#define SEST_SEED_KEY "seed"

// Globals
static bool G_seed_available;
static uint8_t G_seed[SEED_LENGTH];

static secp256k1_context* sp_ctx = NULL;

bool seed_init() {
    // Init the secp256k1 context
    if (!sp_ctx)
        sp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    memset(G_seed, 0, sizeof(G_seed));
    G_seed_available = false;

    if (!sest_exists(SEST_SEED_KEY)) {
        // Module is in a wiped state
        return true;
    }

    // Read seed
    uint8_t seed_length = 0;
    if (!(seed_length = sest_read(SEST_SEED_KEY, G_seed, sizeof(G_seed)))) {
        LOG("Could not load the current seed\n");
        return false;
    }

    // Make sure seed is sound
    if (seed_length != sizeof(G_seed)) {
        LOG("Detected invalid seed\n");
        return false;
    }

    G_seed_available = true;
    LOG("Seed loaded\n");

    return true;
}

bool seed_wipe() {
    bool success = sest_remove(SEST_SEED_KEY);
    memset(G_seed, 0, sizeof(G_seed));
    G_seed_available = false;

    return success;
}

bool seed_generate(uint8_t* client_seed, uint8_t client_seed_size) {
    if (G_seed_available) {
        LOG("Seed already exists\n");
        return false;
    }

    if (client_seed_size != SEED_LENGTH) {
        LOG("Invalid client seed size\n");
        return false;
    }

    uint8_t random_bytes[SEED_LENGTH];
    if (!random_getrandom(random_bytes, sizeof(random_bytes))) {
        LOG("Error generating random seed\n");
        return false;
    }

    for (size_t i = 0; i < SEED_LENGTH; i++) {
        G_seed[i] = random_bytes[i] ^ client_seed[i];
    }

    if (!sest_write(SEST_SEED_KEY, G_seed, SEED_LENGTH)) {
        LOG("Error persisting generated seed\n");
        memset(G_seed, 0, sizeof(G_seed));
        return false;
    }

    G_seed_available = true;
    printf("Seed generated\n");
    return true;
}

static bool derive_privkey(uint32_t* path,
                           uint8_t path_length,
                           uint8_t* privkey_out,
                           size_t privkey_out_size) {
    if (!bip32_derive_private(privkey_out,
                              privkey_out_size,
                              G_seed,
                              sizeof(G_seed),
                              path,
                              path_length)) {
        return false;
    }

    return true;
}

bool seed_available() {
    return G_seed_available;
}

bool seed_derive_pubkey(uint32_t* path,
                        uint8_t path_length,
                        uint8_t* pubkey_out,
                        uint8_t* pubkey_out_length) {
    secp256k1_pubkey sp_pubkey;
    uint8_t derived_privkey[PRIVATE_KEY_LENGTH];

    LOG("Deriving public key for path...\n");

    // Derive the private key
    if (!derive_privkey(
            path, path_length, derived_privkey, sizeof(derived_privkey))) {
        LOG("Error deriving private key for public key gathering\n");
        return false;
    }

    // Derive the public key and serialize it uncompressed
    if (!secp256k1_ec_pubkey_create(sp_ctx, &sp_pubkey, derived_privkey)) {
        LOG("Error deriving public key\n");
        return false;
    }

    if (*pubkey_out_length < PUBKEY_UNCMP_LENGTH) {
        LOG("Overflow while deriving public key\n");
        return false;
    }
    size_t temp_length = *pubkey_out_length;
    secp256k1_ec_pubkey_serialize(sp_ctx,
                                  pubkey_out,
                                  &temp_length,
                                  &sp_pubkey,
                                  SECP256K1_EC_UNCOMPRESSED);

    if (temp_length != PUBKEY_UNCMP_LENGTH) {
        LOG("Unexpected error while deriving public key\n");
        return false;
    }
    *pubkey_out_length = (uint8_t)temp_length;

    LOG_HEX("Pubkey for path is:", pubkey_out, *pubkey_out_length);

    return true;
}

bool seed_sign(uint32_t* path,
               uint8_t path_length,
               uint8_t* hash32,
               uint8_t* sig_out,
               uint8_t* sig_out_length) {
    secp256k1_ecdsa_signature sp_sig;
    uint8_t derived_privkey[PRIVATE_KEY_LENGTH];

    if (*sig_out_length < MAX_SIGNATURE_LENGTH) {
        LOG("Overflow while signing\n");
        return false;
    }

    LOG_HEX("Signing hash:", hash32, HASH_LENGTH);

    // Derive the private key
    if (!derive_privkey(
            path, path_length, derived_privkey, sizeof(derived_privkey))) {
        LOG("Error deriving private key for signing\n");
        return false;
    }

    // Sign and serialize as DER
    secp256k1_ecdsa_sign(sp_ctx, &sp_sig, hash32, derived_privkey, NULL, NULL);
    size_t temp_length = *sig_out_length;
    secp256k1_ecdsa_signature_serialize_der(
        sp_ctx, sig_out, &temp_length, &sp_sig);
    if (temp_length > MAX_SIGNATURE_LENGTH) {
        LOG("Overflow while signing\n");
        return false;
    }
    *sig_out_length = (uint8_t)temp_length;

    LOG_HEX("Signature is: ", sig_out, *sig_out_length);

    return true;
}

bool seed_output_USE_FROM_EXPORT_ONLY(uint8_t* out, size_t* out_size) {
    // We need a seed
    if (!G_seed_available) {
        LOG("Seed: no seed available to output\n");
        return false;
    }

    // Output buffer validations
    if (*out_size < sizeof(G_seed)) {
        LOG("Seed: output buffer to small to write seed\n");
        return false;
    }
    if (!oe_is_within_enclave(out, *out_size)) {
        LOG("Seed: output buffer not strictly within the enclave\n");
        return false;
    }

    // Write seed
    memcpy(out, G_seed, sizeof(G_seed));
    *out_size = sizeof(G_seed);
    return true;
}

bool seed_set_USE_FROM_EXPORT_ONLY(uint8_t* in, size_t in_size) {
    // We need no seed
    if (G_seed_available) {
        LOG("Seed: already set\n");
        return false;
    }

    // Input buffer validations
    if (in_size < sizeof(G_seed)) {
        LOG("Seed: input buffer too small to set seed\n");
        return false;
    }
    if (!oe_is_within_enclave(in, in_size)) {
        LOG("Seed: input buffer not strictly within the enclave\n");
        return false;
    }

    // Set seed
    G_seed_available = false;
    memcpy(G_seed, in, sizeof(G_seed));
    if (!sest_write(SEST_SEED_KEY, G_seed, SEED_LENGTH)) {
        LOG("Seed: error persisting given seed\n");
        memset(G_seed, 0, sizeof(G_seed));
        return false;
    }

    G_seed_available = true;
    LOG("Seed set\n");
    return true;
}
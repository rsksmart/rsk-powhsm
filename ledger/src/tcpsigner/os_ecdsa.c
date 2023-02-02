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

#include "os_ecdsa.h"

#include <string.h>
#include <secp256k1.h>

#include "hsmsim_ecdsa.h"
#include "hsmsim_exceptions.h"
#include "constants.h"

#include "hsmsim_random.h"

#define PUBKEY_UNCOMPRESSED_LENGTH 65

static secp256k1_context *sp_ctx = NULL;

void os_ecdsa_initialize() {
    // Init the secp256k1 context
    if (!sp_ctx)
        sp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
}

void os_perso_derive_node_bip32(cx_curve_t curve,
                                unsigned int *path,
                                unsigned int pathLength,
                                unsigned char *privateKey,
                                unsigned char *chain) {

    if (!hsmsim_ecdsa_get_key((unsigned char *)path, privateKey)) {
        THROW(HSMSIM_EXC_INVALID_PATH);
    }
}

int cx_ecdsa_init_private_key(cx_curve_t curve,
                              unsigned char *rawkey,
                              unsigned int key_len,
                              cx_ecfp_private_key_t *key) {

    memmove(key->K, rawkey, key_len);
    return 0; // Return value not used atm
}

int cx_ecfp_generate_pair(cx_curve_t curve,
                          cx_ecfp_public_key_t *pubkey,
                          cx_ecfp_private_key_t *privkey,
                          int keepprivate) {

    secp256k1_pubkey sp_pubkey;

    // Calculate the public key and serialize it uncompressed
    if (!secp256k1_ec_pubkey_create(sp_ctx, &sp_pubkey, privkey->K)) {
        THROW(HSMSIM_EXC_SECP_ERROR);
    }
    size_t pubkey_size = sizeof(pubkey->W);
    secp256k1_ec_pubkey_serialize(
        sp_ctx, pubkey->W, &pubkey_size, &sp_pubkey, SECP256K1_EC_UNCOMPRESSED);
    pubkey->W_len = (unsigned int)pubkey_size;
    return 0; // Return value not used atm
}

int cx_ecdsa_sign(cx_ecfp_private_key_t *key,
                  int mode,
                  cx_md_t hashID,
                  unsigned char *hash,
                  unsigned int hash_len,
                  unsigned char *sig) {

    secp256k1_ecdsa_signature sp_sig;
    size_t sig_serialized_size = MAX_SIGNATURE_LENGTH;

    // Sign and serialize as DER
    secp256k1_ecdsa_sign(sp_ctx, &sp_sig, hash, key->K, NULL, NULL);
    secp256k1_ecdsa_signature_serialize_der(
        sp_ctx, sig, &sig_serialized_size, &sp_sig);

    return (int)sig_serialized_size;
}

size_t hsmsim_helper_getpubkey(const unsigned char *key,
                               unsigned char *dest,
                               size_t dest_size,
                               bool compressed) {
    secp256k1_pubkey pubkey;

    // Calculate the public key and serialize it compressed
    if (!secp256k1_ec_pubkey_create(sp_ctx, &pubkey, key)) {
        return 0;
    }
    secp256k1_ec_pubkey_serialize(sp_ctx,
                                  dest,
                                  &dest_size,
                                  &pubkey,
                                  compressed ? SECP256K1_EC_COMPRESSED
                                             : SECP256K1_EC_UNCOMPRESSED);

    return dest_size;
}

size_t hsmsim_helper_tweak_sign(const unsigned char *key,
                                const unsigned char *tweak,
                                const unsigned char *hash,
                                unsigned char *sig) {
    unsigned char tweaked_key[PRIVATE_KEY_LENGTH];
    secp256k1_ecdsa_signature sp_sig;
    size_t sig_serialized_size = MAX_SIGNATURE_LENGTH;

    // Tweak private key
    memmove(tweaked_key, key, sizeof(tweaked_key));
    if (!secp256k1_ec_privkey_tweak_add(sp_ctx, tweaked_key, tweak))
        return 0;

    // Sign and serialize as DER
    secp256k1_ecdsa_sign(sp_ctx, &sp_sig, hash, tweaked_key, NULL, NULL);
    secp256k1_ecdsa_signature_serialize_der(
        sp_ctx, sig, &sig_serialized_size, &sp_sig);

    return (int)sig_serialized_size;
}

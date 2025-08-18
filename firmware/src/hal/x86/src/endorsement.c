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
#include <secp256k1.h>

#include "hal/constants.h"
#include "hal/endorsement.h"
#include "hal/seed.h"
#include "hal/exceptions.h"
#include "hal/log.h"

#include "random.h"
#include "hmac_sha256.h"
#include "cJSON.h"
#include "json.h"
#include "hex_reader.h"

#define ATTESTATION_KEY_KEY "attestationKey"
#define CODE_HASH_KEY "codeHash"

static secp256k1_context* sp_ctx = NULL;
attestation_id_t attestation_id;

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

/**
 * Write current attestation id in JSON-format to the given path
 */
static bool write_attestation_id_file(char* attid_file_path) {
    cJSON* json = cJSON_CreateObject();

    unsigned long max_size =
        sizeof(attestation_id.key) > sizeof(attestation_id.code_hash)
            ? sizeof(attestation_id.key)
            : sizeof(attestation_id.code_hash);

    char hex_str[max_size * 2 + 1];

    // Write attestation key
    for (int i = 0; i < sizeof(attestation_id.key); i++)
        sprintf(hex_str + i * 2, "%02x", attestation_id.key[i]);
    hex_str[sizeof(attestation_id.key) * 2] = '\0';
    cJSON_AddStringToObject(json, ATTESTATION_KEY_KEY, hex_str);

    // Write code hash
    for (int i = 0; i < sizeof(attestation_id.code_hash); i++)
        sprintf(hex_str + i * 2, "%02x", attestation_id.code_hash[i]);
    hex_str[sizeof(attestation_id.code_hash) * 2] = '\0';
    cJSON_AddStringToObject(json, CODE_HASH_KEY, hex_str);

    return write_json_file(attid_file_path, json);
}

static inline bool read_hex_value_into(cJSON* json,
                                       char* key,
                                       unsigned char* dest) {
    cJSON* entry = cJSON_GetObjectItemCaseSensitive(json, key);
    if (entry == NULL || !cJSON_IsString(entry))
        return false;
    char* hex_value = cJSON_GetStringValue(entry);
    read_hex(hex_value, strlen(hex_value), dest);
    return true;
}

bool endorsement_init(char* att_file_path) {
    // Init the secp256k1 context
    if (!sp_ctx)
        sp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    LOG("Loading endorsement file '%s'\n", att_file_path);
    cJSON* json = read_json_file(att_file_path);

    if (json == NULL) {
        LOG("Endorsement file not found or file format incorrect. Creating a "
            "random endorsement id (key and code hash pair)\n");

        // Init new random key and code hash
        random_getrandom(attestation_id.key, sizeof(attestation_id.key));
        random_getrandom(attestation_id.code_hash,
                         sizeof(attestation_id.code_hash));

        // Write attestation id to the file
        if (!write_attestation_id_file(att_file_path)) {
            LOG("Error writing attestation id to %s\n", att_file_path);
            return false;
        }
        LOG("Attestation id created and saved to %s\n", att_file_path);
    } else {
        // Load attestation id into memory
        if (!cJSON_IsObject(json)) {
            LOG("Expected an object as top level element of %s\n",
                att_file_path);
            return false;
        }

        // Read attestation key
        if (!read_hex_value_into(
                json, ATTESTATION_KEY_KEY, attestation_id.key)) {
            LOG("'%s' not found in '%s'\n", ATTESTATION_KEY_KEY, att_file_path);
            return false;
        }

        // Read code hash
        if (!read_hex_value_into(
                json, CODE_HASH_KEY, attestation_id.code_hash)) {
            LOG("'%s' not found in '%s'\n", CODE_HASH_KEY, att_file_path);
            return false;
        }
    }

    // Grab attestation id public key
    unsigned char pubkey[PUBKEY_CMP_LENGTH];
    if (seed_derive_pubkey_format(attestation_id.key, pubkey, true) !=
        PUBKEY_CMP_LENGTH) {
        LOG("Error getting compressed public key for attestation id key\n");
        return false;
    }
    LOG("Loaded attestation id:\n");
    LOG("\tPublic key: ");
    for (int i = 0; i < sizeof(pubkey); i++)
        LOG("%02x", pubkey[i]);
    LOG("\n");
    LOG("\tCode hash: ");
    for (int i = 0; i < sizeof(attestation_id.code_hash); i++)
        LOG("%02x", attestation_id.code_hash[i]);
    LOG("\n");

    return true;
}

uint8_t* endorsement_get_envelope() {
    return NULL;
}

size_t endorsement_get_envelope_length() {
    return 0;
}

bool endorsement_sign(uint8_t* msg,
                      size_t msg_size,
                      uint8_t* signature_out,
                      uint8_t* signature_out_length) {

    uint8_t pubkey[PUBKEY_UNCMP_LENGTH];
    uint8_t tweak[HMAC_SHA256_SIZE];
    uint8_t hash[HASH_LENGTH];

    if (*signature_out_length < MAX_SIGNATURE_LENGTH) {
        return false;
    }

    sha256(msg, msg_size, hash, sizeof(hash));

    if (seed_derive_pubkey_format(attestation_id.key, pubkey, false) !=
        sizeof(pubkey)) {
        LOG("Error deriving public key for endorsement\n");
        return false;
    }

    if (hmac_sha256(attestation_id.code_hash,
                    sizeof(attestation_id.code_hash),
                    pubkey,
                    sizeof(pubkey),
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
        tweak_sign(attestation_id.key, tweak, hash, signature_out);

    return true;
}

bool endorsement_get_code_hash(uint8_t* code_hash_out,
                               uint8_t* code_hash_out_length) {

    if (*code_hash_out_length < HASH_LENGTH) {
        LOG("Output buffer for code hash too small: %u bytes\n",
            *code_hash_out_length);
        return false;
    }

    memmove(code_hash_out,
            attestation_id.code_hash,
            sizeof(attestation_id.code_hash));
    *code_hash_out_length = sizeof(attestation_id.code_hash);

    return true;
}

bool endorsement_get_public_key(uint8_t* public_key_out,
                                uint8_t* public_key_out_length) {
    uint8_t tempbuf[PUBKEY_UNCMP_LENGTH];

    if (*public_key_out_length < PUBKEY_UNCMP_LENGTH) {
        LOG("Output buffer for public key too small: %u bytes\n",
            *public_key_out_length);
        return false;
    }

    *public_key_out_length =
        seed_derive_pubkey_format(attestation_id.key, tempbuf, false);
    memcpy(public_key_out, tempbuf, *public_key_out_length);

    return true;
}
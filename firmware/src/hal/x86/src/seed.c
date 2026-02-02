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
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <secp256k1.h>

#include "hal/constants.h"
#include "hal/seed.h"
#include "hal/log.h"
#include "random.h"

#include "bip32_path.h"
#include "cJSON.h"
#include "hex_reader.h"
#include "hsmsim_kvstore.h"

#define SEED_DEFAULT_IS_ONBOARDED (true)

typedef struct private_key_mapping_s {
    const char* bip32_path;
    uint8_t binary_path[BIP32_PATH_LENGTH];
    uint8_t key[PRIVATE_KEY_LENGTH];
} private_key_mapping_t;

static seed_data_t seed_data;
static secp256k1_context* sp_ctx = NULL;

#define MAX_PRIVATE_KEYS 10
static private_key_mapping_t private_keys[MAX_PRIVATE_KEYS];
static unsigned int total_private_keys = 0;

/**
 * Write current private keys in JSON-format to the given path
 */
static bool write_key_file(const char* key_file_path) {
    cJSON* json = cJSON_CreateObject();
    char hex_key[sizeof(private_keys[0].key) * 2 + 1];

    for (int i = 0; i < total_private_keys; i++) {
        for (int j = 0; j < sizeof(private_keys[0].key); j++)
            sprintf(hex_key + j * 2, "%02x", private_keys[i].key[j]);
        hex_key[sizeof(hex_key) - 1] = '\0';
        cJSON* json_hex_key = cJSON_CreateString(hex_key);
        cJSON_AddStringToObject(json, private_keys[i].bip32_path, hex_key);
    }

    char* json_s = cJSON_Print(json);
    bool result = hsmsim_kvstore_save((char*)key_file_path, json_s, strlen(json_s));
    cJSON_free(json_s);
    cJSON_Delete(json);
    return result;
}

/**
 * Get the key corresponding to the given path
 */
static bool get_key(uint32_t* path, uint8_t path_length, unsigned char* dest) {
    // TODO: validate path length
    bool found = false;
    for (int i = 0; i < total_private_keys; i++) {
        // Compare paths, skip first byte of stored path (length, not included
        // in the path parameter)
        if (!memcmp(
                path, private_keys[i].binary_path + 1, BIP32_PATH_LENGTH - 1)) {
            found = true;
            memmove(dest, private_keys[i].key, sizeof(private_keys[i].key));
            break;
        }
    }
    return found;
}

uint8_t seed_derive_pubkey_format(const unsigned char* key,
                                  unsigned char* dest,
                                  bool compressed) {
    secp256k1_pubkey pubkey;
    size_t dest_size = compressed ? PUBKEY_CMP_LENGTH : PUBKEY_UNCMP_LENGTH;

    // Calculate the public key and serialize it according to
    // the compressed argument
    if (!secp256k1_ec_pubkey_create(sp_ctx, &pubkey, key)) {
        return 0;
    }

    secp256k1_ec_pubkey_serialize(sp_ctx,
                                  dest,
                                  &dest_size,
                                  &pubkey,
                                  compressed ? SECP256K1_EC_COMPRESSED
                                             : SECP256K1_EC_UNCOMPRESSED);

    return (uint8_t)dest_size;
}

static bool add_bip32_path(const char* bip32_path) {
    private_keys[total_private_keys].bip32_path = bip32_path;
    uint8_t* bpath = private_keys[total_private_keys].binary_path;
    if (bip32_parse_path(bip32_path, bpath) != BIP32_PATH_LENGTH) {
        LOG("Invalid BIP32 path given: %s\n", bip32_path);
        return false;
    }
    total_private_keys++;
    return true;
}

bool seed_init(const char* key_file_path,
               const char* bip32_paths[],
               const size_t bip32_paths_count) {
    // Init the secp256k1 context
    if (!sp_ctx)
        sp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    // Initialize the onboarded value
    seed_data.is_onboarded = SEED_DEFAULT_IS_ONBOARDED;

    // Configure BIP32 paths
    for (int i = 0; i < bip32_paths_count; i++) {
        if (!add_bip32_path((const char*)(bip32_paths[i]))) {
            LOG("Error during seed initialization when trying to add path: "
                "%s\n",
                bip32_paths[i]);
            return false;
        }
    }

    // Load keys
    uint8_t buffer[UINT16_MAX];
    LOG("Loading keys from storage slot '%s'\n", key_file_path);
    size_t buffer_size = hsmsim_kvstore_get((char*)key_file_path, buffer, sizeof(buffer));
    cJSON* json = NULL;
    if (buffer_size) {
        json = cJSON_ParseWithLength(buffer, buffer_size);
    }

    if (json == NULL) {
        LOG("Keyfile not found or file format incorrect. Creating a new "
            "random set of keys\n");
        // Init new random keys
        for (int i = 0; i < total_private_keys; i++) {
            random_getrandom(private_keys[i].key, sizeof(private_keys[i].key));
        }

        // Write keys to the file
        if (!write_key_file(key_file_path)) {
            LOG("Error writing keys to %s\n", key_file_path);
            return false;
        }
        LOG("Keys created and saved to %s\n", key_file_path);
    } else {
        // Load keys into memory
        if (!cJSON_IsObject(json)) {
            LOG("Expected an object as top level element of %s\n",
                key_file_path);
            return false;
        }

        for (int i = 0; i < total_private_keys; i++) {
            cJSON* key_entry = cJSON_GetObjectItemCaseSensitive(
                json, private_keys[i].bip32_path);
            if (key_entry == NULL || !cJSON_IsString(key_entry)) {
                LOG("Path \"%s\" not found in \"%s\"\n",
                    bip32_paths[i],
                    key_file_path);
                return false;
            }
            char* hex_key = cJSON_GetStringValue(key_entry);
            read_hex(hex_key, strlen(hex_key), private_keys[i].key);
        }
    }

    unsigned char pubkey[PUBKEY_CMP_LENGTH];
    LOG("Loaded keys:\n");
    for (int i = 0; i < total_private_keys; i++) {
        if (seed_derive_pubkey_format(private_keys[i].key, pubkey, true) !=
            PUBKEY_CMP_LENGTH) {
            LOG("Error getting public key for path \"%s\"\n",
                private_keys[i].bip32_path);
            return false;
        }
        LOG("\t%s: ", private_keys[i].bip32_path);
        for (int j = 0; j < sizeof(pubkey); j++)
            LOG("%02x", pubkey[j]);
        LOG("\n");
    }

    return true;
}

void seed_set_is_onboarded(bool is_onboarded) {
    seed_data.is_onboarded = is_onboarded;
}

bool seed_available() {
    return seed_data.is_onboarded;
}

bool seed_derive_pubkey(uint32_t* path,
                        uint8_t path_length,
                        uint8_t* pubkey_out,
                        uint8_t* pubkey_out_length) {

    uint8_t key[PRIVATE_KEY_LENGTH];
    if (!get_key(path, path_length, key)) {
        LOG("Invalid path given: %s\n", (unsigned char*)path);
        return false;
    }

    if (*pubkey_out_length < PUBKEY_CMP_LENGTH) {
        LOG("Output buffer for public key too small: %u bytes\n",
            *pubkey_out_length);
        return false;
    }

    *pubkey_out_length = seed_derive_pubkey_format(key, pubkey_out, false);
    if (!(*pubkey_out_length)) {
        LOG("Error deriving public key for path: %s\n", (unsigned char*)path);
        return false;
    }

    return true;
}

bool seed_sign(uint32_t* path,
               uint8_t path_length,
               uint8_t* hash32,
               uint8_t* sig_out,
               uint8_t* sig_out_length) {

    secp256k1_ecdsa_signature sp_sig;
    size_t sig_serialized_size = MAX_SIGNATURE_LENGTH;

    uint8_t key[PRIVATE_KEY_LENGTH];
    if (!get_key(path, path_length, key)) {
        LOG("Invalid path given: %s\n", (unsigned char*)path);
        return false;
    }

    if (*sig_out_length < MAX_SIGNATURE_LENGTH) {
        LOG("Output buffer for signature too small: %u bytes\n",
            *sig_out_length);
        return false;
    }

    // Sign and serialize as DER
    secp256k1_ecdsa_sign(sp_ctx, &sp_sig, hash32, key, NULL, NULL);
    secp256k1_ecdsa_signature_serialize_der(
        sp_ctx, sig_out, &sig_serialized_size, &sp_sig);
    *sig_out_length = (uint8_t)sig_serialized_size;

    return true;
}

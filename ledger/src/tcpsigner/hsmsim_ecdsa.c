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

#include "hsmsim_ecdsa.h"
#include "os_ecdsa.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "hsmsim_random.h"
#include "pathAuth.h"
#include "constants.h"
#include "cJSON.h"
#include "json.h"
#include "hex_reader.h"
#include "log.h"

struct private_key_mapping_s {
    const unsigned char* path;
    unsigned char key[PRIVATE_KEY_LENGTH];
};

static struct private_key_mapping_s private_keys[TOTAL_AUTHORIZED_PATHS];

// Hardcoded BIP32 paths for the JSON keyfile
// (no real use in writing conversion routines to/from binary
// since there's no real use for the paths themselves
// other than serving as map keys)
// The order is based on the 'ordered_paths' constant defined in 'pathAuth.c'
// (which means that if that changes, this should be updated accordingly)
const char bip32_paths[][20] = {
    "m/44'/0'/0'/0/0",   // BTC
    "m/44'/1'/0'/0/0",   // tBTC
    "m/44'/1'/1'/0/0",   // tRSK
    "m/44'/1'/2'/0/0",   // tMST
    "m/44'/137'/0'/0/0", // RSK
    "m/44'/137'/1'/0/0", // MST
};

/**
 * Write current private keys in JSON-format to the given path
 */
static bool write_key_file(char* key_file_path) {
    cJSON* json = cJSON_CreateObject();
    char hex_key[sizeof(private_keys[0].key) * 2 + 1];
    char bip32_path[100];

    for (int i = 0; i < KEY_PATH_COUNT(); i++) {
        for (int j = 0; j < sizeof(private_keys[0].key); j++)
            sprintf(hex_key + j * 2, "%02x", private_keys[i].key[j]);
        hex_key[sizeof(hex_key) - 1] = '\0';
        cJSON* json_hex_key = cJSON_CreateString(hex_key);
        cJSON_AddStringToObject(json, bip32_paths[i], hex_key);
    }

    return write_json_file(key_file_path, json);
}

bool hsmsim_ecdsa_initialize(char* key_file_path) {
    info("Loading key file '%s'\n", key_file_path);
    cJSON* json = read_json_file(key_file_path);

    if (json == NULL) {
        info("Keyfile not found or file format incorrect. Creating a new "
             "random set of keys\n");
        // Init new random keys
        for (int i = 0; i < KEY_PATH_COUNT(); i++) {
            private_keys[i].path = (const unsigned char*)get_ordered_path(i);
            getrandom(private_keys[i].key, sizeof(private_keys[i].key), 0);
        }

        // Write keys to the file
        if (!write_key_file(key_file_path)) {
            info("Error writing keys to %s\n", key_file_path);
            return false;
        }
        info("Keys created and saved to %s\n", key_file_path);
    } else {
        // Load keys into memory
        if (!cJSON_IsObject(json)) {
            info("Expected an object as top level element of %s\n",
                 key_file_path);
            return false;
        }

        for (int i = 0; i < KEY_PATH_COUNT(); i++) {
            cJSON* key_entry =
                cJSON_GetObjectItemCaseSensitive(json, bip32_paths[i]);
            if (key_entry == NULL || !cJSON_IsString(key_entry)) {
                info("Path '%s' not found in '%s'\n",
                     bip32_paths[i],
                     key_file_path);
                return false;
            }
            private_keys[i].path = (const unsigned char*)get_ordered_path(i);
            char* hex_key = cJSON_GetStringValue(key_entry);
            read_hex(hex_key, strlen(hex_key), private_keys[i].key);
        }
    }

    // Init OS ECDSA
    os_ecdsa_initialize();

    unsigned char pubkey[PUBKEY_CMP_LENGTH];
    info("Loaded keys:\n");
    for (int i = 0; i < KEY_PATH_COUNT(); i++) {
        if (hsmsim_helper_getpubkey(
                private_keys[i].key, pubkey, sizeof(pubkey), true) !=
            PUBKEY_CMP_LENGTH) {
            info("Error getting public key for key '%s'\n", bip32_paths[i]);
            return false;
        }
        printf("\t%s: ", bip32_paths[i]);
        for (int j = 0; j < sizeof(pubkey); j++)
            printf("%02x", pubkey[j]);
        printf("\n");
    }

    return true;
}

bool hsmsim_ecdsa_get_key(unsigned char* path, unsigned char* dest) {
    bool found = false;
    for (int i = 0; i < TOTAL_AUTHORIZED_PATHS; i++) {
        // Compare paths, skip first byte of stored path (length, not included
        // in the path parameter)
        if (!memcmp(
                path, private_keys[i].path + 1, SINGLE_PATH_SIZE_BYTES - 1)) {
            found = true;
            memmove(dest, private_keys[i].key, sizeof(private_keys[i].key));
            break;
        }
    }
    return found;
}

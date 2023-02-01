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

#include "hsmsim_attestation.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "hsmsim_random.h"
#include "cJSON.h"
#include "json.h"
#include "hex_reader.h"
#include "os_ecdsa.h"
#include "log.h"

#define ATTESTATION_KEY_KEY "attestationKey"
#define CODE_HASH_KEY "codeHash"

attestation_id_t attestation_id;

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

bool hsmsim_attestation_initialize(char* att_file_path) {
    info("Loading attestation file '%s'\n", att_file_path);
    cJSON* json = read_json_file(att_file_path);

    if (json == NULL) {
        info("Attestation file not found or file format incorrect. Creating a "
             "random attestation id (key and code hash pair)\n");

        // Init new random key and code hash
        getrandom(attestation_id.key, sizeof(attestation_id.key), 0);
        getrandom(
            attestation_id.code_hash, sizeof(attestation_id.code_hash), 0);

        // Write attestation id to the file
        if (!write_attestation_id_file(att_file_path)) {
            info("Error writing attestation id to %s\n", att_file_path);
            return false;
        }
        info("Attestation id created and saved to %s\n", att_file_path);
    } else {
        // Load attestation id into memory
        if (!cJSON_IsObject(json)) {
            info("Expected an object as top level element of %s\n",
                 att_file_path);
            return false;
        }

        // Read attestation key
        if (!read_hex_value_into(
                json, ATTESTATION_KEY_KEY, attestation_id.key)) {
            info(
                "'%s' not found in '%s'\n", ATTESTATION_KEY_KEY, att_file_path);
            return false;
        }

        // Read code hash
        if (!read_hex_value_into(
                json, CODE_HASH_KEY, attestation_id.code_hash)) {
            info("'%s' not found in '%s'\n", CODE_HASH_KEY, att_file_path);
            return false;
        }
    }

    // Init OS ECDSA
    os_ecdsa_initialize();

    // Grab attestation id public key
    unsigned char pubkey[PUBKEY_CMP_LENGTH];
    if (hsmsim_helper_getpubkey(
            attestation_id.key, pubkey, sizeof(pubkey), true) !=
        PUBKEY_CMP_LENGTH) {
        info("Error getting compressed public key for attestation id key\n");
        return false;
    }
    info("Loaded attestation id:\n");
    printf("\tPublic key: ");
    for (int i = 0; i < sizeof(pubkey); i++)
        printf("%02x", pubkey[i]);
    printf("\n");
    printf("\tCode hash: ");
    for (int i = 0; i < sizeof(attestation_id.code_hash); i++)
        printf("%02x", attestation_id.code_hash[i]);
    printf("\n");

    return true;
}

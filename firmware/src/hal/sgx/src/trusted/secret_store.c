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
#include <stdlib.h>

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/seal.h>
#include <sys/mount.h>

#include "hal/platform.h"
#include "hal/log.h"
#include "secret_store.h"
#include "hsm_t.h"

#define SEAL_POLICY_UNIQUE 1
#define SEAL_POLICY_PRODUCT 2

#ifdef DEBUG_BUILD
#define SEAL_POLICY SEAL_POLICY_PRODUCT
#else
#define SEAL_POLICY SEAL_POLICY_UNIQUE
#endif

#define SEST_ERROR (0)

#define MAX_BLOB_SIZE (1024 * 1024)

// To avoid performing dynamic memory allocation whenever we need to read a
// secret, we use this static buffer to temporarily store the sealed blobs we
// read from the untrusted modules.
static uint8_t G_secrets_buffer[MAX_BLOB_SIZE];

// The file format of the sealed secrets. This is the format we use to read and
// write sealed the data to disk.
typedef struct {
    size_t blob_size;
    uint8_t* blob;
} sealed_secret_t;

/**
 * @brief Obtains the plaintext data from a sealed secret.
 *
 * @param sealed_secret The sealed secret to unseal.
 * @param dest The destination buffer for the unsealed data. This must be
 * pre-allocated and large enough to hold the unsealed data.
 * @param dest_length The length of the pre-allocated destination buffer.
 *
 * @returns the length of the unsealed data, or SEST_ERROR upon error
 */
static uint8_t unseal_data(const sealed_secret_t* sealed_secret,
                           uint8_t* dest,
                           size_t dest_length) {
#ifndef SIM_BUILD
    uint8_t* plaintext = NULL;
    size_t plaintext_size = 0;
    oe_result_t result = oe_unseal(sealed_secret->blob,
                                   sealed_secret->blob_size,
                                   NULL,
                                   0,
                                   &plaintext,
                                   &plaintext_size);
    if (result != OE_OK) {
        LOG("Unsealing failed with result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto unseal_data_error;
    }

    if (plaintext_size > dest_length) {
        LOG("Unsealed data is too large\n");
        goto unseal_data_error;
    }

    platform_memmove(dest, plaintext, plaintext_size);
    oe_free(plaintext);
    return plaintext_size;

unseal_data_error:
    if (plaintext)
        oe_free(plaintext);
    return SEST_ERROR;
#else
    // *************************************************** //
    // UNSAFE SIMULATOR-ONLY UNSEAL IMPLEMENTATION         //
    // NOT FOR PRODUCTION USE                              //
    if (sealed_secret->blob_size > MAX_BLOB_SIZE) {
        LOG("Sealed blob size is too large\n");
        return SEST_ERROR;
    }

    if (sealed_secret->blob_size > dest_length) {
        LOG("Unsealed data is too large\n");
        return SEST_ERROR;
    }

    platform_memmove(dest, sealed_secret->blob, sealed_secret->blob_size);

    return sealed_secret->blob_size;
    // *************************************************** //
#endif
}

/**
 * @brief Seals the given data into a sealed secret.
 *
 * @param data The data to seal.
 * @param data_length The length of the data to seal.
 * @param sealed_secret The destination for the sealed secret.
 */
static bool seal_data(uint8_t* data,
                      size_t data_length,
                      sealed_secret_t* sealed_secret) {
#ifndef SIM_BUILD
    uint8_t* blob = NULL;
    size_t blob_size = 0;
    const oe_seal_setting_t settings[] = {OE_SEAL_SET_POLICY(SEAL_POLICY)};
    oe_result_t result = oe_seal(NULL,
                                 settings,
                                 sizeof(settings) / sizeof(settings[0]),
                                 data,
                                 data_length,
                                 NULL,
                                 0,
                                 &blob,
                                 &blob_size);
    if (result != OE_OK) {
        LOG("Sealing failed with result=%u (%s)\n",
            result,
            oe_result_str(result));
        oe_free(blob);
        return false;
    }

    sealed_secret->blob = blob;
    sealed_secret->blob_size = blob_size;
    return true;
#else
    // *************************************************** //
    // UNSAFE SIMULATOR-ONLY SEAL IMPLEMENTATION           //
    // NOT FOR PRODUCTION USE                              //
    sealed_secret->blob = oe_malloc(data_length);
    memcpy(sealed_secret->blob, data, data_length);
    sealed_secret->blob_size = data_length;
    return true;
    // *************************************************** //
#endif
}

// Public API
bool sest_init() {
    explicit_bzero(G_secrets_buffer, sizeof(G_secrets_buffer));
    return true;
}

bool sest_exists(char* key) {
    LOG("Attempting determine secret existence for <%s>...\n", key);

    bool exists;
    oe_result_t oe_result = ocall_kvstore_exists(&exists, key);

    if (oe_result != OE_OK) {
        LOG("Key-value store exists query failed with result=%u (%s)\n",
            oe_result,
            oe_result_str(oe_result));
        return false;
    }

    return exists;
}

uint8_t sest_read(char* key, uint8_t* dest, size_t dest_length) {
    LOG("Attempting to read secret for <%s>...\n", key);

    size_t blob_size = 0;
    oe_result_t oe_result = ocall_kvstore_get(
        &blob_size, key, G_secrets_buffer, sizeof(G_secrets_buffer));
    if (oe_result != OE_OK) {
        LOG("Key-value store read failed with result=%u (%s)\n",
            oe_result,
            oe_result_str(oe_result));
        return SEST_ERROR;
    }

    if (!blob_size) {
        LOG("No secret found for key <%s>\n", key);
        return SEST_ERROR;
    }

    // This is just an extra sanity check, this can never happen in
    // practice since the ocall will fail if the blob size
    // is too large for the buffer.
    if (blob_size > sizeof(G_secrets_buffer)) {
        LOG("Sealed blob too large\n");
        return SEST_ERROR;
    }

    sealed_secret_t sealed_secret = {
        .blob_size = blob_size,
        .blob = G_secrets_buffer,
    };

    uint8_t plaintext_length = unseal_data(&sealed_secret, dest, dest_length);
    if (plaintext_length == SEST_ERROR) {
        LOG("Unable to read secret stored in key <%s>\n", key);
        return SEST_ERROR;
    }

    // Clean up the buffer just in case.
    explicit_bzero(G_secrets_buffer, sizeof(G_secrets_buffer));

    return plaintext_length;
}

bool sest_write(char* key, uint8_t* secret, size_t secret_length) {
    LOG("Attempting to write secret for <%s>...\n", key);
    if (!secret_length) {
        LOG("Invalid zero-length secret given for key <%s>\n", key);
        return false;
    }

    sealed_secret_t sealed_secret = {
        .blob_size = 0,
        .blob = NULL,
    };

    if (!seal_data(secret, secret_length, &sealed_secret)) {
        LOG("Error sealing secret for key <%s>\n", key);
        return false;
    }

    if (sealed_secret.blob_size > MAX_BLOB_SIZE) {
        LOG("Sealed blob too large\n");
        goto sest_write_error;
    }

    bool save_success = false;
    oe_result_t oe_result = ocall_kvstore_save(
        &save_success, key, sealed_secret.blob, sealed_secret.blob_size);
    if (oe_result != OE_OK) {
        LOG("Key-value store write failed with result=%u (%s)\n",
            oe_result,
            oe_result_str(oe_result));
        goto sest_write_error;
    }

    if (!save_success) {
        LOG("Error saving secret for key <%s>\n", key);
        goto sest_write_error;
    }

    oe_free(sealed_secret.blob);
    return true;

sest_write_error:
    if (sealed_secret.blob)
        oe_free(sealed_secret.blob);
    return false;
}

bool sest_remove(char* key) {
    bool remove_success = false;
    oe_result_t oe_result = ocall_kvstore_remove(&remove_success, key);
    if (oe_result != OE_OK) {
        LOG("ocall_oestore_remove_secret() failed with result=%u (%s)\n",
            oe_result,
            oe_result_str(oe_result));
        return false;
    }

    if (!remove_success) {
        LOG("Error removing secret for key <%s>\n", key);
        return false;
    }

    return true;
}

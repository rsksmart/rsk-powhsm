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
#include "keyvalue_db.h"
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
#define MAX_VALUE_SIZE (1024)

#define SEST_DB_KEY "database"

// In-memory cache of the sealed database blob loaded at initialization.
static uint8_t G_sealed_blob[MAX_BLOB_SIZE];
static size_t G_sealed_blob_size = 0;
static bool G_initialized = false;

static bool unseal_data(const uint8_t* sealed_data,
                        size_t sealed_data_size,
                        uint8_t* unsealed_data,
                        size_t* unsealed_data_size) {
    if (!unsealed_data || !unsealed_data_size)
        return false;

    size_t unsealed_data_capacity = *unsealed_data_size;
    *unsealed_data_size = 0;

#ifndef SIM_BUILD
    uint8_t* tmp_unsealed_data = NULL;
    size_t tmp_unsealed_data_size = 0;
    oe_result_t result = oe_unseal(sealed_data,
                                   sealed_data_size,
                                   NULL,
                                   0,
                                   &tmp_unsealed_data,
                                   &tmp_unsealed_data_size);
    if (result != OE_OK) {
        DEBUG("Unsealing failed with result=%u (%s)\n",
              result,
              oe_result_str(result));
        goto unseal_data_error;
    }

    if (tmp_unsealed_data_size > unsealed_data_capacity) {
        DEBUG("Unsealed data is too large\n");
        goto unseal_data_error;
    }

    platform_memmove(unsealed_data, tmp_unsealed_data, tmp_unsealed_data_size);
    *unsealed_data_size = tmp_unsealed_data_size;
    oe_free(tmp_unsealed_data);
    return true;

unseal_data_error:
    if (tmp_unsealed_data)
        oe_free(tmp_unsealed_data);
    return false;
#else
    // *************************************************** //
    // UNSAFE SIMULATOR-ONLY UNSEAL IMPLEMENTATION         //
    // NOT FOR PRODUCTION USE                              //
    if (sealed_data_size > unsealed_data_capacity) {
        DEBUG("Unsealed data is too large\n");
        return false;
    }

    platform_memmove(unsealed_data, sealed_data, sealed_data_size);
    *unsealed_data_size = sealed_data_size;

    return true;
    // *************************************************** //
#endif
}

static bool seal_data(uint8_t* data,
                      size_t data_size,
                      uint8_t* sealed_data,
                      size_t* sealed_data_size) {
    if (!sealed_data || !sealed_data_size)
        return false;

#ifndef SIM_BUILD
    uint8_t* tmp_sealed_data = NULL;
    size_t tmp_sealed_data_size = 0;
    const oe_seal_setting_t settings[] = {OE_SEAL_SET_POLICY(SEAL_POLICY)};
    oe_result_t result = oe_seal(NULL,
                                 settings,
                                 sizeof(settings) / sizeof(settings[0]),
                                 data,
                                 data_size,
                                 NULL,
                                 0,
                                 &tmp_sealed_data,
                                 &tmp_sealed_data_size);
    if (result != OE_OK) {
        DEBUG("Sealing failed with result=%u (%s)\n",
              result,
              oe_result_str(result));
        goto seal_data_error;
    }

    if (tmp_sealed_data_size > MAX_BLOB_SIZE) {
        DEBUG("Sealed blob too large\n");
        goto seal_data_error;
    }

    memcpy(sealed_data, tmp_sealed_data, tmp_sealed_data_size);
    *sealed_data_size = tmp_sealed_data_size;
    oe_free(tmp_sealed_data);

    return true;

seal_data_error:
    if (tmp_sealed_data)
        oe_free(tmp_sealed_data);
    return false;
#else
    // *************************************************** //
    // UNSAFE SIMULATOR-ONLY SEAL IMPLEMENTATION           //
    // NOT FOR PRODUCTION USE                              //
    memcpy(sealed_data, data, data_size);
    *sealed_data_size = data_size;
    return true;
    // *************************************************** //
#endif
}

static bool load_database_blob(uint8_t* sealed_db,
                               size_t sealed_db_capacity,
                               size_t* sealed_db_size) {
    if (!sealed_db || !sealed_db_size)
        return false;

    explicit_bzero(sealed_db, sealed_db_capacity);

    size_t sealed_db_size_from_store = 0;
    oe_result_t oe_result = ocall_kvstore_get(&sealed_db_size_from_store,
                                              (char*)SEST_DB_KEY,
                                              sealed_db,
                                              sealed_db_capacity);
    if (oe_result != OE_OK) {
        DEBUG("Key-value store read failed with result=%u (%s)\n",
              oe_result,
              oe_result_str(oe_result));
        return false;
    }

    if (sealed_db_size_from_store == 0) {
        *sealed_db_size = 0;
        return true;
    }

    if (sealed_db_size_from_store > sealed_db_capacity) {
        DEBUG("Sealed blob too large\n");
        return false;
    }

    *sealed_db_size = sealed_db_size_from_store;
    return true;
}

static bool init_db(keyvalue_db_t* db) {
    if (!db)
        return false;

    db->buffer = malloc(MAX_BLOB_SIZE);
    db->capacity = MAX_BLOB_SIZE;
    db->size = 0;

    if (!db->buffer)
        return false;

    if (G_sealed_blob_size == 0) {
        if (!kvdb_new(db))
            goto init_db_error;
        return true;
    }

    size_t db_size = db->capacity;
    if (!unseal_data(G_sealed_blob, G_sealed_blob_size, db->buffer, &db_size))
        goto init_db_error;

    db->size = db_size;
    return true;

init_db_error:
    explicit_bzero(db->buffer, db->capacity);
    free(db->buffer);
    db->buffer = NULL;
    db->capacity = 0;
    db->size = 0;
    return false;
}

static bool save_db(const keyvalue_db_t* db) {
    if (!db || !db->buffer)
        return false;

    static uint8_t sealed_data[MAX_BLOB_SIZE] = {0};
    explicit_bzero(sealed_data, sizeof(sealed_data));
    size_t sealed_data_size = 0;

    if (!seal_data(db->buffer, db->size, sealed_data, &sealed_data_size)) {
        DEBUG("Error sealing database\n");
        return false;
    }

    bool save_success = false;
    oe_result_t oe_result = ocall_kvstore_save(
        &save_success, (char*)SEST_DB_KEY, sealed_data, sealed_data_size);

    if (oe_result != OE_OK) {
        DEBUG("Key-value store write failed with result=%u (%s)\n",
              oe_result,
              oe_result_str(oe_result));
        return false;
    }

    if (!save_success) {
        DEBUG("Error saving secret database\n");
        return false;
    }

    memcpy(G_sealed_blob, sealed_data, sealed_data_size);
    G_sealed_blob_size = sealed_data_size;

    return true;
}

static void free_db(keyvalue_db_t* db) {
    if (!db)
        return;

    if (db->buffer) {
        explicit_bzero(db->buffer, db->capacity);
        free(db->buffer);
    }

    db->buffer = NULL;
    db->capacity = 0;
    db->size = 0;
}

// Public API
bool sest_init() {
    if (G_initialized)
        return true;

    if (!load_database_blob(
            G_sealed_blob, sizeof(G_sealed_blob), &G_sealed_blob_size)) {
        return false;
    }

    keyvalue_db_t db = {0};
    if (!init_db(&db))
        return false;

    if (!kvdb_check(&db)) {
        free_db(&db);
        return false;
    }

    free_db(&db);

    G_initialized = true;

    return true;
}

bool sest_exists(char* key) {
    if (!G_initialized)
        return false;

    INFO("Attempting determine secret existence for <%s>...\n", key);

    keyvalue_db_t db = {0};
    if (!init_db(&db))
        return false;

    size_t tmp_value_capacity = MAX_VALUE_SIZE;
    uint8_t* tmp_value = malloc(tmp_value_capacity);
    if (!tmp_value) {
        free_db(&db);
        return false;
    }

    size_t value_length = tmp_value_capacity;
    bool found = kvdb_get(&db, key, tmp_value, &value_length);
    explicit_bzero(tmp_value, tmp_value_capacity);
    free(tmp_value);
    free_db(&db);
    return found;
}

size_t sest_read(char* key, uint8_t* dest, size_t dest_length) {
    if (!G_initialized)
        return SEST_ERROR;

    if (!dest || !dest_length) {
        DEBUG("Invalid arguments for read\n");
        return SEST_ERROR;
    }

    INFO("Attempting to read secret for <%s>...\n", key);

    keyvalue_db_t db = {0};
    if (!init_db(&db))
        return SEST_ERROR;

    size_t value_length = dest_length;
    if (!kvdb_get(&db, key, dest, &value_length)) {
        free_db(&db);
        INFO("No secret found for key <%s>\n", key);
        return SEST_ERROR;
    }

    free_db(&db);
    return value_length;
}

bool sest_write(char* key, uint8_t* secret, size_t secret_length) {
    if (!G_initialized)
        return false;

    if (!secret || !secret_length) {
        DEBUG("Invalid arguments for write\n");
        return false;
    }

    if (secret_length > MAX_VALUE_SIZE) {
        DEBUG("Secret too large\n");
        return false;
    }

    INFO("Attempting to write secret for <%s>...\n", key);

    keyvalue_db_t db = {0};
    if (!init_db(&db))
        return false;

    if (!kvdb_upsert(&db, key, secret, secret_length)) {
        free_db(&db);
        return false;
    }

    bool success = save_db(&db);
    free_db(&db);
    return success;
}

bool sest_remove(char* key) {
    if (!G_initialized)
        return false;

    keyvalue_db_t db = {0};
    if (!init_db(&db))
        return false;

    if (!kvdb_remove(&db, key)) {
        free_db(&db);
        return false;
    }

    bool success = save_db(&db);
    free_db(&db);
    if (!success)
        return false;

    return true;
}

#ifdef SEST_TEST_ONLY
// Test-only hook used by unit tests to reset module static state between cases.
void sest_reset_for_tests() {
    explicit_bzero(G_sealed_blob, sizeof(G_sealed_blob));
    G_sealed_blob_size = 0;
    G_initialized = false;
}
#endif

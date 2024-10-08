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

#include <assert.h>
#include <string.h>
#include "mock_seal.h"
#include "assert_utils.h"

// The maximum allowed blob size, as defined in secret_store.c
#define MAX_BLOB_SIZE (1024 * 1024)

// A prefix added to sealed blobs in this mock implementation.
// This is just to keep things simple and easily distinguishable.
#define SEALED_PREFIX "SEALED - "

// Captures the arguments passed to oe_seal
typedef struct oe_seal_args {
    const void* plugin_id;
    oe_seal_setting_t settings;
    size_t settings_count;
    const uint8_t* plaintext;
    size_t plaintext_size;
    const uint8_t* additional_data;
    size_t additional_data_size;
} oe_seal_args_t;

// Captures the arguments passed to oe_unseal
typedef struct oe_unseal_args {
    uint8_t blob[MAX_BLOB_SIZE];
    size_t blob_size;
    const uint8_t* additional_data;
    size_t additional_data_size;
} oe_unseal_args_t;

// Global variables to capture the arguments passed to oe_seal and oe_unseal
static oe_seal_args_t G_oe_seal_args;
static oe_unseal_args_t G_oe_unseal_args;
// The next failure type to simulate
mock_seal_failure_type_t G_next_failure = SEAL_FAILURE_NONE;

void mock_seal_init() {
    memset(&G_oe_seal_args, 0, sizeof(G_oe_seal_args));
    memset(&G_oe_unseal_args, 0, sizeof(G_oe_unseal_args));
    G_next_failure = SEAL_FAILURE_NONE;
}

oe_result_t mock_oe_seal(const void* plugin_id,
                         const oe_seal_setting_t* settings,
                         size_t settings_count,
                         const uint8_t* plaintext,
                         size_t plaintext_size,
                         const uint8_t* additional_data,
                         size_t additional_data_size,
                         uint8_t** blob,
                         size_t* blob_size) {
    G_oe_seal_args.plugin_id = plugin_id;
    memcpy(&G_oe_seal_args.settings, settings, sizeof(oe_seal_setting_t));
    G_oe_seal_args.settings_count = settings_count;
    G_oe_seal_args.plaintext = plaintext;
    G_oe_seal_args.plaintext_size = plaintext_size;
    G_oe_seal_args.additional_data = additional_data;
    G_oe_seal_args.additional_data_size = additional_data_size;

    if (G_next_failure == SEAL_FAILURE_OE_FAILURE) {
        G_next_failure = SEAL_FAILURE_NONE;
        return OE_FAILURE;
    }

    size_t prefix_length = strlen(SEALED_PREFIX);
    *blob_size = plaintext_size + prefix_length;
    *blob = malloc(*blob_size);
    assert(*blob != NULL);
    memcpy(*blob, SEALED_PREFIX, prefix_length);
    memcpy(*blob + prefix_length, plaintext, plaintext_size);

    return OE_OK;
}

oe_result_t mock_oe_unseal(const uint8_t* blob,
                           size_t blob_size,
                           const uint8_t* additional_data,
                           size_t additional_data_size,
                           uint8_t** plaintext,
                           size_t* plaintext_size) {
    memcpy(G_oe_unseal_args.blob, blob, blob_size);
    G_oe_unseal_args.blob_size = blob_size;
    G_oe_unseal_args.additional_data = additional_data;
    G_oe_unseal_args.additional_data_size = additional_data_size;

    switch (G_next_failure) {
    case SEAL_FAILURE_OE_FAILURE:
        G_next_failure = SEAL_FAILURE_NONE;
        return OE_FAILURE;
    case SEAL_FAILURE_OE_UNSEAL_PLAINTEXT_TOO_LARGE:
        *plaintext_size = MAX_BLOB_SIZE + 1;
        G_next_failure = SEAL_FAILURE_NONE;
        break;
    case SEAL_FAILURE_NONE:
        *plaintext_size = blob_size - strlen(SEALED_PREFIX);
        break;
    default:
        assert(false);
        break;
    }

    *plaintext = malloc(*plaintext_size);
    assert(*plaintext != NULL);
    memcpy(*plaintext, blob + strlen(SEALED_PREFIX), *plaintext_size);

    return OE_OK;
}

void assert_oe_seal_called_with(const void* plugin_id,
                                const oe_seal_setting_t* settings,
                                size_t settings_count,
                                const uint8_t* plaintext,
                                size_t plaintext_size,
                                const uint8_t* additional_data,
                                size_t additional_data_size) {
    assert(G_oe_seal_args.plugin_id == plugin_id &&
           memcmp(&G_oe_seal_args.settings, settings, sizeof(*settings)) == 0 &&
           G_oe_seal_args.settings_count == settings_count &&
           G_oe_seal_args.plaintext == plaintext &&
           G_oe_seal_args.plaintext_size == plaintext_size &&
           G_oe_seal_args.additional_data == additional_data &&
           G_oe_seal_args.additional_data_size == additional_data_size);
}

void assert_oe_unseal_called_with(const uint8_t* blob,
                                  size_t blob_size,
                                  const uint8_t* additional_data,
                                  size_t additional_data_size) {
    assert((memcmp(blob, G_oe_unseal_args.blob, blob_size) == 0) &&
           G_oe_unseal_args.blob_size == blob_size &&
           G_oe_unseal_args.additional_data == additional_data &&
           G_oe_unseal_args.additional_data_size == additional_data_size);
}

void assert_oe_unseal_not_called() {
    ASSERT_ARRAY_CLEARED(G_oe_unseal_args.blob);
    assert(G_oe_unseal_args.blob_size == 0);
    assert(G_oe_unseal_args.additional_data == NULL);
    assert(G_oe_unseal_args.additional_data_size == 0);
}

void assert_oe_seal_not_called() {
    assert(G_oe_seal_args.plugin_id == NULL);
    assert(G_oe_seal_args.settings.policy == 0);
    assert(G_oe_seal_args.settings_count == 0);
    assert(G_oe_seal_args.plaintext == NULL);
    assert(G_oe_seal_args.plaintext_size == 0);
    assert(G_oe_seal_args.additional_data == NULL);
    assert(G_oe_seal_args.additional_data_size == 0);
}

void mock_seal_fail_next(mock_seal_failure_type_t failure) {
    G_next_failure = failure;
}

size_t mock_seal_get_max_plaintext_size() {
    return MAX_BLOB_SIZE - strlen(SEALED_PREFIX);
}

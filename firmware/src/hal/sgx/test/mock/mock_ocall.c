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

#include <string.h>
#include "openenclave/common.h"
#include "mock_ocall.h"

// Maximum size of a sealed blob, as defined in secret_store.c
#define MAX_BLOB_SIZE (1024 * 1024)

// Trivial key-value store implementation for testing purposes
// This key-value store is only capable of storing a single key-value pair
static char G_kvstore_key[256];
static uint8_t G_kvstore_data[256];
static size_t G_kvstore_data_size;
// The type of failure to simulate on the next call to the mock implementation
static mock_kvstore_failure_type_t G_next_failure;

void mock_ocall_init() {
    memset(G_kvstore_key, 0, sizeof(G_kvstore_key));
    memset(G_kvstore_data, 0, sizeof(G_kvstore_data));
    G_kvstore_data_size = 0;
    G_next_failure = KVSTORE_FAILURE_NONE;
}

oe_result_t ocall_kvstore_save(bool* _retval,
                               char* key,
                               uint8_t* data,
                               size_t data_size) {
    if (G_next_failure == KVSTORE_FAILURE_SAVE) {
        G_next_failure = KVSTORE_FAILURE_NONE;
        *_retval = false;
        return OE_OK;
    } else if (G_next_failure == KVSTORE_FAILURE_OE_FAILURE) {
        G_next_failure = KVSTORE_FAILURE_NONE;
        return OE_FAILURE;
    }

    strcpy(G_kvstore_key, key);
    memcpy(G_kvstore_data, data, data_size);
    G_kvstore_data_size = data_size;
    *_retval = true;
    return OE_OK;
}

oe_result_t ocall_kvstore_exists(bool* _retval, char* key) {
    if (G_next_failure == KVSTORE_FAILURE_OE_FAILURE) {
        G_next_failure = KVSTORE_FAILURE_NONE;
        return OE_FAILURE;
    }

    *_retval = (strcmp(key, G_kvstore_key) == 0);
    return OE_OK;
}

oe_result_t ocall_kvstore_get(size_t* _retval,
                              char* key,
                              uint8_t* data_buf,
                              size_t buffer_size) {
    if (G_next_failure == KVSTORE_FAILURE_OE_FAILURE) {
        G_next_failure = KVSTORE_FAILURE_NONE;
        return OE_FAILURE;
    }

    if (strcmp(key, G_kvstore_key) == 0) {
        if (G_next_failure == KVSTORE_FAILURE_GET_SEALED_BLOB_TOO_LARGE) {
            // Return a blob size that exceeds the limit allowed by the caller
            G_next_failure = KVSTORE_FAILURE_NONE;
            *_retval = MAX_BLOB_SIZE + 1;
        } else {
            *_retval = G_kvstore_data_size;
        }
        memcpy(data_buf, G_kvstore_data, G_kvstore_data_size);
    } else {
        *_retval = 0;
    }
    return OE_OK;
}

oe_result_t ocall_kvstore_remove(bool* _retval, char* key) {
    if (G_next_failure == KVSTORE_FAILURE_OE_FAILURE) {
        G_next_failure = KVSTORE_FAILURE_NONE;
        return OE_FAILURE;
    }
    if (strcmp(key, G_kvstore_key) == 0) {
        memset(G_kvstore_key, 0, sizeof(G_kvstore_key));
        memset(G_kvstore_data, 0, sizeof(G_kvstore_data));
        G_kvstore_data_size = 0;
        *_retval = true;
    } else {
        *_retval = false;
    }
    return OE_OK;
}

void mock_ocall_kvstore_fail_next(mock_kvstore_failure_type_t failure) {
    G_next_failure = failure;
}

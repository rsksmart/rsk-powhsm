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

#ifndef __MOCK_OCALL_H
#define __MOCK_OCALL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "openenclave/common.h"

// Types of failures that can be simulated in this mock implementation
typedef enum mock_kvstore_failure_type {
    KVSTORE_FAILURE_NONE,
    KVSTORE_FAILURE_SAVE,
    KVSTORE_FAILURE_GET_SEALED_BLOB_TOO_LARGE,
    KVSTORE_FAILURE_OE_FAILURE,
} mock_kvstore_failure_type_t;

/**
 * @brief Initializes the mock ocall implementation
 */
void mock_ocall_init();

/**
 * @brief Mock implementation of ocall_kvstore_save
 */
oe_result_t ocall_kvstore_save(bool* _retval,
                               char* key,
                               uint8_t* data,
                               size_t data_size);

/**
 * @brief Mock implementation of ocall_kvstore_exists
 */
oe_result_t ocall_kvstore_exists(bool* _retval, char* key);

/**
 * @brief Mock implementation of ocall_kvstore_get
 */
oe_result_t ocall_kvstore_get(size_t* _retval,
                              char* key,
                              uint8_t* data_buf,
                              size_t buffer_size);

/**
 * @brief Mock implementation of ocall_kvstore_remove
 */
oe_result_t ocall_kvstore_remove(bool* _retval, char* key);

/**
 * @brief Simulates a failure on the next call to this mock implementation
 *
 * @param failure the type of failure to simulate
 */
void mock_ocall_kvstore_fail_next(mock_kvstore_failure_type_t failure);

#endif // __MOCK_OCALL_H
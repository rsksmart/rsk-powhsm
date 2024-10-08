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

#ifndef __MOCK_SEAL_H
#define __MOCK_SEAL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "openenclave/common.h"
#include "openenclave/seal.h"

/**
 * @brief Initializes the mock seal implementation
 */
void mock_seal_init();

/**
 * @brief Mock implementation of oe_seal API function
 */
oe_result_t mock_oe_seal(const void* plugin_id,
                         const oe_seal_setting_t* settings,
                         size_t settings_count,
                         const uint8_t* plaintext,
                         size_t plaintext_size,
                         const uint8_t* additional_data,
                         size_t additional_data_size,
                         uint8_t** blob,
                         size_t* blob_size);

/**
 * @brief Mock implementation of oe_unseal API function
 */
oe_result_t mock_oe_unseal(const uint8_t* blob,
                           size_t blob_size,
                           const uint8_t* additional_data,
                           size_t additional_data_size,
                           uint8_t** plaintext,
                           size_t* plaintext_size);

/**
 * @brief Asserts that the last call to oe_seal was made with the expected
 * parameters
 */
void assert_oe_seal_called_with(const void* plugin_id,
                                const oe_seal_setting_t* settings,
                                size_t settings_count,
                                const uint8_t* plaintext,
                                size_t plaintext_size,
                                const uint8_t* additional_data,
                                size_t additional_data_size);

/**
 * @brief Asserts that the last call to oe_unseal was made with the expected
 * parameters
 */
void assert_oe_unseal_called_with(const uint8_t* blob,
                                  size_t blob_size,
                                  const uint8_t* additional_data,
                                  size_t additional_data_size);

/**
 * @brief Asserts that oe_unseal was not called since the mock was initialized
 */
void assert_oe_unseal_not_called();

/**
 * @brief Asserts that oe_seal was not called since the mock was initialized
 */
void assert_oe_seal_not_called();

/**
 * @brief Simulates a failure on the next call to this mock implementation
 */
void mock_seal_fail_next();

#endif // #ifndef __MOCK_SEAL_H

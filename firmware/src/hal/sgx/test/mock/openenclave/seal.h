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

#ifndef __MOCK_OE_SEAL_H
#define __MOCK_OE_SEAL_H

#include <stdlib.h>
#include <stdint.h>
#include "common.h"

// Simplified version of the seal settings type. This is only used to ensure
// that the API was called with the expected parameters.
typedef struct {
    int policy;
} oe_seal_setting_t;

#define OE_SEAL_SET_POLICY(policy) \
    { (int)(policy) }

oe_result_t oe_seal(const void* plugin_id,
                    const oe_seal_setting_t* settings,
                    size_t settings_count,
                    const uint8_t* plaintext,
                    size_t plaintext_size,
                    const uint8_t* additional_data,
                    size_t additional_data_size,
                    uint8_t** blob,
                    size_t* blob_size);

oe_result_t oe_unseal(const uint8_t* blob,
                      size_t blob_size,
                      const uint8_t* additional_data,
                      size_t additional_data_size,
                      uint8_t** plaintext,
                      size_t* plaintext_size);

#endif // #ifndef __MOCK_OE_SEAL_H
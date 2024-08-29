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

#ifndef __ENCLAVE_PROVIDER_H
#define __ENCLAVE_PROVIDER_H

#include <openenclave/host.h>

/**
 * @brief Initializes the enclave provider with the given enclave binary path
 * 
 * @returns Whether initialization succeeded
 */
bool ep_init(char* enclave_path);

/**
 * @brief Returns a pointer to the HSM enclave. This function should always 
 * return a valid pointer to the enclave, which can be used to perform 
 * ecall operations.
 * 
 * @returns A valid pointer to the HSM enclave, or NULL if an error occurred
 */
oe_enclave_t* ep_get_enclave();

/**
 * @brief Terminates the HSM enclave. After this function is called,
 * all ecall operations will fail.
 */
void ep_finalize_enclave();

#endif // __ENCLAVE_PROVIDER_H

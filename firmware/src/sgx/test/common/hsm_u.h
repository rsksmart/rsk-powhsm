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

#ifndef __MOCK_HSM_U_H
#define __MOCK_HSM_U_H

#include <openenclave/host.h>

oe_result_t oe_create_hsm_enclave(const char* path,
                                  oe_enclave_type_t type,
                                  uint32_t flags,
                                  const oe_enclave_setting_t* settings,
                                  uint32_t setting_count,
                                  oe_enclave_t** enclave);

oe_result_t ecall_system_init(oe_enclave_t* enclave,
                              bool* _retval,
                              unsigned char* msg_buffer,
                              size_t msg_buffer_size);

oe_result_t ecall_system_finalise(oe_enclave_t* enclave);

oe_result_t ecall_system_process_apdu(oe_enclave_t* enclave,
                                      unsigned int* _retval,
                                      unsigned int rx);

bool ocall_kvstore_save(char* key, uint8_t* data, size_t data_size);

bool ocall_kvstore_exists(char* key);

size_t ocall_kvstore_get(char* key, uint8_t* data_buf, size_t buffer_size);

bool ocall_kvstore_remove(char* key);

#endif // __MOCK_HSM_U_H
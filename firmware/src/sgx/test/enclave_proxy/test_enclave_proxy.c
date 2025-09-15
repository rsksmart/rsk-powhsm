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
#include <assert.h>
#include <string.h>
#include <openenclave/host.h>

#include "hsm_u.h"
#include "enclave_proxy.h"

#define MOCK_ENCLAVE_PTR ((oe_enclave_t*)0x12345678)

// Mocks
struct {
    oe_result_t ecall_system_init_result;
    bool ecall_system_init_retval;
    oe_result_t ecall_system_finalise_result;
    oe_result_t ecall_system_process_apdu_result;
    unsigned int ecall_system_process_apdu_retval;
    oe_enclave_t* epro_get_enclave_result;
    bool kvstore_save_result;
    bool kvstore_exists_result;
    size_t kvstore_get_result;
    bool kvstore_remove_result;
} G_mocks;

struct {
    bool ecall_system_init;
    bool ecall_system_finalise;
    bool ecall_system_process_apdu;
    bool epro_get_enclave;
    bool kvstore_save;
    bool kvstore_exists;
    bool kvstore_get;
    bool kvstore_remove;
} G_called;

struct {
    struct {
        oe_enclave_t* enclave;
        bool* _retval;
        unsigned char* msg_buffer;
        size_t msg_buffer_size;
    } ecall_system_init;

    struct {
        oe_enclave_t* enclave;
    } ecall_system_finalise;

    struct {
        oe_enclave_t* enclave;
        unsigned int* _retval;
        unsigned int rx;
    } ecall_system_process_apdu;

    struct {
        char* key;
        uint8_t* data;
        size_t data_size;
    } kvstore_save;

    struct {
        char* key;
    } kvstore_exists;

    struct {
        char* key;
        uint8_t* data_buf;
        size_t buffer_size;
    } kvstore_get;

    struct {
        char* key;
    } kvstore_remove;
} G_args;

// Mock implementations
oe_result_t ecall_system_init(oe_enclave_t* enclave,
                              bool* _retval,
                              unsigned char* msg_buffer,
                              size_t msg_buffer_size) {
    G_called.ecall_system_init = true;
    G_args.ecall_system_init.enclave = enclave;
    G_args.ecall_system_init._retval = _retval;
    G_args.ecall_system_init.msg_buffer = msg_buffer;
    G_args.ecall_system_init.msg_buffer_size = msg_buffer_size;

    if (_retval) {
        *_retval = G_mocks.ecall_system_init_retval;
    }

    return G_mocks.ecall_system_init_result;
}

oe_result_t ecall_system_finalise(oe_enclave_t* enclave) {
    G_called.ecall_system_finalise = true;
    G_args.ecall_system_finalise.enclave = enclave;
    return G_mocks.ecall_system_finalise_result;
}

oe_result_t ecall_system_process_apdu(oe_enclave_t* enclave,
                                      unsigned int* _retval,
                                      unsigned int rx) {
    G_called.ecall_system_process_apdu = true;
    G_args.ecall_system_process_apdu.enclave = enclave;
    G_args.ecall_system_process_apdu._retval = _retval;
    G_args.ecall_system_process_apdu.rx = rx;

    if (_retval) {
        *_retval = G_mocks.ecall_system_process_apdu_retval;
    }

    return G_mocks.ecall_system_process_apdu_result;
}

oe_enclave_t* epro_get_enclave() {
    G_called.epro_get_enclave = true;
    return G_mocks.epro_get_enclave_result;
}

bool kvstore_save(char* key, uint8_t* data, size_t data_size) {
    G_called.kvstore_save = true;
    G_args.kvstore_save.key = key;
    G_args.kvstore_save.data = data;
    G_args.kvstore_save.data_size = data_size;
    return G_mocks.kvstore_save_result;
}

bool kvstore_exists(char* key) {
    G_called.kvstore_exists = true;
    G_args.kvstore_exists.key = key;
    return G_mocks.kvstore_exists_result;
}

size_t kvstore_get(char* key, uint8_t* data_buf, size_t buffer_size) {
    G_called.kvstore_get = true;
    G_args.kvstore_get.key = key;
    G_args.kvstore_get.data_buf = data_buf;
    G_args.kvstore_get.buffer_size = buffer_size;
    return G_mocks.kvstore_get_result;
}

bool kvstore_remove(char* key) {
    G_called.kvstore_remove = true;
    G_args.kvstore_remove.key = key;
    return G_mocks.kvstore_remove_result;
}

// Test helper functions
void setup() {
    explicit_bzero(&G_mocks, sizeof(G_mocks));
    explicit_bzero(&G_called, sizeof(G_called));
    explicit_bzero(&G_args, sizeof(G_args));

    G_mocks.ecall_system_init_result = OE_OK;
    G_mocks.ecall_system_init_retval = true;
    G_mocks.ecall_system_finalise_result = OE_OK;
    G_mocks.ecall_system_process_apdu_result = OE_OK;
    G_mocks.ecall_system_process_apdu_retval = 0;
    G_mocks.epro_get_enclave_result = MOCK_ENCLAVE_PTR;
    G_mocks.kvstore_save_result = true;
    G_mocks.kvstore_exists_result = false;
    G_mocks.kvstore_get_result = 0;
    G_mocks.kvstore_remove_result = true;
}

// eprx_system_init tests
void test_eprx_system_init_success() {
    setup();
    printf("Testing eprx_system_init success...\n");

    unsigned char msg_buffer[256];
    size_t msg_buffer_size = sizeof(msg_buffer);

    bool result = eprx_system_init(msg_buffer, msg_buffer_size);

    assert(result == true);
    assert(G_called.epro_get_enclave);
    assert(G_called.ecall_system_init);
    assert(G_args.ecall_system_init.enclave == MOCK_ENCLAVE_PTR);
    assert(G_args.ecall_system_init.msg_buffer == msg_buffer);
    assert(G_args.ecall_system_init.msg_buffer_size == msg_buffer_size);
}

void test_eprx_system_init_enclave_null() {
    setup();
    printf("Testing eprx_system_init with null enclave...\n");

    unsigned char msg_buffer[256];
    size_t msg_buffer_size = sizeof(msg_buffer);

    G_mocks.epro_get_enclave_result = NULL;

    bool result = eprx_system_init(msg_buffer, msg_buffer_size);

    assert(result == false);
    assert(G_called.epro_get_enclave);
    assert(!G_called.ecall_system_init);
}

void test_eprx_system_init_ecall_fails() {
    setup();
    printf("Testing eprx_system_init with ecall failure...\n");

    unsigned char msg_buffer[256];
    size_t msg_buffer_size = sizeof(msg_buffer);

    G_mocks.ecall_system_init_result = OE_FAILURE;

    bool result = eprx_system_init(msg_buffer, msg_buffer_size);

    assert(result == false);
    assert(G_called.epro_get_enclave);
    assert(G_called.ecall_system_init);
}

void test_eprx_system_init_ecall_success_false_result() {
    setup();
    printf("Testing eprx_system_init with ecall success but false result...\n");

    unsigned char msg_buffer[256];
    size_t msg_buffer_size = sizeof(msg_buffer);

    G_mocks.ecall_system_init_retval = false;

    bool result = eprx_system_init(msg_buffer, msg_buffer_size);

    assert(result == false);
    assert(G_called.epro_get_enclave);
    assert(G_called.ecall_system_init);
}

// eprx_system_finalise tests
void test_eprx_system_finalise_success() {
    setup();
    printf("Testing eprx_system_finalise success...\n");

    eprx_system_finalise();

    assert(G_called.epro_get_enclave);
    assert(G_called.ecall_system_finalise);
    assert(G_args.ecall_system_finalise.enclave == MOCK_ENCLAVE_PTR);
}

void test_eprx_system_finalise_enclave_null() {
    setup();
    printf("Testing eprx_system_finalise with null enclave...\n");

    G_mocks.epro_get_enclave_result = NULL;

    eprx_system_finalise();

    assert(G_called.epro_get_enclave);
    assert(!G_called.ecall_system_finalise);
}

void test_eprx_system_finalise_ecall_fails() {
    setup();
    printf("Testing eprx_system_finalise with ecall failure...\n");

    G_mocks.ecall_system_finalise_result = OE_FAILURE;

    eprx_system_finalise();

    assert(G_called.epro_get_enclave);
    assert(G_called.ecall_system_finalise);
    assert(G_args.ecall_system_finalise.enclave == MOCK_ENCLAVE_PTR);
}

// eprx_system_process_apdu tests
void test_eprx_system_process_apdu_success() {
    setup();
    printf("Testing eprx_system_process_apdu success...\n");

    unsigned int rx = 123;
    unsigned int expected_result = 456;

    G_mocks.ecall_system_process_apdu_retval = expected_result;

    unsigned int result = eprx_system_process_apdu(rx);

    assert(result == expected_result);
    assert(G_called.epro_get_enclave);
    assert(G_called.ecall_system_process_apdu);
    assert(G_args.ecall_system_process_apdu.enclave == MOCK_ENCLAVE_PTR);
    assert(G_args.ecall_system_process_apdu.rx == rx);
}

void test_eprx_system_process_apdu_enclave_null() {
    setup();
    printf("Testing eprx_system_process_apdu with null enclave...\n");

    unsigned int rx = 123;

    G_mocks.epro_get_enclave_result = NULL;

    unsigned int result = eprx_system_process_apdu(rx);

    assert(result == false);
    assert(G_called.epro_get_enclave);
    assert(!G_called.ecall_system_process_apdu);
}

void test_eprx_system_process_apdu_ecall_fails() {
    setup();
    printf("Testing eprx_system_process_apdu with ecall failure...\n");

    unsigned int rx = 123;

    G_mocks.ecall_system_process_apdu_result = OE_FAILURE;

    unsigned int result = eprx_system_process_apdu(rx);

    assert(result == false);
    assert(G_called.epro_get_enclave);
    assert(G_called.ecall_system_process_apdu);
    assert(G_args.ecall_system_process_apdu.enclave == MOCK_ENCLAVE_PTR);
    assert(G_args.ecall_system_process_apdu.rx == rx);
}

// OCALL wrapper tests
void test_ocall_kvstore_save_success() {
    setup();
    printf("Testing ocall_kvstore_save success...\n");

    char* key = "test_key";
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    size_t data_size = sizeof(data);

    bool result = ocall_kvstore_save(key, data, data_size);

    assert(result == true);
    assert(G_called.kvstore_save);
    assert(G_args.kvstore_save.key == key);
    assert(G_args.kvstore_save.data == data);
    assert(G_args.kvstore_save.data_size == data_size);
}

void test_ocall_kvstore_save_fails() {
    setup();
    printf("Testing ocall_kvstore_save failure...\n");

    char* key = "test_key";
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    size_t data_size = sizeof(data);

    G_mocks.kvstore_save_result = false;

    bool result = ocall_kvstore_save(key, data, data_size);

    assert(result == false);
    assert(G_called.kvstore_save);
    assert(G_args.kvstore_save.key == key);
    assert(G_args.kvstore_save.data == data);
    assert(G_args.kvstore_save.data_size == data_size);
}

void test_ocall_kvstore_exists_true() {
    setup();
    printf("Testing ocall_kvstore_exists returns true...\n");

    char* key = "existing_key";

    G_mocks.kvstore_exists_result = true;

    bool result = ocall_kvstore_exists(key);

    assert(result == true);
    assert(G_called.kvstore_exists);
    assert(G_args.kvstore_exists.key == key);
}

void test_ocall_kvstore_exists_false() {
    setup();
    printf("Testing ocall_kvstore_exists returns false...\n");

    char* key = "nonexistent_key";

    bool result = ocall_kvstore_exists(key);

    assert(result == false);
    assert(G_called.kvstore_exists);
    assert(G_args.kvstore_exists.key == key);
}

void test_ocall_kvstore_get_success() {
    setup();
    printf("Testing ocall_kvstore_get success...\n");

    char* key = "test_key";
    uint8_t data_buf[256];
    size_t buffer_size = sizeof(data_buf);
    size_t expected_size = 10;

    G_mocks.kvstore_get_result = expected_size;

    size_t result = ocall_kvstore_get(key, data_buf, buffer_size);

    assert(result == expected_size);
    assert(G_called.kvstore_get);
    assert(G_args.kvstore_get.key == key);
    assert(G_args.kvstore_get.data_buf == data_buf);
    assert(G_args.kvstore_get.buffer_size == buffer_size);
}

void test_ocall_kvstore_get_fails() {
    setup();
    printf("Testing ocall_kvstore_get failure...\n");

    char* key = "test_key";
    uint8_t data_buf[256];
    size_t buffer_size = sizeof(data_buf);

    size_t result = ocall_kvstore_get(key, data_buf, buffer_size);

    assert(result == 0);
    assert(G_called.kvstore_get);
    assert(G_args.kvstore_get.key == key);
    assert(G_args.kvstore_get.data_buf == data_buf);
    assert(G_args.kvstore_get.buffer_size == buffer_size);
}

void test_ocall_kvstore_remove_success() {
    setup();
    printf("Testing ocall_kvstore_remove success...\n");

    char* key = "test_key";

    bool result = ocall_kvstore_remove(key);

    assert(result == true);
    assert(G_called.kvstore_remove);
    assert(G_args.kvstore_remove.key == key);
}

void test_ocall_kvstore_remove_fails() {
    setup();
    printf("Testing ocall_kvstore_remove failure...\n");

    char* key = "test_key";

    G_mocks.kvstore_remove_result = false;

    bool result = ocall_kvstore_remove(key);

    assert(result == false);
    assert(G_called.kvstore_remove);
    assert(G_args.kvstore_remove.key == key);
}

int main() {
    test_eprx_system_init_success();
    test_eprx_system_init_enclave_null();
    test_eprx_system_init_ecall_fails();
    test_eprx_system_init_ecall_success_false_result();

    test_eprx_system_finalise_success();
    test_eprx_system_finalise_enclave_null();
    test_eprx_system_finalise_ecall_fails();

    test_eprx_system_process_apdu_success();
    test_eprx_system_process_apdu_enclave_null();
    test_eprx_system_process_apdu_ecall_fails();

    test_ocall_kvstore_save_success();
    test_ocall_kvstore_save_fails();
    test_ocall_kvstore_exists_true();
    test_ocall_kvstore_exists_false();
    test_ocall_kvstore_get_success();
    test_ocall_kvstore_get_fails();
    test_ocall_kvstore_remove_success();
    test_ocall_kvstore_remove_fails();

    printf("All enclave_proxy tests passed!\n");
    return 0;
}
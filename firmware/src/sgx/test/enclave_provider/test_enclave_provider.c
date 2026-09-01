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
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "hsm_u.h"
#include "enclave_provider.h"

#define MOCK_ENCLAVE_PTR ((oe_enclave_t*)0x12345678)

// Test file paths
#define VALID_ENCLAVE_PATH "/tmp/test_enclave_valid.bin"
#define INVALID_ENCLAVE_PATH "/tmp/nonexistent_enclave.bin"

// Mock control structures
struct {
    bool oe_create_hsm_enclave_success;
    bool oe_terminate_enclave_success;
    oe_result_t oe_create_hsm_enclave_result;
    oe_result_t oe_terminate_enclave_result;
    bool should_allocate_enclave;
} G_mocks;

struct {
    bool oe_create_hsm_enclave_called;
    bool oe_terminate_enclave_called;
    const char* last_create_enclave_path;
    oe_enclave_t* last_terminate_enclave;
    oe_enclave_type_t last_enclave_type;
    uint32_t last_enclave_flags;
    uint32_t last_setting_count;
} G_called;

// File management helper functions
void cleanup_test_files() {
    unlink(VALID_ENCLAVE_PATH);
    unlink(INVALID_ENCLAVE_PATH);
}

void setup_test_files() {
    // Ensure any previous test files are removed before creating new ones
    cleanup_test_files();

    // Create a dummy valid enclave file
    FILE* valid_file = fopen(VALID_ENCLAVE_PATH, "w");
    if (valid_file) {
        // Write some dummy enclave data
        const char* dummy_data = "dummy_enclave_binary_data_for_testing";
        fwrite(dummy_data, 1, strlen(dummy_data), valid_file);
        fclose(valid_file);
    }
}

oe_result_t oe_create_hsm_enclave(const char* path,
                                  oe_enclave_type_t type,
                                  uint32_t flags,
                                  const oe_enclave_setting_t* settings,
                                  uint32_t setting_count,
                                  oe_enclave_t** enclave) {
    G_called.oe_create_hsm_enclave_called = true;
    G_called.last_create_enclave_path = path;
    G_called.last_enclave_type = type;
    G_called.last_enclave_flags = flags;
    G_called.last_setting_count = setting_count;

    if (G_mocks.oe_create_hsm_enclave_success &&
        G_mocks.should_allocate_enclave) {
        *enclave = MOCK_ENCLAVE_PTR;
    } else if (!G_mocks.oe_create_hsm_enclave_success) {
        *enclave = NULL;
    }

    return G_mocks.oe_create_hsm_enclave_result;
}

oe_result_t oe_terminate_enclave(oe_enclave_t* enclave) {
    G_called.oe_terminate_enclave_called = true;
    G_called.last_terminate_enclave = enclave;
    return G_mocks.oe_terminate_enclave_result;
}

// Test helper functions
void setup() {
    setup_test_files();

    // Reset mock state
    explicit_bzero(&G_mocks, sizeof(G_mocks));
    explicit_bzero(&G_called, sizeof(G_called));

    G_mocks.oe_create_hsm_enclave_success = true;
    G_mocks.oe_terminate_enclave_success = true;
    G_mocks.oe_create_hsm_enclave_result = OE_OK;
    G_mocks.oe_terminate_enclave_result = OE_OK;
    G_mocks.should_allocate_enclave = true;

    epro_finalize_enclave();
}

// Test cases for epro_init
void test_epro_init_valid_path() {
    setup();
    printf("Testing epro_init with valid path...\n");

    bool result = epro_init(VALID_ENCLAVE_PATH);

    assert(result == true);
}

void test_epro_init_invalid_path() {
    setup();
    printf("Testing epro_init with invalid path...\n");

    bool result = epro_init(INVALID_ENCLAVE_PATH);

    assert(result == false);
}

void test_epro_init_null_path() {
    setup();
    printf("Testing epro_init with NULL path...\n");

    bool result = epro_init(NULL);

    assert(result == false);
}

// Test cases for epro_get_enclave
void test_epro_get_enclave_first_call_success() {
    setup();
    printf("Testing epro_get_enclave first call success...\n");

    char* test_path = VALID_ENCLAVE_PATH;
    epro_init(test_path);

    oe_enclave_t* enclave = epro_get_enclave();

    assert(enclave == MOCK_ENCLAVE_PTR);
    assert(G_called.oe_create_hsm_enclave_called == true);
    assert(strcmp(G_called.last_create_enclave_path, test_path) == 0);
    assert(G_called.last_enclave_type == OE_ENCLAVE_TYPE_AUTO);
    assert(G_called.last_enclave_flags == 0);
    assert(G_called.last_setting_count == 0);
}

void test_epro_get_enclave_subsequent_calls() {
    setup();
    printf("Testing epro_get_enclave subsequent calls...\n");

    epro_init(VALID_ENCLAVE_PATH);

    oe_enclave_t* enclave1 = epro_get_enclave();

    // Reset mock call tracking
    G_called.oe_create_hsm_enclave_called = false;

    oe_enclave_t* enclave2 = epro_get_enclave();
    oe_enclave_t* enclave3 = epro_get_enclave();

    assert(enclave1 == enclave2);
    assert(enclave2 == enclave3);
    assert(enclave1 == MOCK_ENCLAVE_PTR);
    // Second and third calls should not create new enclave
    assert(G_called.oe_create_hsm_enclave_called == false);
}

void test_epro_get_enclave_creation_failure() {
    setup();
    printf("Testing epro_get_enclave creation failure...\n");

    G_mocks.oe_create_hsm_enclave_success = false;
    G_mocks.oe_create_hsm_enclave_result = OE_FAILURE;
    G_mocks.should_allocate_enclave = false;

    epro_init(VALID_ENCLAVE_PATH);

    oe_enclave_t* enclave = epro_get_enclave();

    assert(enclave == NULL);
    assert(G_called.oe_create_hsm_enclave_called == true);
}

// Test cases for epro_finalize_enclave
void test_epro_finalize_enclave_with_active_enclave() {
    setup();
    printf("Testing epro_finalize_enclave with active enclave...\n");

    epro_init(VALID_ENCLAVE_PATH);
    oe_enclave_t* enclave = epro_get_enclave();
    assert(enclave == MOCK_ENCLAVE_PTR);

    epro_finalize_enclave();

    assert(G_called.oe_terminate_enclave_called == true);
    assert(G_called.last_terminate_enclave == MOCK_ENCLAVE_PTR);
}

void test_epro_finalize_enclave_without_active_enclave() {
    setup();
    printf("Testing epro_finalize_enclave without active enclave...\n");

    // Don't create an enclave first
    epro_finalize_enclave();

    assert(G_called.oe_terminate_enclave_called == false);
}

void test_epro_finalize_enclave_multiple_calls() {
    setup();
    printf("Testing multiple epro_finalize_enclave calls...\n");

    char* test_path = VALID_ENCLAVE_PATH;
    epro_init(test_path);
    oe_enclave_t* enclave = epro_get_enclave();
    assert(enclave != NULL);

    epro_finalize_enclave();
    assert(G_called.oe_terminate_enclave_called == true);

    // Reset call tracking
    G_called.oe_terminate_enclave_called = false;

    // Second call should be safe and do nothing
    epro_finalize_enclave();
    assert(G_called.oe_terminate_enclave_called == false);
}

int main() {
    // Test epro_init function
    test_epro_init_valid_path();
    test_epro_init_invalid_path();
    test_epro_init_null_path();

    // Test epro_get_enclave function
    test_epro_get_enclave_first_call_success();
    test_epro_get_enclave_subsequent_calls();
    test_epro_get_enclave_creation_failure();

    // Test epro_finalize_enclave function
    test_epro_finalize_enclave_with_active_enclave();
    test_epro_finalize_enclave_without_active_enclave();
    test_epro_finalize_enclave_multiple_calls();

    // Clean up test files
    cleanup_test_files();

    printf("All enclave_provider tests passed!\n");
    return 0;
}
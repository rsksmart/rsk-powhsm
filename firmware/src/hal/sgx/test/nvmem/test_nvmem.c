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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hal/nvmem.h"
#include "assert_utils.h"
#include "mock.h"

#define TEST_NVMEM_NUM_BLOCKS 5
#define TEST_NVMEM_BLOCK_SIZE 255
#define TEST_NVMEM_KEY_SIZE 32

// Hand over the secret store calls to the mock implementation
bool sest_exists(char *key) {
    return mock_sest_exists(key);
}

uint8_t sest_read(char *key, uint8_t *dest, size_t dest_length) {
    return mock_sest_read(key, dest, dest_length);
}

bool sest_write(char *key, uint8_t *secret, size_t secret_length) {
    return mock_sest_write(key, secret, secret_length);
}

// Helper functions
static void setup() {
    mock_sest_init();
    nvmem_init();
}

static void teardown() {
    mock_sest_reset();
}

// Test cases
void test_register_single_block() {
    setup();
    printf("Test nvmem register a single block...\n");

    char block[TEST_NVMEM_BLOCK_SIZE];
    assert(nvmem_register_block("key", block, sizeof(block)));
    teardown();
}

void test_register_multiple_blocks() {
    setup();
    printf("Test nvmem register multiple blocks...\n");

    size_t num_blocks = TEST_NVMEM_NUM_BLOCKS;
    char blocks[num_blocks][TEST_NVMEM_BLOCK_SIZE];
    for (int i = 0; i < num_blocks; i++) {
        char key[TEST_NVMEM_KEY_SIZE];
        sprintf(key, "key-%d", i);
        assert(nvmem_register_block(key, blocks[i], sizeof(blocks[i])));
    }
}

void test_register_blocks_over_limit() {
    setup();
    printf("Test nvmem register blocks over the allowed limit...\n");

    size_t num_blocks = TEST_NVMEM_NUM_BLOCKS + 1;
    char blocks[num_blocks][TEST_NVMEM_BLOCK_SIZE];
    for (int i = 0; i < num_blocks; i++) {
        char key[TEST_NVMEM_KEY_SIZE];
        sprintf(key, "key-%d", i);
        if (i < TEST_NVMEM_NUM_BLOCKS) {
            assert(nvmem_register_block(key, blocks[i], sizeof(blocks[i])));
        } else {
            assert(!nvmem_register_block(key, blocks[i], sizeof(blocks[i])));
        }
    }
    teardown();
}

void test_write_single_block() {
    setup();
    printf("Test nvmem write and load single block...\n");

    // Register the block with a key and write data to it
    uint8_t block[TEST_NVMEM_BLOCK_SIZE];
    assert(nvmem_register_block("key", block, sizeof(block)));
    char data[] = "INITIAL TEST DATA";
    assert(nvmem_write(block, data, sizeof(data)));
    // The block should now contain the data
    ASSERT_MEMCMP(block, data, sizeof(data));
    // Create a copy for comparison and overwrite the original block
    char block_copy[TEST_NVMEM_BLOCK_SIZE];
    memcpy(block_copy, block, sizeof(block));
    memset(block, 0, sizeof(block));
    // The block should now have been entirely overwritten
    ASSERT_ARRAY_CLEARED(block);
    // Load the block from nvmem
    assert(nvmem_load());
    // The block should now contain the original data
    ASSERT_MEMCMP(block, block_copy, sizeof(block_copy));
    teardown();
}

void test_reset_single_block() {
    setup();
    printf("Test reset single block...\n");

    // Register the address block with a key and reset it
    uint8_t block[TEST_NVMEM_BLOCK_SIZE];
    assert(nvmem_register_block("key", block, sizeof(block)));
    assert(nvmem_write(block, NULL, sizeof(block)));
    ASSERT_ARRAY_CLEARED(block);
    // Overwrite the block with a magic number
    memset(block, 0x42, sizeof(block));
    ASSERT_ARRAY_VALUE(block, 0x42);
    // Now load the block from nvmem
    assert(nvmem_load());
    // The block should now be cleared
    ASSERT_ARRAY_CLEARED(block);
    teardown();
}

void test_multiple_writes_single_block() {
    setup();
    printf("Test multiple writes to a single block...\n");

    char *test_data[] = {
        "Some test data",
        "Some more test data",
        "Another test string",
    };
    int num_writes = sizeof(test_data) / sizeof(test_data[0]);
    // Register the address block with a key
    uint8_t block[TEST_NVMEM_BLOCK_SIZE];
    assert(nvmem_register_block("key", block, sizeof(block)));
    for (int i = 0; i < num_writes; i++) {
        // Write the data to the block
        assert(nvmem_write(block, test_data[i], strlen(test_data[i])));
        // The block should now contain the data
        ASSERT_MEMCMP(block, test_data[i], strlen(test_data[i]));
    }
    // Overwrite the local copy of the block with zeros
    memset(block, 0, sizeof(block));
    // Load the block from nvmem
    assert(nvmem_load());
    // The block should now contain the last written data
    char *expected_data = test_data[num_writes - 1];
    ASSERT_MEMCMP(block, expected_data, strlen(expected_data));
    teardown();
}

void test_write_block_without_register() {
    setup();
    printf("Test write block without registering it...\n");

    uint8_t block[TEST_NVMEM_BLOCK_SIZE];
    // Write some data to the block without registering it
    char data[] = "TEST DATA";
    assert(nvmem_write(block, data, strlen(data)));
    // The block should have been updated with the data
    ASSERT_MEMCMP(block, data, strlen(data));
    // Now overwrite the block with a magic number and try to load it back
    memset(block, 0x42, sizeof(block));
    ASSERT_ARRAY_VALUE(block, 0x42);
    assert(nvmem_load());
    // The block's contents should be unchanged
    ASSERT_ARRAY_VALUE(block, 0x42);

    teardown();
}

void test_load_single_block_without_writing() {
    setup();
    printf("Test load single block without writing...\n");

    uint8_t block[TEST_NVMEM_BLOCK_SIZE];
    // Register the block but don't write any data to it
    assert(nvmem_register_block("key", block, sizeof(block)));
    // Initialize the block with a magic number
    memset(block, 0x42, sizeof(block));
    ASSERT_ARRAY_VALUE(block, 0x42);
    // Load the block from nvmem
    assert(nvmem_load());
    // The block should now contain only zeros
    ASSERT_ARRAY_CLEARED(block);
    teardown();
}

void test_write_on_sest_failure() {
    setup();
    printf("Test write fails when secret store write fails...\n");

    // Register the block and write initial data
    uint8_t block[TEST_NVMEM_BLOCK_SIZE];
    char initial_data[] = "INITIAL NVMEM DATA";
    assert(nvmem_register_block("key", block, sizeof(block)));
    assert(nvmem_write(block, initial_data, strlen(initial_data)));
    ASSERT_MEMCMP(block, initial_data, strlen(initial_data));
    // Forces the mock secret store to fail on the next write operation
    mock_sest_fail_next_write(true);
    // Attempt to write new data to the nvmem, and fail
    char new_data[] = "NEW NVMEM DATA";
    assert(!nvmem_write(block, new_data, strlen(new_data)));
    // The local copy was updated, but the nvmem was not
    ASSERT_MEMCMP(block, new_data, strlen(new_data));
    assert(nvmem_load());
    ASSERT_MEMCMP(block, initial_data, strlen(initial_data));
    teardown();
}

void test_load_fails_on_sest_failure() {
    setup();
    printf("Test load fails when secret store read fails...\n");

    // Register the block and write initial data
    uint8_t block[TEST_NVMEM_BLOCK_SIZE];
    char initial_data[] = "INITIAL NVMEM DATA";
    assert(nvmem_register_block("key", block, sizeof(block)));
    assert(nvmem_write(block, initial_data, strlen(initial_data)));
    ASSERT_MEMCMP(block, initial_data, strlen(initial_data));
    // Overwrite the block with a magic number
    memset(block, 0x42, sizeof(block));
    ASSERT_ARRAY_VALUE(block, 0x42);
    // Forces the mock secret store to fail on the next read operation
    mock_sest_fail_next_read(true);
    // Attempt to load the nvmem, and fail
    assert(!nvmem_load());
    // The load error should cause the block to be cleared
    ASSERT_ARRAY_CLEARED(block);
    teardown();
}

int main() {
    test_register_single_block();
    test_register_multiple_blocks();
    test_register_blocks_over_limit();
    test_write_single_block();
    test_reset_single_block();
    test_multiple_writes_single_block();
    test_write_block_without_register();
    test_load_single_block_without_writing();
    test_write_on_sest_failure();
    test_load_fails_on_sest_failure();

    return 0;
}

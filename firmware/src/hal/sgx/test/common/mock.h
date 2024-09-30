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
#include <stdlib.h>

// Mock functions for the secret store

/**
 * @brief Initializes the mock secret store
 */
void mock_sest_init();

/**
 * @brief Mock implementation of sest_exists
 *
 * @param key the key for the secret
 *
 * @returns whether the provided key corresponds to a secret in the store
 */
bool mock_sest_exists(char *key);

/**
 * @brief Mock implementation of sest_write
 *
 * @param key the key for the secret
 * @param secret the secret to write
 * @param secret_length the length of the secret
 *
 * @returns Whether the write was successful.
 *
 * NOTE: This mock implementation will always return true unless the
 * fail_next_write flag is set.
 */
bool mock_sest_write(char *key, uint8_t *secret, size_t secret_length);

/**
 * @brief Mock implementation of sest_read
 *
 * @param key the key for the secret
 * @param dest the destination buffer for the read secret
 * @param dest_length the length of the destination buffer
 *
 * @returns the length of the secret read, or ZERO upon error.
 *
 * NOTE: This mock implementation will fail if the fail_next_read flag is set,
 * regardless of the key provided.
 */
uint8_t mock_sest_read(char *key, uint8_t *dest, size_t dest_length);

/**
 * @brief Resets the mock secret store to its initial state
 */
void mock_sest_reset();

/**
 * @brief Sets the value of the fail_next_read flag
 *
 * @param fail whether the next call to sest_read should fail
 */
void mock_sest_fail_next_read(bool fail);

/**
 * @brief Sets the value of the fail_next_write flag
 *
 * @param fail whether the next call to sest_write should fail
 */
void mock_sest_fail_next_write(bool fail);

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

#ifndef __TRUSTED_SECRET_STORE_H
#define __TRUSTED_SECRET_STORE_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Initializes the secret store
 *
 * @returns whether the secret store was successfully initialized
 */
bool sest_init();

/**
 * @brief Determine whether a secret exists in the store
 *
 * @param key the key for the secret
 *
 * @returns whether the secret exists. Note that this doesn't
 * indicate whether attempting to read the secret will yield an
 * error, only whether a potential secret can be read at the
 * given key.
 */
bool sest_exists(char* key);

/**
 * @brief Read a secret from the store
 *
 * @param key the key for the secret
 * @param dest the destination buffer for the read secret
 * @param dest_length the length of the destination buffer
 *
 * @returns the length of the secret read, or ZERO upon error
 */
uint8_t sest_read(char* key, uint8_t* dest, size_t dest_length);

/**
 * @brief Write a secret to the store
 *
 * @param key the key for the secret
 * @param secret the secret to write
 * @param secret_length the secret length
 *
 * @returns whether the write was successful
 */
bool sest_write(char* key, uint8_t* secret, size_t secret_length);

/**
 * @brief Write protect a secret in the store
 *
 * @param key the key to protect
 *
 * @returns whether the write protection was successfully applied
 */
bool sest_protect(char* key);

/**
 * @brief Remove a stored secret
 *
 * @param the key for the secret
 *
 * @returns whether the deletion was successful
 */
bool sest_remove(char* key);

#endif // __TRUSTED_SECRET_STORE_H

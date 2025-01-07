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

#ifndef __KEYVALUE_STORE_H
#define __KEYVALUE_STORE_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Tell whether a given key currently exists
 * 
 * @param key the key to check for
 * 
 * @returns whether the key exists
 */
bool kvstore_exists(char* key);

/**
 * @brief Save the given data to the given key
 * 
 * @param key the key to save the data to
 * @param data the buffer containing the data to write
 * @param data_size the data size in bytes
 * 
 * @returns whether saving succeeded
 */
bool kvstore_save(char* key, uint8_t* data, size_t data_size);

/**
 * @brief Read the given key into the given buffer
 * 
 * @param key the key to read from
 * @param data_buf the buffer to read the data to
 * @param buffer_size the buffer size in bytes
 * 
 * @returns the number of bytes read, or ZERO upon error
 */
size_t kvstore_get(char* key, uint8_t* data_buf, size_t buffer_size);

/**
 * @brief Remove any data associated with the given key
 * 
 * @param key the key to remove
 * 
 * @returns whether key removal was successful
 */
bool kvstore_remove(char* key);

#endif // __KEYVALUE_STORE_H
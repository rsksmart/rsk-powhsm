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

#ifndef __TRUSTED_KEYVALUE_DB_H
#define __TRUSTED_KEYVALUE_DB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t* buffer;
    size_t capacity;
    size_t size;
} keyvalue_db_t;

/**
 * @brief Initialize an empty keyvalue database with the required header
 *
 * @param db the output database context (buffer and capacity must be set)
 *
 * @returns whether initialization was successful
 */
bool kvdb_new(keyvalue_db_t* db);

/**
 * @brief Validate keyvalue database structure and encoding sanity
 *
 * @param db the input database
 *
 * @returns whether the database is structurally valid
 */
bool kvdb_check(const keyvalue_db_t* db);

/**
 * @brief Find the first value associated with the given key in the database
 *
 * @param db the input database
 * @param key the key to look up
 * @param value output buffer for the decoded binary value
 * @param value_size input/output value buffer capacity/resulting size in bytes
 *
 * @returns whether the key was found and decoded successfully
 */
bool kvdb_get(const keyvalue_db_t* db,
              const char* key,
              uint8_t* value,
              size_t* value_size);

/**
 * @brief Insert or update the given key with the given binary value
 *
 * @param db the input/output database
 * @param key the key to insert or update
 * @param value the binary value to store
 * @param value_size the binary value size in bytes
 *
 * @returns whether the insert/update operation was successful
 */
bool kvdb_upsert(keyvalue_db_t* db,
                 const char* key,
                 const uint8_t* value,
                 size_t value_size);

/**
 * @brief Remove all entries associated with the given key
 *
 * @param db the input/output database
 * @param key the key to remove
 *
 * @returns whether removal processing was successful. This is true even when
 * the key is not present.
 */
bool kvdb_remove(keyvalue_db_t* db, const char* key);

#endif // __TRUSTED_KEYVALUE_DB_H

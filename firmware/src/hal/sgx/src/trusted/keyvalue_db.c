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

#include <string.h>
#include <stdlib.h>

#include "keyvalue_db.h"
#include "hex_codec.h"

#define KEY_VALUE_SEPARATOR '='
#define LINE_SEPARATOR '\n'
#define DB_HEADER "KVDB1\n"
#define DB_HEADER_SIZE (sizeof(DB_HEADER) - 1)

typedef struct {
    const uint8_t* start;
    size_t length;
    const char* key_start;
    size_t key_length;
    const char* value_start;
    size_t value_length;
} line_info_t;

static bool is_key_valid_with_length(const char* key, size_t key_len) {
    if (!key)
        return false;

    if (key_len == 0)
        return false;

    for (size_t i = 0; i < key_len; i++) {
        char c = key[i];
        bool is_lower_alpha = c >= 'a' && c <= 'z';
        bool is_upper_alpha = c >= 'A' && c <= 'Z';
        bool is_digit = c >= '0' && c <= '9';
        bool is_special = c == '-' || c == '_';
        if (!is_lower_alpha && !is_upper_alpha && !is_digit && !is_special) {
            return false;
        }
    }

    return true;
}

static bool is_key_valid(const char* key) {
    if (!key)
        return false;

    return is_key_valid_with_length(key, strlen(key));
}

static bool key_equals(const char* a, size_t a_len, const char* b) {
    size_t b_len = strlen(b);
    return a_len == b_len && memcmp(a, b, a_len) == 0;
}

static bool copy_line(uint8_t* out_db,
                      size_t out_db_size,
                      size_t* out_offset,
                      const line_info_t* line) {
    if (!line)
        return false;

    if (*out_offset > out_db_size)
        return false;
    if (line->length > (out_db_size - *out_offset))
        return false;

    memcpy(out_db + *out_offset, line->start, line->length);
    *out_offset += line->length;
    return true;
}

static bool append_encoded_line(uint8_t* out_db,
                                size_t out_db_size,
                                size_t* out_offset,
                                const char* key,
                                const uint8_t* value,
                                size_t value_size) {
    size_t key_len = strlen(key);
    size_t encoded_len = 0;

    if (value_size > 0 && !value)
        return false;

    if (*out_offset > out_db_size)
        return false;
    if (key_len > (out_db_size - *out_offset))
        return false;

    memcpy(out_db + *out_offset, key, key_len);
    *out_offset += key_len;

    if (*out_offset >= out_db_size)
        return false;
    out_db[*out_offset] = KEY_VALUE_SEPARATOR;
    *out_offset += 1;

    if (value_size > 0) {
        encoded_len = out_db_size - *out_offset;
        if (!hexcd_encode(value,
                          value_size,
                          (char*)(out_db + *out_offset),
                          &encoded_len)) {
            return false;
        }
    }

    *out_offset += encoded_len;

    if (*out_offset >= out_db_size)
        return false;
    out_db[*out_offset] = LINE_SEPARATOR;
    *out_offset += 1;

    return true;
}

static bool parse_next_line(const uint8_t* db,
                            size_t db_size,
                            size_t* offset,
                            line_info_t* line) {
    if (!db || !offset || !line)
        return false;

    if (*offset >= db_size)
        return false;

    size_t start = *offset;
    size_t end = start;
    while (end < db_size && db[end] != LINE_SEPARATOR) {
        end++;
    }

    if (end >= db_size || db[end] != LINE_SEPARATOR)
        return false;

    if (end == start)
        return false;

    size_t eq_index = start;
    while (eq_index < end && db[eq_index] != KEY_VALUE_SEPARATOR) {
        eq_index++;
    }

    if (eq_index == start || eq_index == end)
        return false;

    if (eq_index >= end || db[eq_index] != KEY_VALUE_SEPARATOR)
        return false;

    const char* key_start = (const char*)(db + start);
    size_t key_length = eq_index - start;
    const char* value_start = (const char*)(db + eq_index + 1);
    size_t value_length = end - (eq_index + 1);

    if (!is_key_valid_with_length(key_start, key_length))
        return false;

    if (!hexcd_is_valid(value_start, value_length))
        return false;

    line->start = db + start;
    line->length = (end - start) + 1;
    line->key_start = key_start;
    line->key_length = key_length;
    line->value_start = value_start;
    line->value_length = value_length;

    *offset = end + 1;
    return true;
}

bool kvdb_check(const keyvalue_db_t* db) {
    if (!db || !db->buffer)
        return false;

    if (db->size == 0 || db->size > db->capacity)
        return false;

    if (db->size < DB_HEADER_SIZE ||
        memcmp(db->buffer, DB_HEADER, DB_HEADER_SIZE) != 0)
        return false;

    size_t offset = DB_HEADER_SIZE;
    while (offset < db->size) {
        line_info_t line;
        if (!parse_next_line(db->buffer, db->size, &offset, &line))
            return false;
    }

    return true;
}

bool kvdb_new(keyvalue_db_t* db) {
    if (!db || !db->buffer)
        return false;

    if (db->capacity < DB_HEADER_SIZE)
        return false;

    memcpy(db->buffer, DB_HEADER, DB_HEADER_SIZE);
    db->size = DB_HEADER_SIZE;
    return true;
}

bool kvdb_get(const keyvalue_db_t* db,
              const char* key,
              uint8_t* value,
              size_t* value_size) {
    if (!value || !value_size)
        return false;

    if (!is_key_valid(key))
        return false;

    size_t value_capacity = *value_size;
    *value_size = 0;

    if (!db || !db->buffer)
        return false;

    if (!kvdb_check(db))
        return false;

    size_t offset = DB_HEADER_SIZE;
    while (offset < db->size) {
        line_info_t line;
        if (!parse_next_line(db->buffer, db->size, &offset, &line))
            return false;

        if (key_equals(line.key_start, line.key_length, key)) {
            size_t decoded_size = value_capacity;
            if (!hexcd_decode(line.value_start,
                              line.value_length,
                              value,
                              &decoded_size)) {
                return false;
            }

            *value_size = decoded_size;
            return true;
        }
    }

    return false;
}

bool kvdb_upsert(keyvalue_db_t* db,
                 const char* key,
                 const uint8_t* value,
                 size_t value_size) {
    if (!db || !db->buffer)
        return false;

    if (value_size > 0 && !value)
        return false;

    if (!is_key_valid(key))
        return false;

    if (!kvdb_check(db))
        return false;

    uint8_t* tmp_db = malloc(db->capacity);
    if (!tmp_db)
        return false;

    size_t out_db_capacity = db->capacity;
    size_t out_offset = DB_HEADER_SIZE;
    bool replaced = false;

    memcpy(tmp_db, DB_HEADER, DB_HEADER_SIZE);

    if (db->size > DB_HEADER_SIZE) {
        size_t offset = DB_HEADER_SIZE;
        while (offset < db->size) {
            line_info_t line;
            if (!parse_next_line(db->buffer, db->size, &offset, &line))
                goto kvdb_upsert_error;

            if (key_equals(line.key_start, line.key_length, key)) {
                if (!replaced) {
                    if (!append_encoded_line(tmp_db,
                                             out_db_capacity,
                                             &out_offset,
                                             key,
                                             value,
                                             value_size)) {
                        goto kvdb_upsert_error;
                    }
                    replaced = true;
                }
            } else if (!copy_line(
                           tmp_db, out_db_capacity, &out_offset, &line)) {
                goto kvdb_upsert_error;
            }
        }
    }

    if (!replaced &&
        !append_encoded_line(
            tmp_db, out_db_capacity, &out_offset, key, value, value_size)) {
        goto kvdb_upsert_error;
    }

    memcpy(db->buffer, tmp_db, out_offset);
    db->size = out_offset;
    explicit_bzero(tmp_db, db->capacity);
    free(tmp_db);
    return true;

kvdb_upsert_error:
    free(tmp_db);
    return false;
}

bool kvdb_remove(keyvalue_db_t* db, const char* key) {
    if (!db || !db->buffer)
        return false;

    if (!is_key_valid(key))
        return false;

    if (!kvdb_check(db))
        return false;

    uint8_t* tmp_db = malloc(db->capacity);
    if (!tmp_db)
        return false;

    size_t out_db_capacity = db->capacity;

    memcpy(tmp_db, DB_HEADER, DB_HEADER_SIZE);

    if (db->size == DB_HEADER_SIZE) {
        explicit_bzero(tmp_db, db->capacity);
        free(tmp_db);
        return true;
    }

    size_t offset = DB_HEADER_SIZE;
    size_t out_offset = DB_HEADER_SIZE;

    while (offset < db->size) {
        line_info_t line;
        if (!parse_next_line(db->buffer, db->size, &offset, &line))
            goto kvdb_remove_error;

        if (key_equals(line.key_start, line.key_length, key)) {
            continue;
        }

        if (!copy_line(tmp_db, out_db_capacity, &out_offset, &line)) {
            goto kvdb_remove_error;
        }
    }

    memcpy(db->buffer, tmp_db, out_offset);
    db->size = out_offset;
    free(tmp_db);
    return true;

kvdb_remove_error:
    free(tmp_db);
    return false;
}

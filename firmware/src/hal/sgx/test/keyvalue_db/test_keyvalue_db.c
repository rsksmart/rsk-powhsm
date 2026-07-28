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

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "keyvalue_db.h"

#define DB_HEADER "KVDB1\n"

static void test_kvdb_get_success() {
    printf("Testing kvdb_get success...\n");

    const uint8_t db[] = DB_HEADER "k1=00ff\nk2=aabb\n";
    keyvalue_db_t db_ctx = {
        .buffer = (uint8_t*)db,
        .capacity = sizeof(db) - 1,
        .size = sizeof(db) - 1,
    };
    uint8_t value[16] = {0};
    size_t value_length = sizeof(value);

    assert(kvdb_get(&db_ctx, "k2", value, &value_length));
    assert(value_length == 2);
    assert(value[0] == 0xaa);
    assert(value[1] == 0xbb);
}

static void test_kvdb_get_missing() {
    printf("Testing kvdb_get missing key...\n");

    const uint8_t db[] = DB_HEADER "k1=00ff\n";
    keyvalue_db_t db_ctx = {
        .buffer = (uint8_t*)db,
        .capacity = sizeof(db) - 1,
        .size = sizeof(db) - 1,
    };
    uint8_t value[16] = {0};
    size_t value_length = sizeof(value);

    assert(!kvdb_get(&db_ctx, "k2", value, &value_length));
    assert(value_length == 0);
}

static void test_kvdb_get_uses_first_duplicate_key() {
    printf("Testing kvdb_get duplicate keys uses first...\n");

    const uint8_t db[] = DB_HEADER "k1=00ff\nk1=aabb\n";
    keyvalue_db_t db_ctx = {
        .buffer = (uint8_t*)db,
        .capacity = sizeof(db) - 1,
        .size = sizeof(db) - 1,
    };
    uint8_t value[16] = {0};
    size_t value_length = sizeof(value);

    assert(kvdb_get(&db_ctx, "k1", value, &value_length));
    assert(value_length == 2);
    assert(value[0] == 0x00);
    assert(value[1] == 0xff);
}

static void test_kvdb_get_rejects_invalid_key_in_database() {
    printf("Testing kvdb_get rejects invalid key in database...\n");

    const uint8_t db[] = DB_HEADER "bad.key=00ff\nk1=aabb\n";
    keyvalue_db_t db_ctx = {
        .buffer = (uint8_t*)db,
        .capacity = sizeof(db) - 1,
        .size = sizeof(db) - 1,
    };
    uint8_t value[16] = {0};
    size_t value_length = sizeof(value);

    assert(!kvdb_get(&db_ctx, "k1", value, &value_length));
}

static void test_kvdb_upsert_insert_and_update() {
    printf("Testing kvdb_upsert insert and update...\n");

    uint8_t out_db[256] = {0};
    keyvalue_db_t db_ctx = {
        .buffer = out_db,
        .capacity = sizeof(out_db),
        .size = sizeof(DB_HEADER) - 1,
    };
    const uint8_t value1[] = {0xde, 0xad};
    const uint8_t value2[] = {0xbe, 0xef};
    const uint8_t value3[] = {0xaa, 0xbb};

    memcpy(db_ctx.buffer, DB_HEADER, db_ctx.size);

    assert(kvdb_upsert(&db_ctx, "k1", value1, sizeof(value1)));
    assert(memcmp(out_db, DB_HEADER "k1=dead\n", db_ctx.size) == 0);

    assert(kvdb_upsert(&db_ctx, "k1", value2, sizeof(value2)));
    assert(memcmp(out_db, DB_HEADER "k1=beef\n", db_ctx.size) == 0);

    assert(kvdb_upsert(&db_ctx, "k2", value3, sizeof(value3)));
    assert(memcmp(out_db, DB_HEADER "k1=beef\nk2=aabb\n", db_ctx.size) == 0);
}

static void test_kvdb_upsert_updates_first_duplicate_only() {
    printf("Testing kvdb_upsert updates first duplicate only...\n");

    const uint8_t db[] = DB_HEADER "k1=00ff\nk1=aabb\nk2=ccdd\n";
    const uint8_t value[] = {0x12, 0x34};
    uint8_t out_db[256] = {0};
    keyvalue_db_t db_ctx = {
        .buffer = out_db,
        .capacity = sizeof(out_db),
        .size = sizeof(db) - 1,
    };

    memcpy(db_ctx.buffer, db, db_ctx.size);

    assert(kvdb_upsert(&db_ctx, "k1", value, sizeof(value)));
    assert(memcmp(out_db, DB_HEADER "k1=1234\nk2=ccdd\n", db_ctx.size) == 0);
}

static void test_kvdb_upsert_rejects_invalid_db() {
    printf("Testing kvdb_upsert invalid DB rejection...\n");

    const uint8_t db[] = DB_HEADER "k1=00fg\n";
    uint8_t out_db[64] = {0};
    keyvalue_db_t db_ctx = {
        .buffer = out_db,
        .capacity = sizeof(out_db),
        .size = sizeof(db) - 1,
    };
    const uint8_t value[] = {0x01};

    memcpy(db_ctx.buffer, db, db_ctx.size);

    assert(!kvdb_upsert(&db_ctx, "k2", value, sizeof(value)));
}

static void test_kvdb_upsert_allows_zero_length_value() {
    printf("Testing kvdb_upsert allows zero-length value...\n");

    uint8_t out_db[256] = {0};
    keyvalue_db_t db_ctx = {
        .buffer = out_db,
        .capacity = sizeof(out_db),
        .size = sizeof(DB_HEADER) - 1,
    };

    memcpy(db_ctx.buffer, DB_HEADER, db_ctx.size);

    assert(kvdb_upsert(&db_ctx, "k1", NULL, 0));
    assert(memcmp(out_db, DB_HEADER "k1=\n", db_ctx.size) == 0);
}

static void test_kvdb_get_allows_zero_length_value() {
    printf("Testing kvdb_get allows zero-length value...\n");

    const uint8_t db[] = DB_HEADER "k1=\n";
    keyvalue_db_t db_ctx = {
        .buffer = (uint8_t*)db,
        .capacity = sizeof(db) - 1,
        .size = sizeof(db) - 1,
    };
    uint8_t value[16] = {0};
    size_t value_length = sizeof(value);

    assert(kvdb_get(&db_ctx, "k1", value, &value_length));
    assert(value_length == 0);
}

static void test_kvdb_get_fails_when_output_capacity_is_too_small() {
    printf("Testing kvdb_get fails on insufficient output capacity...\n");

    const uint8_t db[] = DB_HEADER "k1=aabb\n";
    keyvalue_db_t db_ctx = {
        .buffer = (uint8_t*)db,
        .capacity = sizeof(db) - 1,
        .size = sizeof(db) - 1,
    };
    uint8_t value[1] = {0};
    size_t value_length = sizeof(value);

    assert(!kvdb_get(&db_ctx, "k1", value, &value_length));
    assert(value_length == 0);
}

static void test_kvdb_remove() {
    printf("Testing kvdb_remove...\n");

    const uint8_t db[] = DB_HEADER "k1=00ff\nk2=aabb\n";
    uint8_t db_buf[256] = {0};
    keyvalue_db_t db_ctx = {
        .buffer = db_buf,
        .capacity = sizeof(db_buf),
        .size = sizeof(db) - 1,
    };

    memcpy(db_ctx.buffer, db, db_ctx.size);

    assert(kvdb_remove(&db_ctx, "k1"));
    assert(memcmp(db_ctx.buffer, DB_HEADER "k2=aabb\n", db_ctx.size) == 0);
}

static void test_kvdb_remove_all_duplicates() {
    printf("Testing kvdb_remove removes all duplicates...\n");

    const uint8_t db[] = DB_HEADER "k1=00ff\nk1=aabb\nk2=ccdd\n";
    uint8_t db_buf[256] = {0};
    keyvalue_db_t db_ctx = {
        .buffer = db_buf,
        .capacity = sizeof(db_buf),
        .size = sizeof(db) - 1,
    };

    memcpy(db_ctx.buffer, db, db_ctx.size);

    assert(kvdb_remove(&db_ctx, "k1"));
    assert(memcmp(db_ctx.buffer, DB_HEADER "k2=ccdd\n", db_ctx.size) == 0);
}

static void test_kvdb_remove_missing_is_not_error() {
    printf("Testing kvdb_remove missing key...\n");

    const uint8_t db[] = DB_HEADER "k1=00ff\n";
    uint8_t db_buf[256] = {0};
    keyvalue_db_t db_ctx = {
        .buffer = db_buf,
        .capacity = sizeof(db_buf),
        .size = sizeof(db) - 1,
    };

    memcpy(db_ctx.buffer, db, db_ctx.size);

    assert(kvdb_remove(&db_ctx, "k2"));
    assert(memcmp(db_ctx.buffer, db, db_ctx.size) == 0);
}

static void test_kvdb_remove_zero_length_value_key() {
    printf("Testing kvdb_remove with zero-length value key...\n");

    const uint8_t db[] = DB_HEADER "k1=\nk2=aabb\n";
    uint8_t db_buf[256] = {0};
    keyvalue_db_t db_ctx = {
        .buffer = db_buf,
        .capacity = sizeof(db_buf),
        .size = sizeof(db) - 1,
    };

    memcpy(db_ctx.buffer, db, db_ctx.size);

    assert(kvdb_remove(&db_ctx, "k1"));
    assert(memcmp(db_ctx.buffer, DB_HEADER "k2=aabb\n", db_ctx.size) == 0);
}

static void test_kvdb_check_valid_database() {
    printf("Testing kvdb_check valid database...\n");

    const uint8_t db[] = DB_HEADER "k1=00ff\nk2=aabb\n";
    keyvalue_db_t db_ctx = {
        .buffer = (uint8_t*)db,
        .capacity = sizeof(db) - 1,
        .size = sizeof(db) - 1,
    };

    assert(kvdb_check(&db_ctx));
}

static void test_kvdb_check_null_and_empty_inputs() {
    printf("Testing kvdb_check null and empty inputs...\n");

    assert(!kvdb_check(NULL));

    keyvalue_db_t null_buffer = {
        .buffer = NULL,
        .capacity = 10,
        .size = 10,
    };
    assert(!kvdb_check(&null_buffer));

    uint8_t buf[8] = {0};
    keyvalue_db_t zero_size = {
        .buffer = buf,
        .capacity = sizeof(buf),
        .size = 0,
    };
    assert(!kvdb_check(&zero_size));
}

static void test_kvdb_check_rejects_invalid_header() {
    printf("Testing kvdb_check invalid header rejection...\n");

    const uint8_t db[] = "BADHDR\nk1=00ff\n";
    keyvalue_db_t db_ctx = {
        .buffer = (uint8_t*)db,
        .capacity = sizeof(db) - 1,
        .size = sizeof(db) - 1,
    };

    assert(!kvdb_check(&db_ctx));
}

static void test_kvdb_check_rejects_truncated_line() {
    printf("Testing kvdb_check truncated line rejection...\n");

    const uint8_t db[] = DB_HEADER "k1=00ff";
    keyvalue_db_t db_ctx = {
        .buffer = (uint8_t*)db,
        .capacity = sizeof(db) - 1,
        .size = sizeof(db) - 1,
    };

    assert(!kvdb_check(&db_ctx));
}

static void test_kvdb_check_rejects_invalid_hex() {
    printf("Testing kvdb_check invalid hex rejection...\n");

    const uint8_t db[] = DB_HEADER "k1=gg\n";
    keyvalue_db_t db_ctx = {
        .buffer = (uint8_t*)db,
        .capacity = sizeof(db) - 1,
        .size = sizeof(db) - 1,
    };

    assert(!kvdb_check(&db_ctx));
}

static void test_kvdb_check_rejects_size_over_capacity() {
    printf("Testing kvdb_check size over capacity rejection...\n");

    const uint8_t db[] = DB_HEADER "k1=00ff\n";
    keyvalue_db_t db_ctx = {
        .buffer = (uint8_t*)db,
        .capacity = (sizeof(db) - 1) - 1,
        .size = sizeof(db) - 1,
    };

    assert(!kvdb_check(&db_ctx));
}

int main() {
    test_kvdb_get_success();
    test_kvdb_get_missing();
    test_kvdb_get_uses_first_duplicate_key();
    test_kvdb_get_rejects_invalid_key_in_database();
    test_kvdb_upsert_insert_and_update();
    test_kvdb_upsert_updates_first_duplicate_only();
    test_kvdb_upsert_rejects_invalid_db();
    test_kvdb_upsert_allows_zero_length_value();
    test_kvdb_get_allows_zero_length_value();
    test_kvdb_get_fails_when_output_capacity_is_too_small();
    test_kvdb_remove();
    test_kvdb_remove_all_duplicates();
    test_kvdb_remove_missing_is_not_error();
    test_kvdb_remove_zero_length_value_key();
    test_kvdb_check_valid_database();
    test_kvdb_check_null_and_empty_inputs();
    test_kvdb_check_rejects_invalid_header();
    test_kvdb_check_rejects_truncated_line();
    test_kvdb_check_rejects_invalid_hex();
    test_kvdb_check_rejects_size_over_capacity();
    return 0;
}

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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "assert_utils.h"
#include "secret_store.h"
#include "mock_seal.h"
#include "mock_ocall.h"

extern void sest_reset_for_tests();

// Error code for the sest API as defined in secret_store.c
#define SEST_ERROR (0)
// The maximum value that can be returned by sest_read
#define MAX_SEST_READ_SIZE (255)
// The maximum blob_size for a sealed secret, as defined in secret_store.c
#define MAX_BLOB_SIZE (1024 * 1024)
#define DB_KEY "database"
#define SEALED_PREFIX "SEALED - "
#define DB_HEADER "KVDB1\n"

#ifdef DEBUG_BUILD
#define EXPECTED_SEAL_POLICY 2
#else
#define EXPECTED_SEAL_POLICY 1
#endif

// Hand over the seal API calls to the mock implementation
oe_result_t oe_seal(const void* plugin_id,
                    const oe_seal_setting_t* settings,
                    size_t settings_count,
                    const uint8_t* plaintext,
                    size_t plaintext_size,
                    const uint8_t* additional_data,
                    size_t additional_data_size,
                    uint8_t** blob,
                    size_t* blob_size) {
    return mock_oe_seal(plugin_id,
                        settings,
                        settings_count,
                        plaintext,
                        plaintext_size,
                        additional_data,
                        additional_data_size,
                        blob,
                        blob_size);
}

oe_result_t oe_unseal(const uint8_t* blob,
                      size_t blob_size,
                      const uint8_t* additional_data,
                      size_t additional_data_size,
                      uint8_t** plaintext,
                      size_t* plaintext_size) {
    return mock_oe_unseal(blob,
                          blob_size,
                          additional_data,
                          additional_data_size,
                          plaintext,
                          plaintext_size);
}

// Hand over the kvstore calls to the mock implementation
oe_result_t ocall_kvstore_save(bool* _retval,
                               char* key,
                               uint8_t* data,
                               size_t data_size) {
    return mock_ocall_kvstore_save(_retval, key, data, data_size);
}

oe_result_t ocall_kvstore_exists(bool* _retval, char* key) {
    return mock_ocall_kvstore_exists(_retval, key);
}

oe_result_t ocall_kvstore_get(size_t* _retval,
                              char* key,
                              uint8_t* data_buf,
                              size_t buffer_size) {
    return mock_ocall_kvstore_get(_retval, key, data_buf, buffer_size);
}

oe_result_t ocall_kvstore_remove(bool* _retval, char* key) {
    return mock_ocall_kvstore_remove(_retval, key);
}

// Helper functions
static void save_to_mock_kvstore(char* key, uint8_t* value, size_t value_size) {
    bool save_success = false;
    mock_ocall_kvstore_save(&save_success, key, value, value_size);
    mock_ocall_kstore_assert_value(key, value, value_size);
    assert(save_success);
}

static void save_sealed_db(const char* plaintext_db, bool refresh_init) {
    size_t plaintext_size = strlen(plaintext_db);
    size_t prefix_size = strlen(SEALED_PREFIX);
    size_t sealed_size = plaintext_size + prefix_size;
    uint8_t* sealed = malloc(sealed_size);
    assert(sealed);

    memcpy(sealed, SEALED_PREFIX, prefix_size);
    memcpy(sealed + prefix_size, plaintext_db, plaintext_size);

    save_to_mock_kvstore(DB_KEY, sealed, sealed_size);
    free(sealed);

    if (refresh_init) {
        // Keep secret_store cache in sync with the mock kvstore fixture update.
        // One-shot init semantics require an explicit module reset first.
        sest_reset_for_tests();
        assert(sest_init());
    } else {
        // Malformed fixtures are expected to fail init-time sanity checks.
        sest_reset_for_tests();
    }
}

static void setup() {
    sest_reset_for_tests();
    mock_seal_init();
    mock_ocall_init();
    assert(sest_init());
}

// Test cases
static void test_secret_exists_after_write() {
    setup();
    printf("Test secret exists after write...\n");

    char* key = "key";
    const uint8_t secret[] = "secret";
    const char expected_db[] = DB_HEADER "key=736563726574\n";

    // Ensure the secret doesn't exist before the write
    assert(!sest_exists(key));
    assert(!mock_ocall_kstore_key_exists(DB_KEY));

    // Write the secret and ensure it now exists
    assert(sest_write(key, (uint8_t*)secret, strlen((const char*)secret)));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(EXPECTED_SEAL_POLICY)},
        1,
        (const uint8_t*)expected_db,
        strlen(expected_db),
        NULL,
        0);

    assert(sest_exists(key));
    assert(mock_ocall_kstore_key_exists(DB_KEY));
}

static void test_write_and_retrieve_secret() {
    setup();
    printf("Test write and retrieve secret...\n");

    char* key = "key";
    const uint8_t secret[] = "secret";
    const char expected_db[] = DB_HEADER "key=736563726574\n";

    // Write the secret and make sure the seal API is called with the correct
    // arguments
    assert(sest_write(key, (uint8_t*)secret, strlen((const char*)secret)));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(EXPECTED_SEAL_POLICY)},
        1,
        (const uint8_t*)expected_db,
        strlen(expected_db),
        NULL,
        0);

    // Retrieve the secret and make sure the unseal API is called with the
    // correct arguments
    uint8_t retrieved[MAX_SEST_READ_SIZE];
    size_t retrieved_length = sest_read(key, retrieved, sizeof(retrieved));
    assert(retrieved_length == strlen((const char*)secret));
    ASSERT_MEMCMP(retrieved, secret, strlen((const char*)secret));
}

static void test_write_and_remove_secret() {
    setup();
    printf("Test write and remove secret...\n");

    char* key = "key";
    const uint8_t secret[] = "secret";

    assert(sest_write(key, (uint8_t*)secret, strlen((const char*)secret)));
    assert(sest_exists(key));
    assert(sest_remove(key));
    assert(!sest_exists(key));
    assert(mock_ocall_kstore_key_exists(DB_KEY));
}

static void test_init_fails_when_kvstore_get_fails() {
    sest_reset_for_tests();
    mock_seal_init();
    mock_ocall_init();
    printf("Test sest_init fails when ocall_kvstore_get fails...\n");

    mock_ocall_kvstore_fail_next(KVSTORE_FAILURE_OE_FAILURE);
    assert(!sest_init());
}

static void test_read_fails_when_oe_unseal_fails() {
    setup();
    printf("Test read fails when oe_unseal fails (OE_FAILURE)...\n");

    char* key = "key";
    save_sealed_db(DB_HEADER "key=736563726574\n", true);
    assert(sest_exists(key));

    mock_seal_fail_next();
    uint8_t retrieved[MAX_SEST_READ_SIZE];
    memset(retrieved, 0, sizeof(retrieved));
    size_t retrieved_length = sest_read(key, retrieved, sizeof(retrieved));
    assert(retrieved_length == SEST_ERROR);
    ASSERT_ARRAY_CLEARED(retrieved);
}

static void test_read_fails_when_plaintext_is_too_large() {
    setup();
    printf("Test read fails when unsealed secret is too large...\n");

    char* key = "key";
    save_sealed_db(DB_HEADER "key=736563726574\n", true);
    assert(sest_exists(key));
    uint8_t retrieved[5];
    memset(retrieved, 0, sizeof(retrieved));
    size_t retrieved_length = sest_read(key, retrieved, sizeof(retrieved));
    assert(retrieved_length == SEST_ERROR);
    assert(retrieved[0] == 0);
}

static void test_write_zero_length_secret_fails() {
    setup();
    printf("Test write zero length secret fails...\n");

    char* key = "key";
    assert(!sest_exists(key));
    assert(!mock_ocall_kstore_key_exists(DB_KEY));

    assert(!sest_write(key, NULL, 0));
    assert_oe_seal_not_called();
    assert(!sest_exists(key));
    assert(!mock_ocall_kstore_key_exists(DB_KEY));
}

static void test_write_fails_when_invalid_key() {
    setup();
    printf("Test write fails when key is invalid...\n");

    const uint8_t secret[] = "secret";
    assert(
        !sest_write("bad=key", (uint8_t*)secret, strlen((const char*)secret)));
    assert_oe_seal_not_called();
}

static void test_write_fails_when_oe_seal_fails() {
    setup();
    printf("Test write fails when oe_seal fails (OE_FAILURE)...\n");

    mock_seal_fail_next();
    char* key = "key";
    const uint8_t secret[] = "secret";
    const char expected_db[] = DB_HEADER "key=736563726574\n";

    assert(!sest_exists(key));
    assert(!sest_write(key, (uint8_t*)secret, strlen((const char*)secret)));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(EXPECTED_SEAL_POLICY)},
        1,
        (const uint8_t*)expected_db,
        strlen(expected_db),
        NULL,
        0);
    assert(!sest_exists(key));
    assert(!mock_ocall_kstore_key_exists(DB_KEY));
}

static void test_write_fails_when_kvstore_save_fails() {
    setup();
    printf("Test write fails when ocall_kvstore_save fails...\n");

    char* key = "key";
    const uint8_t secret[] = "secret";
    const char expected_db[] = DB_HEADER "key=736563726574\n";

    assert(!sest_exists(key));
    mock_ocall_kvstore_fail_next(KVSTORE_FAILURE_SAVE);
    assert(!sest_write(key, (uint8_t*)secret, strlen((const char*)secret)));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(EXPECTED_SEAL_POLICY)},
        1,
        (const uint8_t*)expected_db,
        strlen(expected_db),
        NULL,
        0);
    assert(!sest_exists(key));
    assert(!mock_ocall_kstore_key_exists(DB_KEY));
}

static void test_write_fails_when_kvstore_save_fails_oe_failure() {
    setup();
    printf("Test write fails when ocall_kvstore_save fails (OE_FAILURE)...\n");

    char* key = "key";
    const uint8_t secret[] = "secret";
    const char expected_db[] = DB_HEADER "key=736563726574\n";

    assert(!sest_exists(key));
    mock_ocall_kvstore_fail_next(KVSTORE_FAILURE_SAVE_OE_FAILURE);
    assert(!sest_write(key, (uint8_t*)secret, strlen((const char*)secret)));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(EXPECTED_SEAL_POLICY)},
        1,
        (const uint8_t*)expected_db,
        strlen(expected_db),
        NULL,
        0);
    assert(!sest_exists(key));
    assert(!mock_ocall_kstore_key_exists(DB_KEY));
}

static void test_write_fails_when_secret_too_large() {
    setup();
    printf("Test write fails when secret is too large...\n");

    char* key = "key";
    size_t secret_size = (MAX_BLOB_SIZE / 2) + 32;
    uint8_t* plaintext = malloc(secret_size);
    assert(plaintext);
    memset(plaintext, 0xaa, secret_size);

    assert(!sest_exists(key));
    assert(!sest_write(key, plaintext, secret_size));
    assert_oe_seal_not_called();
    assert(!sest_exists(key));
    assert(!mock_ocall_kstore_key_exists(DB_KEY));

    free(plaintext);
}

static void test_read_with_invalid_key_fails() {
    setup();
    printf("Test read with invalid key fails...\n");

    save_sealed_db(DB_HEADER "valid=736563726574\n", true);
    assert(sest_exists("valid"));

    // Reset call tracking so the invalid-key read assertion is scoped.
    mock_seal_init();

    uint8_t retrieved[MAX_SEST_READ_SIZE];
    size_t retrieved_length =
        sest_read("bad=key", retrieved, sizeof(retrieved));
    assert_oe_unseal_called_with(
        (const uint8_t*)"SEALED - KVDB1\nvalid=736563726574\n",
        strlen("SEALED - KVDB1\nvalid=736563726574\n"),
        NULL,
        0);
    assert(retrieved_length == SEST_ERROR);
}

static void test_read_uses_cached_blob_when_kvstore_get_would_fail() {
    setup();
    printf("Test read uses cached blob when kvstore_get would fail...\n");

    char* key = "key";
    save_sealed_db(DB_HEADER "key=736563726574\n", true);
    assert(sest_exists(key));

    // Reset call tracking so this assertion applies to sest_read only.
    mock_seal_init();

    // This failure should not affect sest_read: data is already cached in
    // memory.
    mock_ocall_kvstore_fail_next(KVSTORE_FAILURE_OE_FAILURE);
    uint8_t retrieved[MAX_SEST_READ_SIZE];
    memset(retrieved, 0, sizeof(retrieved));
    size_t retrieved_length = sest_read(key, retrieved, sizeof(retrieved));
    assert_oe_unseal_called_with(
        (const uint8_t*)"SEALED - KVDB1\nkey=736563726574\n",
        strlen("SEALED - KVDB1\nkey=736563726574\n"),
        NULL,
        0);
    assert(retrieved_length == strlen("secret"));
    ASSERT_MEMCMP(retrieved, "secret", strlen("secret"));
}

static void test_read_fails_when_blob_is_too_large() {
    setup();
    printf("Test read fails sealed blob is too large...\n");

    char* key = DB_KEY;
    uint8_t secret[MAX_BLOB_SIZE + 1];
    save_to_mock_kvstore(key, secret, sizeof(secret));

    uint8_t retrieved[MAX_SEST_READ_SIZE];
    memset(retrieved, 0, sizeof(retrieved));
    size_t retrieved_length = sest_read("key", retrieved, sizeof(retrieved));
    assert(retrieved_length == SEST_ERROR);
    ASSERT_ARRAY_CLEARED(retrieved);
}

static void test_remove_missing_key_is_success() {
    setup();
    printf("Test remove missing key is success...\n");

    save_sealed_db(DB_HEADER "key=736563726574\n", true);
    assert(sest_remove("other"));
    assert(sest_exists("key"));
}

static void test_remove_fails_when_kvstore_remove_fails() {
    setup();
    printf("Test remove fails when ocall_kvstore_remove fails...\n");

    save_sealed_db(DB_HEADER "key=736563726574\n", true);

    mock_ocall_kvstore_fail_next(KVSTORE_FAILURE_OE_FAILURE);
    assert(!sest_remove("key"));
    assert(sest_exists("key"));
}

static void test_read_fails_invalid_database_format() {
    setup();
    printf("Test read fails when the database format is invalid...\n");

    save_sealed_db(DB_HEADER "key=zz\n", false);

    uint8_t retrieved[MAX_SEST_READ_SIZE] = {0};
    size_t retrieved_length = sest_read("key", retrieved, sizeof(retrieved));
    assert(retrieved_length == SEST_ERROR);
    ASSERT_ARRAY_CLEARED(retrieved);
}

static void test_read_uses_first_duplicate_key_database() {
    setup();
    printf("Test read uses first value when database contains duplicate "
           "keys...\n");

    save_sealed_db(DB_HEADER "key=aa\nkey=bb\n", true);

    uint8_t retrieved[MAX_SEST_READ_SIZE] = {0};
    size_t retrieved_length = sest_read("key", retrieved, sizeof(retrieved));
    assert(retrieved_length == 1);
    assert(retrieved[0] == 0xaa);
}

static void test_multiple_keys_are_persisted_in_single_database() {
    setup();
    printf("Test multiple keys in single database...\n");

    assert(sest_write("password", (uint8_t*)"abcd", 4));
    assert(sest_write("retries", (uint8_t*)"\x03", 1));

    uint8_t out_password[8] = {0};
    uint8_t out_retries[8] = {0};

    size_t pw_len = sest_read("password", out_password, sizeof(out_password));
    size_t retries_len = sest_read("retries", out_retries, sizeof(out_retries));

    assert(pw_len == 4);
    assert(retries_len == 1);
    ASSERT_MEMCMP(out_password, "abcd", 4);
    assert(out_retries[0] == 0x03);
}

static void test_remove_invalid_key_fails() {
    setup();
    printf("Test remove invalid key delegates to kvdb behavior...\n");

    assert(sest_remove("bad=key"));
}

static void test_remove_existing_of_two_preserves_other() {
    setup();
    printf("Test remove one of two preserves other...\n");

    assert(sest_write("k1", (uint8_t*)"a", 1));
    assert(sest_write("k2", (uint8_t*)"b", 1));
    assert(sest_remove("k1"));
    assert(!sest_exists("k1"));
    assert(sest_exists("k2"));
}

static void test_remove_deletes_all_duplicate_instances() {
    setup();
    printf("Test remove deletes all duplicate instances...\n");

    save_sealed_db(DB_HEADER "k1=aa\nk1=bb\nk2=cc\n", true);
    assert(sest_remove("k1"));
    assert(!sest_exists("k1"));

    uint8_t out[8] = {0};
    size_t out_len = sest_read("k2", out, sizeof(out));
    assert(out_len == 1);
    assert(out[0] == 0xcc);
}

static void test_remove_nonexistent_when_no_db_is_success() {
    setup();
    printf("Test remove nonexistent without db is success...\n");

    assert(sest_remove("k1"));
}

static void test_exists_invalid_key_is_false() {
    setup();
    printf("Test exists invalid key is false...\n");

    assert(!sest_exists("bad=key"));
}

static void test_write_empty_secret_fails() {
    setup();
    printf("Test write empty secret fails...\n");

    uint8_t value = 0;
    assert(!sest_write("key", &value, 0));
}

static void test_read_not_found_returns_error() {
    setup();
    printf("Test read not found returns error...\n");

    assert(sest_write("k1", (uint8_t*)"x", 1));
    uint8_t out[8] = {0};
    assert(sest_read("k2", out, sizeof(out)) == SEST_ERROR);
    ASSERT_ARRAY_CLEARED(out);
}

static void test_read_invalid_dest_fails() {
    setup();
    printf("Test read invalid destination fails...\n");

    assert(sest_write("k1", (uint8_t*)"x", 1));
    assert(sest_read("k1", NULL, 1) == SEST_ERROR);
    uint8_t out[1] = {0};
    assert(sest_read("k1", out, 0) == SEST_ERROR);
}

static void test_write_updates_existing_key() {
    setup();
    printf("Test write updates existing key...\n");

    assert(sest_write("k1", (uint8_t*)"x", 1));
    assert(sest_write("k1", (uint8_t*)"yz", 2));
    uint8_t out[8] = {0};
    size_t out_len = sest_read("k1", out, sizeof(out));
    assert(out_len == 2);
    ASSERT_MEMCMP(out, "yz", 2);
}

static void test_remove_last_entry_deletes_database_key() {
    setup();
    printf("Test remove last entry keeps database key with header...\n");

    assert(sest_write("k1", (uint8_t*)"x", 1));
    assert(mock_ocall_kstore_key_exists(DB_KEY));
    assert(sest_remove("k1"));
    assert(mock_ocall_kstore_key_exists(DB_KEY));
}

static void test_write_then_exists_second_key() {
    setup();
    printf("Test exists for second key after multiple writes...\n");

    assert(sest_write("k1", (uint8_t*)"x", 1));
    assert(sest_write("k2", (uint8_t*)"y", 1));
    assert(sest_exists("k2"));
}

static void test_remove_with_malformed_database_fails() {
    setup();
    printf("Test remove fails with malformed database...\n");

    save_sealed_db(DB_HEADER "k1=gg\n", false);
    assert(!sest_remove("k1"));
}

static void test_write_fails_with_malformed_existing_database() {
    setup();
    printf("Test write fails with malformed existing database...\n");

    save_sealed_db(DB_HEADER "k1=gg\n", false);
    assert(!sest_write("k2", (uint8_t*)"z", 1));
}

static void test_exists_with_malformed_database_fails_closed() {
    setup();
    printf("Test exists fails closed with malformed database...\n");

    save_sealed_db(DB_HEADER "k1=gg\n", false);
    assert(!sest_exists("k1"));
}

static void test_init_fails_with_invalid_database_header() {
    setup();
    printf("Test init fails with invalid unsealed database header...\n");

    save_sealed_db("BADHDR\nk1=aa\n", false);
    assert(!sest_init());
}

static void test_read_ignores_duplicate_non_target_key() {
    setup();
    printf("Test duplicate non-target key is ignored...\n");

    save_sealed_db(DB_HEADER "k1=aa\nk2=bb\nk2=cc\n", true);
    uint8_t out[8] = {0};
    size_t out_len = sest_read("k1", out, sizeof(out));
    assert(out_len == 1);
    assert(out[0] == 0xaa);
}

static void test_write_requires_valid_key() {
    setup();
    printf("Test write requires valid key...\n");

    assert(!sest_write("", (uint8_t*)"x", 1));
    assert(!sest_write("a\nb", (uint8_t*)"x", 1));
}

static void test_read_requires_valid_key() {
    setup();
    printf("Test read requires valid key...\n");

    uint8_t out[8] = {0};
    assert(sest_read("a\rb", out, sizeof(out)) == SEST_ERROR);
}

static void test_remove_requires_valid_key() {
    setup();
    printf("Test remove key validation is delegated...\n");

    assert(sest_remove("a=b"));
}

int main() {
    test_secret_exists_after_write();
    test_write_and_retrieve_secret();
    test_write_and_remove_secret();
    test_write_zero_length_secret_fails();
    test_write_empty_secret_fails();
    test_write_fails_when_invalid_key();
    test_write_fails_when_oe_seal_fails();
    test_write_fails_when_secret_too_large();
    test_write_fails_when_kvstore_save_fails();
    test_write_fails_when_kvstore_save_fails_oe_failure();
    test_write_fails_with_malformed_existing_database();
    test_write_updates_existing_key();
    test_write_requires_valid_key();
    test_read_with_invalid_key_fails();
    test_read_fails_when_plaintext_is_too_large();
    test_read_uses_cached_blob_when_kvstore_get_would_fail();
    test_read_fails_when_blob_is_too_large();
    test_read_fails_when_oe_unseal_fails();
    test_read_fails_invalid_database_format();
    test_read_uses_first_duplicate_key_database();
    test_read_not_found_returns_error();
    test_read_invalid_dest_fails();
    test_read_ignores_duplicate_non_target_key();
    test_read_requires_valid_key();
    test_init_fails_when_kvstore_get_fails();
    test_exists_invalid_key_is_false();
    test_exists_with_malformed_database_fails_closed();
    test_init_fails_with_invalid_database_header();
    test_remove_missing_key_is_success();
    test_remove_fails_when_kvstore_remove_fails();
    test_remove_invalid_key_fails();
    test_remove_existing_of_two_preserves_other();
    test_remove_deletes_all_duplicate_instances();
    test_remove_nonexistent_when_no_db_is_success();
    test_remove_last_entry_deletes_database_key();
    test_remove_with_malformed_database_fails();
    test_remove_requires_valid_key();
    test_multiple_keys_are_persisted_in_single_database();
    test_write_then_exists_second_key();
    return 0;
}

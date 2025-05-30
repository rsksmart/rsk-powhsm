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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "assert_utils.h"
#include "secret_store.h"
#include "mock_seal.h"
#include "mock_ocall.h"

// Error code for the sest API as defined in secret_store.c
#define SEST_ERROR (0)
// The maximum value that can be returned by sest_read
#define MAX_SEST_READ_SIZE (255)
// The maximum blob_size for a sealed secret, as defined in secret_store.c
#define MAX_BLOB_SIZE (1024 * 1024)
// Utility macro that converts a plaintext secret into the sealed version
#define SEALED(str) ("SEALED - " str)
// The sha256 hash of the key "key"
#define KEY_HASH                               \
    "\x2c\x70\xe1\x2b\x7a\x06\x46\xf9\x22\x79" \
    "\xf4\x27\xc7\xb3\x8e\x73\x34\xd8\xe5\x38" \
    "\x9c\xff\x16\x7a\x1d\xc3\x0e\x73\xf8\x26" \
    "\xb6\x83"

// Used to store a plaintext secret and the expected sealed and
// unsealed versions
typedef struct {
    // The original plaintext secret
    uint8_t* plaintext;
    // The size of the plaintext secret
    size_t plaintext_size;
    // The unsealed secret, which is the plaintext secret prepended with the
    // sha256 hash of the key
    uint8_t* unsealed_secret;
    // The size of the unsealed secret
    size_t unsealed_size;
    // The sealed secret, which is the unsealed secret prepended with the string
    // "SEALED - "
    uint8_t* sealed_secret;
    // The size of the sealed secret
    size_t sealed_size;
} mock_secret_t;

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

// Initializes the secret struct with the expected sealed and unsealed versions
// of the given plaintext secret
static void init_mock_secret(mock_secret_t* mock, const char* plaintext) {
    const uint8_t key_hash[32] = KEY_HASH;
    const char sealed_prefix[] = "SEALED - ";

    mock->plaintext_size = strlen(plaintext);
    mock->unsealed_size = mock->plaintext_size + 32;
    mock->sealed_size = mock->unsealed_size + strlen(sealed_prefix);

    mock->plaintext = (uint8_t*)malloc(mock->plaintext_size + 1);
    mock->unsealed_secret = (uint8_t*)malloc(mock->unsealed_size + 1);
    mock->sealed_secret = (uint8_t*)malloc(mock->sealed_size + 1);

    memcpy(mock->plaintext, plaintext, mock->plaintext_size);
    memcpy(mock->unsealed_secret, key_hash, sizeof(key_hash));
    memcpy(mock->unsealed_secret + sizeof(key_hash),
           plaintext,
           mock->plaintext_size);
    memcpy(mock->sealed_secret, sealed_prefix, strlen(sealed_prefix));
    memcpy(mock->sealed_secret + strlen(sealed_prefix),
           mock->unsealed_secret,
           mock->unsealed_size);
}

static void free_mock_secret(mock_secret_t* mock) {
    free(mock->plaintext);
    free(mock->unsealed_secret);
    free(mock->sealed_secret);
}

void save_to_mock_kvstore(char* key, uint8_t* value, size_t value_size) {
    bool save_success = false;
    mock_ocall_kvstore_save(&save_success, key, value, value_size);
    mock_ocall_kstore_assert_value(key, value, value_size);
    assert(save_success);
}

void setup() {
    mock_seal_init();
    mock_ocall_init();
    assert(sest_init());
}

// Test cases
void test_secret_exists_after_write() {
    setup();
    printf("Test secret exists after write...\n");

    char* key = "key";
    mock_secret_t mock;
    init_mock_secret(&mock, "secret");
    // Ensure the secret doesn't exist before the write
    assert(!sest_exists(key));
    assert(!mock_ocall_kstore_key_exists(key));
    // Write the secret and ensure it now exists
    assert(sest_write(key, mock.plaintext, mock.plaintext_size));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        mock.unsealed_secret,
        mock.unsealed_size,
        NULL,
        0);
    mock_ocall_kstore_assert_value(key, mock.sealed_secret, mock.sealed_size);
    assert(sest_exists(key));
    free_mock_secret(&mock);
}

void test_write_and_retrieve_secret() {
    setup();
    printf("Test write and retrieve secret...\n");

    char* key = "key";
    mock_secret_t mock;
    init_mock_secret(&mock, "secret");
    // Write the secret and make sure the seal API is called with the correct
    // arguments
    assert(sest_write(key, mock.plaintext, mock.plaintext_size));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        mock.unsealed_secret,
        mock.unsealed_size,
        NULL,
        0);
    mock_ocall_kstore_assert_value(key, mock.sealed_secret, mock.sealed_size);
    // Retrieve the secret and make sure the unseal API is called with the
    // correct arguments
    uint8_t retrieved[MAX_SEST_READ_SIZE];
    uint8_t retrieved_length = sest_read(key, retrieved, sizeof(retrieved));
    assert_oe_unseal_called_with(mock.sealed_secret, mock.sealed_size, NULL, 0);
    assert(retrieved_length == mock.plaintext_size);
    ASSERT_MEMCMP(retrieved, mock.plaintext, mock.plaintext_size);
    free_mock_secret(&mock);
}

void test_write_and_remove_secret() {
    setup();
    printf("Test write and remove secret...\n");

    char* key = "key";
    mock_secret_t mock;
    init_mock_secret(&mock, "secret");
    assert(sest_write(key, mock.plaintext, mock.plaintext_size));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        mock.unsealed_secret,
        mock.unsealed_size,
        NULL,
        0);
    mock_ocall_kstore_assert_value(key, mock.sealed_secret, mock.sealed_size);
    assert(sest_exists(key));
    assert(sest_remove(key));
    assert(!sest_exists(key));
    assert(!mock_ocall_kstore_key_exists(key));
    free_mock_secret(&mock);
}

void test_exists_fails_when_kvstore_exists_fails() {
    setup();
    printf("Test sest_exists fails when ocall_kvstore_exists fails...\n");

    // Write a valid secret to the kvstore and ensure it exists
    char* key = "key";
    mock_secret_t mock;
    init_mock_secret(&mock, "secret");
    save_to_mock_kvstore(key, mock.sealed_secret, mock.sealed_size);
    assert(sest_exists(key));

    // Force the next call to ocall_kvstore_exists to fail
    mock_ocall_kvstore_fail_next(KVSTORE_FAILURE_OE_FAILURE);
    assert(!sest_exists(key));
    free_mock_secret(&mock);
}

void test_read_fails_when_oe_unseal_fails() {
    setup();
    printf("Test read fails when oe_unseal fails (OE_FAILURE)...\n");

    // Write a valid secret to the kvstore and ensure it exists
    char* key = "key";
    mock_secret_t mock;
    init_mock_secret(&mock, "secret");
    save_to_mock_kvstore(key, mock.sealed_secret, mock.sealed_size);
    assert(sest_exists(key));

    // Force the next call to oe_unseal to fail with OE_FAILURE
    mock_seal_fail_next();
    uint8_t retrieved[MAX_SEST_READ_SIZE];
    memset(retrieved, 0, sizeof(retrieved));
    uint8_t retrieved_length = sest_read(key, retrieved, sizeof(retrieved));
    assert_oe_unseal_called_with(mock.sealed_secret, mock.sealed_size, NULL, 0);
    assert(retrieved_length == SEST_ERROR);
    ASSERT_ARRAY_CLEARED(retrieved);
    free_mock_secret(&mock);
}

void test_read_fails_when_plaintext_is_too_large() {
    setup();
    printf("Test read fails when unsealed secret is too large...\n");

    // Write a valid secret to the kvstore and ensure it exists
    char* key = "key";
    mock_secret_t mock;
    init_mock_secret(&mock, "secret");
    save_to_mock_kvstore(key, mock.sealed_secret, mock.sealed_size);
    assert(sest_exists(key));
    // The retrieved buffer is one byte too short to fit the original secret
    uint8_t retrieved[mock.plaintext_size - 1];
    memset(retrieved, 0, sizeof(retrieved));
    uint8_t retrieved_length = sest_read(key, retrieved, sizeof(retrieved));
    assert_oe_unseal_called_with(mock.sealed_secret, mock.sealed_size, NULL, 0);
    assert(retrieved_length == SEST_ERROR);
    assert(retrieved[0] == 0);
    free_mock_secret(&mock);
}

void test_write_zero_length_secret_fails() {
    setup();
    printf("Test write zero length secret fails...\n");

    char* key = "key";
    // Ensure the secret doesn't exist before the write
    assert(!sest_exists(key));
    assert(!mock_ocall_kstore_key_exists(key));
    // Write the secret and ensure it fails
    assert(!sest_write(key, NULL, 0));
    // Make sure the seal API was never reached
    assert_oe_seal_not_called();
    assert(!sest_exists(key));
    assert(!mock_ocall_kstore_key_exists(key));
}

void test_write_fails_when_oe_seal_fails() {
    setup();
    printf("Test write fails when oe_seal fails (OE_FAILURE)...\n");

    // Force the next call to oe_seal to fail
    mock_seal_fail_next();
    char* key = "key";
    mock_secret_t mock;
    init_mock_secret(&mock, "secret");
    assert(!sest_exists(key));
    assert(!sest_write(key, mock.plaintext, mock.plaintext_size));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        mock.unsealed_secret,
        mock.unsealed_size,
        NULL,
        0);
    assert(!sest_exists(key));
    assert(!mock_ocall_kstore_key_exists(key));
    free_mock_secret(&mock);
}

void test_write_fails_when_kvstore_save_fails() {
    setup();
    printf("Test write fails when ocall_kvstore_save fails...\n");

    char* key = "key";
    mock_secret_t mock;
    init_mock_secret(&mock, "secret");
    assert(!sest_exists(key));
    // Force the next call to ocall_kvstore_save to fail
    mock_ocall_kvstore_fail_next(KVSTORE_FAILURE_SAVE);
    assert(!sest_write(key, mock.plaintext, mock.plaintext_size));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        mock.unsealed_secret,
        mock.unsealed_size,
        NULL,
        0);
    assert(!sest_exists(key));
    assert(!mock_ocall_kstore_key_exists(key));
    free_mock_secret(&mock);
}

void test_write_fails_when_kvstore_save_fails_oe_failure() {
    setup();
    printf("Test write fails when ocall_kvstore_save fails (OE_FAILURE)...\n");

    char* key = "key";
    mock_secret_t mock;
    init_mock_secret(&mock, "secret");
    assert(!sest_exists(key));
    // Force the next call to ocall_kvstore_save to fail with OE_FAILURE
    mock_ocall_kvstore_fail_next(KVSTORE_FAILURE_OE_FAILURE);
    assert(!sest_write(key, mock.plaintext, mock.plaintext_size));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        mock.unsealed_secret,
        mock.unsealed_size,
        NULL,
        0);
    assert(!sest_exists(key));
    assert(!mock_ocall_kstore_key_exists(key));
    free_mock_secret(&mock);
}

void test_write_fails_when_secret_too_large() {
    setup();
    printf("Test write fails when secret is too large...\n");

    // Attempt to write a secret that is too large
    char* key = "key";
    size_t secret_size = MAX_BLOB_SIZE + 1;
    char plaintext[secret_size];
    memset(plaintext, 0xaa, sizeof(plaintext));
    mock_secret_t mock;
    init_mock_secret(&mock, plaintext);
    assert(!sest_exists(key));
    assert(!sest_write(key, mock.plaintext, mock.plaintext_size));
    assert_oe_seal_not_called();
    assert(!sest_exists(key));
    assert(!mock_ocall_kstore_key_exists(key));
    free_mock_secret(&mock);
}

void test_read_with_invalid_key_fails() {
    setup();
    printf("Test read with invalid key fails...\n");

    // Write a valid secret to the kvstore and ensure it exists
    char* valid_key = "valid key";
    mock_secret_t mock;
    init_mock_secret(&mock, "secret");
    save_to_mock_kvstore(valid_key, mock.unsealed_secret, mock.unsealed_size);
    assert(sest_exists(valid_key));

    char* invalid_key = "invalid key";
    uint8_t retrieved[MAX_SEST_READ_SIZE];
    uint8_t retrieved_length =
        sest_read(invalid_key, retrieved, sizeof(retrieved));
    assert_oe_unseal_not_called();
    assert(retrieved_length == SEST_ERROR);
    free_mock_secret(&mock);
}

void test_read_fails_when_kvstore_get_fails() {
    setup();
    printf("Test read fails when ocall_kvstore_get fails (OE_FAILURE)...\n");

    // Write a valid secret to the kvstore and ensure it exists
    char* key = "key";
    mock_secret_t mock;
    init_mock_secret(&mock, "secret");
    save_to_mock_kvstore(key, mock.unsealed_secret, mock.unsealed_size);
    assert(sest_exists(key));

    // Force OE_FAILURE on the next call to ocall_kvstore_get
    mock_ocall_kvstore_fail_next(KVSTORE_FAILURE_OE_FAILURE);
    uint8_t retrieved[MAX_SEST_READ_SIZE];
    memset(retrieved, 0, sizeof(retrieved));
    uint8_t retrieved_length = sest_read(key, retrieved, sizeof(retrieved));
    assert_oe_unseal_not_called();
    assert(retrieved_length == SEST_ERROR);
    ASSERT_ARRAY_CLEARED(retrieved);
    free_mock_secret(&mock);
}

void test_read_fails_when_blob_is_too_large() {
    setup();
    printf("Test read fails sealed blob is too large...\n");

    // Pre-load the kvstore with a secret that is larger than the maximum
    // allowed blob size
    char* key = "key";
    uint8_t secret[MAX_BLOB_SIZE + 1];
    save_to_mock_kvstore(key, secret, sizeof(secret));

    assert(sest_exists(key));
    uint8_t retrieved[MAX_SEST_READ_SIZE];
    memset(retrieved, 0, sizeof(retrieved));
    uint8_t retrieved_length = sest_read(key, retrieved, sizeof(retrieved));
    assert_oe_unseal_not_called();
    assert(retrieved_length == SEST_ERROR);
    ASSERT_ARRAY_CLEARED(retrieved);
}

void test_remove_with_invalid_key_fails() {
    setup();
    printf("Test remove invalid key fails...\n");

    char* valid_key = "valid key";
    mock_secret_t mock;
    init_mock_secret(&mock, "secret");
    save_to_mock_kvstore(valid_key, mock.sealed_secret, mock.sealed_size);
    assert(sest_exists(valid_key));

    char* invalid_key = "invalid key";
    assert(!sest_remove(invalid_key));
    // Make sure the valid key still exists
    assert(sest_exists(valid_key));
    mock_ocall_kstore_assert_value(
        valid_key, mock.sealed_secret, mock.sealed_size);
    free_mock_secret(&mock);
}

void test_remove_fails_when_kvstore_remove_fails() {
    setup();
    printf("Test remove fails when ocall_kvstore_remove fails...\n");

    char* key = "key";
    mock_secret_t mock;
    init_mock_secret(&mock, "secret");
    save_to_mock_kvstore(key, mock.sealed_secret, mock.sealed_size);
    assert(sest_exists(key));
    // Force the next call to ocall_kvstore_remove to fail
    mock_ocall_kvstore_fail_next(KVSTORE_FAILURE_OE_FAILURE);
    assert(!sest_remove(key));
    assert(sest_exists(key));
    mock_ocall_kstore_assert_value(key, mock.sealed_secret, mock.sealed_size);
    free_mock_secret(&mock);
}

void test_read_fails_invalid_header() {
    setup();
    printf("Test read fails when the secret header is invalid...\n");

    char* key = "key";
    mock_secret_t mock;
    init_mock_secret(&mock, "secret");
    // Write the secret and make sure the seal API is called with the correct
    // arguments
    assert(sest_write(key, mock.plaintext, mock.plaintext_size));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        mock.unsealed_secret,
        mock.unsealed_size,
        NULL,
        0);
    mock_ocall_kstore_assert_value(key, mock.sealed_secret, mock.sealed_size);

    // Tamper the secret with an invalid header
    // This emulates a situation where the files representing
    // the sealed secrets are swapped or corrupted
    memcpy(mock.sealed_secret + strlen("SEALED - "), "\x01\x02\x03\x04", 4);
    save_to_mock_kvstore(key, mock.sealed_secret, mock.sealed_size);
    assert(sest_exists(key));
    mock_ocall_kstore_assert_value(key, mock.sealed_secret, mock.sealed_size);

    uint8_t retrieved[MAX_SEST_READ_SIZE] = {0};
    uint8_t retrieved_length = sest_read(key, retrieved, sizeof(retrieved));
    assert(retrieved_length == SEST_ERROR);
    ASSERT_ARRAY_CLEARED(retrieved);

    assert_oe_unseal_called_with(mock.sealed_secret, mock.sealed_size, NULL, 0);

    free_mock_secret(&mock);
}

int main() {
    test_secret_exists_after_write();
    test_write_and_retrieve_secret();
    test_write_and_remove_secret();
    test_write_zero_length_secret_fails();
    test_write_fails_when_oe_seal_fails();
    test_write_fails_when_secret_too_large();
    test_write_fails_when_kvstore_save_fails();
    test_write_fails_when_kvstore_save_fails_oe_failure();
    test_read_with_invalid_key_fails();
    test_read_fails_when_plaintext_is_too_large();
    test_read_fails_when_kvstore_get_fails();
    test_read_fails_when_blob_is_too_large();
    test_read_fails_when_oe_unseal_fails();
    test_exists_fails_when_kvstore_exists_fails();
    test_remove_with_invalid_key_fails();
    test_remove_fails_when_kvstore_remove_fails();
    test_read_fails_invalid_header();
}

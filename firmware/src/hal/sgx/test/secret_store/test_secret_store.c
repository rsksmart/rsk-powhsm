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

void setup() {
    mock_seal_init();
    mock_ocall_init();
    assert(sest_init());
}

void test_secret_exists_after_write() {
    setup();
    printf("Test secret exists after write...\n");

    char* key = "key";
    uint8_t secret[] = "secret";
    // Ensure the secret doesn't exist before the write
    assert(!sest_exists(key));
    // Write the secret and ensure it now exists
    assert(sest_write("key", secret, sizeof(secret)));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        secret,
        sizeof(secret),
        NULL,
        0);
    assert(sest_exists("key"));
}

void test_write_and_retrieve_secret() {
    setup();
    printf("Test write and retrieve secret...\n");

    char* key = "key";
    uint8_t secret[] = "secret";
    // Write the secret and make sure the seal API is called with the correct
    // arguments
    assert(sest_write(key, secret, sizeof(secret)));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        secret,
        sizeof(secret),
        NULL,
        0);
    // Retrieve the secret and make sure the unseal API is called with the
    // correct arguments
    uint8_t retrieved[MAX_SEST_READ_SIZE];
    uint8_t retrieved_length = sest_read(key, retrieved, sizeof(retrieved));
    uint8_t expected_sealed_blob[] = "SEALED - secret";
    assert_oe_unseal_called_with(
        expected_sealed_blob, sizeof(expected_sealed_blob), NULL, 0);
    assert(retrieved_length == sizeof(secret));
    ASSERT_MEMCMP(retrieved, secret, retrieved_length);
}

void test_write_and_remove_secret() {
    setup();
    printf("Test write and remove secret...\n");

    char* key = "key";
    uint8_t secret[] = "secret";
    assert(sest_write(key, secret, sizeof(secret)));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        secret,
        sizeof(secret),
        NULL,
        0);
    assert(sest_exists(key));
    assert(sest_remove(key));
    assert(!sest_exists(key));
}

void test_exists_fails_when_kvstore_exists_fails() {
    setup();
    printf("Test sest_exists fails when ocall_kvstore_exists fails...\n");

    // Write a valid secret and ensure it exists
    char* key = "key";
    uint8_t secret[] = "secret";
    assert(!sest_exists(key));
    assert(sest_write(key, secret, sizeof(secret)));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        secret,
        sizeof(secret),
        NULL,
        0);
    assert(sest_exists(key));

    // Force the next call to ocall_kvstore_exists to fail
    mock_ocall_kvstore_fail_next(KVSTORE_FAILURE_OE_FAILURE);
    assert(!sest_exists(key));
}

void test_read_fails_when_oe_unseal_fails() {
    setup();
    printf("Test read fails when oe_unseal fails (OE_FAILURE)...\n");

    char* key = "key";
    uint8_t secret[] = "secret";
    assert(sest_write(key, secret, sizeof(secret)));
    assert(sest_exists(key));
    // Force the next call to oe_unseal to fail with OE_FAILURE
    mock_seal_fail_next(SEAL_FAILURE_OE_FAILURE);
    uint8_t retrieved[MAX_SEST_READ_SIZE];
    memset(retrieved, 0, sizeof(retrieved));
    uint8_t retrieved_length = sest_read(key, retrieved, sizeof(retrieved));
    uint8_t expected_sealed_blob[] = "SEALED - secret";
    assert_oe_unseal_called_with(
        expected_sealed_blob, sizeof(expected_sealed_blob), NULL, 0);
    assert(retrieved_length == SEST_ERROR);
    ASSERT_ARRAY_CLEARED(retrieved);
}

void test_read_fails_when_plaintext_is_too_large() {
    setup();
    printf("Test read fails when unsealed secret is too large...\n");

    char* key = "key";
    uint8_t secret[] = "secret";
    assert(sest_write(key, secret, sizeof(secret)));
    assert(sest_exists(key));
    // Force the next call to oe_unseal to fail by returning a plaintext that is
    // too large
    mock_seal_fail_next(SEAL_FAILURE_OE_UNSEAL_PLAINTEXT_TOO_LARGE);
    uint8_t retrieved[MAX_SEST_READ_SIZE];
    memset(retrieved, 0, sizeof(retrieved));
    uint8_t retrieved_length = sest_read(key, retrieved, sizeof(retrieved));
    uint8_t expected_sealed_blob[] = "SEALED - secret";
    assert_oe_unseal_called_with(
        expected_sealed_blob, sizeof(expected_sealed_blob), NULL, 0);
    assert(retrieved_length == SEST_ERROR);
    ASSERT_ARRAY_CLEARED(retrieved);
}

void test_write_zero_length_secret_fails() {
    setup();
    printf("Test write zero length secret fails...\n");

    char* key = "key";
    // Ensure the secret doesn't exist before the write
    assert(!sest_exists(key));
    // Write the secret and ensure it fails
    assert(!sest_write(key, NULL, 0));
    // Make sure the seal API was never reached
    assert_oe_seal_not_called();
    assert(!sest_exists(key));
}

void test_write_fails_when_oe_seal_fails() {
    setup();
    printf("Test write fails when oe_seal fails (OE_FAILURE)...\n");

    // Force the next call to oe_seal to fail
    mock_seal_fail_next(SEAL_FAILURE_OE_FAILURE);
    char* key = "key";
    uint8_t secret[] = "secret";
    assert(!sest_exists(key));
    assert(!sest_write(key, secret, sizeof(secret)));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        secret,
        sizeof(secret),
        NULL,
        0);
    assert(!sest_exists(key));
}

void test_write_fails_when_kvstore_save_fails() {
    setup();
    printf("Test write fails when ocall_kvstore_save fails...\n");

    char* key = "key";
    uint8_t secret[] = "secret";
    assert(!sest_exists(key));
    // Force the next call to ocall_kvstore_save to fail
    mock_ocall_kvstore_fail_next(KVSTORE_FAILURE_SAVE);
    assert(!sest_write(key, secret, sizeof(secret)));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        secret,
        sizeof(secret),
        NULL,
        0);
    assert(!sest_exists(key));
}

void test_write_fails_when_kvstore_save_fails_oe_failure() {
    setup();
    printf("Test write fails when ocall_kvstore_save fails (OE_FAILURE)...\n");

    char* key = "key";
    uint8_t secret[] = "secret";
    assert(!sest_exists(key));
    // Force the next call to ocall_kvstore_save to fail with OE_FAILURE
    mock_ocall_kvstore_fail_next(KVSTORE_FAILURE_OE_FAILURE);
    assert(!sest_write(key, secret, sizeof(secret)));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        secret,
        sizeof(secret),
        NULL,
        0);
    assert(!sest_exists(key));
}

void test_write_fails_when_secret_too_large() {
    setup();
    printf("Test write fails when secret is too large...\n");

    // Attempt to write a secret that is too large
    char* key = "key";
    size_t secret_size = mock_seal_get_max_plaintext_size() + 1;
    uint8_t secret[secret_size];
    assert(!sest_exists(key));
    assert(!sest_write(key, secret, secret_size));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        secret,
        secret_size,
        NULL,
        0);
    assert(!sest_exists(key));
}

void test_read_with_invalid_key_fails() {
    setup();
    printf("Test read with invalid key fails...\n");

    char* valid_key = "valid key";
    uint8_t secret[] = "secret";
    assert(sest_write(valid_key, secret, sizeof(secret)));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        secret,
        sizeof(secret),
        NULL,
        0);
    assert(sest_exists(valid_key));

    char* invalid_key = "invalid key";
    uint8_t retrieved[MAX_SEST_READ_SIZE];
    uint8_t retrieved_length =
        sest_read(invalid_key, retrieved, sizeof(retrieved));
    assert_oe_unseal_not_called();
    assert(retrieved_length == SEST_ERROR);
}

void test_read_fails_when_kvstore_get_fails() {
    setup();
    printf("Test read fails when ocall_kvstore_get fails (OE_FAILURE)...\n");

    char* key = "key";
    uint8_t secret[] = "secret";
    // Write the secret
    assert(sest_write(key, secret, sizeof(secret)));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        secret,
        sizeof(secret),
        NULL,
        0);
    assert(sest_exists(key));
    // Force OE_FAILURE on the next call to ocall_kvstore_get
    mock_ocall_kvstore_fail_next(KVSTORE_FAILURE_OE_FAILURE);
    uint8_t retrieved[MAX_SEST_READ_SIZE];
    memset(retrieved, 0, sizeof(retrieved));
    uint8_t retrieved_length = sest_read(key, retrieved, sizeof(retrieved));
    assert_oe_unseal_not_called();
    assert(retrieved_length == SEST_ERROR);
    ASSERT_ARRAY_CLEARED(retrieved);
}

void test_read_fails_when_blob_is_too_large() {
    setup();
    printf("Test read fails sealed blob is too large...\n");

    char* key = "key";
    uint8_t secret[] = "secret";
    // Write the secret
    assert(sest_write(key, secret, sizeof(secret)));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        secret,
        sizeof(secret),
        NULL,
        0);
    assert(sest_exists(key));
    // Force the next call to ocall_kvstore_get to return a blob that is too
    // large
    mock_ocall_kvstore_fail_next(KVSTORE_FAILURE_GET_SEALED_BLOB_TOO_LARGE);
    uint8_t retrieved[MAX_SEST_READ_SIZE];
    memset(retrieved, 0, sizeof(retrieved));
    uint8_t retrieved_length = sest_read(key, retrieved, sizeof(retrieved));
    assert_oe_unseal_not_called();
    assert(retrieved_length == SEST_ERROR);
    ASSERT_ARRAY_CLEARED(retrieved);
}

void test_remove_with_invalid_key_fails() {
    setup();
    printf("Test write and remove invalid key fails...\n");

    char* valid_key = "valid key";
    uint8_t secret[] = "secret";
    assert(sest_write(valid_key, secret, sizeof(secret)));
    assert(sest_exists(valid_key));
    char* invalid_key = "invalid key";
    assert(!sest_remove(invalid_key));
}

void test_remove_fails_when_kvstore_remove_fails() {
    setup();
    printf("Test remove fails when ocall_kvstore_remove fails...\n");

    char* key = "key";
    uint8_t secret[] = "secret";
    assert(sest_write(key, secret, sizeof(secret)));
    assert_oe_seal_called_with(
        NULL,
        (const oe_seal_setting_t[]){OE_SEAL_SET_POLICY(1)},
        1,
        secret,
        sizeof(secret),
        NULL,
        0);
    assert(sest_exists(key));
    // Force the next call to ocall_kvstore_remove to fail
    mock_ocall_kvstore_fail_next(KVSTORE_FAILURE_OE_FAILURE);
    assert(!sest_remove(key));
    assert(sest_exists(key));
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
}

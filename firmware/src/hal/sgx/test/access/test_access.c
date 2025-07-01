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

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "assert_utils.h"

#include "hal/access.h"

// Mocks
struct {
    bool sest_exists_password;
    bool sest_exists_retries;
    bool sest_read_success;
    bool sest_read_password_fail;
    bool sest_read_retries_fail;
    bool sest_write_success;
    bool sest_remove_success;
    bool pin_policy_is_valid_pin_success;
    bool oe_is_within_enclave_success;
} G_mocks;

struct {
    bool sest_exists;
    bool sest_read;
    bool sest_write;
    bool sest_remove;
    bool pin_policy_is_valid_pin;
    bool oe_is_within_enclave;
    bool wiped_callback;
} G_called;

struct {
    struct {
        char* key;
    } sest_exists;

    struct {
        char* key;
        uint8_t* dest;
        size_t dest_length;
    } sest_read;

    struct {
        char* key;
        uint8_t* secret;
        size_t secret_length;
    } sest_write;

    struct {
        char* key;
    } sest_remove;

    struct {
        const char* pin;
        size_t pin_length;
    } pin_policy;

    struct {
        uint8_t* buffer;
        size_t size;
    } oe_is_within_enclave;
} G_args;

// Mock stored data for secret store
static char G_stored_password[] = "1234567a";
static uint8_t G_stored_password_length = 8;
static uint8_t G_stored_retries = 3;

// Mock implementations
bool sest_exists(char* key) {
    G_called.sest_exists = true;
    G_args.sest_exists.key = key;

    if (strcmp(key, "password") == 0) {
        return G_mocks.sest_exists_password;
    } else if (strcmp(key, "retries") == 0) {
        return G_mocks.sest_exists_retries;
    }
    return false;
}

uint8_t sest_read(char* key, uint8_t* dest, size_t dest_length) {
    G_called.sest_read = true;
    G_args.sest_read.key = key;
    G_args.sest_read.dest = dest;
    G_args.sest_read.dest_length = dest_length;

    if (!G_mocks.sest_read_success) {
        return 0;
    }

    if (strcmp(key, "password") == 0) {
        if (G_mocks.sest_read_password_fail) {
            return 0;
        }
        if (dest_length >= G_stored_password_length) {
            memcpy(dest, G_stored_password, G_stored_password_length);
            return G_stored_password_length;
        }
        return 0;
    } else if (strcmp(key, "retries") == 0) {
        if (G_mocks.sest_read_retries_fail) {
            return 0;
        }
        if (dest_length >= sizeof(uint8_t)) {
            memcpy(dest, &G_stored_retries, sizeof(uint8_t));
            return sizeof(uint8_t);
        }
        return 0;
    }

    return 0;
}

bool sest_write(char* key, uint8_t* secret, size_t secret_length) {
    G_called.sest_write = true;
    G_args.sest_write.key = key;
    G_args.sest_write.secret = secret;
    G_args.sest_write.secret_length = secret_length;

    // Update mock stored data
    if (strcmp(key, "password") == 0 && G_mocks.sest_write_success) {
        memcpy(G_stored_password, secret, secret_length);
        G_stored_password_length = secret_length;
    } else if (strcmp(key, "retries") == 0 && G_mocks.sest_write_success) {
        G_stored_retries = *(uint8_t*)secret;
    }

    return G_mocks.sest_write_success;
}

bool sest_remove(char* key) {
    G_called.sest_remove = true;
    G_args.sest_remove.key = key;
    return G_mocks.sest_remove_success;
}

bool pin_policy_is_valid_pin(const char* pin, size_t pin_length) {
    G_called.pin_policy_is_valid_pin = true;
    G_args.pin_policy.pin = pin;
    G_args.pin_policy.pin_length = pin_length;
    return G_mocks.pin_policy_is_valid_pin_success;
}

bool oe_is_within_enclave(const void* buffer, size_t size) {
    G_called.oe_is_within_enclave = true;
    G_args.oe_is_within_enclave.buffer = (uint8_t*)buffer;
    G_args.oe_is_within_enclave.size = size;
    return G_mocks.oe_is_within_enclave_success;
}

void test_wiped_callback() {
    G_called.wiped_callback = true;
}

void test_access_init() {
    G_mocks.sest_exists_password = true;
    G_mocks.sest_exists_retries = true;

    bool init_ok = access_init(test_wiped_callback);

    assert(init_ok);
    assert(G_called.sest_exists);
    assert(G_called.sest_read);
    assert(G_called.pin_policy_is_valid_pin);

    // Reset call flags
    explicit_bzero(&G_called, sizeof(G_called));
}

void test_access_init_wiped() {
    G_mocks.sest_exists_password = false;
    G_mocks.sest_exists_retries = false;

    bool init_ok = access_init(test_wiped_callback);

    assert(init_ok);
    assert(G_called.sest_exists);
    assert(!G_called.sest_read);
    assert(!G_called.pin_policy_is_valid_pin);

    // Reset call flags
    explicit_bzero(&G_called, sizeof(G_called));
}

void test_access_init_unlock() {
    test_access_init();
    char password[] = "1234567a";
    uint8_t password_length = 8;
    bool unlock_ok = access_unlock(password, password_length);

    assert(unlock_ok);
    assert(G_called.sest_write);

    // Reset call flags
    explicit_bzero(&G_called, sizeof(G_called));
}

// Unit tests
void setup() {
    explicit_bzero(&G_mocks, sizeof(G_mocks));
    explicit_bzero(&G_called, sizeof(G_called));
    explicit_bzero(&G_args, sizeof(G_args));

    G_mocks.sest_exists_password = false;
    G_mocks.sest_exists_retries = false;
    G_mocks.sest_read_success = true;
    G_mocks.sest_read_password_fail = false;
    G_mocks.sest_read_retries_fail = false;
    G_mocks.sest_write_success = true;
    G_mocks.sest_remove_success = true;
    G_mocks.pin_policy_is_valid_pin_success = true;
    G_mocks.oe_is_within_enclave_success = true;

    strcpy(G_stored_password, "1234567a");
    G_stored_password_length = 8;
    G_stored_retries = 3;
}

void test_access_init_wiped_state_ok() {
    setup();
    printf("Testing access_init succeeds when module is wiped...\n");

    test_access_init_wiped();

    assert(access_is_wiped() == true);
    assert(access_is_locked() == true);
}

void test_access_init_with_valid_stored_data_ok() {
    setup();
    printf("Testing access_init succeeds with valid stored data...\n");

    test_access_init();

    assert(access_is_wiped() == false);
    assert(access_is_locked() == true);
    assert(access_get_retries() == 3);
}

void test_access_init_password_read_fails() {
    setup();
    printf("Testing access_init fails when password read fails...\n");

    G_mocks.sest_exists_password = true;
    G_mocks.sest_exists_retries = true;
    G_mocks.sest_read_password_fail = true;

    bool result = access_init(test_wiped_callback);

    assert(result == false);
    assert(G_called.sest_read);
    assert(!G_called.pin_policy_is_valid_pin);
}

void test_access_init_invalid_password() {
    setup();
    printf("Testing access_init fails when stored password is invalid...\n");

    G_mocks.sest_exists_password = true;
    G_mocks.sest_exists_retries = true;
    G_mocks.pin_policy_is_valid_pin_success = false;

    bool result = access_init(test_wiped_callback);

    assert(result == false);
    assert(G_called.sest_read);
    assert(G_called.pin_policy_is_valid_pin);
}

void test_access_init_retries_read_fails() {
    setup();
    printf("Testing access_init fails when retries read fails...\n");

    G_mocks.sest_exists_password = true;
    G_mocks.sest_exists_retries = true;
    G_mocks.sest_read_retries_fail = true;

    bool result = access_init(test_wiped_callback);

    assert(result == false);
    assert(G_called.sest_read);
    assert(G_called.pin_policy_is_valid_pin);
}

void test_access_init_invalid_retries_zero() {
    setup();
    printf("Testing access_init fails when stored retries is zero...\n");

    G_mocks.sest_exists_password = true;
    G_mocks.sest_exists_retries = true;
    G_stored_retries = 0;

    bool result = access_init(test_wiped_callback);

    assert(result == false);
    assert(G_called.sest_read);
    assert(G_called.pin_policy_is_valid_pin);
}

void test_access_init_invalid_retries_too_high() {
    setup();
    printf("Testing access_init fails when stored retries is too high...\n");

    G_mocks.sest_exists_password = true;
    G_mocks.sest_exists_retries = true;
    G_stored_retries = 4;

    bool result = access_init(test_wiped_callback);

    assert(result == false);
    assert(G_called.sest_read);
    assert(G_called.pin_policy_is_valid_pin);
}

void test_access_wipe_when_not_wiped_ok() {
    setup();
    printf("Testing access_wipe succeeds when not wiped...\n");

    test_access_init();

    bool result = access_wipe();
    assert(result == true);
    assert(access_is_wiped() == true);
    assert(access_is_locked() == true);
    assert(G_called.sest_remove);
}

void test_access_wipe_already_wiped_ok() {
    setup();
    printf("Testing access_wipe succeeds when already wiped...\n");

    test_access_init_wiped();

    bool result = access_wipe();

    assert(result == true);
    assert(access_is_wiped() == true);
    assert(access_is_locked() == true);
    assert(G_called.sest_remove);
}

void test_access_wipe_sest_remove_fails() {
    setup();
    printf("Testing access_wipe fails when sest_remove fails...\n");

    test_access_init();

    G_mocks.sest_remove_success = false;

    bool result = access_wipe();

    assert(result == false);
    assert(access_is_wiped() == true);
    assert(access_is_locked() == true);
    assert(G_called.sest_remove);
}

void test_access_unlock_ok() {
    setup();
    printf("Testing access_unlock succeeds...\n");

    test_access_init_unlock();

    assert(access_is_locked() == false);
    assert(access_get_retries() == 3);
}

void test_access_unlock_wiped() {
    setup();
    printf("Testing access_unlock fails when module is wiped...\n");

    test_access_init_wiped();

    char password[] = "1234567a";
    bool result = access_unlock(password, 8);

    assert(result == false);
    assert(access_is_wiped() == true);
    assert(access_is_locked() == true);
}

void test_access_unlock_already_unlocked() {
    setup();
    printf("Testing access_unlock succeeds when already unlocked...\n");

    test_access_init_unlock();

    bool second_unlock = access_unlock("1234567a", 8);

    assert(second_unlock == true);
    assert(access_is_locked() == false);
    assert(!G_called.sest_write);
}

void test_access_unlock_wrong_password() {
    setup();
    printf("Testing access_unlock fails with wrong password...\n");

    test_access_init();

    char wrong_password[] = "wrong";
    bool result = access_unlock(wrong_password, 5);

    assert(result == false);
    assert(access_is_locked() == true);
    assert(access_get_retries() == 2);
    assert(G_called.sest_write);
}

void test_access_unlock_wrong_password_length() {
    setup();
    printf("Testing access_unlock with wrong password length...\n");

    test_access_init();

    char password[] = "1234567a";
    bool result = access_unlock(password, 7);

    assert(result == false);
    assert(access_is_locked() == true);
    assert(access_get_retries() == 2);
    assert(G_called.sest_write);
}

void test_access_unlock_excessive_retries() {
    setup();
    printf("Testing access_unlock excessive retries triggers wipe...\n");

    G_stored_retries = 1;
    test_access_init();

    char wrong_password[] = "wrong";
    bool result = access_unlock(wrong_password, 5);

    assert(result == false);
    assert(access_is_wiped() == true);
    assert(access_get_retries() == 0);
    assert(G_called.wiped_callback);
    assert(G_called.sest_remove);
}

void test_access_set_password_when_wiped_ok() {
    setup();
    printf("Testing access_set_password succeeds when module is wiped...\n");

    test_access_init_wiped();

    char new_password[] = "newpass";
    bool result = access_set_password(new_password, 7);

    assert(result == true);
    assert(access_is_wiped() == false);
    assert(access_is_locked() == true);
    assert(access_get_retries() == 3);
    assert(G_called.pin_policy_is_valid_pin);
    assert(G_called.sest_write);
}

void test_access_set_password_when_unlocked_ok() {
    setup();
    printf("Testing access_set_password succeeds when unlocked...\n");

    test_access_init_unlock();

    char new_password[] = "newpass";
    bool result = access_set_password(new_password, 7);

    assert(result == true);
    assert(access_is_locked() == true);
    assert(access_get_retries() == 3);
    assert(G_called.pin_policy_is_valid_pin);
    assert(G_called.sest_write);
}

void test_access_set_password_when_locked_fails() {
    setup();
    printf("Testing access_set_password fails when locked and not wiped...\n");

    test_access_init();

    char new_password[] = "newpass";
    bool result = access_set_password(new_password, 7);

    assert(result == false);
    assert(access_is_locked() == true);
    assert(!G_called.pin_policy_is_valid_pin);
    assert(!G_called.sest_write);
}

void test_access_set_password_invalid_pin() {
    setup();
    printf("Testing access_set_password fails with invalid pin...\n");

    test_access_init_unlock();

    G_mocks.pin_policy_is_valid_pin_success = false;

    char invalid_password[] = "12345678";
    bool result = access_set_password(invalid_password, 8);

    assert(result == false);
    assert(G_called.pin_policy_is_valid_pin);
    assert(!G_called.sest_write);
}

void test_access_set_password_sest_write_fails() {
    setup();
    printf("Testing access_set_password fails when sest_write fails...\n");

    test_access_init_unlock();

    G_mocks.sest_write_success = false;

    char new_password[] = "newpass";
    bool result = access_set_password(new_password, 7);

    assert(result == false);
    assert(G_called.pin_policy_is_valid_pin);
    assert(G_called.sest_write);
}

void test_access_output_password_ok() {
    setup();
    printf("Testing access_output_password succeeds...\n");

    test_access_init_unlock();

    uint8_t output[16];
    size_t output_size = sizeof(output);

    bool result =
        access_output_password_USE_FROM_EXPORT_ONLY(output, &output_size);

    assert(result == true);
    assert(output_size == 8);
    assert(G_called.oe_is_within_enclave);
    ASSERT_MEMCMP(output, G_stored_password, output_size);
}

void test_access_output_password_wiped() {
    setup();
    printf("Testing access_output_password fails when module is wiped...\n");

    test_access_init_wiped();

    uint8_t output[] = "not-the-password";
    size_t output_size = sizeof(output);

    bool result =
        access_output_password_USE_FROM_EXPORT_ONLY(output, &output_size);

    assert(result == false);
    ASSERT_MEMCMP(output, "not-the-password", sizeof(output));
}

void test_access_output_password_buffer_too_small() {
    setup();
    printf("Testing access_output_password fails with buffer too small...\n");

    test_access_init_unlock();

    uint8_t output[] = "not-the-password";
    size_t output_size = 4;

    bool result =
        access_output_password_USE_FROM_EXPORT_ONLY(output, &output_size);

    assert(result == false);
    ASSERT_MEMCMP(output, "not-the-password", sizeof(output));
}

void test_access_output_password_buffer_not_in_enclave() {
    setup();
    printf("Testing access_output_password fails outside of enclave...\n");

    test_access_init_unlock();

    G_mocks.oe_is_within_enclave_success = false;

    uint8_t output[] = "not-the-password";
    size_t output_size = sizeof(output);

    bool result =
        access_output_password_USE_FROM_EXPORT_ONLY(output, &output_size);

    assert(result == false);
    assert(G_called.oe_is_within_enclave);
    ASSERT_MEMCMP(output, "not-the-password", sizeof(output));
}

int main() {
    test_access_init_wiped_state_ok();
    test_access_init_with_valid_stored_data_ok();
    test_access_init_password_read_fails();
    test_access_init_invalid_password();
    test_access_init_retries_read_fails();
    test_access_init_invalid_retries_zero();
    test_access_init_invalid_retries_too_high();

    test_access_wipe_when_not_wiped_ok();
    test_access_wipe_already_wiped_ok();
    test_access_wipe_sest_remove_fails();

    test_access_unlock_ok();
    test_access_unlock_wiped();
    test_access_unlock_already_unlocked();
    test_access_unlock_wrong_password();
    test_access_unlock_wrong_password_length();
    test_access_unlock_excessive_retries();

    test_access_set_password_when_wiped_ok();
    test_access_set_password_when_unlocked_ok();
    test_access_set_password_when_locked_fails();
    test_access_set_password_invalid_pin();
    test_access_set_password_sest_write_fails();

    test_access_output_password_ok();
    test_access_output_password_wiped();
    test_access_output_password_buffer_too_small();
    test_access_output_password_buffer_not_in_enclave();

    printf("All access tests passed!\n");
    return 0;
}

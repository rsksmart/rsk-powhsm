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
#include <stdio.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>
#include <secp256k1.h>
#include "assert_utils.h"
#include "hal/constants.h"
#include "hal/seed.h"
#include "bip32.h"
#include "mock.h"

// The key used to store the seed in the secret store
#define SEST_SEED_KEY "seed"

// The key pair that will be used throughout the tests
uint8_t G_privkey[PRIVATE_KEY_LENGTH] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};

uint8_t G_pubkey[PUBKEY_UNCMP_LENGTH] = {
    0x04, 0x6a, 0x04, 0xab, 0x98, 0xd9, 0xe4, 0x77, 0x4a, 0xd8, 0x06,
    0xe3, 0x02, 0xdd, 0xde, 0xb6, 0x3b, 0xea, 0x16, 0xb5, 0xcb, 0x5f,
    0x22, 0x3e, 0xe7, 0x74, 0x78, 0xe8, 0x61, 0xbb, 0x58, 0x3e, 0xb3,
    0x36, 0xb6, 0xfb, 0xcb, 0x60, 0xb5, 0xb3, 0xd4, 0xf1, 0x55, 0x1a,
    0xc4, 0x5e, 0x5f, 0xfc, 0x49, 0x36, 0x46, 0x6e, 0x7d, 0x98, 0xf6,
    0xc7, 0xc0, 0xec, 0x73, 0x65, 0x39, 0xf7, 0x46, 0x91, 0xa6};

// This is the only path that will generate a valid private key
uint32_t G_valid_path[] = {0x8000002c, 0x80000000, 0x80000000, 0, 0};

// A fixed client seed that will be used throughout the tests
uint8_t G_client_seed[SEED_LENGTH] = {
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb};

// The hash256 of the string "a-test-message", used to test seed_sign
uint8_t G_hash[HASH_LENGTH] = {0xb4, 0xeb, 0x5c, 0xa8, 0xd8, 0x05, 0x33, 0xa2,
                               0xec, 0xc1, 0x32, 0xd9, 0xaf, 0x5e, 0x96, 0x95,
                               0x34, 0xe7, 0x2e, 0xa5, 0xb2, 0xd9, 0x9f, 0x99,
                               0xf0, 0x0a, 0xb4, 0x0b, 0x60, 0x5a, 0xc6, 0x7b};

// A buffer containing the random bytes that will be used to generate the seed
// This buffer is overwritten for each test
uint8_t G_random_buffer[SEED_LENGTH];
// See setup() for the computaion of the valid seed
// A distinct valid seed is generated for each test
uint8_t G_valid_seed[SEED_LENGTH];
// Injects an error in the next call to random_getrandom
bool G_getrandom_fail_next = false;
// Forces the next call to bip32_derive_private to return success, even if the
// derived private key is invalid
bool G_force_derive_private_success = false;
bool G_mock_oe_is_within_enclave;

// Mock implementations
bool bip32_derive_private(uint8_t *out,
                          const size_t out_size,
                          const uint8_t *seed,
                          const unsigned int seed_length,
                          const uint32_t *path,
                          const unsigned int path_length) {
    assert(out != NULL);
    assert(path != NULL);
    assert(path_length > 0);
    assert(seed_length == SEED_LENGTH);
    ASSERT_MEMCMP(seed, G_valid_seed, seed_length);

    // If the provided path is exactly the same as the expected, the valid
    // private key is generated. Otherwise, the private key is set to all zeros
    bool success = true;
    if ((memcmp(path, G_valid_path, sizeof(G_valid_path)) == 0)) {
        memcpy(out, G_privkey, sizeof(G_privkey));
    } else {
        memset(out, 0, PRIVATE_KEY_LENGTH);
        success = false;
    }

    // We also want to be able to force the function to return success, even if
    // the derived private key is invalid to test seed_derive_pubkey
    bool force_success = G_force_derive_private_success;
    G_force_derive_private_success = false;
    return success || force_success;
}

bool random_getrandom(void *buffer, size_t length) {
    assert(length <= sizeof(G_random_buffer));
    bool ret = true;
    if (G_getrandom_fail_next) {
        ret = false;
        G_getrandom_fail_next = false;
    }
    memcpy(buffer, G_random_buffer, length);
    return ret;
}

// Mock SEST functions
bool sest_exists(char *key) {
    return mock_sest_exists(key);
}

uint8_t sest_read(char *key, uint8_t *dest, size_t dest_length) {
    return mock_sest_read(key, dest, dest_length);
}

bool sest_write(char *key, uint8_t *secret, size_t secret_length) {
    return mock_sest_write(key, secret, secret_length);
}

bool sest_remove(char *key) {
    return mock_sest_remove(key);
}

bool oe_is_within_enclave(const void *ptr, size_t size) {
    return G_mock_oe_is_within_enclave;
}

// Helper functions
static void setup() {
    mock_sest_init();
    // Set up the random buffer and compute the valid seed. The same random
    // bytes wil be used by the seed module to derive the internal seed
    syscall(SYS_getrandom, G_random_buffer, sizeof(G_random_buffer), 0);
    for (size_t i = 0; i < SEED_LENGTH; i++) {
        G_valid_seed[i] = G_client_seed[i] ^ G_random_buffer[i];
    }
}

static void teardown() {
    mock_sest_reset();
    memset(G_random_buffer, 0, sizeof(G_random_buffer));
    memset(G_valid_seed, 0, sizeof(G_valid_seed));
}

static void load_valid_seed() {
    mock_sest_write(SEST_SEED_KEY, G_valid_seed, sizeof(G_valid_seed));
}

static void assert_seed_valid() {
    assert(mock_sest_exists(SEST_SEED_KEY));
    uint8_t seed[SEED_LENGTH];
    mock_sest_read(SEST_SEED_KEY, seed, sizeof(seed));
    ASSERT_MEMCMP(seed, G_valid_seed, sizeof(G_valid_seed));
    assert(seed_available());
}

static void assert_seed_wiped() {
    assert(!mock_sest_exists(SEST_SEED_KEY));
    assert(!seed_available());
}

static void init_wiped() {
    assert(seed_init());
    assert_seed_wiped();
}

static void init_with_valid_seed() {
    load_valid_seed();
    assert(seed_init());
    assert_seed_valid();
}

static void assert_seed_generate_fails(uint8_t *client_seed,
                                       size_t client_seed_size) {
    assert(!seed_generate(client_seed, client_seed_size));
    assert_seed_wiped();
}

static void assert_seed_derive_pubkey_fails(uint32_t *path,
                                            size_t path_length) {
    uint8_t pubkey[PUBKEY_UNCMP_LENGTH] = {0};
    uint8_t pubkey_length = sizeof(pubkey);
    assert(!seed_derive_pubkey(path, path_length, pubkey, &pubkey_length));
    ASSERT_ARRAY_CLEARED(pubkey);
}

static void assert_signature_valid(uint8_t *hash,
                                   uint8_t *pubkey,
                                   uint8_t *sig,
                                   size_t sig_length) {
    secp256k1_context *sp_ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_ecdsa_signature sp_sig;
    secp256k1_pubkey sp_pubkey;
    assert(1 == secp256k1_ecdsa_signature_parse_der(
                    sp_ctx, &sp_sig, sig, sig_length));
    assert(1 == secp256k1_ec_pubkey_parse(
                    sp_ctx, &sp_pubkey, pubkey, PUBKEY_UNCMP_LENGTH));
    assert(1 == secp256k1_ecdsa_verify(sp_ctx, &sp_sig, hash, &sp_pubkey));
    secp256k1_context_destroy(sp_ctx);
}

// Test cases
void test_seed_init_success() {
    setup();
    printf("Test seed_init success...\n");

    init_wiped();
    teardown();
}

void test_seed_init_fails_when_sest_read_fails() {
    setup();
    printf("Test seed_init fails when seed exists but sest_read fails...\n");

    load_valid_seed();
    mock_sest_fail_next_read(true);
    assert(!seed_init());
    assert(!seed_available());
    teardown();
}

void test_seed_init_fails_when_seed_is_invalid() {
    setup();
    printf("Test seed_init fails when an invalid seed exists...\n");

    uint8_t *invalid_seed = (uint8_t *)"an-invalid-seed";
    mock_sest_write(SEST_SEED_KEY, invalid_seed, sizeof(invalid_seed));
    assert(!seed_init());
    assert(!seed_available());
    teardown();
}

void test_seed_wipe_succeedes_when_seed_present() {
    setup();
    printf("Test seed_wipe succeedes when the seed is present...\n");

    init_with_valid_seed();
    assert(seed_wipe());
    assert_seed_wiped();
    teardown();
}

void test_seed_wipe_fails_when_seed_already_wiped() {
    setup();
    printf("Test seed_wipe fails when the seed is already wiped...\n");

    init_wiped();
    assert(!seed_wipe());
    assert_seed_wiped();
    teardown();
}

void test_seed_generate_sucess() {
    setup();
    printf("Test seed_generate succeeds...\n");

    init_wiped();
    assert(seed_generate(G_client_seed, sizeof(G_client_seed)));
    assert_seed_valid();
    teardown();
}

void test_seed_generate_fails_when_seed_available() {
    setup();
    printf("Test seed_generate fails when the seed is already available...\n");

    init_with_valid_seed();
    assert(!seed_generate(G_client_seed, sizeof(G_client_seed)));
    assert_seed_valid();
    teardown();
}

void test_seed_generate_fails_when_getrandom_fails() {
    setup();
    printf("Test seed_generate fails when getrandom fails...\n");

    init_wiped();
    G_getrandom_fail_next = true;
    assert_seed_generate_fails(G_client_seed, sizeof(G_client_seed));
    teardown();
}

void test_seed_generate_fails_when_client_seed_invalid() {
    setup();
    printf("Test seed_generate fails when the client seed is invalid...\n");

    init_wiped();
    assert_seed_generate_fails(G_client_seed, SEED_LENGTH - 1);
    teardown();
}

void test_seed_generate_fails_when_sest_write_fails() {
    setup();
    printf("Test seed_generate fails when sest_write fails...\n");

    init_wiped();
    mock_sest_fail_next_write(true);
    assert_seed_generate_fails(G_client_seed, sizeof(G_client_seed));
    teardown();
}

void test_seed_derive_pubkey_success() {
    setup();
    printf("Test derive_pubkey success...\n");

    init_with_valid_seed();
    uint8_t pubkey[PUBKEY_UNCMP_LENGTH];
    uint8_t pubkey_length = sizeof(pubkey);
    assert(seed_derive_pubkey(
        G_valid_path, sizeof(G_valid_path), pubkey, &pubkey_length));
    assert(pubkey_length == PUBKEY_UNCMP_LENGTH);
    ASSERT_MEMCMP(pubkey, G_pubkey, pubkey_length);
    teardown();
}

void test_seed_derive_pubkey_fails_when_bip32_derive_fails() {
    setup();
    printf("Test derive_pubkey fails when bip32_derive_private fails...\n");

    init_with_valid_seed();
    uint32_t invalid_path[] = {0, 0, 0, 0, 0};
    assert_seed_derive_pubkey_fails(invalid_path, sizeof(invalid_path));
    teardown();
}

void test_seed_derive_pubkey_fails_when_privkey_is_invalid() {
    setup();
    printf("Test derive_pubkey fails when the private key is invalid...\n");

    init_with_valid_seed();
    // The invalid path will make bip32_derive_private return an invalid private
    // key, but we will force it to return success anyway
    uint32_t invalid_path[] = {0, 0, 0, 0, 0};
    G_force_derive_private_success = true;
    assert_seed_derive_pubkey_fails(invalid_path, sizeof(invalid_path));
    teardown();
}

void test_seed_derive_pubkey_fails_when_pubkey_buf_too_small() {
    setup();
    printf("Test derive_pubkey fails when the pubkey buffer is too small...\n");

    init_with_valid_seed();
    uint8_t pubkey[PUBKEY_UNCMP_LENGTH] = {0};
    uint8_t pubkey_length = sizeof(pubkey) - 1;
    assert(!seed_derive_pubkey(
        G_valid_path, sizeof(G_valid_path), pubkey, &pubkey_length));
    ASSERT_ARRAY_CLEARED(pubkey);
    teardown();
}

void test_seed_sign_success() {
    setup();
    printf("Test seed_sign success...\n");

    init_with_valid_seed();
    uint8_t sig[MAX_SIGNATURE_LENGTH];
    uint8_t sig_length = sizeof(sig);
    assert(seed_sign(
        G_valid_path, sizeof(G_valid_path), G_hash, sig, &sig_length));
    assert(sig_length <= MAX_SIGNATURE_LENGTH);
    assert_signature_valid(G_hash, G_pubkey, sig, sig_length);
    teardown();
}

void test_seed_sign_fails_when_sig_buffer_too_small() {
    setup();
    printf("Test seed_sign fails when the signature buffer is too small...\n");

    init_with_valid_seed();
    uint8_t sig[MAX_SIGNATURE_LENGTH] = {0};
    uint8_t sig_length = sizeof(sig) - 1;
    assert(!seed_sign(
        G_valid_path, sizeof(G_valid_path), G_hash, sig, &sig_length));
    ASSERT_ARRAY_CLEARED(sig);
    teardown();
}

void test_seed_sign_fails_when_bip32_derive_fails() {
    setup();
    printf("Test seed_sign fails when bip32_derive_private fails...\n");

    init_with_valid_seed();
    uint8_t sig[MAX_SIGNATURE_LENGTH];
    uint8_t sig_length = sizeof(sig);
    uint32_t invalid_path[] = {0, 0, 0, 0, 0};
    assert(!seed_sign(
        invalid_path, sizeof(invalid_path), G_hash, sig, &sig_length));
    ASSERT_ARRAY_CLEARED(sig);
    teardown();
}

void test_seed_output_USE_FROM_EXPORT_ONLY_success() {
    setup();
    printf("Test seed_output_USE_FROM_EXPORT_ONLY success...\n");

    init_with_valid_seed();
    G_mock_oe_is_within_enclave = true;
    uint8_t out[SEED_LENGTH + 10];
    size_t out_size = sizeof(out);
    assert(seed_output_USE_FROM_EXPORT_ONLY(out, &out_size));
    assert(SEED_LENGTH == out_size);
    assert(!memcmp(G_valid_seed, out, out_size));

    teardown();
}

void test_seed_output_USE_FROM_EXPORT_ONLY_fails_when_no_valid_seed() {
    setup();
    printf("Test seed_output_USE_FROM_EXPORT_ONLY fails when seed is not "
           "available...\n");

    init_wiped();
    G_mock_oe_is_within_enclave = true;
    uint8_t out[SEED_LENGTH + 10];
    size_t out_size = sizeof(out);
    assert(!seed_output_USE_FROM_EXPORT_ONLY(out, &out_size));

    teardown();
}

void test_seed_output_USE_FROM_EXPORT_ONLY_fails_when_buffer_too_small() {
    setup();
    printf("Test seed_output_USE_FROM_EXPORT_ONLY fails when output buffer is "
           "too small...\n");

    init_with_valid_seed();
    G_mock_oe_is_within_enclave = true;
    uint8_t out[SEED_LENGTH - 10];
    size_t out_size = sizeof(out);
    assert(!seed_output_USE_FROM_EXPORT_ONLY(out, &out_size));

    teardown();
}

void test_seed_output_USE_FROM_EXPORT_ONLY_fails_when_output_is_outside_enclave() {
    setup();
    printf("Test seed_output_USE_FROM_EXPORT_ONLY fails when output buffer is "
           "outside enclave...\n");

    init_with_valid_seed();
    G_mock_oe_is_within_enclave = false;
    uint8_t out[SEED_LENGTH + 10];
    size_t out_size = sizeof(out);
    assert(!seed_output_USE_FROM_EXPORT_ONLY(out, &out_size));

    teardown();
}

void test_seed_set_USE_FROM_EXPORT_ONLY_success() {
    setup();
    printf("Test seed_set_USE_FROM_EXPORT_ONLY success...\n");

    init_wiped();
    G_mock_oe_is_within_enclave = true;
    uint8_t in[] = "01234567890123456789012345678912";
    assert(seed_set_USE_FROM_EXPORT_ONLY(in, sizeof(in)));

    assert(mock_sest_exists(SEST_SEED_KEY));
    uint8_t seed[SEED_LENGTH];
    mock_sest_read(SEST_SEED_KEY, seed, sizeof(seed));
    ASSERT_MEMCMP(seed, "01234567890123456789012345678912", SEED_LENGTH);
    assert(seed_available());

    teardown();
}

void test_seed_set_USE_FROM_EXPORT_ONLY_fails_when_seed_available() {
    setup();
    printf("Test seed_set_USE_FROM_EXPORT_ONLY fails when seed available...\n");

    init_with_valid_seed();
    G_mock_oe_is_within_enclave = true;
    uint8_t in[] = "01234567890123456789012345678912";
    assert(!seed_set_USE_FROM_EXPORT_ONLY(in, sizeof(in)));
    assert_seed_valid();

    teardown();
}

void test_seed_set_USE_FROM_EXPORT_ONLY_fails_when_input_buffer_too_small() {
    setup();
    printf("Test seed_set_USE_FROM_EXPORT_ONLY fails when input buffer too "
           "small...\n");

    init_wiped();
    G_mock_oe_is_within_enclave = true;
    uint8_t in[] = "too-small";
    assert(!seed_set_USE_FROM_EXPORT_ONLY(in, sizeof(in)));
    assert(!seed_available());

    teardown();
}

void test_seed_set_USE_FROM_EXPORT_ONLY_fails_when_input_buffer_outside_enclave() {
    setup();
    printf("Test seed_set_USE_FROM_EXPORT_ONLY fails when input buffer is "
           "outside the enclave...\n");

    init_wiped();
    G_mock_oe_is_within_enclave = false;
    uint8_t in[] = "01234567890123456789012345678912";
    assert(!seed_set_USE_FROM_EXPORT_ONLY(in, sizeof(in)));
    assert(!seed_available());

    teardown();
}

void test_seed_set_USE_FROM_EXPORT_ONLY_fails_when_secret_store_writing_fails() {
    setup();
    printf("Test seed_set_USE_FROM_EXPORT_ONLY fails when secret store writing "
           "fails...\n");

    init_wiped();
    G_mock_oe_is_within_enclave = true;
    mock_sest_fail_next_write(true);
    uint8_t in[] = "01234567890123456789012345678912";
    assert(!seed_set_USE_FROM_EXPORT_ONLY(in, sizeof(in)));
    assert(!seed_available());

    teardown();
}

int main() {
    test_seed_init_success();
    test_seed_init_fails_when_sest_read_fails();
    test_seed_init_fails_when_seed_is_invalid();

    test_seed_wipe_succeedes_when_seed_present();
    test_seed_wipe_fails_when_seed_already_wiped();

    test_seed_generate_sucess();
    test_seed_generate_fails_when_seed_available();
    test_seed_generate_fails_when_getrandom_fails();
    test_seed_generate_fails_when_client_seed_invalid();
    test_seed_generate_fails_when_sest_write_fails();

    test_seed_derive_pubkey_success();
    test_seed_derive_pubkey_fails_when_bip32_derive_fails();
    test_seed_derive_pubkey_fails_when_privkey_is_invalid();
    test_seed_derive_pubkey_fails_when_pubkey_buf_too_small();

    test_seed_sign_success();
    test_seed_sign_fails_when_sig_buffer_too_small();
    test_seed_sign_fails_when_bip32_derive_fails();

    test_seed_output_USE_FROM_EXPORT_ONLY_success();
    test_seed_output_USE_FROM_EXPORT_ONLY_fails_when_no_valid_seed();
    test_seed_output_USE_FROM_EXPORT_ONLY_fails_when_buffer_too_small();
    test_seed_output_USE_FROM_EXPORT_ONLY_fails_when_output_is_outside_enclave();

    test_seed_set_USE_FROM_EXPORT_ONLY_success();
    test_seed_set_USE_FROM_EXPORT_ONLY_fails_when_seed_available();
    test_seed_set_USE_FROM_EXPORT_ONLY_fails_when_input_buffer_too_small();
    test_seed_set_USE_FROM_EXPORT_ONLY_fails_when_input_buffer_outside_enclave();
    test_seed_set_USE_FROM_EXPORT_ONLY_fails_when_secret_store_writing_fails();

    return 0;
}

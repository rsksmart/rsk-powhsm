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
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "migrate.h"

// Mocks
struct {
    bool seed_wipe;
    bool seed_output_USE_FROM_EXPORT_ONLY;
    bool seed_set_USE_FROM_EXPORT_ONLY;
    bool access_set_password;
    bool access_wipe;
    bool access_output_password_USE_FROM_EXPORT_ONLY;
    bool inconsistent_mocks;
    bool aes_gcm_encrypt;
    bool aes_gcm_decrypt;
} G_mocks;

struct {
    bool seed_wipe;
    bool access_wipe;
} G_called;

bool seed_wipe() {
    G_called.seed_wipe = true;
    return G_mocks.seed_wipe;
}

bool seed_output_USE_FROM_EXPORT_ONLY(uint8_t* out, size_t* out_size) {
    if (G_mocks.inconsistent_mocks) {
        *out_size = 31;
        return true;
    }
    memcpy(out, "01234567890123456789012345678901", 32);
    *out_size = 32;
    return G_mocks.seed_output_USE_FROM_EXPORT_ONLY;
}

bool seed_set_USE_FROM_EXPORT_ONLY(uint8_t* in, size_t in_size) {
    if (!G_mocks.seed_set_USE_FROM_EXPORT_ONLY)
        return false;
    assert(!memcmp(in, "abcdefabcdefabcdefabcdef12345678", in_size));
    return true;
}

bool access_set_password(char* password, uint8_t password_length) {
    if (!G_mocks.access_set_password)
        return false;
    assert(!memcmp(password, "ABCDEF12", password_length));
    return true;
}

bool access_wipe() {
    G_called.access_wipe = true;
    return G_mocks.access_wipe;
}

bool access_output_password_USE_FROM_EXPORT_ONLY(uint8_t* out,
                                                 size_t* out_size) {
    if (G_mocks.inconsistent_mocks) {
        *out_size = 7;
        return true;
    }
    memcpy(out, "abcABC89", 8);
    *out_size = 8;
    return G_mocks.access_output_password_USE_FROM_EXPORT_ONLY;
}

size_t aes_gcm_get_encrypted_size(size_t cleartext_size) {
    return cleartext_size + 10;
}

bool aes_gcm_encrypt(uint8_t* key,
                     size_t key_size,
                     uint8_t* in,
                     size_t in_size,
                     uint8_t* out,
                     size_t* out_size) {
    assert(32 == key_size);
    assert(!memcmp("0123ABCDEF0123ABCDEF0123ABCDEF55", key, key_size));

    *out_size = in_size + 10;
    memcpy(out, "encrypted:", 10);
    memcpy(out + 10, in, in_size);

    return G_mocks.aes_gcm_encrypt;
}

bool aes_gcm_decrypt(uint8_t* key,
                     size_t key_size,
                     uint8_t* in,
                     size_t in_size,
                     uint8_t* out,
                     size_t* out_size) {
    assert(32 == key_size);
    assert(!memcmp("0123ABCDEF0123ABCDEF0123ABCDEF55", key, key_size));

    *out_size = in_size - 10;
    memcpy(out, in + 10, *out_size);

    return G_mocks.aes_gcm_decrypt;
}

// Test output buffer and size
#define IMPORT_EXPORT_SIZE 50 // Seed + max pasword length + encrypted OH
uint8_t G_out[IMPORT_EXPORT_SIZE];
size_t G_out_size;

// Test input buffer
uint8_t G_in[IMPORT_EXPORT_SIZE];

// Mock key
uint8_t G_key[32] = "0123ABCDEF0123ABCDEF0123ABCDEF55";

// Unit tests
void setup() {
    explicit_bzero(&G_mocks, sizeof(G_mocks));
    explicit_bzero(&G_called, sizeof(G_called));
    memcpy(G_in,
           "encrypted:abcdefabcdefabcdefabcdef12345678ABCDEF12",
           IMPORT_EXPORT_SIZE);
}

// Exporting
void test_migrate_export_ok() {
    setup();
    printf("Test exporting...\n");

    G_mocks.seed_output_USE_FROM_EXPORT_ONLY = true;
    G_mocks.access_output_password_USE_FROM_EXPORT_ONLY = true;
    G_mocks.aes_gcm_encrypt = true;

    G_out_size = sizeof(G_out);
    assert(migrate_export(G_key, sizeof(G_key), G_out, &G_out_size));
    assert(!memcmp(G_out,
                   "encrypted:01234567890123456789012345678901abcABC89",
                   sizeof(G_out)));
}

void test_migrate_export_err_buftoosmall() {
    setup();
    printf("Test exporting when the output buffer is too small...\n");

    G_mocks.seed_output_USE_FROM_EXPORT_ONLY = true;
    G_mocks.access_output_password_USE_FROM_EXPORT_ONLY = true;
    G_mocks.aes_gcm_encrypt = true;

    uint8_t out[IMPORT_EXPORT_SIZE - 1];
    G_out_size = sizeof(out);
    assert(!migrate_export(G_key, sizeof(G_key), out, &G_out_size));
}

void test_migrate_export_err_seed() {
    setup();
    printf("Test exporting when exporting the seed fails...\n");

    G_mocks.seed_output_USE_FROM_EXPORT_ONLY = false;
    G_mocks.access_output_password_USE_FROM_EXPORT_ONLY = true;
    G_mocks.aes_gcm_encrypt = true;

    G_out_size = sizeof(G_out);
    assert(!migrate_export(G_key, sizeof(G_key), G_out, &G_out_size));
}

void test_migrate_export_err_access() {
    setup();
    printf("Test exporting when exporting the password fails...\n");

    G_mocks.seed_output_USE_FROM_EXPORT_ONLY = true;
    G_mocks.access_output_password_USE_FROM_EXPORT_ONLY = false;
    G_mocks.aes_gcm_encrypt = true;

    G_out_size = sizeof(G_out);
    assert(!migrate_export(G_key, sizeof(G_key), G_out, &G_out_size));
}

void test_migrate_export_err_encrypting() {
    setup();
    printf("Test exporting when encrypting fails...\n");

    G_mocks.seed_output_USE_FROM_EXPORT_ONLY = true;
    G_mocks.access_output_password_USE_FROM_EXPORT_ONLY = true;
    G_mocks.aes_gcm_encrypt = false;

    G_out_size = sizeof(G_out);
    assert(!migrate_export(G_key, sizeof(G_key), G_out, &G_out_size));
}

void test_migrate_export_err_inconsistency() {
    setup();
    printf("Test exporting when there is an inconsistency in "
           "the exported values from other modules...\n");

    G_mocks.inconsistent_mocks = true;

    G_out_size = sizeof(G_out);
    assert(!migrate_export(G_key, sizeof(G_key), G_out, &G_out_size));
}

// Importing
void test_migrate_import_ok() {
    setup();
    printf("Test importing...\n");

    G_mocks.seed_set_USE_FROM_EXPORT_ONLY = true;
    G_mocks.access_set_password = true;
    G_mocks.aes_gcm_decrypt = true;

    assert(migrate_import(G_key, sizeof(G_key), G_in, strlen((char*)G_in)));
    assert(!G_called.access_wipe);
    assert(!G_called.seed_wipe);
}

void test_migrate_import_err_buftoosmall() {
    setup();
    printf("Test importing when input buffer is too small...\n");

    G_mocks.seed_set_USE_FROM_EXPORT_ONLY = true;
    G_mocks.access_set_password = true;
    G_mocks.aes_gcm_decrypt = true;

    assert(
        !migrate_import(G_key, sizeof(G_key), G_in, strlen((char*)G_in) - 1));
    assert(G_called.access_wipe);
    assert(G_called.seed_wipe);
}

void test_migrate_import_decrypt() {
    setup();
    printf("Test importing when decrypting fails...\n");

    G_mocks.seed_set_USE_FROM_EXPORT_ONLY = true;
    G_mocks.access_set_password = true;
    G_mocks.aes_gcm_decrypt = false;

    assert(!migrate_import(G_key, sizeof(G_key), G_in, strlen((char*)G_in)));
    assert(G_called.access_wipe);
    assert(G_called.seed_wipe);
}

void test_migrate_import_err_seed() {
    setup();
    printf("Test importing when seed importing fails...\n");

    G_mocks.seed_set_USE_FROM_EXPORT_ONLY = false;
    G_mocks.access_set_password = true;
    G_mocks.aes_gcm_decrypt = true;

    assert(!migrate_import(G_key, sizeof(G_key), G_in, strlen((char*)G_in)));
    assert(G_called.access_wipe);
    assert(G_called.seed_wipe);
}

void test_migrate_import_err_access() {
    setup();
    printf("Test importing when password importing fails...\n");

    G_mocks.seed_set_USE_FROM_EXPORT_ONLY = true;
    G_mocks.access_set_password = false;
    G_mocks.aes_gcm_decrypt = true;

    assert(!migrate_import(G_key, sizeof(G_key), G_in, strlen((char*)G_in)));
    assert(G_called.access_wipe);
    assert(G_called.seed_wipe);
}

int main() {
    test_migrate_export_ok();
    test_migrate_export_err_buftoosmall();
    test_migrate_export_err_seed();
    test_migrate_export_err_access();
    test_migrate_export_err_encrypting();
    test_migrate_export_err_inconsistency();

    test_migrate_import_ok();
    test_migrate_import_err_buftoosmall();
    test_migrate_import_decrypt();
    test_migrate_import_err_seed();
    test_migrate_import_err_access();

    return 0;
}

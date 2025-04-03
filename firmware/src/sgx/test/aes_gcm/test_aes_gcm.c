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

#include "aes_gcm.h"
#include "mocks/mbedtls/gcm.h"

// Mocks
struct {
    int mbedtls_gcm_setkey;
    int mbedtls_gcm_crypt_and_tag;
    int mbedtls_gcm_auth_decrypt;
    bool random_getrandom;
} G_mocks;

struct {
    bool mbedtls_gcm_setkey;
    bool mbedtls_gcm_free;
} G_called;

bool random_getrandom(void *buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        ((uint8_t *)buffer)[i] = 0xA0 + (i % 16);
    }
    return G_mocks.random_getrandom;
}

void mbedtls_gcm_init(mbedtls_gcm_context *ctx) {
    *ctx = 345;
}

int mbedtls_gcm_setkey(mbedtls_gcm_context *ctx,
                       mbedtls_cipher_id_t cipher,
                       const unsigned char *key,
                       unsigned int keybits) {
    assert(345 == *ctx);
    assert(MBEDTLS_CIPHER_ID_AES == cipher);
    assert(32 == keybits / 8);
    assert(0 == keybits % 8);
    assert(!memcmp("012345678901234567890123456789AB", key, 32));
    G_called.mbedtls_gcm_setkey = true;
    return G_mocks.mbedtls_gcm_setkey;
}

int mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context *ctx,
                              int mode,
                              size_t length,
                              const unsigned char *iv,
                              size_t iv_len,
                              const unsigned char *add,
                              size_t add_len,
                              const unsigned char *input,
                              unsigned char *output,
                              size_t tag_len,
                              unsigned char *tag) {
    assert(345 == *ctx);
    assert(MBEDTLS_GCM_ENCRYPT == mode);
    assert(G_called.mbedtls_gcm_setkey);
    assert(iv_len == 12);
    for (size_t i = 0; i < iv_len; i++)
        assert(0xA0 + (i % 16) == iv[i]);
    assert(!add && !add_len);
    assert(strlen("some clear text") == length);
    assert(!memcmp("some clear text", input, length));
    assert(16 == tag_len);
    memcpy(output, "encrypted clear", strlen("encrypted clear"));
    memcpy(tag, "1122334455667788", 16);

    return G_mocks.mbedtls_gcm_crypt_and_tag;
}

int mbedtls_gcm_auth_decrypt(mbedtls_gcm_context *ctx,
                             size_t length,
                             const unsigned char *iv,
                             size_t iv_len,
                             const unsigned char *add,
                             size_t add_len,
                             const unsigned char *tag,
                             size_t tag_len,
                             const unsigned char *input,
                             unsigned char *output) {
    assert(345 == *ctx);
    assert(G_called.mbedtls_gcm_setkey);
    assert(48 - 12 - 16 == length);
    assert(12 == iv_len);
    assert(!memcmp("1234567890EF", iv, iv_len));
    assert(!add && !add_len);
    assert(16 == tag_len);
    assert(!memcmp("THETAG0123456789", tag, tag_len));
    memcpy(output, "something very clear", strlen("something very clear"));
    return G_mocks.mbedtls_gcm_auth_decrypt;
}

void mbedtls_gcm_free(mbedtls_gcm_context *ctx) {
    *ctx += 55;
    assert(400 == *ctx);
    G_called.mbedtls_gcm_free = true;
}

// Unit tests
void setup() {
    explicit_bzero(&G_mocks, sizeof(G_mocks));
    explicit_bzero(&G_called, sizeof(G_called));
}

void test_aes_gcm_get_encrypted_size_ok() {
    printf("Testing aes_gcm_get_encrypted_size succeeds...\n");
    assert(123 + 12 + 16 == aes_gcm_get_encrypted_size(123));
}

void test_aes_gcm_get_encrypted_size_overflow() {
    printf("Testing aes_gcm_get_encrypted_size when size overflows...\n");
    assert(aes_gcm_get_encrypted_size((size_t) - (12 + 16 + 1)));
    assert(!aes_gcm_get_encrypted_size((size_t) - (12 + 16)));
}

// Encrypt
void test_aes_gcm_encrypt_ok() {
    printf("Testing aes_gcm_encrypt succeeds...\n");

    uint8_t out[15 + 12 + 16 + 10];
    size_t out_size = sizeof(out);

    G_mocks.random_getrandom = true;
    G_mocks.mbedtls_gcm_setkey = 0;
    G_mocks.mbedtls_gcm_crypt_and_tag = 0;

    assert(aes_gcm_encrypt((uint8_t *)"012345678901234567890123456789AB",
                           32,
                           (uint8_t *)"some clear text",
                           15,
                           out,
                           &out_size));

    assert(15 + 16 + 12 == out_size);
    assert(!memcmp("\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB"
                   "encrypted clear"
                   "1122334455667788",
                   out,
                   out_size));
    assert(G_called.mbedtls_gcm_free);
}

void test_aes_gcm_encrypt_encrypt_fails() {
    printf("Testing aes_gcm_encrypt when gcm encrypt fails...\n");

    uint8_t out[15 + 12 + 16 + 10];
    size_t out_size = sizeof(out);

    G_mocks.random_getrandom = true;
    G_mocks.mbedtls_gcm_setkey = 0;
    G_mocks.mbedtls_gcm_crypt_and_tag = 1;

    assert(!aes_gcm_encrypt((uint8_t *)"012345678901234567890123456789AB",
                            32,
                            (uint8_t *)"some clear text",
                            15,
                            out,
                            &out_size));

    assert(G_called.mbedtls_gcm_free);
}

void test_aes_gcm_encrypt_setkey_fails() {
    printf("Testing aes_gcm_encrypt when gcm setkey fails...\n");

    uint8_t out[15 + 12 + 16 + 10];
    size_t out_size = sizeof(out);

    G_mocks.random_getrandom = true;
    G_mocks.mbedtls_gcm_setkey = 1;
    G_mocks.mbedtls_gcm_crypt_and_tag = 0;

    assert(!aes_gcm_encrypt((uint8_t *)"012345678901234567890123456789AB",
                            32,
                            (uint8_t *)"some clear text",
                            15,
                            out,
                            &out_size));

    assert(G_called.mbedtls_gcm_free);
}

void test_aes_gcm_encrypt_getrandom_fails() {
    printf("Testing aes_gcm_encrypt when getrandom fails...\n");

    uint8_t out[15 + 12 + 16 + 10];
    size_t out_size = sizeof(out);

    G_mocks.random_getrandom = false;
    G_mocks.mbedtls_gcm_setkey = 0;
    G_mocks.mbedtls_gcm_crypt_and_tag = 0;

    assert(!aes_gcm_encrypt((uint8_t *)"012345678901234567890123456789AB",
                            32,
                            (uint8_t *)"some clear text",
                            15,
                            out,
                            &out_size));

    assert(G_called.mbedtls_gcm_free);
}

void test_aes_gcm_encrypt_keysize_error() {
    printf("Testing aes_gcm_encrypt when keysize is incorrect...\n");

    uint8_t out[15 + 12 + 16 + 10];
    size_t out_size = sizeof(out);

    G_mocks.random_getrandom = true;
    G_mocks.mbedtls_gcm_setkey = 0;
    G_mocks.mbedtls_gcm_crypt_and_tag = 0;

    assert(!aes_gcm_encrypt((uint8_t *)"012345678901234567890123456789ABC",
                            33,
                            (uint8_t *)"some clear text",
                            15,
                            out,
                            &out_size));

    assert(G_called.mbedtls_gcm_free);
    G_called.mbedtls_gcm_free = false;

    assert(!aes_gcm_encrypt((uint8_t *)"012345678901234567890123456789A",
                            31,
                            (uint8_t *)"some clear text",
                            15,
                            out,
                            &out_size));

    assert(G_called.mbedtls_gcm_free);
}

void test_aes_gcm_encrypt_empty_input() {
    printf("Testing aes_gcm_encrypt when input is empty...\n");

    uint8_t out[15 + 12 + 16 + 10];
    size_t out_size = sizeof(out);

    G_mocks.random_getrandom = true;
    G_mocks.mbedtls_gcm_setkey = 0;
    G_mocks.mbedtls_gcm_crypt_and_tag = 0;

    assert(!aes_gcm_encrypt((uint8_t *)"012345678901234567890123456789AB",
                            32,
                            NULL,
                            0,
                            out,
                            &out_size));

    assert(G_called.mbedtls_gcm_free);
}

void test_aes_gcm_encrypt_output_toosmall() {
    printf("Testing aes_gcm_encrypt when output is too small...\n");

    uint8_t out[15 + 12 + 16 - 1];
    size_t out_size = sizeof(out);

    G_mocks.random_getrandom = true;
    G_mocks.mbedtls_gcm_setkey = 0;
    G_mocks.mbedtls_gcm_crypt_and_tag = 0;

    assert(!aes_gcm_encrypt((uint8_t *)"012345678901234567890123456789AB",
                            32,
                            (uint8_t *)"some clear text",
                            15,
                            out,
                            &out_size));

    assert(G_called.mbedtls_gcm_free);
}

// Decrypt
void test_aes_gcm_decrypt_ok() {
    printf("Testing aes_gcm_decrypt succeeds...\n");

    uint8_t out[48 - 12 - 16 + 10];
    size_t out_size = sizeof(out);

    G_mocks.mbedtls_gcm_setkey = 0;
    G_mocks.mbedtls_gcm_auth_decrypt = 0;

    assert(aes_gcm_decrypt(
        (uint8_t *)"012345678901234567890123456789AB",
        32,
        (uint8_t *)"1234567890EFsome encrypted stuffTHETAG0123456789",
        48,
        out,
        &out_size));

    assert(48 - 12 - 16 == out_size);
    assert(!memcmp("something very clear", out, out_size));
    assert(G_called.mbedtls_gcm_free);
}

void test_aes_gcm_decrypt_decrypt_fails() {
    printf("Testing aes_gcm_decrypt when decrypt fails...\n");

    uint8_t out[48 - 12 - 16 + 10];
    size_t out_size = sizeof(out);

    G_mocks.mbedtls_gcm_setkey = 0;
    G_mocks.mbedtls_gcm_auth_decrypt = 1;

    assert(!aes_gcm_decrypt(
        (uint8_t *)"012345678901234567890123456789AB",
        32,
        (uint8_t *)"1234567890EFsome encrypted stuffTHETAG0123456789",
        48,
        out,
        &out_size));

    assert(G_called.mbedtls_gcm_free);
}

void test_aes_gcm_decrypt_setkey_fails() {
    printf("Testing aes_gcm_decrypt when setkey fails...\n");

    uint8_t out[48 - 12 - 16 + 10];
    size_t out_size = sizeof(out);

    G_mocks.mbedtls_gcm_setkey = 1;
    G_mocks.mbedtls_gcm_auth_decrypt = 0;

    assert(!aes_gcm_decrypt(
        (uint8_t *)"012345678901234567890123456789AB",
        32,
        (uint8_t *)"1234567890EFsome encrypted stuffTHETAG0123456789",
        48,
        out,
        &out_size));

    assert(G_called.mbedtls_gcm_free);
}

void test_aes_gcm_decrypt_keysize_error() {
    printf("Testing aes_gcm_decrypt when keysize is incorrect...\n");

    uint8_t out[48 - 12 - 16 + 10];
    size_t out_size = sizeof(out);

    G_mocks.mbedtls_gcm_setkey = 0;
    G_mocks.mbedtls_gcm_auth_decrypt = 0;

    assert(!aes_gcm_decrypt(
        (uint8_t *)"012345678901234567890123456789ABC",
        33,
        (uint8_t *)"1234567890EFsome encrypted stuffTHETAG0123456789",
        48,
        out,
        &out_size));

    assert(G_called.mbedtls_gcm_free);
    G_called.mbedtls_gcm_free = false;

    assert(!aes_gcm_decrypt(
        (uint8_t *)"012345678901234567890123456789A",
        31,
        (uint8_t *)"1234567890EFsome encrypted stuffTHETAG0123456789",
        48,
        out,
        &out_size));

    assert(G_called.mbedtls_gcm_free);
}

void test_aes_gcm_decrypt_input_toosmall() {
    printf("Testing aes_gcm_decrypt when input is too small...\n");

    uint8_t out[48 - 12 - 16 + 10];
    size_t out_size = sizeof(out);

    G_mocks.mbedtls_gcm_setkey = 0;
    G_mocks.mbedtls_gcm_auth_decrypt = 0;

    assert(!aes_gcm_decrypt((uint8_t *)"012345678901234567890123456789AB",
                            32,
                            (uint8_t *)"1234567890EFTHETAG012345678",
                            12 + 16 - 1,
                            out,
                            &out_size));

    assert(G_called.mbedtls_gcm_free);
}

void test_aes_gcm_decrypt_output_toosmall() {
    printf("Testing aes_gcm_decrypt when output is too small...\n");

    uint8_t out[48 - 12 - 16 - 1];
    size_t out_size = sizeof(out);

    G_mocks.mbedtls_gcm_setkey = 0;
    G_mocks.mbedtls_gcm_auth_decrypt = 0;

    assert(!aes_gcm_decrypt(
        (uint8_t *)"012345678901234567890123456789AB",
        32,
        (uint8_t *)"1234567890EFsome encrypted stuffTHETAG0123456789",
        48,
        out,
        &out_size));

    assert(G_called.mbedtls_gcm_free);
}

int main() {
    test_aes_gcm_get_encrypted_size_ok();
    test_aes_gcm_get_encrypted_size_overflow();

    test_aes_gcm_encrypt_ok();
    test_aes_gcm_encrypt_encrypt_fails();
    test_aes_gcm_encrypt_setkey_fails();
    test_aes_gcm_encrypt_getrandom_fails();
    test_aes_gcm_encrypt_keysize_error();
    test_aes_gcm_encrypt_empty_input();
    test_aes_gcm_encrypt_output_toosmall();

    test_aes_gcm_decrypt_ok();
    test_aes_gcm_decrypt_decrypt_fails();
    test_aes_gcm_decrypt_setkey_fails();
    test_aes_gcm_decrypt_keysize_error();
    test_aes_gcm_decrypt_input_toosmall();
    test_aes_gcm_decrypt_output_toosmall();

    return 0;
}

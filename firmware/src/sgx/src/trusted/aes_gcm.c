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

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "hal/log.h"
#include "random.h"
#include <openenclave/corelibc/stdlib.h>
#include <mbedtls/gcm.h>

#define AES_GCM_KEY_SIZE 32 // AES-256
#define AES_IV_SIZE 12      // Recommended IV size for GCM
#define AES_TAG_SIZE 16     // Authentication tag size

size_t aes_gcm_get_encrypted_size(size_t cleartext_size) {
    if (cleartext_size + AES_IV_SIZE + AES_TAG_SIZE < cleartext_size)
        return 0; // Overflow
    return cleartext_size + AES_IV_SIZE + AES_TAG_SIZE;
}

bool aes_gcm_encrypt(uint8_t* key,
                     size_t key_size,
                     uint8_t* in,
                     size_t in_size,
                     uint8_t* out,
                     size_t* out_size) {
    bool retval = false;
    mbedtls_gcm_context gcm_ctx;
    mbedtls_gcm_init(&gcm_ctx);
    uint8_t iv[AES_IV_SIZE];
    uint8_t tag[AES_TAG_SIZE];
    uint8_t* ciphertext = NULL;

    // Sizes check
    if (AES_GCM_KEY_SIZE != key_size) {
        LOG("AES-GCM encrypt error: expected a %u-byte key\n",
            AES_GCM_KEY_SIZE);
        goto aes_gcm_encrypt_exit;
    }
    if (in_size == 0) {
        LOG("AES-GCM encrypt error: input buffer too small\n");
        goto aes_gcm_encrypt_exit;
    }
    if (*out_size < in_size + sizeof(iv) + sizeof(tag)) {
        LOG("AES-GCM encrypt error: output buffer too small\n");
        goto aes_gcm_encrypt_exit;
    }

    // Init buffers
    ciphertext = oe_malloc(in_size);
    if (!ciphertext) {
        LOG("AES-GCM encrypt error: unable to allocate memory\n");
        goto aes_gcm_encrypt_exit;
    }

    if (!random_getrandom(iv, sizeof(iv))) {
        LOG("AES-GCM encrypt error: error generating IV\n");
        goto aes_gcm_encrypt_exit;
    }

    // Set key
    if (mbedtls_gcm_setkey(
            &gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, key_size * 8) != 0) {
        LOG("AES-GCM encrypt error: failed to set key\n");
        goto aes_gcm_encrypt_exit;
    }

    // Encrypt
    if (mbedtls_gcm_crypt_and_tag(&gcm_ctx,
                                  MBEDTLS_GCM_ENCRYPT,
                                  in_size,
                                  iv,
                                  sizeof(iv),
                                  NULL,
                                  0,
                                  in,
                                  ciphertext,
                                  sizeof(tag),
                                  tag)) {
        LOG("AES-GCM encrypt error: encryption failed\n");
        goto aes_gcm_encrypt_exit;
    }

    // Output
    explicit_bzero(out, *out_size);
    memcpy(out, iv, sizeof(iv));
    memcpy(out + sizeof(iv), ciphertext, in_size);
    memcpy(out + sizeof(iv) + in_size, tag, sizeof(tag));
    *out_size = sizeof(iv) + in_size + sizeof(tag);
    retval = true;

aes_gcm_encrypt_exit:
    mbedtls_gcm_free(&gcm_ctx);
    if (ciphertext)
        oe_free(ciphertext);
    return retval;
}

bool aes_gcm_decrypt(uint8_t* key,
                     size_t key_size,
                     uint8_t* in,
                     size_t in_size,
                     uint8_t* out,
                     size_t* out_size) {
    bool retval = false;
    mbedtls_gcm_context gcm_ctx;
    mbedtls_gcm_init(&gcm_ctx);
    size_t cleartext_size = in_size - AES_IV_SIZE - AES_TAG_SIZE;

    // Sizes check
    if (AES_GCM_KEY_SIZE != key_size) {
        LOG("AES-GCM decrypt error: expected a %u-byte key\n",
            AES_GCM_KEY_SIZE);
        goto aes_gcm_decrypt_exit;
    }
    if (in_size <= AES_IV_SIZE + AES_TAG_SIZE) {
        LOG("AES-GCM decrypt error: input buffer too small\n");
        goto aes_gcm_decrypt_exit;
    }
    if (*out_size < cleartext_size) {
        LOG("AES-GCM decrypt error: output buffer too small\n");
        goto aes_gcm_decrypt_exit;
    }

    // Set key
    if (mbedtls_gcm_setkey(
            &gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, key_size * 8) != 0) {
        LOG("AES-GCM decrypt error: failed to set key\n");
        goto aes_gcm_decrypt_exit;
    }

    // Decrypt
    if (mbedtls_gcm_auth_decrypt(&gcm_ctx,
                                 cleartext_size,
                                 in,
                                 AES_IV_SIZE,
                                 NULL,
                                 0,
                                 &in[AES_IV_SIZE + cleartext_size],
                                 AES_TAG_SIZE,
                                 &in[AES_IV_SIZE],
                                 out) != 0) {
        LOG("AES-GCM decrypt error: decryption failed\n");
        goto aes_gcm_decrypt_exit;
    }

    // Ok
    *out_size = cleartext_size;
    retval = true;

aes_gcm_decrypt_exit:
    mbedtls_gcm_free(&gcm_ctx);
    return retval;
}

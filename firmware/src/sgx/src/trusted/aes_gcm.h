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

#ifndef __TRUSTED_AES_GCM_H
#define __TRUSTED_AES_GCM_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Gets the size of encrypted content for
 * the given cleartext size
 *
 * @param cleartext_size the cleartext size
 *
 * @returns the size of the corresponding encrypted content
 */
size_t aes_gcm_get_encrypted_size(size_t cleartext_size);

/**
 * @brief Encrypts the contents of the given buffer
 *
 * @param key       encryption key
 * @param key_size  encryption key size
 * @param in        input buffer
 * @param in_size   input buffer size
 * @param out       output buffer
 * @param out_size  [in/out] output buffer size
 *
 * @returns whether decrypting succeeded
 */
bool aes_gcm_encrypt(uint8_t* key,
                     size_t key_size,
                     uint8_t* in,
                     size_t in_size,
                     uint8_t* out,
                     size_t* out_size);

/**
 * @brief Decrypts the contents of the given buffer
 *
 * @param key       decryption key
 * @param key_size  decryption key size
 * @param in        input buffer
 * @param in_size   input buffer size
 * @param out       output buffer
 * @param out_size  [in/out] output buffer size
 *
 * @returns whether decrypting succeeded
 */
bool aes_gcm_decrypt(uint8_t* key,
                     size_t key_size,
                     uint8_t* in,
                     size_t in_size,
                     uint8_t* out,
                     size_t* out_size);

#endif // __TRUSTED_AES_GCM_H

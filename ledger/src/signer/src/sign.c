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

#include <string.h>

#include "os.h"
#include "cx.h"

#include "sign.h"
#include "defs.h"
#include "memutil.h"

/*
 * Derive the public key for a given path.
 * Store the public key into the given destination buffer.
 *
 * @arg[in] path derivation path
 * @arg[in] path_length length of the derivation path
 * @arg[in] dest destination buffer
 * @arg[in] dest destination buffer size
 * @ret     size of the public key derived,
 *          or DO_PUBKEY_ERROR in case of error
 */
int do_pubkey(unsigned int* path,
              unsigned char path_length,
              unsigned char* dest,
              size_t dest_size) {

    volatile unsigned char private_key_data[PRIVATE_KEY_LENGTH];
    volatile cx_ecfp_private_key_t private_key;
    volatile cx_ecfp_public_key_t public_key;

    volatile int pubkey_size;

    BEGIN_TRY {
        TRY {
            // Derive and init private key
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       path,
                                       path_length,
                                       (unsigned char*)private_key_data,
                                       NULL);
            cx_ecdsa_init_private_key(CX_CURVE_256K1,
                                      (unsigned char*)private_key_data,
                                      PRIVATE_KEY_LENGTH,
                                      (cx_ecfp_private_key_t*)&private_key);
            // Cleanup private key data
            explicit_bzero((void*)private_key_data, sizeof(private_key_data));
            // Derive public key
            cx_ecfp_generate_pair(CX_CURVE_256K1,
                                  (cx_ecfp_public_key_t*)&public_key,
                                  (cx_ecfp_private_key_t*)&private_key,
                                  1);
            // Cleanup private key
            explicit_bzero((void*)&private_key, sizeof(private_key));
            // Output the public key
            pubkey_size = public_key.W_len;
            SAFE_MEMMOVE(dest,
                         dest_size,
                         MEMMOVE_ZERO_OFFSET,
                         (void*)public_key.W,
                         public_key.W_len,
                         MEMMOVE_ZERO_OFFSET,
                         public_key.W_len,
                         { pubkey_size = DO_PUBKEY_ERROR; })
            // Cleanup public key
            explicit_bzero((void*)&public_key, sizeof(public_key));
        }
        CATCH_OTHER(e) {
            // Cleanup key data and fail
            explicit_bzero((void*)private_key_data, sizeof(private_key_data));
            explicit_bzero((void*)&private_key, sizeof(private_key));
            explicit_bzero((void*)&public_key, sizeof(public_key));
            // Signal error deriving public key
            pubkey_size = DO_PUBKEY_ERROR;
        }
        FINALLY {
        }
    }
    END_TRY;
    // Return public key size
    return pubkey_size;
}

/*
 * Sign a message with a given path.
 * Store the signature into the given destination buffer.
 *
 * @arg[in] path derivation path
 * @arg[in] path_length length of the derivation path
 * @arg[in] message message buffer
 * @arg[in] message_size message size
 * @arg[in] dest destination buffer
 * @arg[in] dest destination buffer size
 * @ret     size of the signature produced,
 *          or DO_SIGN_ERROR in case of error
 */
int do_sign(unsigned int* path,
            unsigned char path_length,
            unsigned char* message,
            size_t message_size,
            unsigned char* dest,
            size_t dest_size) {

    volatile unsigned char private_key_data[PRIVATE_KEY_LENGTH];
    volatile cx_ecfp_private_key_t private_key;

    volatile int sig_size;

    // Check the destination buffer won't be overflowed by the signature
    if (dest_size < MAX_SIGNATURE_LENGTH) {
        return DO_SIGN_ERROR;
    }

    BEGIN_TRY {
        TRY {
            // Derive and init private key
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       path,
                                       path_length,
                                       (unsigned char*)private_key_data,
                                       NULL);
            cx_ecdsa_init_private_key(CX_CURVE_256K1,
                                      (unsigned char*)private_key_data,
                                      PRIVATE_KEY_LENGTH,
                                      (cx_ecfp_private_key_t*)&private_key);
            // Cleanup private key data
            explicit_bzero((void*)private_key_data, sizeof(private_key_data));
            sig_size = cx_ecdsa_sign((void*)&private_key,
                                     CX_RND_RFC6979 | CX_LAST,
                                     CX_SHA256,
                                     message,
                                     message_size,
                                     dest);
            // Cleanup private key
            explicit_bzero((void*)&private_key, sizeof(private_key));
        }
        CATCH_OTHER(e) {
            // Cleanup key data and fail
            explicit_bzero((void*)private_key_data, sizeof(private_key_data));
            explicit_bzero((void*)&private_key, sizeof(private_key));
            // Signal error signing
            sig_size = DO_SIGN_ERROR;
        }
        FINALLY {
        }
    }
    END_TRY;
    // Return signature size
    return sig_size;
}
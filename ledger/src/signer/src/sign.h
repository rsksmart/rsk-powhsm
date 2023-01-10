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

#ifndef __SIGN_H
#define __SIGN_H

#define DO_SIGN_ERROR (0)
#define DO_PUBKEY_ERROR (0)

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
              size_t dest_size);

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
            size_t dest_size);

#endif // __SIGN_H

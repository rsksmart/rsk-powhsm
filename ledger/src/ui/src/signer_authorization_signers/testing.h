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

#ifndef __SIGNER_AUTHORIZATION_SIGNERS_H
#define __SIGNER_AUTHORIZATION_SIGNERS_H

// IMPORTANT: these keys are FOR TESTING PURPOSES ONLY
// In order to get the private keys associated with each
// of these three public keys, compute the keccak256 of
// the ASCII-encoded strings RSK_POWHSM_TEST_AUTHORIZER_0,
// RSK_POWHSM_TEST_AUTHORIZER_1 and RSK_POWHSM_TEST_AUTHORIZER_2
// clang-format off
#define AUTHORIZERS_PUBKEYS                         \
    {                                               \
        "\x04\x93\x80\x75\x4c\xb3\xd2\x1b\x61\x78"  \
        "\xe7\x56\x91\x52\xc4\x96\xf2\x8e\xea\xcf"  \
        "\xb4\xb8\xd2\x4a\x24\x15\x36\xc6\x1e\x40"  \
        "\x7f\xaf\x76\x61\x8f\x2b\xed\x07\xc0\x4f"  \
        "\x86\xf7\xf4\x6c\x2b\xfd\xe3\x58\xec\x33"  \
        "\xec\x5a\xd3\xeb\x04\xfb\x6f\x0a\x6e\xda"  \
        "\xdb\xab\x2a\x24\x69",                     \
                                                    \
        "\x04\x1b\xc9\xb8\x0b\x1f\xb5\xd0\x18\x47"  \
        "\x9f\x56\x78\x53\x72\x4f\xe4\x47\x5f\x23"  \
        "\xb6\x4c\x9d\x16\x93\x17\x6d\xf1\xc8\x24"  \
        "\x79\xf4\xf1\x99\x64\xcf\x4a\x51\x65\x11"  \
        "\x80\xb0\x28\x7c\x75\xb7\xec\xdc\xae\xe4"  \
        "\x2b\x2b\xb6\xb9\x29\xbd\x3a\xd2\x79\x49"  \
        "\x86\x68\x62\x91\x95",                     \
                                                    \
        "\x04\xa0\x99\x14\xc2\x1e\x86\x28\x3d\x4f"  \
        "\x37\x5c\x7a\x46\x0d\x82\x80\x67\x24\x37"  \
        "\x5e\xb3\xd4\x87\xea\xac\x69\xd0\x86\x98"  \
        "\xe0\x29\xa5\x69\x13\xb6\x89\xcb\x1d\xe3"  \
        "\x1c\xc5\x7c\x2b\xe1\xe4\xa5\xbe\x2d\x40"  \
        "\xa4\x2e\x49\x7b\x6d\x57\x78\xeb\x8a\x00"  \
        "\xf5\x90\xc4\xae\x61",                     \
    }
// clang-format on

#endif // __SIGNER_AUTHORIZATION_SIGNERS_H

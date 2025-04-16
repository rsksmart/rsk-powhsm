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

// clang-format off

// This defines the Aleph wallet signer authorization signers
// The wallet is a 3 of 5 multisig

// Name: Bernardo Codesido
// Role: Head of Security at IOVlabs
// Address: 0x922d80bd157dbf5f9be37c653a468ef36acc377e
#define APK_MEMBER1                             \
    "\x04\x2d\x13\xf9\x69\xdd\xa8\xdb\xfd\x1b"  \
    "\xfb\x60\x32\x75\x0b\x1b\x6b\x25\xa7\xaa"  \
    "\x8e\x08\xdf\xb4\xb8\x5e\xd7\x93\x6a\x2d"  \
    "\x68\xc7\xce\xb3\x91\xc0\x6d\xfd\x1a\xd9"  \
    "\xa2\x8f\xb3\x5c\xe8\x73\x41\x4b\x39\x0a"  \
    "\x76\xc4\x14\x46\xd6\x23\xb1\xc4\x34\x9f"  \
    "\x02\x63\x82\x97\x70"

// Name: Tim Paymans
// Role: Chief of Product at IOVlabs
// Address: 0xf7ac04052ddcaa351e23c7d29659a15c2bc6648f
#define APK_MEMBER2                             \
    "\x04\x1b\x08\xba\xd6\xca\xfc\x11\xaf\x01"  \
    "\x97\x43\xe5\xde\x82\xc7\xfa\x23\xed\x17"  \
    "\xcd\x0f\x89\x37\xfb\xa1\x77\x42\x3c\x45"  \
    "\xfa\x32\x36\x1a\x72\xc6\x03\xd3\x9c\xe5"  \
    "\x7c\x63\x59\xbb\xc3\xb1\x6c\x7a\xa6\x4f"  \
    "\xca\x03\xa7\xf8\xdd\x54\x0f\xc8\x76\x6a"  \
    "\x5d\x6c\x3b\x38\x6e"

// Name: Jose Dahlquist
// Role: Engineering Director at IOVlabs
// Address: 0xa420af120ec6515870b65e811fa7ce147d491402
#define APK_MEMBER3                             \
    "\x04\x3d\x92\xa6\x1c\x48\x8b\x72\xba\xb9"  \
    "\xcc\x54\x1d\x9c\x43\x00\xd9\x17\x77\xeb"  \
    "\x7c\x6b\x60\x82\xa0\xae\x24\x6b\x15\x45"  \
    "\x13\xda\x51\x27\x43\x3d\xc2\x81\x05\x0c"  \
    "\x15\x95\x10\x00\x9f\x03\xcf\x1a\xac\xf2"  \
    "\x2d\x42\xa0\x6e\x78\x2d\x1c\xdf\xc9\x7c"  \
    "\x92\xf4\xe3\x94\x9e"

// Name: Henrik Jondell
// Role: Chief of Technology at IOVlabs
// Address: 0xf1d5f8b99a9884ed80e033af596b1a6298c34b4b
#define APK_MEMBER4                             \
    "\x04\x22\x4e\xd7\x3e\xa9\xba\x1e\xbd\x07"  \
    "\x60\xf8\xd9\xea\x38\xe1\x8c\xf3\x9a\xc2"  \
    "\x4d\x35\xf7\x68\x63\x2b\x29\x84\xf8\x63"  \
    "\xa1\x3e\xe1\x56\x16\x2c\xa9\x25\xdd\x96"  \
    "\xe3\xaf\x13\x09\xbb\x20\xfe\xbc\x71\x7f"  \
    "\xe2\x43\xec\x2d\xb1\x48\xbf\x20\xbf\x28"  \
    "\xac\x24\xe6\xe7\xf3"

// Name: Daniel Fogg
// Role: CEO at IOVlabs
// Address: 0x22e83204d1d86f3f02ed44dfa4e0c61cb40321e1
#define APK_MEMBER5                             \
    "\x04\x83\x97\xb7\xd9\x85\xb5\x32\x82\x26"  \
    "\xa9\xda\x1e\xf2\x3d\xfd\x3e\x97\x23\xb1"  \
    "\xca\x62\x4a\x13\xe2\xbd\xef\xea\x29\x72"  \
    "\xcb\x94\x4b\xac\x9a\x1f\x9c\x3e\x9a\x16"  \
    "\xda\x1b\xda\x7f\x4a\x9d\x92\x0e\xf0\x5d"  \
    "\xf8\x32\xf6\x3d\xe1\x3b\xc7\x40\x0f\x2c"  \
    "\x45\xa9\xc1\x44\xef"

#define AUTHORIZERS_PUBKEYS \
    {                       \
        APK_MEMBER1,        \
        APK_MEMBER2,        \
        APK_MEMBER3,        \
        APK_MEMBER4,        \
        APK_MEMBER5,        \
    }
// clang-format on

#endif // __SIGNER_AUTHORIZATION_SIGNERS_H

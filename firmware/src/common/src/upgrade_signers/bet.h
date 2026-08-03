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

#ifndef __SIGNER_AUTHORIZATION_SIGNERS__BET_H
#define __SIGNER_AUTHORIZATION_SIGNERS__BET_H

// clang-format off

// This defines the Bet wallet signer authorization signers
// The wallet is a 3 of 5 multisig

// Name: Bernardo Codesido
// Role: Head of Security at RootstockLabs
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
// Role: Chief of Product at RootstockLabs
// Address: 0xc174149c9dc50cf941c629a7105f45313e7b0df0
#define APK_MEMBER2                             \
    "\x04\xa2\xe0\x4a\x13\x7a\x68\x08\x44\x8e"  \
    "\xb6\x2b\x8e\x8a\xec\x8d\x78\x69\x84\xf8"  \
    "\xab\x88\x2a\xce\xdd\x8d\x25\xcc\x79\x7f"  \
    "\x71\xfb\x22\xf3\x8f\xb6\xf4\xca\xf8\xf2"  \
    "\x73\x7f\x49\x9c\x2f\x86\xf7\x72\x20\x84"  \
    "\x2a\xfa\x67\x51\xfc\xae\xf9\xfa\x79\xd4"  \
    "\x4b\x03\xba\xf4\x26"

// Name: Jose Dahlquist
// Role: Engineering Director at RootstockLabs
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
// Role: Chief of Technology at RootstockLabs
// Address: 0xf1d5f8b99a9884ed80e033af596b1a6298c34b4b
#define APK_MEMBER4                             \
    "\x04\x22\x4e\xd7\x3e\xa9\xba\x1e\xbd\x07"  \
    "\x60\xf8\xd9\xea\x38\xe1\x8c\xf3\x9a\xc2"  \
    "\x4d\x35\xf7\x68\x63\x2b\x29\x84\xf8\x63"  \
    "\xa1\x3e\xe1\x56\x16\x2c\xa9\x25\xdd\x96"  \
    "\xe3\xaf\x13\x09\xbb\x20\xfe\xbc\x71\x7f"  \
    "\xe2\x43\xec\x2d\xb1\x48\xbf\x20\xbf\x28"  \
    "\xac\x24\xe6\xe7\xf3"

// Name: Dary McGovern
// Role: Chief of Operations at RootstockLabs
// Address: 0xe92b4590903a1067dfa8fe04b89a5db288acbf5f
#define APK_MEMBER5                             \
    "\x04\xeb\xa7\x5c\x93\xf2\x72\x58\x19\x2c"  \
    "\xe0\xee\x0d\xc3\xa6\x32\x58\xfd\xda\xba"  \
    "\xc0\xea\x73\x1f\xde\xc0\x86\xb6\x59\x85"  \
    "\xfd\xfa\x26\xb2\xda\x2e\xc7\x29\x6f\xe1"  \
    "\xeb\x86\x31\xe6\xbf\x62\xe2\x44\xe8\x3e"  \
    "\xb3\xf0\xd9\xe0\x65\x86\x18\x08\xf5\x11"  \
    "\x3e\xd9\x2f\x00\xdc"

#ifdef AUTHORIZERS_PUBKEYS
#error "AUTHORIZERS_PUBKEYS already defined; include only one upgrade wallet"
#endif

// Static check: make sure that the public keys are exactly 65 bytes long
typedef char apk_member1_len_check[(sizeof(APK_MEMBER1) == 66) ? 1 : -1];
typedef char apk_member2_len_check[(sizeof(APK_MEMBER2) == 66) ? 1 : -1];
typedef char apk_member3_len_check[(sizeof(APK_MEMBER3) == 66) ? 1 : -1];
typedef char apk_member4_len_check[(sizeof(APK_MEMBER4) == 66) ? 1 : -1];
typedef char apk_member5_len_check[(sizeof(APK_MEMBER5) == 66) ? 1 : -1];

#define AUTHORIZERS_PUBKEYS \
    {                       \
        APK_MEMBER1,        \
        APK_MEMBER2,        \
        APK_MEMBER3,        \
        APK_MEMBER4,        \
        APK_MEMBER5,        \
    }
// clang-format on

#endif // __SIGNER_AUTHORIZATION_SIGNERS__BET_H

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

/**
 * Taken from https://github.com/someone42/hardware-bitcoin-wallet @
 * 102c300d994712484c3c028b215f90a6f99d6155 and adapted for use with
 * the powHSM HAL by RootstockLabs. LICENSE transcribed below.
 */

/*
  Copyright (c) 2011-2012 someone42
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

      Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

      Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "bip32.h"
#include "test_helpers.h"

// Mock function behavior
struct {
    bool random_getrandom_fail;
} G_mocks;

/** Length of write canary (for testing writing beyond the end of an array),
 * in bytes. */
#define CANARY_LENGTH 100
/** Length of serialised BIP32 extended private key, in bytes. */
#define SERIALISED_BIP32_KEY_LENGTH 82

/** Characters for the base 58 representation of numbers. */
static const char base58_char_list[58] = {
    '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
    'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

/** Test vector for BIP32 key derivation. */
struct BIP32TestVector {
    /** Master seed. */
    uint8_t master[256];
    /** Length of master seed, in bytes. */
    unsigned int master_length;
    /** Key derivation path. */
    uint32_t path[16];
    /** Number of steps in derivation path. */
    unsigned int path_length;
    /** Expected private key, as a base58-encoded serialised extended private
     * key as described in the BIP32 specification. */
    char base58_private[256];
};

// Master seed for RootStock test cases
// 0x52a26d029f271256d6807e4cf6d9581a5912b8cccc447e5e64482928c9face80
#define ROOTSTOCK_MS                                                      \
    {                                                                     \
        0x52, 0xa2, 0x6d, 0x02, 0x9f, 0x27, 0x12, 0x56, 0xd6, 0x80, 0x7e, \
        0x4c, 0xf6, 0xd9, 0x58, 0x1a, 0x59, 0x12, 0xb8, 0xcc, 0xcc, 0x44, \
        0x7e, 0x5e, 0x64, 0x48, 0x29, 0x28, 0xc9, 0xfa, 0xce, 0x80,       \
    },                                                                    \
        32

/** Test cases from BIP 32 specification.
 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#user-content-Test_Vectors
 */

#define TEST_VECTOR_1 \
    {                 \
        0x00,         \
        0x01,         \
        0x02,         \
        0x03,         \
        0x04,         \
        0x05,         \
        0x06,         \
        0x07,         \
        0x08,         \
        0x09,         \
        0x0a,         \
        0x0b,         \
        0x0c,         \
        0x0d,         \
        0x0e,         \
        0x0f,         \
    },                \
        16

#define TEST_VECTOR_2                                                     \
    {                                                                     \
        0xff, 0xfc, 0xf9, 0xf6, 0xf3, 0xf0, 0xed, 0xea, 0xe7, 0xe4, 0xe1, \
        0xde, 0xdb, 0xd8, 0xd5, 0xd2, 0xcf, 0xcc, 0xc9, 0xc6, 0xc3, 0xc0, \
        0xbd, 0xba, 0xb7, 0xb4, 0xb1, 0xae, 0xab, 0xa8, 0xa5, 0xa2, 0x9f, \
        0x9c, 0x99, 0x96, 0x93, 0x90, 0x8d, 0x8a, 0x87, 0x84, 0x81, 0x7e, \
        0x7b, 0x78, 0x75, 0x72, 0x6f, 0x6c, 0x69, 0x66, 0x63, 0x60, 0x5d, \
        0x5a, 0x57, 0x54, 0x51, 0x4e, 0x4b, 0x48, 0x45, 0x42,             \
    },                                                                    \
        64

const struct BIP32TestVector test_cases[] = {

    {
        // Test vector 1, chain m
        TEST_VECTOR_1,
        {0}, // derivation path
        0,   // steps in derivation path
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPG"
        "JxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi" // extended private key
    },

    {
        // Test vector 1, chain m/0H
        TEST_VECTOR_1,
        {0x80000000}, // derivation path
        1,            // steps in derivation path
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6K"
        "CesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7" // extended private key
    },

    {
        // Test vector 1, chain m/0H/1
        TEST_VECTOR_1,
        {0x80000000, 1}, // derivation path
        2,               // steps in derivation path
        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYP"
        "xLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs" // extended private key
    },

    {
        // Test vector 1, chain m/0H/1/2H
        TEST_VECTOR_1,
        {0x80000000, 1, 0x80000002}, // derivation path
        3,                           // steps in derivation path
        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3r"
        "yjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM" // extended private key
    },

    {
        // Test vector 1, chain m/0H/1/2H/2
        TEST_VECTOR_1,
        {0x80000000, 1, 0x80000002, 2}, // derivation path
        4,                              // steps in derivation path
        "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f"
        "7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334" // extended private key
    },

    {
        // Test vector 1, chain m/0H/1/2H/2/1000000000
        TEST_VECTOR_1,
        {0x80000000, 1, 0x80000002, 2, 1000000000}, // derivation path
        5,                                          // steps in derivation path
        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4"
        "WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76" // extended private key
    },

    {
        // Test vector 2, chain m
        TEST_VECTOR_2,
        {0}, // derivation path
        0,   // steps in derivation path
        "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK"
        "4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U" // extended private key
    },

    {
        // Test vector 2, chain m/0
        TEST_VECTOR_2,
        {0}, // derivation path
        1,   // steps in derivation path
        "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2y"
        "JD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt" // extended private key
    },

    {
        // Test vector 2, chain m/0/2147483647H
        TEST_VECTOR_2,
        {0, 0xffffffff}, // derivation path
        2,               // steps in derivation path
        "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwC"
        "d6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9" // extended private key
    },

    {
        // Test vector 2, chain m/0/2147483647H/1
        TEST_VECTOR_2,
        {0, 0xffffffff, 1}, // derivation path
        3,                  // steps in derivation path
        "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9"
        "yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef" // extended private key
    },

    {
        // Test vector 2, chain m/0/2147483647H/1/2147483646H
        TEST_VECTOR_2,
        {0, 0xffffffff, 1, 0xfffffffe}, // derivation path
        4,                              // steps in derivation path
        "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39nj"
        "GVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc" // extended private key
    },

    {
        // Test vector 2, chain m/0/2147483647H/1/2147483646H/2
        TEST_VECTOR_2,
        {0, 0xffffffff, 1, 0xfffffffe, 2}, // derivation path
        5,                                 // steps in derivation path
        "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq3"
        "8EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j" // extended private key
    },

    // Test cases for powHSM derivation paths
    {// BTC
     ROOTSTOCK_MS,
     {0x8000002c, 0x80000000, 0x80000000, 0, 0},
     5, // m/44'/0'/0'/0/0
     "xprvA2UeNN7RNEZziKLXKBSefpya4kH15PWnvXByUVexASEiD3ugfgNDb1SkqPcz5Z3qFBy85"
     "VbFHkuxEZLxRr38U2QJjCZACzG87StyGiZzSND"},

    {// RSK
     ROOTSTOCK_MS,
     {0x8000002c, 0x80000089, 0x80000000, 0, 0},
     5, // m/44'/137'/0'/0/0
     "xprvA3mkFU5ToBWn1BL63Ms2NLwX1wetEVveBGJXbvJyuA4r6VTYjzzyUgzggKtJhXdyVW6Rx"
     "MaGFdNMGTYYEn74HaN1zVwQBN8ktd3kMupDD8c"},

    {// MST
     ROOTSTOCK_MS,
     {0x8000002c, 0x80000089, 0x80000001, 0, 0},
     5, // m/44'/137'/1'/0/0
     "xprvA3xqgq7Bq4w6JeD6fRQMojVYUeeHpVHq2uSSBzdpYrSFGGKPVdFeziEHxhA8BaBC9F9AT"
     "NL6LhzSLSgJyxifCGdoQP4zrPsLLCdggmq34m1"},

    {// tBTC
     ROOTSTOCK_MS,
     {0x8000002c, 0x80000001, 0x80000000, 0, 0},
     5, // m/44'/1'/0'/0/0
     "xprvA3wQwmmVVpN9kFPhJanvESUgk7TaL3kzfxDzmur8Hmy7Q5fs77LbzYAeuDFXMqMTSFug3"
     "gWn4Tqn9pzJ5iA3hvqNfVFJYonnQQQicdUmEgv"},

    {// tRSK
     ROOTSTOCK_MS,
     {0x8000002c, 0x80000001, 0x80000001, 0, 0},
     5, // m/44'/1'/1'/0/0
     "xprvA327ZZEydaEeVDtp8AoTiEaAWak4UwYm4E3FsrnW8fhrm6wKj8L8MzFL8e1vnAAq1QRiH"
     "FcTDJ8LkAsuECPL51LBQDoHcC86dLTppTD9s1o"},

    {// tMST
     ROOTSTOCK_MS,
     {0x8000002c, 0x80000001, 0x80000002, 0, 0},
     5, // m/44'/1'/2'/0/0
     "xprvA2n1UrdXdG7D2kHi8i8wLS2auY8WJma8XfRKfTQ9xYfTGNg81p786NbUcZVCgP64Nqnk3"
     "cAyKkJ8AzzUUd5u4iFVe4jU8UpQonvoYX6QSqh"},

};

static void reverse(uint8_t *arr, const unsigned int len) {
    uint8_t tmp;
    for (unsigned int i = 0; i < len / 2; i++) {
        tmp = arr[i];
        arr[i] = arr[len - 1 - i];
        arr[len - 1 - i] = tmp;
    }
}

static void base58_decode_bip32_key(uint8_t *out,
                                    const char *in,
                                    const unsigned int len) {
    unsigned int i;
    unsigned int j;
    unsigned int digit;
    unsigned int carry;
    unsigned int result;

    memset(out, 0, SERIALISED_BIP32_KEY_LENGTH);
    for (i = 0; i < len; i++) {
        digit = 0;
        for (j = 0; j < 58; j++) {
            if (in[i] == base58_char_list[j]) {
                digit = j;
                break;
            }
        }
        // multiply by 58
        carry = 0;
        for (j = 0; j < SERIALISED_BIP32_KEY_LENGTH; j++) {
            result = (unsigned int)out[j] * 58 + carry;
            out[j] = (uint8_t)result;
            carry = result >> 8;
        }
        // add digit
        carry = 0;
        for (j = 0; j < SERIALISED_BIP32_KEY_LENGTH; j++) {
            result = (unsigned int)out[j] + carry;
            if (j == 0) {
                result += digit;
            }
            out[j] = (uint8_t)result;
            carry = result >> 8;
        }
    }
    reverse(out, SERIALISED_BIP32_KEY_LENGTH);
}

static void printf_hex(uint8_t *buf, size_t len) {
    printf("0x");
    for (unsigned int i = 0; i < len; i++) {
        printf("%02x", ((unsigned char *)buf)[i]);
    }
    printf("\n");
}

bool random_getrandom(void *buffer, size_t length) {
    if (G_mocks.random_getrandom_fail)
        return false;

    for (size_t i = 0; i < length; i++)
        ((uint8_t *)buffer)[i] = (uint8_t)(rand() & 0xFF);
    return true;
}

void setup() {
    memset(&G_mocks, 0, sizeof(G_mocks));
}

void test_derivation() {
    uint8_t expected_bytes[SERIALISED_BIP32_KEY_LENGTH];
    uint8_t canary[CANARY_LENGTH];
    uint8_t out[32 + CANARY_LENGTH];
    unsigned int i;

    printf("Testing derivation is ok...\n");
    setup();
    init_tests(__FILE__);

    for (i = 0; i < (sizeof(test_cases) / sizeof(struct BIP32TestVector));
         i++) {
        fill_with_random(canary, sizeof(canary));
        memcpy(&(out[32]), canary, sizeof(canary));
        if (!bip32_derive_private(out,
                                  sizeof(out),
                                  test_cases[i].master,
                                  test_cases[i].master_length,
                                  test_cases[i].path,
                                  test_cases[i].path_length)) {
            printf("Test vector %u failed to derive\n", i);
            report_failure();
        } else {
            base58_decode_bip32_key(expected_bytes,
                                    test_cases[i].base58_private,
                                    strlen(test_cases[i].base58_private));
            if (memcmp(out, &expected_bytes[46], 32) != 0) {
                printf("Test vector %u derivation mismatch\n", i);
                printf("Derived: ");
                printf_hex(out, 32);
                printf("\n");
                printf("Expected: ");
                printf_hex(&expected_bytes[46], 32);
                printf("\n");
                report_failure();
            } else if (memcmp(&(out[32]), canary, sizeof(canary)) != 0) {
                printf("Test vector %u caused write to canary\n", i);
                report_failure();
            } else {
                report_success();
            }
        }
    }

    finish_tests();
    assert(!tests_failed());
}

void test_derivation_fails_if_output_buffer_too_small() {
    uint8_t out_ok[32];
    uint8_t out_error[31];

    printf("Testing derivation fails if output buffer is too small...\n");
    setup();

    const struct BIP32TestVector *test_case = &test_cases[0];

    assert(bip32_derive_private(out_ok,
                                sizeof(out_ok),
                                test_case->master,
                                test_case->master_length,
                                test_case->path,
                                test_case->path_length));

    assert(!bip32_derive_private(out_error,
                                 sizeof(out_error),
                                 test_case->master,
                                 test_case->master_length,
                                 test_case->path,
                                 test_case->path_length));
}

void test_derivation_fails_if_getrandom_fails() {
    uint8_t out_ok[32];

    printf("Testing derivation fails if getrandom fails...\n");
    setup();

    const struct BIP32TestVector *test_case = &test_cases[0];

    assert(bip32_derive_private(out_ok,
                                sizeof(out_ok),
                                test_case->master,
                                test_case->master_length,
                                test_case->path,
                                test_case->path_length));

    G_mocks.random_getrandom_fail = true;

    assert(bip32_derive_private(out_ok,
                                sizeof(out_ok),
                                test_case->master,
                                test_case->master_length,
                                test_case->path,
                                test_case->path_length));
}

int main() {
    srand(time(NULL));

    test_derivation();
    test_derivation_fails_if_output_buffer_too_small();
    test_derivation_fails_if_getrandom_fails();

    return 0;
}

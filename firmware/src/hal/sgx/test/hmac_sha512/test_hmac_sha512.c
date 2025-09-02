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
#include <string.h>
#include <assert.h>
#include "hmac_sha512.h"
#include "test_helpers.h"

/** Get minimum of a and b.
 * \warning Do not use this if the evaluation of a and b has side effects.
 */
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

/** Run unit tests using test vectors from a file. The file is expected to be
 * in the same format as the NIST "HMAC Test Vectors", which can be obtained
 * from:
 * http://csrc.nist.gov/groups/STM/cavp/index.html#07
 * \param filename The name of the file containing the test vectors.
 */
static void scanTestVectors(char *filename) {
    FILE *f;
    unsigned int i;
    unsigned int key_length;
    unsigned int message_length;
    unsigned int result_length;
    unsigned int compare_length;
    int test_number;
    int value;
    uint8_t *key;
    uint8_t *message;
    uint8_t *expected_result;
    uint8_t actual_result[SHA512_HASH_LENGTH];
    char buffer[2048];

    f = fopen(filename, "r");
    if (f == NULL) {
        printf("Could not open %s, please get it \
(HMAC Test Vectors) from \
http://csrc.nist.gov/groups/STM/cavp/index.html#07",
               filename);
        exit(1);
    }

    // Skip to past [L=64] (since we want the SHA-512 based tests).
    test_number = 1;
    while (!feof(f)) {
        fgets(buffer, sizeof(buffer), f);
        if (!strcmp(buffer, "[L=64]\n")) {
            break;
        }
    }
    while (!feof(f)) {
        skip_whitespace(f);
        skip_line(f); // skip "Count =" line
        // Get length of key and result.
        if (!fscanf(f, "Klen = %u", &key_length)) {
            printf("fscanf error when reading key length\n");
            exit(1);
        }
        skip_line(f);
        if (!fscanf(f, "Tlen = %u", &result_length)) {
            printf("fscanf error when reading result length\n");
            exit(1);
        }
        message_length = 128; // that seems to be the case
        // Get key.
        skip_whitespace(f);
        fgets(buffer, 7, f);
        if (strcmp(buffer, "Key = ")) {
            printf("Parse error; expected \"Key = \"\n");
            exit(1);
        }
        key = malloc(key_length);
        for (i = 0; i < key_length; i++) {
            fscanf(f, "%02x", &value);
            key[i] = (uint8_t)value;
        }
        // Get message.
        skip_whitespace(f);
        fgets(buffer, 7, f);
        if (strcmp(buffer, "Msg = ")) {
            printf("Parse error; expected \"Msg = \"\n");
            exit(1);
        }
        message = malloc(message_length);
        for (i = 0; i < message_length; i++) {
            fscanf(f, "%02x", &value);
            message[i] = (uint8_t)value;
        }
        // Get expected result.
        skip_whitespace(f);
        fgets(buffer, 7, f);
        if (strcmp(buffer, "Mac = ")) {
            printf("Parse error; expected \"Mac = \"\n");
            exit(1);
        }
        expected_result = malloc(result_length);
        for (i = 0; i < result_length; i++) {
            fscanf(f, "%02x", &value);
            expected_result[i] = (uint8_t)value;
        }
        skip_whitespace(f);
        // Calculate HMAC-SHA512 and compare.
        if (!hmac_sha512(actual_result,
                         sizeof(actual_result),
                         key,
                         key_length,
                         message,
                         message_length)) {
            printf("HMAC-SHA512 failed\n");
            exit(1);
        }
        compare_length = MIN(result_length, sizeof(actual_result));
        if (!memcmp(actual_result, expected_result, compare_length)) {
            report_success();
        } else {
            printf("Test number %d failed (key len = %u, result len = %u)\n",
                   test_number,
                   key_length,
                   result_length);
            report_failure();
        }
        free(key);
        free(message);
        free(expected_result);
        test_number++;
    }
    fclose(f);
}

void test_hmac_fails_when_out_buffer_too_small() {
    uint8_t small_buffer[SHA512_HASH_LENGTH - 1];
    uint8_t ok_buffer[SHA512_HASH_LENGTH];
    const uint8_t key[] = {11, 22, 33, 44, 55, 66, 77, 88, 99, 00};
    const char message[] = "this-is-a-message";
    assert(!hmac_sha512(small_buffer,
                        sizeof(small_buffer),
                        key,
                        sizeof(key),
                        (const uint8_t *)message,
                        strlen(message)));
    assert(hmac_sha512(ok_buffer,
                       sizeof(ok_buffer),
                       key,
                       sizeof(key),
                       (const uint8_t *)message,
                       strlen(message)));
}

int main(void) {
    init_tests(__FILE__);
    scanTestVectors("HMAC.rsp");
    finish_tests();
    test_hmac_fails_when_out_buffer_too_small();
    exit(0);
}
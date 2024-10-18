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

/** \file test_helpers.c
 *
 * \brief Common helper functions for unit tests.
 *
 * If TEST is not defined, this file will appear as an empty translation
 * unit to the compiler. Thus this file should not be compiled in non-test
 * builds.
 *
 * This file is licensed as described by the file LICENCE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "test_helpers.h"

/** Number of test cases which succeeded. */
static int succeeded;
/** Number of test cases which failed. */
static int failed;
/** Time when unit tests were started. */
static time_t start_time;

/** Skip whitespace in an open file, starting from the current position within
 * the file and ending such that the file position points to the first
 * non-whitespace character found.
 * \param f The file to skip whitespace in.
 */
void skip_whitespace(FILE *f) {
    int one_char;
    do {
        one_char = fgetc(f);
    } while (((one_char == ' ') || (one_char == '\t') || (one_char == '\n') ||
              (one_char == '\r')) &&
             !feof(f));
    ungetc(one_char, f);
}

/** Skip the contents of a line in an open file, starting from the current
 * position within the file and ending such that the file position points to
 * the first character of the next line.
 * \param f The file to skip a line in.
 */
void skip_line(FILE *f) {
    int one_char;
    do {
        one_char = fgetc(f);
    } while ((one_char != '\n') && !feof(f));
}

/** Fill array with pseudo-random testing data.
 * \param out Byte array to fill.
 * \param len Number of bytes to write.
 */
void fill_with_random(uint8_t *out, unsigned int len) {
    unsigned int i;

    for (i = 0; i < len; i++) {
        out[i] = (uint8_t)rand();
    }
}

/** Call this whenever a test case succeeds. */
void report_success(void) {
    succeeded++;
}

/** Call this whenever a test case fails. */
void report_failure(void) {
    failed++;
}

/** This must be called before running any unit tests.
 * \param source_file_name The name of the file being unit tested. The use
 *                         of the __FILE__ macro is probably a good idea.
 */
void init_tests(const char *source_file_name) {
    succeeded = 0;
    failed = 0;
    srand(42); // make sure tests which rely on rand() are deterministic
    printf("Running unit tests for file: %s\n", source_file_name);
    time(&start_time);
}

/** This must be called after running all unit tests for a file. It will
 * report test statistics.
 */
void finish_tests(void) {
    time_t finish_time;

    time(&finish_time);
    printf("Tests required about %g seconds\n",
           difftime(finish_time, start_time));
    printf("Tests which succeeded: %d\n", succeeded);
    printf("Tests which failed: %d\n", failed);
}

bool tests_failed() {
    return failed > 0;
}

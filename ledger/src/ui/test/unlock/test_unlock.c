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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "apdu.h"
#include "os.h"
#include "unlock.h"

void test_ok() {
    printf("Test OK...\n");

    pin_t pin_ctx;
    init_pin_ctx(&pin_ctx, (unsigned char *)"1234567a\0\0");

    unsigned int tx = unlock(&pin_ctx);
    assert(tx == 3);
    assert(APDU_OP() == 1);
}

void test_wrong_pin() {
    printf("Test wrong pin...\n");

    pin_t pin_ctx;
    init_pin_ctx(&pin_ctx, (unsigned char *)"wrong-pin\0");

    unsigned int tx = unlock(&pin_ctx);
    assert(tx == 3);
    assert(APDU_OP() == 0);
}

int main() {
    // Set device pin
    mock_set_pin((unsigned char *)"1234567a", strlen("1234567a"));

    test_ok();
    test_wrong_pin();

    return 0;
}

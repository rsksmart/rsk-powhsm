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
#include <string.h>
#include <assert.h>

#include "defs.h"
#include "communication.h"
#include "os.h"
#include "pin.h"

void test_echo() {
    printf("Test echo...\n");
    unsigned int rx = 4;
    assert(4 == echo(rx));
}

void test_get_mode() {
    printf("Test get mode...\n");
    assert(2 == get_mode());
    assert(RSK_MODE_BOOTLOADER == APDU_AT(1));
}

void test_get_retries() {
    printf("Test get retries...\n");

    assert(3 == get_retries());
    assert(MOCK_INTERNAL_RETRIES_COUNTER == APDU_AT(2));
}

int main() {
    test_echo();
    test_get_mode();
    test_get_retries();

    return 0;
}

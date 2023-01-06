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
#include "apdu_utils.h"
#include "assert_utils.h"
#include "defs.h"
#include "mock.h"
#include "unlock.h"

// Mock variables
static bool G_pin_accepted;

// Mock functions from other modules
unsigned int unlock_with_pin(bool prepended_length) {
    return G_pin_accepted;
}

void test_unlock() {
    printf("Test unlock...\n");
    G_pin_accepted = true;
    unsigned int rx;
    SET_APDU("\x80\xfe", rx); // RSK_UNLOCK_CMD

    assert(3 == unlock());
    ASSERT_APDU("\x80\xfe\x01");
}

void test_unlock_wrong_pin() {
    printf("Test unlock (wrong pin)...\n");
    G_pin_accepted = false;
    unsigned int rx;
    SET_APDU("\x80\xfe", rx); // RSK_UNLOCK_CMD

    assert(3 == unlock());
    ASSERT_APDU("\x80\xfe\x00");
}

int main() {
    test_unlock();
    test_unlock_wrong_pin();

    return 0;
}

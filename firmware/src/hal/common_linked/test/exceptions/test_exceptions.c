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
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "hal/exceptions.h"

// Test helper variables for tracking execution flow
static bool G_try_executed = false;
static bool G_catch_executed = false;
static bool G_finally_executed = false;

// Exception constants for testing
#define TEST_EXCEPTION_A 0x1234
#define TEST_EXCEPTION_B 0x5678

void setup() {
    G_try_executed = false;
    G_finally_executed = false;
    G_catch_executed = false;
}

void test_catch_no_exception() {
    setup();
    printf("Testing CATCH when no exception is thrown...\n");

    BEGIN_TRY {
        TRY {
            printf("Not throwing an exception\n");
            G_try_executed = true;
        }
        CATCH(TEST_EXCEPTION_A) {
            // Should not be executed
            G_catch_executed = true;
            assert(false);
        }
        FINALLY {
            G_finally_executed = true;
        }
    }
    END_TRY;

    assert(G_try_executed);
    assert(!G_catch_executed);
    assert(G_finally_executed);
}

void test_catch_with_throw() {
    setup();
    printf("Testing CATCH when exception is thrown...\n");

    BEGIN_TRY {
        TRY {
            printf("Throwing exception: 0x%x\n", TEST_EXCEPTION_A);
            G_try_executed = true;
            THROW(TEST_EXCEPTION_A);
            assert(false);
        }
        CATCH(TEST_EXCEPTION_A) {
            printf("Caught exception: 0x%x\n", TEST_EXCEPTION_A);
            G_catch_executed = true;
        }
        FINALLY {
            G_finally_executed = true;
        }
    }
    END_TRY;

    assert(G_try_executed);
    assert(G_catch_executed);
    assert(G_finally_executed);
}

void test_catch_multiple_blocks() {
    setup();
    printf("Testing CATCH with multiple CATCH blocks...\n");

    BEGIN_TRY {
        TRY {
            G_try_executed = true;
            printf("Throwing exception: 0x%x\n", TEST_EXCEPTION_B);
            THROW(TEST_EXCEPTION_B);
            assert(false);
        }
        CATCH(TEST_EXCEPTION_A) {
            // Should not be executed
            assert(false);
        }
        CATCH(TEST_EXCEPTION_B) {
            printf("Caught exception: 0x%x\n", TEST_EXCEPTION_B);
            G_catch_executed = true;
        }
        FINALLY {
            G_finally_executed = true;
        }
    }
    END_TRY;

    assert(G_try_executed);
    assert(G_catch_executed);
    assert(G_finally_executed);
}

void test_catch_other_no_exception() {
    setup();
    printf("Testing CATCH_OTHER when no exception is thrown...\n");

    BEGIN_TRY {
        TRY {
            printf("Not throwing an exception\n");
            G_try_executed = true;
        }
        CATCH_OTHER(e) {
            // Should not be executed
            G_catch_executed = true;
            assert(false);
        }
        FINALLY {
            G_finally_executed = true;
        }
    }
    END_TRY;

    assert(G_try_executed);
    assert(!G_catch_executed);
    assert(G_finally_executed);
}

void test_catch_other_with_throw() {
    setup();
    printf("Testing CATCH_OTHER when exception is thrown...\n");

    BEGIN_TRY {
        TRY {
            printf("Throwing exception: 0x%x\n", TEST_EXCEPTION_A);
            G_try_executed = true;
            THROW(TEST_EXCEPTION_A);
            // Should not be executed
            assert(false);
        }
        CATCH_OTHER(e) {
            printf("Caught exception: 0x%x\n", e);
            G_catch_executed = true;
            assert(e == TEST_EXCEPTION_A);
        }
        FINALLY {
            G_finally_executed = true;
        }
    }
    END_TRY;

    assert(G_try_executed);
    assert(G_catch_executed);
    assert(G_finally_executed);
}

void test_catch_other_with_catch() {
    setup();
    printf("Testing CATCH_OTHER with CATCH...\n");

    BEGIN_TRY {
        TRY {
            printf("Throwing exception: 0x%x\n", TEST_EXCEPTION_A);
            G_try_executed = true;
            THROW(TEST_EXCEPTION_A);
            // Should not be executed
            assert(false);
        }
        CATCH(TEST_EXCEPTION_A) {
            printf("Caught exception: 0x%x\n", TEST_EXCEPTION_A);
            G_catch_executed = true;
        }
        CATCH_OTHER(e) {
            // Should not be executed
            assert(false);
        }
        FINALLY {
            G_finally_executed = true;
        }
    }
    END_TRY;

    assert(G_try_executed);
    assert(G_catch_executed);
    assert(G_finally_executed);
}

void test_catch_other_miss_catch() {
    setup();
    printf("Testing CATCH_OTHER with CATCH (missed catch)...\n");

    BEGIN_TRY {
        TRY {
            printf("Throwing exception: 0x%x\n", TEST_EXCEPTION_B);
            G_try_executed = true;
            THROW(TEST_EXCEPTION_B);
            printf("Should not be executed\n");
            assert(false);
        }
        CATCH(TEST_EXCEPTION_A) {
            // Should not be executed
            assert(false);
        }
        CATCH_OTHER(e) {
            printf("Caught exception: 0x%x\n", e);
            G_catch_executed = true;
            assert(e == TEST_EXCEPTION_B);
        }
        FINALLY {
            G_finally_executed = true;
        }
    }
    END_TRY;

    assert(G_try_executed);
    assert(G_catch_executed);
    assert(G_finally_executed);
}

void test_catch_all_no_exception() {
    setup();
    printf("Testing CATCH_ALL when no exception is thrown...\n");

    BEGIN_TRY {
        TRY {
            printf("Not throwing an exception\n");
            G_try_executed = true;
        }
        CATCH_ALL {
            // Should not be executed
            G_catch_executed = true;
            assert(false);
        }
        FINALLY {
            G_finally_executed = true;
        }
    }
    END_TRY;

    assert(G_try_executed);
    assert(!G_catch_executed);
    assert(G_finally_executed);
}

void test_catch_all_with_throw() {
    setup();
    printf("Testing CATCH_ALL when exception is thrown...\n");

    BEGIN_TRY {
        TRY {
            printf("Throwing exception: 0x%x\n", TEST_EXCEPTION_A);
            G_try_executed = true;
            THROW(TEST_EXCEPTION_A);
            // Should not be executed
            assert(false);
        }
        CATCH_ALL {
            printf("Caught exception!\n");
            G_catch_executed = true;
        }
        FINALLY {
            G_finally_executed = true;
        }
    }
    END_TRY;

    assert(G_try_executed);
    assert(G_catch_executed);
    assert(G_finally_executed);
}

void test_catch_all_with_catch() {

    setup();
    printf("Testing CATCH_ALL with CATCH...\n");

    BEGIN_TRY {
        TRY {
            printf("Throwing exception: 0x%x\n", TEST_EXCEPTION_A);
            G_try_executed = true;
            THROW(TEST_EXCEPTION_A);
            // Should not be executed
            assert(false);
        }
        CATCH(TEST_EXCEPTION_A) {
            printf("Caught exception: 0x%x\n", TEST_EXCEPTION_A);
            G_catch_executed = true;
        }
        CATCH_ALL {
            // Should not be executed
            assert(false);
        }
        FINALLY {
            G_finally_executed = true;
        }
    }
    END_TRY;

    assert(G_try_executed);
    assert(G_catch_executed);
    assert(G_finally_executed);
}

void test_catch_all_miss_catch() {
    setup();
    printf("Testing CATCH_ALL with CATCH (missed catch)...\n");

    BEGIN_TRY {
        TRY {
            printf("Throwing exception: 0x%x\n", TEST_EXCEPTION_B);
            G_try_executed = true;
            THROW(TEST_EXCEPTION_B);
            // Should not be executed
            assert(false);
        }
        CATCH(TEST_EXCEPTION_A) {
            // Should not be executed
            assert(false);
        }
        CATCH_ALL {
            printf("Caught exception!\n");
            G_catch_executed = true;
        }
        FINALLY {
            G_finally_executed = true;
        }
    }
    END_TRY;

    assert(G_try_executed);
    assert(G_catch_executed);
    assert(G_finally_executed);
}

int main() {
    test_catch_no_exception();
    test_catch_with_throw();
    test_catch_multiple_blocks();
    test_catch_other_no_exception();
    test_catch_other_with_throw();
    test_catch_other_with_catch();
    test_catch_other_miss_catch();
    test_catch_all_no_exception();
    test_catch_all_with_throw();
    test_catch_all_with_catch();
    test_catch_all_miss_catch();

    printf("All tests passed!\n");
    return 0;
}
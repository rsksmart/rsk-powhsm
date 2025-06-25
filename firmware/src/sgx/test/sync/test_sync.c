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

#include <assert.h>

#include "sync.h"

// Test helpers.
int sync_aquire_lock_or_fail(int error_code) {
    SYNC_AQUIRE_LOCK(error_code);
    return 0;
}

// Unit tests.
void setup() {
    sync_release_lock();
}

void test_sync_try_aqcuire_lock_ok() {
    setup();
    printf("Testing sync_try_aqcuire_lock succeeds...\n");

    bool acquire_result = sync_try_aqcuire_lock();

    assert(acquire_result == true);
}

void test_sync_try_aqcuire_lock_already_locked_fails() {
    setup();
    printf("Testing sync_try_aqcuire_lock fails when lock already taken...\n");

    bool first_acquire = sync_try_aqcuire_lock();
    bool second_acquire = sync_try_aqcuire_lock();

    assert(first_acquire == true);
    assert(second_acquire == false);
}

void test_sync_aquire_lock_macro_ok() {
    setup();
    printf("Testing SYNC_AQUIRE_LOCK macro succeeds...\n");

    int result = sync_aquire_lock_or_fail(-99);
    assert(result == 0);
}

void test_sync_aquire_lock_macro_error_code() {
    setup();
    printf("Testing SYNC_AQUIRE_LOCK macro fails with error code...\n");

    // Aquire the lock so that the next call fails.
    sync_try_aqcuire_lock();

    int result = sync_aquire_lock_or_fail(-99);
    assert(result == -99);
}

void test_sync_release_lock_ok() {
    setup();
    printf("Testing sync_release_lock succeeds...\n");

    // Succeeds
    bool first_acquire = sync_try_aqcuire_lock();
    // Fails: lock already taken
    bool second_acquire = sync_try_aqcuire_lock();
    sync_release_lock();
    // Succeeds
    bool third_acquire = sync_try_aqcuire_lock();

    assert(first_acquire == true);
    assert(second_acquire == false);
    assert(third_acquire == true);
}

void test_sync_release_lock_macro_ok() {
    setup();
    printf("Testing SYNC_RELEASE_LOCK macro succeeds...\n");

    // Succeeds
    bool first_acquire = sync_try_aqcuire_lock();
    // Fails: lock already taken
    bool second_acquire = sync_try_aqcuire_lock();
    SYNC_RELEASE_LOCK();
    // Succeeds
    bool third_acquire = sync_try_aqcuire_lock();

    assert(first_acquire == true);
    assert(second_acquire == false);
    assert(third_acquire == true);
}

void test_sync_release_lock_when_not_locked() {
    setup();
    printf("Testing sync_release_lock when lock is not acquired succeeds...\n");

    sync_release_lock();

    // Should still be able to acquire
    bool acquire_result = sync_try_aqcuire_lock();
    assert(acquire_result == true);
}

void test_sync_multiple_cycles() {
    setup();
    printf("Testing multiple acquire/release cycles...\n");

    for (int i = 0; i < 100; i++) {
        bool acquire_result = sync_try_aqcuire_lock();
        assert(acquire_result == true);

        // Verify locked
        bool second_acquire = sync_try_aqcuire_lock();
        assert(second_acquire == false);

        // Release
        sync_release_lock();

        // Verify unlocked
        bool reacquire_result = sync_try_aqcuire_lock();
        assert(reacquire_result == true);

        // Release for next iteration
        sync_release_lock();
    }
}

void test_sync_lock_state_consistency() {
    setup();
    printf("Test lock state consistency...\n");

    // Initial state - should be unlocked
    bool initial_acquire = sync_try_aqcuire_lock();
    assert(initial_acquire == true);

    // Multiple attempts to acquire should fail
    assert(sync_try_aqcuire_lock() == false);
    assert(sync_try_aqcuire_lock() == false);
    assert(sync_try_aqcuire_lock() == false);

    // Single release
    sync_release_lock();

    // Should be able to acquire again
    bool after_release_acquire = sync_try_aqcuire_lock();
    assert(after_release_acquire == true);

    // Multiple releases should not break state
    sync_release_lock();
    sync_release_lock();
    sync_release_lock();

    // Should still be able to acquire
    bool final_acquire = sync_try_aqcuire_lock();
    assert(final_acquire == true);
}

int main() {
    test_sync_try_aqcuire_lock_ok();
    test_sync_try_aqcuire_lock_already_locked_fails();
    test_sync_aquire_lock_macro_ok();
    test_sync_aquire_lock_macro_error_code();
    test_sync_release_lock_ok();
    test_sync_release_lock_macro_ok();
    test_sync_release_lock_when_not_locked();
    test_sync_multiple_cycles();
    test_sync_lock_state_consistency();
    test_sync_aquire_lock_macro_ok();

    printf("All sync tests passed!\n");
    return 0;
}

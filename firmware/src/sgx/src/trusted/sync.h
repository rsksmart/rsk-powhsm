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

#ifndef __TRUSTED_SYNC_H
#define __TRUSTED_SYNC_H

#include <stdbool.h>
#include "hal/log.h"

#define SYNC_AQUIRE_LOCK()                                                     \
    if (!sync_try_aqcuire_lock()) {                                            \
        LOG("Failed to acquire lock, ecall %s was not executed!\n", __func__); \
        return false;                                                          \
    }

#define SYNC_RELEASE_LOCK() sync_release_lock()

/**
 * @brief Tries to aqcuire the lock. This function will verify if the lock is
 * currently available and if so, it will aqcuire it and return true. If the
 * lock is already taken, it will return false.
 *
 * @return true if the lock was aqcuired, false otherwise.
 *
 * @note This function is not thread safe and should be called only from a
 * single thread. All trusted modules need to aqcuire the lock before calling
 * any ecalls or ocalls. This is to ensure that only one single ecall or ocall
 * is executed at a time, preventing nested ecals.
 */
bool sync_try_aqcuire_lock();

/**
 * @brief Releases the lock. This function will release the lock if it was
 * aqcuired. If the lock was not aqcuired, this function will do nothing.
 *
 * @note This function is not thread safe and should be called only from a
 * single thread. All trusted modules need to release the lock after calling any
 * ecalls or ocalls.
 */
void sync_release_lock();

#endif // __TRUSTED_SYNC_H

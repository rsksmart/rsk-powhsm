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

#ifndef __HAL_ACCESS_H
#define __HAL_ACCESS_H

#include <stdbool.h>

/**
 * @brief Returns whether the module is locked
 *
 * @returns whether the module is locked
 */
bool access_is_locked();

// BEGINNING of platform-dependent code
#if defined(HSM_PLATFORM_SGX)

#include <stdint.h>

typedef void (*access_wiped_callback_t)();

/**
 * @brief Initializes the access module
 *
 * @param wiped_callback function to call when the module is wiped
 *
 * @returns whether the initialisation succeeded
 */
bool access_init(access_wiped_callback_t wiped_callback);

/**
 * @brief Unlocks the access module
 *
 * @param password
 * @param password_length
 *
 * @returns whether the unlock was successful
 */
bool access_unlock(char* password, uint8_t password_length);

/**
 * @brief Returns the number of unlocking retries available
 */
uint8_t access_get_retries();

/**
 * @brief Returns whether the module is in a wiped state
 *
 * @returns whether the module is in a wiped state
 */
bool access_is_wiped();

/**
 * @brief Wipes the module
 */
bool access_wipe();

/**
 * @brief Changes the password.
 * The module needs to be in an unlocked or wiped state.
 *
 * @param password
 * @param password_length
 *
 * @returns whether the password change was successful
 */
bool access_set_password(char* password, uint8_t password_length);

/**
 * @brief Writes the password to the given buffer
 *
 * @param out               output buffer
 * @param out_size [in/out] output buffer size
 *
 * @return whether the output succeeded
 */
bool access_output_password_USE_FROM_EXPORT_ONLY(uint8_t* out,
                                                 size_t* out_size);

#endif
// END of platform-dependent code

#endif // __HAL_ACCESS_H

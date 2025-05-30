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

#ifndef __TRUSTED_UPGRADE_H
#define __TRUSTED_UPGRADE_H

#include <stdint.h>

// -----------------------------------------------------------------------
// SGX upgrade authorization & migration
// -----------------------------------------------------------------------

/**
 * Initialize the upgrade module
 */
void upgrade_init();

/**
 * @brief Reset any ongoing reset operations
 * and clear any current operation context
 */
void upgrade_reset();

/**
 * @brief Implement the upgrade protocol.
 *
 * @arg[in] rx  number of received bytes from the host
 * @returns     number of transmited bytes to the host
 */
unsigned int upgrade_process_apdu(volatile unsigned int rx);

#endif // __TRUSTED_UPGRADE_H

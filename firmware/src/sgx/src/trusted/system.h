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

#ifndef __TRUSTED_SYSTEM_H
#define __TRUSTED_SYSTEM_H

/**
 * @brief Initializes the system module
 *
 * @param msg_buffer the APDU buffer to use
 * @param msg_buffer_size the size of the APDU buffer in bytes
 *
 * @returns whether the initialisation succeeded
 */
bool system_init(unsigned char *msg_buffer, size_t msg_buffer_size);

/**
 * @brief Process an APDU message
 *
 * @param rx number of received bytes
 *
 * @returns number of bytes to transmit
 */
unsigned int system_process_apdu(unsigned int rx);

#endif // __TRUSTED_SYSTEM_H

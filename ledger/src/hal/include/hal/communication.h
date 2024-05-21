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

#ifndef __HAL_COMMUNICATION_H
#define __HAL_COMMUNICATION_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Initializes the communication module
 *
 * @param msg_buffer The buffer to use for communication
 * @param msg_buffer_size The size of the message buffer in bytes
 * 
 * @returns whether the initialisation succeeded
 */
bool communication_init(unsigned char* msg_buffer, size_t msg_buffer_size);

/**
 * @brief Get a pointer to the message buffer
 * 
 * @returns a pointer to the message buffer
 */
unsigned char* communication_get_msg_buffer();

/**
 * @brief Get the message buffer size
 * 
 * @returns the message buffer size
 */
size_t communication_get_msg_buffer_size();

/**
 * @brief Exchanges bytes with the host. This function blocks until the host sends a
 * message.
 *
 *  The message exchanges data with the host using the msg_buffer. If there are any bytes
 *  to transmit, they are transmitted first. After that the function blocks until a new
 *  message is received from the host.
 *
 * @param tx The number of bytes sent to the host
 *
 * @returns the number of bytes received from the host
 */
unsigned short communication_io_exchange(unsigned short tx);

/**
 * @brief Finalizes the communication module
 */
void communication_finalize(void);

#endif // __HAL_COMMUNICATION_H

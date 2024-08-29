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

#ifndef __IO_H
#define __IO_H

#include <stdbool.h>

/**
 * APDU buffer
 */
#define APDU_BUFFER_SIZE 85
extern unsigned char io_apdu_buffer[APDU_BUFFER_SIZE];

/**
 * @brief Initializes the I/O module. Starts a TCP server at the given host and 
 * port.
 * 
 * @param port the port on which to listen for connections
 * @param host the interface to bind to
 * 
 */
bool io_init(int port, const char *host);

/**
 * @brief Exchanges bytes with the host. This function blocks until the host
 * sends a message.
 *
 * The message exchanges data with the host using the msg_buffer. If there are
 * any bytes to transmit, they are transmitted first. After that the function
 * blocks until a new message is received from the host.
 *
 * @param tx The number of bytes to send to the host
 *
 * @returns the number of bytes received from the host
 */
unsigned short io_exchange(unsigned short tx);

/**
 * @brief Finalises the I/O module. Closes any outstanding connections and shuts
 * the server down.
 */
void io_finalise();

#endif // __IO_H
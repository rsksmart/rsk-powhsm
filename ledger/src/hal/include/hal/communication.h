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
bool communication_init(unsigned char *msg_buffer, size_t msg_buffer_size);

/**
 * @brief Get a pointer to the message buffer
 *
 * @returns a pointer to the message buffer
 */
unsigned char *communication_get_msg_buffer();

/**
 * @brief Get the message buffer size
 *
 * @returns the message buffer size
 */
size_t communication_get_msg_buffer_size();

/**
 * @brief Exchanges bytes with the host. This function blocks until the host
 * sends a message.
 *
 * The message exchanges data with the host using the msg_buffer. If there are
 * any bytes to transmit, they are transmitted first. After that the function
 * blocks until a new message is received from the host.
 *
 * @param tx The number of bytes sent to the host
 *
 * @returns the number of bytes received from the host
 */
unsigned short communication_io_exchange(unsigned short tx);

// BEGINNING of platform-dependent code
#if defined(HSM_PLATFORM_X86)

#include <stdio.h>

/**
 * @brief For an external module processing
 * APDU messages
 *
 * @param cb the external module processing callback
 */
typedef unsigned short (*communication_external_module_process_t)(
    unsigned short tx);
void communication_set_external_module_process(
    communication_external_module_process_t cb);

/**
 * @brief Starts a TCP server at the given host and port and sets it as the
 * channel on which communication_io_exchange will perform the IO operations
 * Either this or communication_set_input_file must be called before
 * using communication_io_exchange.
 *
 * @param port the port on which to listen for connections
 * @param host the interface to bind to
 */
void communication_set_and_start_server(int port, const char *host);

/**
 * @brief Sets the input file from which communication_io_exchange
 * will read the input.
 * Either this or communication_set_server must be called before
 * using communication_io_exchange.
 *
 * @param _input_file the input file that is used for I/O
 */
void communication_set_input_file(FILE *_input_file);

/**
 * @brief Sets the replica file to which communication_io_exchange will
 * write the input. Setting this is optional.
 *
 * @param _replica_file the file to which to replicate the inputs
 */
void communication_set_replica_file(FILE *_replica_file);

/**
 * @brief Perform an empty message write on the IO channel
 */
void communication_reply();

#endif
// END of platform-dependent code

#endif // __HAL_COMMUNICATION_H

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

#ifndef __SIMULATOR_OS_IO_H
#define __SIMULATOR_OS_IO_H

#include <stdio.h>

/**
 * APDU buffer
 */
#define CHANNEL_APDU 0
#define IO_APDU_BUFFER_SIZE 85
extern unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

/*
 * Sets the server on which io_exchange will perform
 * the IO operations
 * Either this or os_io_set_input_file must be called before
 * using io_exchange.
 */
void os_io_set_server(int svr);

/*
 * Sets the input file from which io_exchange will
 * read the input.
 * Either this or os_io_set_server must be called before
 * using io_exchange.
 */
void os_io_set_input_file(FILE *_input_file);

/*
 * Sets the replica file to which io_exchange will
 * write the input. Optional.
 */
void os_io_set_replica_file(FILE *_replica_file);

/**
 * Perform an empty message
 * write on the IO channel
 */
void io_exchange_reply();

/*
 * This function performs the input / output to a simulated dongle,
 * either via a TCP server of via an input file depending on global state.
 * @arg[in] channel_and_flags   must be CHANNEL_APDU
 * @arg[in] tx                  amount of bytes to transmit to the client
 * @ret                         amount of bytes received from the client
 */
unsigned short io_exchange(unsigned char channel_and_flags, unsigned short tx);
/*
 * This function emulates USB device, writing bytes to tcpsocket instead
 * @arg[in] channel_and_flags   must be CHANNEL_APDU
 * @arg[in] tx                  amount of bytes to transmit to the client
 * @ret                         amount of bytes received from the client
 */
unsigned short io_exchange_server(unsigned char channel_and_flags,
                                  unsigned short tx);

/* This function emulates the HOST device, reading bytes to a file instead
 * @arg[in] channel_and_flags   must be CHANNEL_APDU
 * @arg[in] tx_len              amount of bytes to transmit to the client
 * @ret                         amount of bytes received from the client
 */
unsigned short io_exchange_file(unsigned char channel_and_flags,
                                unsigned char tx_len,
                                FILE *inputfd);

/* Append a received command to file
 * @arg[in] filename        Binary file to append commands
 * @arg[in] rx              Lenght of the command
 * @ret number of bytes written
 */
unsigned int replicate_to_file(FILE *replica_file, unsigned short rx);

#endif // __SIMULATOR_OS_IO_H

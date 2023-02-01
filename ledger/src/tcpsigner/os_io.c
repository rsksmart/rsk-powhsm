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

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <netdb.h>
#include <limits.h>

#include "os_io.h"
#include "tcp.h"
#include "log.h"
#include "defs.h"
#include "hsmsim_admin.h"
#include "apdu.h"

/**
 * APDU buffer
 */
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

#define MAX_FUZZ_TRANSFER IO_APDU_BUFFER_SIZE

enum io_mode_e { IO_MODE_SERVER, IO_MODE_INPUT_FILE };
enum io_mode_e io_mode;

/**
 * For the TCP server
 */
int server;
int socketfd;

/**
 * For the file input mode
 */
FILE *input_file;

/**
 * Copy all input to this file, if set.
 */
FILE *replica_file;

/**
 * For flushing in between mains
 */
static bool io_exchange_write_only;

/*
 * Sets the server on which io_exchange will perform
 * the IO operations
 * (This *MUST* be set before using io_exchange)
 */
void os_io_set_server(int svr) {
    server = svr;
    socketfd = 0;
    io_mode = IO_MODE_SERVER;
    io_exchange_write_only = false;
}

void os_io_set_input_file(FILE *_input_file) {
    input_file = _input_file;
    io_mode = IO_MODE_INPUT_FILE;
}

void os_io_set_replica_file(FILE *_replica_file) {
    replica_file = _replica_file;
}

unsigned short io_exchange(unsigned char channel_and_flags, unsigned short tx) {
    unsigned short rx;
    switch (io_mode) {
    case IO_MODE_SERVER:
        rx = io_exchange_server(channel_and_flags, tx);
        break;
    case IO_MODE_INPUT_FILE:
        rx = io_exchange_file(channel_and_flags, tx, input_file);
        break;
    default:
        info("[TCPSigner] No IO Mode set! This is a bug.");
        exit(1);
        break;
    }

    if (replica_file != NULL) {
        int written = replicate_to_file(replica_file, rx);
        if (written != rx + 1) {
            info("Error writting to output file %s\n", replica_file);
            exit(-1);
        }
    }

    // Process one APDU message using the admin module
    // if need be (there shouldn't normally
    // be many of these in a row, so the stack shouldn't overflow)
    if (hsmsim_admin_need_process(rx)) {
        tx = hsmsim_admin_process_apdu(rx);
        return io_exchange(channel_and_flags, tx);
    }

    return rx;
}

/**
 * Perform an empty message
 * write on the IO channel
 */
void io_exchange_reply() {
    io_exchange_write_only = true;
    G_io_apdu_buffer[0] = (APDU_OK & 0xff00) >> 8;
    G_io_apdu_buffer[1] = APDU_OK & 0xff;
    io_exchange(0, 2);
}

/*
 * This function emulates USB device, writing bytes to tcpsocket instead
 * @arg[in] channel_and_flags   must be CHANNEL_APDU
 * @arg[in] tx                  amount of bytes to transmit to the client
 * @ret                         amount of bytes received from the client
 */
unsigned short io_exchange_server(unsigned char channel_and_flags,
                                  unsigned short tx) {
    uint32_t tx_net, rx_net;
    unsigned int rx;
    int readlen;

    // "Test" correct value on channel and flags in every call
    if (channel_and_flags != CHANNEL_APDU) {
        info("Invalid channel and flags specified for io_exchange: %d "
             "(expected %d). Terminating TCPSigner.\n",
             channel_and_flags,
             CHANNEL_APDU);
        exit(1);
    }

    while (true) {
        if (!socketfd) {
            socketfd = accept_connection(server);
            tx = 0;
        }

        // Write len (Compatibility with LegerBlue commTCP.py)
        if (tx > 0) {
            // Write APDU length minus two bytes of the sw
            // (encoded in 4 bytes network byte-order)
            // (compatibility with LegerBlue commTCP.py)
            tx_net = tx - 2;
            tx_net = htonl(tx_net);
            size_t written;
            if (send(socketfd, &tx_net, sizeof(tx_net), MSG_NOSIGNAL) == -1) {
                info("Connection closed by the client\n");
                socketfd = 0;
                continue;
            }
            // Write APDU
            if (send(socketfd, G_io_apdu_buffer, tx, MSG_NOSIGNAL) == -1) {
                info("Connection closed by the client\n");
                socketfd = 0;
                continue;
            }
            info_hex("Dongle =>", G_io_apdu_buffer, tx);
        }

        // Only write? We're done
        if (io_exchange_write_only) {
            io_exchange_write_only = false;
            return 0;
        }

        // Read APDU length
        // (encoded in 4 bytes network byte-order)
        // (compatibility with LegerBlue commTCP.py)
        readlen = read(socketfd, &rx_net, sizeof(rx_net));
        if (readlen == sizeof(rx_net)) {
            rx = ntohl(rx_net);
            if (rx > 0) {
                // Read APDU from socket
                readlen =
                    read(socketfd, G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
                if (readlen != rx) {
                    info("Error reading APDU (got %d bytes != %d bytes). "
                         "Disconnected\n",
                         readlen,
                         rx);
                    socketfd = 0;
                    continue;
                }
                info_hex("Dongle <=", G_io_apdu_buffer, rx);
            } else {
                // Empty packet
                info("Dongle <= <EMPTY MESSAGE>\n");
            }

            return rx;
        } else if (readlen == 0) {
            // EOF => socket closed
            info("Connection closed by the client\n");
        } else if (readlen == -1) {
            // Error reading
            info("Error reading from socket. Disconnected\n");
        } else {
            // Invalid packet header
            info("Error reading APDU length (got %d bytes != %ld bytes). "
                 "Disconnected\n",
                 readlen,
                 sizeof(rx_net));
        }
        socketfd = 0;
    }
}

/* This function emulates the HOST device, reading bytes from a file instead
 * @arg[in] channel_and_flags   must be CHANNEL_APDU
 * @arg[in] tx_len              amount of bytes to transmit to the client
 * @arg[in] inputfd             the input file
 * @ret                         amount of bytes received from the client
 */
unsigned short io_exchange_file(unsigned char channel_and_flags,
                                unsigned char tx,
                                FILE *input_file) {
    // File input format: |1 byte length| |len bytes data|
    static unsigned long file_index = 0;
    info_hex("Dongle => ", G_io_apdu_buffer, tx);

    // Only write? We're done
    if (io_exchange_write_only) {
        io_exchange_write_only = false;
        return 0;
    }

    unsigned char announced_rx;
    if (fread(&announced_rx, sizeof(char), 1, input_file) != 1) {
        if (feof(input_file)) {
            info("Server: EOF\n");
            exit(0);
        }
        info("Server: could not read rx size\n");
        exit(1);
    }

    // Read a capped amount of bytes to keep it reasonably realistic
    unsigned short capped_rx;
    if (announced_rx <= MAX_FUZZ_TRANSFER) {
        capped_rx = announced_rx;
    } else {
        capped_rx = MAX_FUZZ_TRANSFER;
    }

    info("Server: reading %d (announced: %d) bytes at index: %d\n",
         capped_rx,
         announced_rx,
         file_index);
    unsigned short rx =
        fread(G_io_apdu_buffer, sizeof(char), capped_rx, input_file);

    if (rx != capped_rx) {
        // if we reach EOF while reading the data portion it means
        // the announced size did not match the file
        if (feof(input_file)) {
            info("Server: malformed input, tried reading %d bytes but reached "
                 "EOF after %d\n",
                 capped_rx,
                 rx);
            exit(1);
        }
        info("Server: Could not read %d bytes (only: %d) from input file\n",
             capped_rx,
             rx);
        exit(1);
    }

    // Move the offset to wherever the input said it should be,
    // even if we actually did not read the whole data.
    // If not, this would lead the file_index
    // interpreting data as the length.
    unsigned long index_offset = announced_rx + 1;
    if (file_index > (ULONG_MAX - index_offset)) {
        info("Server: input file too big, can't store offset.");
        exit(1);
    }

    file_index += index_offset;
    info_hex("Dongle <= ", G_io_apdu_buffer, rx);
    return capped_rx;
}

/* Append a received command to file
 * @arg[in] filename        Binary file to append commands
 * @arg[in] rx              Lenght of the command
 * @ret number of bytes written
 */
unsigned int replicate_to_file(FILE *replica_file, unsigned short rx) {
    unsigned char rx_byte = rx;
    info_hex("Replica =>", G_io_apdu_buffer, rx_byte);
    unsigned int written = fwrite(&rx_byte, sizeof(char), 1, replica_file);
    written += fwrite(G_io_apdu_buffer, sizeof(char), rx_byte, replica_file);

    // XXX: This should not be necessary. We are correctly closing the file
    // at the end of the process. But for whatever reason, this does not seem
    // to work for small inputs. Force flushing after every input to avoid
    // corrupted replica files.
    fflush(replica_file);
    return written;
}

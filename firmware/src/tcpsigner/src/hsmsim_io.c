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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include "hal/log.h"
#include "hsmsim_io.h"
#include "apdu.h"

/**
 * APDU buffer
 */
#define IO_APDU_BUFFER_SIZE 85
static unsigned char io_apdu_buffer[IO_APDU_BUFFER_SIZE];

#define MAX_FUZZ_TRANSFER IO_APDU_BUFFER_SIZE

enum io_mode_e { IO_MODE_SERVER, IO_MODE_INPUT_FILE };
enum io_mode_e io_mode;

/**
 * For the TCP server
 */
int server;
int connfd;
struct sockaddr_in servaddr, cliaddr;

/**
 * For the file input mode
 */
static FILE *input_file;

/**
 * Copy all input to this file, if set.
 */
static FILE *replica_file;

/**
 * For flushing in between mains
 */
static bool io_exchange_write_only;

/**
 * For an external module processing
 * APDU messages
 */
typedef unsigned short (*hsmsim_io_external_module_process_t)(
    unsigned short tx);
hsmsim_io_external_module_process_t external_module_process_cb = NULL;

void hsmsim_io_set_external_module_process(
    hsmsim_io_external_module_process_t cb) {
    external_module_process_cb = cb;
}

/**
 * @brief Start server, return a socket on connection
 *
 * @arg[in] PORT   tcp port
 * @arg[in] HOST   HOST string
 *
 * @returns socket file descriptor
 */
static int start_server(int port, const char *host) {
    int sockfd;
    struct hostent *hostinfo;
    hostinfo = gethostbyname(host);

    if (hostinfo == NULL) {
        LOG("Host not found.\n");
        exit(1);
    }

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        LOG("Socket creation failed...\n");
        exit(1);
    }

    bzero(&servaddr, sizeof(servaddr));

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) <
        0) {
        LOG("Socket option setting failed failed\n");
        exit(1);
    }

    if (setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0) {
        LOG("Socket option setting failed failed\n");
        exit(1);
    }

    // Set address and port
    servaddr.sin_family = AF_INET;
    memcpy(&servaddr.sin_addr, hostinfo->h_addr_list[0], hostinfo->h_length);
    servaddr.sin_port = htons(port);

    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
        LOG("Socket bind failed...\n");
        exit(1);
    }

    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        LOG("Listen failed...\n");
        exit(1);
    }

    LOG("Server listening...\n");
    return sockfd;
}

/**
 * @brief Accept the data packet from client and verification
 *
 * @arg[in] sockfd  server socket
 *
 * @returns connection file descriptor
 */
static int accept_connection(int sockfd) {
    int len = sizeof(cliaddr);
    int connfd = accept(sockfd, (struct sockaddr *)&cliaddr, &len);
    if (connfd < 0) {
        LOG("Client connection failed...\n");
        exit(1);
    }

    LOG("Client connected...\n");
    return connfd;
}

void hsmsim_io_init() {
    communication_init(io_apdu_buffer, sizeof(io_apdu_buffer));
}

void hsmsim_io_set_and_start_server(int port, const char *host) {
    server = start_server(port, host);
    connfd = 0;
    io_mode = IO_MODE_SERVER;
    io_exchange_write_only = false;
}

void hsmsim_io_set_input_file(FILE *_input_file) {
    input_file = _input_file;
    io_mode = IO_MODE_INPUT_FILE;
}

void hsmsim_io_set_replica_file(FILE *_replica_file) {
    replica_file = _replica_file;
}

/**
 * Perform an empty message
 * write on the IO channel
 */
void hsmsim_io_reply() {
    io_exchange_write_only = true;
    io_apdu_buffer[0] = (APDU_OK & 0xff00) >> 8;
    io_apdu_buffer[1] = APDU_OK & 0xff;
    hsmsim_io_exchange(2);
}

/*
 * This function emulates USB device, writing bytes to tcpsocket instead
 * @arg[in] tx                  amount of bytes to transmit to the client
 * @ret                         amount of bytes received from the client
 */
static unsigned short io_exchange_server(unsigned short tx) {
    uint32_t tx_net, rx_net;
    unsigned int rx;
    int readlen;

    while (true) {
        if (!connfd) {
            connfd = accept_connection(server);
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
            if (send(connfd, &tx_net, sizeof(tx_net), MSG_NOSIGNAL) == -1) {
                LOG("Connection closed by the client\n");
                connfd = 0;
                continue;
            }
            // Write APDU
            if (send(connfd, io_apdu_buffer, tx, MSG_NOSIGNAL) == -1) {
                LOG("Connection closed by the client\n");
                connfd = 0;
                continue;
            }
            LOG_HEX("Dongle =>", io_apdu_buffer, tx);
        }

        // Only write? We're done
        if (io_exchange_write_only) {
            io_exchange_write_only = false;
            return 0;
        }

        // Read APDU length
        // (encoded in 4 bytes network byte-order)
        // (compatibility with LedgerBlue commTCP.py)
        readlen = read(connfd, &rx_net, sizeof(rx_net));
        if (readlen == sizeof(rx_net)) {
            rx = ntohl(rx_net);
            if (rx > 0) {
                // Read APDU from socket
                readlen = read(connfd, io_apdu_buffer, sizeof(io_apdu_buffer));
                if (readlen < 0) {
                    LOG("Error reading APDU. Disconnected\n");
                    connfd = 0;
                    continue;
                } else if ((unsigned int)readlen != rx) {
                    LOG("Warning: APDU read length mismatch "
                        "(got %d bytes, expected %u bytes). "
                        "Resetting request buffer\n",
                        readlen,
                        rx);
                    // Empty the request buffer
                    int bytes_available;
                    char c;
                    if (ioctl(connfd, FIONREAD, &bytes_available) < 0) {
                        LOG("Error peeking APDU. Disconnected\n");
                        connfd = 0;
                        continue;
                    }
                    while (bytes_available--)
                        read(connfd, &c, 1);
                }
                LOG_HEX("Dongle <=", io_apdu_buffer, readlen);
            } else {
                // Empty packet
                LOG("Dongle <= <EMPTY MESSAGE>\n");
            }

            return rx;
        } else if (readlen == 0) {
            // EOF => socket closed
            LOG("Connection closed by the client\n");
        } else if (readlen == -1) {
            // Error reading
            LOG("Error reading from socket. Disconnected\n");
        } else {
            // Invalid packet header
            LOG("Error reading APDU length (got %d bytes != %ld bytes). "
                "Disconnected\n",
                readlen,
                sizeof(rx_net));
        }
        connfd = 0;
    }
}

/* This function emulates the HOST device, reading bytes from a file instead
 * @arg[in] tx_len              amount of bytes to transmit to the client
 * @arg[in] inputfd             the input file
 * @ret                         amount of bytes received from the client
 */
static unsigned short io_exchange_file(unsigned char tx, FILE *input_file) {
    // File input format: |1 byte length| |len bytes data|
    static unsigned long file_index = 0;
    LOG_HEX("Dongle => ", io_apdu_buffer, tx);

    // Only write? We're done
    if (io_exchange_write_only) {
        io_exchange_write_only = false;
        return 0;
    }

    unsigned char announced_rx;
    if (fread(&announced_rx, sizeof(char), 1, input_file) != 1) {
        if (feof(input_file)) {
            LOG("Server: EOF\n");
            exit(0);
        }
        LOG("Server: could not read rx size\n");
        exit(1);
    }

    // Read a capped amount of bytes to keep it reasonably realistic
    unsigned short capped_rx;
    if (announced_rx <= MAX_FUZZ_TRANSFER) {
        capped_rx = announced_rx;
    } else {
        capped_rx = MAX_FUZZ_TRANSFER;
    }

    LOG("Server: reading %d (announced: %d) bytes at index: %d\n",
        capped_rx,
        announced_rx,
        file_index);
    unsigned short rx =
        fread(io_apdu_buffer, sizeof(char), capped_rx, input_file);

    if (rx != capped_rx) {
        // if we reach EOF while reading the data portion it means
        // the announced size did not match the file
        if (feof(input_file)) {
            LOG("Server: malformed input, tried reading %d bytes but reached "
                "EOF after %d\n",
                capped_rx,
                rx);
            exit(1);
        }
        LOG("Server: Could not read %d bytes (only: %d) from input file\n",
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
        LOG("Server: input file too big, can't store offset.");
        exit(1);
    }

    file_index += index_offset;
    LOG_HEX("Dongle <= ", io_apdu_buffer, rx);
    return capped_rx;
}

/* Append a received command to file
 * @arg[in] filename        Binary file to append commands
 * @arg[in] rx              Lenght of the command
 * @ret number of bytes written
 */
static unsigned int replicate_to_file(FILE *replica_file, unsigned short rx) {
    unsigned char rx_byte = rx;
    LOG_HEX("Replica =>", io_apdu_buffer, rx_byte);
    unsigned int written = fwrite(&rx_byte, sizeof(char), 1, replica_file);
    written += fwrite(io_apdu_buffer, sizeof(char), rx_byte, replica_file);

    // XXX: This should not be necessary. We are correctly closing the file
    // at the end of the process. But for whatever reason, this does not seem
    // to work for small inputs. Force flushing after every input to avoid
    // corrupted replica files.
    fflush(replica_file);
    return written;
}

unsigned short hsmsim_io_exchange(unsigned short tx) {
    unsigned short rx, tx_ex;

    switch (io_mode) {
    case IO_MODE_SERVER:
        rx = io_exchange_server(tx);
        break;
    case IO_MODE_INPUT_FILE:
        rx = io_exchange_file(tx, input_file);
        break;
    default:
        LOG("[TCPSigner] No IO Mode set! This is a bug.");
        exit(1);
        break;
    }

    if (replica_file != NULL) {
        int written = replicate_to_file(replica_file, rx);
        if (written != rx + 1) {
            LOG("Error writting to output file %s\n", replica_file);
            exit(-1);
        }
    }

    // Process one APDU message using an external module callback
    // (there should generally speaking be at most one of these in a row,
    // so the stack shouldn't overflow)
    if (external_module_process_cb) {
        tx_ex = external_module_process_cb(rx);
        if (tx_ex) {
            return hsmsim_io_exchange(tx_ex);
        }
    }

    return rx;
}

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

#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>

#include "io.h"
#include "log.h"

/**
 * APDU buffer
 */
unsigned char io_apdu_buffer[APDU_BUFFER_SIZE];

/**
 * For the TCP server
 */
int serverfd;
int connfd;
struct sockaddr_in servaddr, cliaddr;

static void close_and_reset_fd(int *fd) {
    if (fd && (*fd != -1)) {
        close(*fd);
        *fd = -1;
    }
}

static int start_server(int port, const char *host) {
    int sockfd;
    struct hostent *hostinfo;
    hostinfo = gethostbyname(host);

    if (hostinfo == NULL) {
        LOG("Host not found.\n");
        return -1;
    }

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        LOG("Socket creation failed...\n");
        return -1;
    }

    explicit_bzero(&servaddr, sizeof(servaddr));

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) <
        0) {
        LOG("Socket option setting failed failed\n");
        return -1;
    }

    if (setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0) {
        LOG("Socket option setting failed failed\n");
        return -1;
    }

    // Set address and port
    servaddr.sin_family = AF_INET;
    memcpy(&servaddr.sin_addr, hostinfo->h_addr_list[0], hostinfo->h_length);
    servaddr.sin_port = htons(port);

    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
        LOG("Socket bind failed...\n");
        return -1;
    }

    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        LOG("Listen failed...\n");
        return -1;
    }

    LOG("Server listening...\n");
    return sockfd;
}

static bool accept_connection() {
    socklen_t len = sizeof(cliaddr);
    connfd = accept(serverfd, (struct sockaddr *)&cliaddr, &len);
    if (connfd == -1) {
        LOG("Client connection failed...\n");
        return 0;
    }

    LOG("Client connected...\n");
    return connfd != -1;
}

bool io_init(int port, const char *host) {
    connfd = -1;
    serverfd = start_server(port, host);
    return (serverfd != -1);
}

void io_finalise() {
    close_and_reset_fd(&connfd);
    close_and_reset_fd(&serverfd);
}

unsigned short io_exchange(unsigned short tx) {
    uint32_t tx_net, rx_net;
    unsigned int rx;
    int readlen;

    while (true) {
        if (connfd == -1) {
            if (!accept_connection()) {
                LOG("Error accepting client connection\n");
                return 0;
            }
            tx = 0;
        }

        // Write len (Compatibility with LegerBlue commTCP.py)
        if (tx > 0) {
            // Write APDU length minus two bytes of the sw
            // (encoded in 4 bytes network byte-order)
            // (compatibility with LegerBlue commTCP.py)
            tx_net = tx - 2;
            tx_net = htonl(tx_net);
            if (send(connfd, &tx_net, sizeof(tx_net), MSG_NOSIGNAL) == -1) {
                LOG("Connection closed by the client\n");
                close_and_reset_fd(&connfd);
                continue;
            }
            // Write APDU
            if (send(connfd, io_apdu_buffer, tx, MSG_NOSIGNAL) == -1) {
                LOG("Connection closed by the client\n");
                close_and_reset_fd(&connfd);
                continue;
            }
            LOG_HEX("I/O =>", io_apdu_buffer, tx);
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
                    close_and_reset_fd(&connfd);
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
                        close_and_reset_fd(&connfd);
                        continue;
                    }
                    while (bytes_available--)
                        read(connfd, &c, 1);
                }
                LOG_HEX("I/O <=", io_apdu_buffer, readlen);
            } else {
                // Empty packet
                LOG("I/O <= <EMPTY MESSAGE>\n");
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
        close_and_reset_fd(&connfd);
    }
}

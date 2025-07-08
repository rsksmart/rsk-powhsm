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

#define CHECK_READ_STATUS(read_result, err_prefix)                            \
    {                                                                         \
        if ((read_result) == 0) {                                             \
            LOG("%s: connection closed by the client\n", err_prefix);         \
            close_and_reset_fd(&connfd);                                      \
            goto end_readloop;                                                \
        } else if ((read_result) == -1) {                                     \
            LOG("%s: error reading from socket. Disconnected\n", err_prefix); \
            close_and_reset_fd(&connfd);                                      \
            goto end_readloop;                                                \
        }                                                                     \
    }

unsigned short io_exchange(unsigned short tx) {
    enum {
        READ_LENGTH,
        READ_PLOAD,
        SKIP_PLOAD,
    } read_state;

    while (true) {
        if (connfd == -1) {
            if (!accept_connection()) {
                LOG("Error accepting client connection\n");
                return 0;
            }
            tx = 0;
        }

        // Write len (Compatibility with LedgerBlue commTCP.py)
        if (tx > 0) {
            // Write APDU length minus two bytes of the sw
            // (encoded in 4 bytes network byte-order)
            // (compatibility with LedgerBlue commTCP.py)
            uint32_t tx_net = tx - 2;
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

        // Read from buffer until whole APDU is read or something happens
        read_state = READ_LENGTH;
        ssize_t readlen;
        uint32_t rx_net;
        uint8_t len_buf[sizeof(rx_net)];
        char discard_buffer[1024 * 1024];
        unsigned int rx;
        unsigned int offset = 0;
        while (true) {
            switch (read_state) {
            case READ_LENGTH:
                readlen =
                    read(connfd, len_buf + offset, sizeof(len_buf) - offset);
                CHECK_READ_STATUS(readlen, "Error while reading APDU length");
                offset += readlen;
                if (offset == sizeof(len_buf)) {
                    memcpy(&rx_net, len_buf, sizeof(rx_net));
                    rx = ntohl(rx_net);
                    // Empty packet?
                    if (rx == 0) {
                        LOG("I/O <= <EMPTY MESSAGE>\n");
                        return 0;
                    } else if (rx > sizeof(io_apdu_buffer) ||
                               rx != (unsigned short)rx) {
                        LOG("Client tried to send a message "
                            "that was too big (%u bytes). "
                            "Skipping payload.\n",
                            rx);
                        // Move onto skipping the APDU payload
                        read_state = SKIP_PLOAD;
                        offset = 0;
                    } else {
                        // Move onto reading the APDU payload
                        read_state = READ_PLOAD;
                        offset = 0;
                    }
                }
                break;
            case READ_PLOAD:
                readlen = read(connfd, io_apdu_buffer + offset, rx - offset);
                CHECK_READ_STATUS(readlen, "Error while reading APDU payload");
                offset += readlen;
                if (offset == rx) {
                    LOG("I/O <= (%u bytes)", rx);
                    LOG_HEX("", io_apdu_buffer, rx);
                    return (unsigned short)rx;
                }
                break;
            case SKIP_PLOAD:
                readlen = read(connfd, discard_buffer, sizeof(discard_buffer));
                CHECK_READ_STATUS(readlen, "Error while skipping APDU payload");
                offset += readlen;
                if (offset == rx) {
                    LOG("I/O <= (%u bytes) <SKIPPED PAYLOAD>\n", rx);
                    memset(io_apdu_buffer, 0, sizeof(io_apdu_buffer));
                    return rx != (unsigned short)rx ? (unsigned short)0xFFFFFFFF
                                                    : (unsigned short)rx;
                }
                break;
            }
        }
    end_readloop:;
    }
}

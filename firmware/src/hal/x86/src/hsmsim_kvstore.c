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
#include <linux/vm_sockets.h>
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

/**
 * For the vsock server
 */
static int connfd = 0;
static struct sockaddr_vm servaddr;

/**
 * @brief Connect to a vsock host listening on cid:port.
 *
 * @returns connected socket file descriptor
 */
static int connect_to_server(unsigned int cid, unsigned int port) {
    int sockfd;

    sockfd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sockfd == -1) {
        LOG("Socket creation failed...\n");
        return -1;
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.svm_family = AF_VSOCK;
    servaddr.svm_cid = cid;
    servaddr.svm_port = port;

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {
        LOG("Connect failed (cid=%u, port=%u)...\n", cid, port);
        close(sockfd);
        return -1;
    }

    LOG("Connected to vsock server (cid=%u, port=%u)...\n", cid, port);
    return sockfd;
}

bool hsmsim_kvstore_init(unsigned int cid, unsigned int port) {
    connfd = connect_to_server(cid, port);
    if (connfd < 0)
        return false;

    return true;
}

void hsmsim_kvstore_finalise() {
    if (connfd > 0) {
        close(connfd);
        connfd = 0;
    }
}


size_t hsmsim_kvstore_get(char* key, uint8_t* data_buf, size_t buffer_size) {
    if (!connfd) return 0;

    uint8_t buf[3];
    buf[0] = 0x01;
    buf[1] = strlen(key);
    if (send(connfd, buf, 2, 0) <= 0 || send(connfd, key, strlen(key), 0) <= 0) {
        LOG("Unable to request read operation\n");
        return 0;
    }

    ssize_t n = recv(connfd, buf, 4, 0);
    if (n != 2 && n != 4) {
        LOG("Invalid read operation response\n");
        return 0;
    }
    if (buf[0] != 0x01) {
        LOG("Invalid read operation protocol\n");
        return 0;
    }
    if (buf[1] != 0x01 || n != 4) {
        LOG("Unable to read key %s\n", key);
        return 0;
    }

    uint16_t data_size = buf[2];
    data_size += buf[3] << 8;

    if (data_size > buffer_size) {
        LOG("Destination buffer too small\n");
        return 0;
    }

    ssize_t data_read = recv(connfd, data_buf, data_size, 0);
    if (data_read != data_size) {
        LOG("Unable to read key %s value\n", key);
        return 0;
    }

    return data_size;
}

bool hsmsim_kvstore_save(char* key, uint8_t* data, size_t data_size) {
    if (!connfd) return false;

    uint8_t buf[260];
    buf[0] = 0x02;
    buf[1] = strlen(key);
    memcpy(buf+2, key, buf[1]);
    buf[buf[1]+2] = (uint8_t)(data_size & 0xFF);
    buf[buf[1]+3] = (uint8_t)((data_size >> 8) & 0xFF);
    if (send(connfd, buf, 4+buf[1], 0) != 4+buf[1]) {
        LOG("Unable to request write operation\n");
        return false;
    }
    if (send(connfd, data, data_size, 0) != data_size) {
        LOG("Unable to send write operation data\n");
        return false;
    }

    if (recv(connfd, buf, 2, 0) != 2) {
        LOG("Invalid write operation response\n");
        return false;
    }
    if (buf[0] != 0x02) {
        LOG("Invalid write operation protocol\n");
        return false;
    }
    return buf[1];
}
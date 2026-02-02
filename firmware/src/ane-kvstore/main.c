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

#include <errno.h>
#include <linux/vm_sockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "keyvalue_store.h"

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

int main(int argc, char **argv) {
    unsigned int port = 1234;
    if (argc > 1) {
        char *end = NULL;
        unsigned long v = strtoul(argv[1], &end, 10);
        if (!argv[1][0] || (end && *end)) {
            fprintf(stderr, "usage: %s [port]\n", argv[0]);
            return 2;
        }
        port = (unsigned int)v;
    }

    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0)
        die("socket");

    struct sockaddr_vm addr;
    memset(&addr, 0, sizeof(addr));
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = VMADDR_CID_ANY;
    addr.svm_port = port;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        die("bind");
    if (listen(fd, 1) < 0)
        die("listen");

    printf("KVstore vsock server listening on port %u\n", port);

    int cfd = 0;
    for (;;) {
        if (!cfd) {
            cfd = accept(fd, NULL, NULL);
            if (cfd < 0) {
                cfd = 0;
                if (errno == EINTR)
                    continue;
                die("accept");
            }
        }

        // Commands:
        // READ:  
        // - Input:  01 [1-byte key length] [n-bytes key]
        // - Output: 01 [1-byte success boolean] [2-byte LE value length] [n-bytes value]
        // WRITE: 
        // - Input: 02 [1-byte key length] [n-bytes key] [2-byte LE value length] [n-bytes value]
        // - Output: 02 [1-byte success boolean]

        unsigned char buf[4+UINT16_MAX+UINT8_MAX];
        unsigned char key[UINT8_MAX];
        uint8_t command, key_length;
        uint16_t value_length;
        size_t n;
        // Get command and key length
        if (read(cfd, buf, 2) != 2) {
            printf("Error reading command and key-length\n");
            close(cfd);
            cfd = 0;
            continue;
        }

        command = buf[0];
        key_length = buf[1];

        if (!key_length) {
            printf("Invalid zero-length key\n");
            continue;
        }

        // Read key (common for read and write)
        n = read(cfd, buf, key_length);
        if (n <= 0) {
            perror("Reading key");
            close(cfd);
            cfd = 0;
            continue;
        }
        if (n != key_length) {
            printf("Key length: read %u bytes but expected %u\n", n, key_length);
            close(cfd);
            cfd = 0;
            continue;
        }
        memcpy(key, buf, key_length);
        key[key_length] = 0;

        switch (command) {
        case 0x01:
            printf("<= READ <%s>\n", key);
            n = kvstore_get(key, buf+4, sizeof(buf)-3);
            if (!n) {
                buf[0] = 0x01;
                buf[1] = 0x00;
                send(cfd, buf, 2, 0);
                printf("=> ERR\n");
                continue;
            }
            buf[0] = 0x01;
            buf[1] = 0x01;
            buf[2] = (uint8_t)(n & 0xFF);
            buf[3] = (uint8_t)((n >> 8) & 0xFF);
            send(cfd, buf, (uint16_t)n+4, 0);
            printf("=> OK\n");
            break;
        case 0x02:
            printf("<= WRITE <%s>\n", key);
            if (read(cfd, buf, 2) != 2) {
                printf("Error reading value-length\n");
                close(cfd);
                cfd = 0;
                continue;
            }
            value_length = buf[0];
            value_length += buf[1] << 8;
            if (value_length) {
                n = read(cfd, buf, value_length);
                if (n <= 0) {
                    perror("Reading value");
                    close(cfd);
                    cfd = 0;
                    continue;
                }
                if (n != value_length) {
                    printf("Value length: read %u bytes but expected %u\n", n, value_length);
                    close(cfd);
                    cfd = 0;
                    continue;
                }
            }
            printf("Writing key %s...\n", key);
            if (!kvstore_save(key, buf, value_length)) {
                buf[0] = 0x02;
                buf[1] = 0x00;
                send(cfd, buf, 2, 0);
                printf("=> ERR\n");
                continue;
            }
            buf[0] = 0x02;
            buf[1] = 0x01;
            send(cfd, buf, 2, 0);
            printf("=> OK\n");
            break;
        default:
            printf("Unknown command: %u\n", buf[0]);
            continue;
        }
    }
}

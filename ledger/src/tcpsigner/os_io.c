/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 * 
 *   OS IO exchange simulation
 ********************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <netdb.h>

#include "os_io.h"
#include "tcp.h"
#include "log.h"

/**
 * APDU buffer
 */
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

/**
 * For the TCP server
 */
int server;
int socketfd;

/*
 * Sets the server on which io_exchange will perform
 * the IO operations
 * (This *MUST* be set before using io_exchange)
 */
void os_io_set_server(int svr) {
    server = svr;
    socketfd = 0;
}

/* 
 * This function emulates USB device, writing bytes to tcpsocket instead
 * @arg[in] channel_and_flags   must be CHANNEL_APDU
 * @arg[in] tx                  amount of bytes to transmit to the client
 * @ret                         amount of bytes received from the client
 */
unsigned short io_exchange(unsigned char channel_and_flags,
                           unsigned short tx) {
    uint32_t tx_net, rx_net;
    unsigned int rx;
    int readlen;

    // "Test" correct value on channel and flags in every call
    if (channel_and_flags != CHANNEL_APDU) {
        info("Invalid channel and flags specified for io_exchange: %d (expected %d). Terminating TCPSigner.\n", 
            channel_and_flags, CHANNEL_APDU);
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
            tx_net = tx-2;
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
        // Read APDU length
        // (encoded in 4 bytes network byte-order)
        // (compatibility with LegerBlue commTCP.py)
        readlen = read(socketfd, &rx_net, sizeof(rx_net));
        if (readlen == sizeof(rx_net)) {
            rx = ntohl(rx_net);
            if (rx > 0) {
                // Read APDU from socket
                readlen = read(socketfd, G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
                if (readlen != rx) {
                    info("Error reading APDU (got %d bytes != %d bytes). Disconnected\n", readlen, rx);
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
            info("Error reading APDU length (got %d bytes != %ld bytes). Disconnected\n", readlen, sizeof(rx_net));
        }
        socketfd = 0;
    }
}
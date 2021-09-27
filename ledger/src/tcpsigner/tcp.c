/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   TCP/USB simulator layer
 ********************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "os.h"
#include "tcp.h"
#include "hsmsim_exceptions.h"

#include "log.h"

// Global socket variables
struct sockaddr_in servaddr, cli;

/* start server, return a socket on connection
 * @arg[in] PORT   tcp port
 * @arg[in] HOST   HOST string
 * @ret     socket file descriptor
 */
int start_server(int port, const char *host) {
    int sockfd;
    struct hostent *hostinfo;
    hostinfo = gethostbyname(host);

    if (hostinfo == NULL) {
        info("Host not found.\n");
        exit(1);
    }

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        info("Socket creation failed...\n");
        exit(1);
    }

    bzero(&servaddr, sizeof(servaddr));

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) <
        0) {
        info("Socket option setting failed failed\n");
        exit(1);
    }

    if (setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0) {
        info("Socket option setting failed failed\n");
        exit(1);
    }

    // Set address and port
    servaddr.sin_family = AF_INET;
    memcpy(&servaddr.sin_addr, hostinfo->h_addr_list[0], hostinfo->h_length);
    servaddr.sin_port = htons(port);

    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
        info("Socket bind failed...\n");
        exit(1);
    }

    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        info("Listen failed...\n");
        exit(1);
    }

    info("Server listening...\n");
    return sockfd;
}

/* Accept the data packet from client and verification
 * @arg[in] sockfd  server socket
 * @ret connection file descriptor
 */
int accept_connection(int sockfd) {
    int len = sizeof(cli);
    int connfd = accept(sockfd, (struct sockaddr *)&cli, &len);
    if (connfd < 0) {
        info("Client connection failed...\n");
        exit(1);
    }

    info("Client connected...\n");
    return connfd;
}

/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   USB-TCP simulator layer
 ********************************************************************************/

#define EXCEPTION_SOCKET -1

// Setup server socket. Returns server socket FD
int start_server(int PORT, const char *HOST);

// Accept connection. Returns connection socket FD
int accept_connection(int sockfd);

// Emulates the HOST device
unsigned short io_exchange(unsigned int tx_len, int socketfd);
/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 *
 *   OS IO exchange simulation
 ********************************************************************************/

#ifndef __SIMULATOR_OS_IO
#define __SIMULATOR_OS_IO

/**
 * APDU buffer
 */
#define CHANNEL_APDU 0
#define IO_APDU_BUFFER_SIZE 85
extern unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

/*
 * Sets the server on which io_exchange will perform
 * the IO operations
 * (This *MUST* be set before using io_exchange)
 */
void os_io_set_server(int svr);

/* 
 * This function emulates USB device, writing bytes to tcpsocket instead
 * @arg[in] channel_and_flags   must be CHANNEL_APDU
 * @arg[in] tx                  amount of bytes to transmit to the client
 * @ret                         amount of bytes received from the client
 */
unsigned short io_exchange(unsigned char channel_and_flags,
                           unsigned short tx);

#endif // __SIMULATOR_OS_IO
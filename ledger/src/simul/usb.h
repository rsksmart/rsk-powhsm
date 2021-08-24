/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   USB simulator layer
 ********************************************************************************/

// the global apdu buffer simulation
#define IO_APDU_BUFFER_SIZE (5 + 80)
extern unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

// Reset data pointers to start a new transfter
void resetTransfer();

// This function emulates the HOST device
unsigned short io_exchange(unsigned char channel_and_flags,
                           unsigned char tx_len);

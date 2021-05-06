#ifndef __DEFS
#define __DEFS

// Sizes
#define HASHSIZE 32
#define SEEDSIZE 32
#define KEYLEN 32
#define COMPRESSEDHASHSIZE 16
#define PUBKEYSIZE 65
#define PUBKEYCOMPRESSEDSIZE 33
#define MAX_SIGNATURE_LENGTH 72

// Useful shorthands
#define APDU_OP_OFFSET 2
#define APDU_OP() (G_io_apdu_buffer[APDU_OP_OFFSET])

#define APDU_DATA_OFFSET 3
#define APDU_DATA_SIZE(rx) ((rx) >= APDU_DATA_OFFSET ? (rx)-APDU_DATA_OFFSET : 0)
#define G_apdu_data (&G_io_apdu_buffer[APDU_DATA_OFFSET])

// Number of bytes to transmit for data payload with size s
#define TX_FOR_DATA_SIZE(s) (APDU_DATA_OFFSET + (s))

// Size of data part of the APDU buffer
#define G_apdu_data_size() (sizeof(G_io_apdu_buffer) - APDU_DATA_OFFSET)

#endif
/**
 * APDU buffer related constants and macros
 */

#ifndef APDU_H
#define APDU_H

// CLA for the entire protocol
#define CLA 0x80

// Offsets within APDU buffer
#define TXLEN 3
#define DATA 3
#define OP 2
#define CMDPOS 1
#define CLAPOS 0

// APDU buffer getters
#define APDU_CLA() (G_io_apdu_buffer[CLAPOS])
#define APDU_CMD() (G_io_apdu_buffer[CMDPOS])
#define APDU_OP() (G_io_apdu_buffer[OP])
#define APDU_TXLEN() (G_io_apdu_buffer[TXLEN])
#define APDU_AT(pos) (G_io_apdu_buffer[pos])

// APDU buffer setters
#define SET_APDU_CLA() (G_io_apdu_buffer[CLAPOS] = CLA)
#define SET_APDU_CMD(cmd) (G_io_apdu_buffer[CMDPOS] = (cmd))
#define SET_APDU_OP(op) (G_io_apdu_buffer[OP] = (op))
#define SET_APDU_TXLEN(len) (G_io_apdu_buffer[TXLEN] = (len))
#define SET_APDU_AT(pos, value) (G_io_apdu_buffer[pos] = (value))

// Get pointer to payload within APDU buffer.
// No args, so it can be treated like an array pointer.
#define APDU_DATA_PTR (G_io_apdu_buffer + DATA)

// Total size of APDU data part
#define APDU_TOTAL_DATA_SIZE (sizeof(G_io_apdu_buffer) - DATA)

// Size of payload in APDU
#define APDU_DATA_SIZE(rx) ((rx) >= DATA ? (rx)-DATA : 0)

// Minimum arbitrarily readable APDU bytes
#define MIN_APDU_BYTES 4

// Number of bytes to transmit for data payload with size s
#define TX_FOR_DATA_SIZE(s) (DATA + (s))

// Number of bytes to transmit when sending no data payload
#define TX_NO_DATA() (DATA)

// Number of bytes to transmit when sending only the number of
// bytes to receive in the subsequent tx
#define TX_FOR_TXLEN() (DATA + 1)

#endif
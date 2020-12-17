/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   Local defs
 ********************************************************************************/

#ifndef DEFS_H
#define DEFS_H

#include <stdint.h>

// Ledger commands
#define CLA 0x80
#define INS_SIGN 0x02

#define P1_PATH 0x01
#define P1_BTC 0x02
#define P1_RECEIPT 0x04
#define P1_MERKLEPROOF 0x08
#define P1_LAST 0x80
#define P1_SUCCESS 0x81

#define MAX_USB_TRANSFER 50

// Offsets inside USB Command
#define TXLEN 3
#define DATA 3
#define OP 2
#define CMDPOS 1
#define CLAPOS 0

// Size constants
#define HASHLEN 32
#define KEYLEN 32
#define PATHLEN 21
#define INPUTINDEXLEN 4

// Number of bytes to transmit for data payload with size s
#define TX_FOR_DATA_SIZE(s) (DATA + (s))

// Number of bytes to transmit when sending no data payload
#define TX_NO_DATA() (DATA)

// APDU buffer getters
#define APDU_CLA() (G_io_apdu_buffer[CLAPOS])
#define APDU_CMD() (G_io_apdu_buffer[CMDPOS])
#define APDU_OP() (G_io_apdu_buffer[OP])
#define APDU_TXLEN() (G_io_apdu_buffer[TXLEN])

// APDU buffer stters
#define SET_APDU_CLA(cla) (G_io_apdu_buffer[CLAPOS] = (cla))
#define SET_APDU_CMD(cmd) (G_io_apdu_buffer[CMDPOS] = (cmd))
#define SET_APDU_OP(op) (G_io_apdu_buffer[OP] = (op))
#define SET_APDU_TXLEN(len) (G_io_apdu_buffer[TXLEN] = (len))

// Get pointer to payload within APDU buffer.
// No args, so it can be treated like an array pointer.
#define APDU_DATA_PTR (G_io_apdu_buffer + DATA)

// Size of payload in APDU
#define APDU_DATA_SIZE(rx) ((rx) >= DATA ? (rx)-DATA : 0)

extern unsigned char G_io_apdu_buffer[];

// Parser state machine:
typedef enum {
    S_CMD_START,
    S_TX_HDR,
    S_TX_VARINT,
    S_TX_INPUT_START,
    S_TX_INPUT_READ,
    S_TX_SCRIPT_READ,
    S_TX_INPUT_REMAINING,
    S_TX_REMAINING,
    S_TX_END,
    S_RLP_HDR,
    S_RLP_FIELD,
    S_RLP_FINISH,
    S_MP_START,
    S_MP_NODE_HDR,
    S_MP_NODE_SHARED_PREFIX_HDR,
    S_MP_NODE_SHARED_PREFIX_BODY,
    S_MP_NODE_SHARED_PREFIX_VARINT_HDR,
    S_MP_NODE_SHARED_PREFIX_VARINT_BODY,
    S_MP_NODE_HDR2,
    S_MP_NODE_LEFT,
    S_MP_NODE_LEFT_BYTES,
    S_MP_NODE_RIGHT,
    S_MP_NODE_RIGHT_BYTES,
    S_MP_NODE_CHILDRENSIZE,
    S_MP_NODE_VARINT_HDR,
    S_MP_NODE_VARINT_BODY,
    S_MP_NODE_VALUE,
    S_MP_NODE_VALUE_LEN,
    S_MP_NODE_REMAINING,
    S_SIGN_MESSAGE,
    S_CMD_FINISHED
} PARSE_STM;

// Topic Offsets
#define EXPECTED_TOPIC_BTC_TX_INDEX 2
#define EXPECTED_TOPIC_SIGNATURE_INDEX 1

#ifdef FEDHM_EMULATOR
#define THROW(x) exit(x)
#endif

#endif // DEFS_H

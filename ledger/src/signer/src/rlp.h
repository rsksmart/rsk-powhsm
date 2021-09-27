/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   RLP parser definitions
 ********************************************************************************/
#ifndef RLP_H
#define RLP_H

#include <stdbool.h>

// Shared decoding functions
bool rlpCanDecode(uint8_t *buffer, uint32_t bufferLength, bool *valid);
bool rlpDecodeLength(uint8_t *buffer,
                     uint32_t *fieldLength,
                     uint32_t *offset,
                     bool *list);

// RLP parser State Machine

// Max amount of bytes to transfer
#define RLP_MAX_TRANSFER 50
// Max amount of rlp tree recursion supported
#define MAX_RLP_RECURSION 10
// Max RLP header len
#define MAX_HEADER_LEN 9

// RLP state machine parsing context
typedef struct {
    // RLP position variables
    unsigned int listLevel;  // List level
    unsigned int fieldCount; // Field count inside list

    // Internal parsing
    int listSize[MAX_RLP_RECURSION];      // Current list Size
    int listRemaining[MAX_RLP_RECURSION]; // Current list remaining bytes
    unsigned int remainingFieldBytes; // Remaining bytes in multi-transfer field
    unsigned int currentFieldLength;
    unsigned int offset;
    unsigned char decodeBuffer[MAX_HEADER_LEN]; // RLP Header buffer
    unsigned char decodeOffset;                 // Offset inside header buffer
    // Input validation
    unsigned char expectedRXBytes;
} RLP_CTX;

void SM_RLP_START(RLP_CTX *ctx,
                  PARSE_STM *state,
                  unsigned int rx,
                  unsigned int *tx); // INIT parser
void SM_RLP_FIELD(RLP_CTX *ctx,
                  PARSE_STM *state,
                  unsigned int rx,
                  unsigned int *tx); // parsing field body
void SM_RLP_HDR(RLP_CTX *ctx,
                PARSE_STM *state,
                unsigned int rx,
                unsigned int *tx); // parsing field header
#define DEBUG true
#endif

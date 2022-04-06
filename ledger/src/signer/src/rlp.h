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

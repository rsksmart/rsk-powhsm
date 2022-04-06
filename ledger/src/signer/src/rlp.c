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

#include "os.h"

#include "dbg.h"

#include <stdbool.h>
#include <string.h>
#include "defs.h"
#include "rlp.h"
#include "memutil.h"

#define SET_APDU_FOR_RECEIPT() \
    SET_APDU_CLA();            \
    SET_APDU_CMD(INS_SIGN);    \
    SET_APDU_OP(P1_RECEIPT);

/* Check if enough data to decode a header in buffer. Returns valid if can
 * decode, false if not enough data in buffer */

bool rlpCanDecode(uint8_t *buffer, uint32_t bufferLength, bool *valid) {
    if (*buffer <= 0x7f) {
    } else if (*buffer <= 0xb7) {
    } else if (*buffer <= 0xbf) {
        if (bufferLength < (1 + (*buffer - 0xb7))) {
            return false;
        }
        if (*buffer > 0xbb) {
            *valid = false; // arbitrary 32 bits length limitation
            return true;
        }
    } else if (*buffer <= 0xf7) {
    } else {
        if (bufferLength < (1 + (*buffer - 0xf7))) {
            return false;
        }
        if (*buffer > 0xfb) {
            *valid = false; // arbitrary 32 bits length limitation
            return true;
        }
    }
    *valid = true;
    return true;
}

/* Decode and returns information about a field: Lenght, offset in buffer and
 * wheter field is a list */
bool rlpDecodeLength(uint8_t *buffer,
                     uint32_t *fieldLength,
                     uint32_t *offset,
                     bool *list) {
    if (*buffer <= 0x7f) {
        *offset = 0;
        *fieldLength = 1;
        *list = false;
    } else if (*buffer <= 0xb7) {
        *offset = 1;
        *fieldLength = *buffer - 0x80;
        *list = false;
    } else if (*buffer <= 0xbf) {
        *offset = 1 + (*buffer - 0xb7);
        *list = false;
        switch (*buffer) {
        case 0xb8:
            *fieldLength = *(buffer + 1);
            break;
        case 0xb9:
            *fieldLength = (*(buffer + 1) << 8) + *(buffer + 2);
            break;
        case 0xba:
            *fieldLength =
                (*(buffer + 1) << 16) + (*(buffer + 2) << 8) + *(buffer + 3);
            break;
        case 0xbb:
            *fieldLength = (*(buffer + 1) << 24) + (*(buffer + 2) << 16) +
                           (*(buffer + 3) << 8) + *(buffer + 4);
            break;
        default:
            return false; // arbitrary 32 bits length limitation
        }
    } else if (*buffer <= 0xf7) {
        *offset = 1;
        *fieldLength = *buffer - 0xc0;
        *list = true;
    } else {
        *offset = 1 + (*buffer - 0xf7);
        *list = true;
        switch (*buffer) {
        case 0xf8:
            *fieldLength = *(buffer + 1);
            break;
        case 0xf9:
            *fieldLength = (*(buffer + 1) << 8) + *(buffer + 2);
            break;
        case 0xfa:
            *fieldLength =
                (*(buffer + 1) << 16) + (*(buffer + 2) << 8) + *(buffer + 3);
            break;
        case 0xfb:
            *fieldLength = (*(buffer + 1) << 24) + (*(buffer + 2) << 16) +
                           (*(buffer + 3) << 8) + *(buffer + 4);
            break;
        default:
            return false; // arbitrary 32 bits length limitation
        }
    }

    return true;
}

/* Simulate getting data from USB */
int readData() {
    // Only used in recursive RLP parser.
    return 0;
};

// RLP parser State Machine
//

// parsing field body
void SM_RLP_FIELD(RLP_CTX *ctx,
                  PARSE_STM *state,
                  unsigned int rx,
                  unsigned int *tx) {
    LOG_N_CHARS('\t', ctx->listLevel);
    unsigned char bytesToCopy = rx - 3;
    if (ctx->remainingFieldBytes < bytesToCopy)
        bytesToCopy = ctx->remainingFieldBytes;
    ctx->remainingFieldBytes -= bytesToCopy;
    LOG("[I] Remaining bytes: %d. ", ctx->remainingFieldBytes);
    if (ctx->remainingFieldBytes == 0) { // Field transfer complete
        *state = S_RLP_HDR;
        SET_APDU_TXLEN(1); // Return 1 byte
        LOG("Field complete\n");
        // Check if the current list is completely tranferred
        if (ctx->listLevel > 0) {
            ctx->listRemaining[ctx->listLevel] -= ctx->currentFieldLength;
            while (ctx->listRemaining[ctx->listLevel] == 0) {
                ctx->listLevel--;
                ctx->listRemaining[ctx->listLevel] -=
                    ctx->listSize[ctx->listLevel + 1]; // substract child list
                                                       // size to current list
            }
        }
    } else { // Field incomplete
        LOG("Partial field.\n");
        if (ctx->remainingFieldBytes <= RLP_MAX_TRANSFER)
            SET_APDU_TXLEN(ctx->remainingFieldBytes); // Return whole field
        else
            SET_APDU_TXLEN(RLP_MAX_TRANSFER); // Return whole field
    }
    SET_APDU_FOR_RECEIPT();
    *tx = TX_FOR_DATA_SIZE(1);
}

// parsing field header
void SM_RLP_HDR(RLP_CTX *ctx,
                PARSE_STM *state,
                unsigned int rx,
                unsigned int *tx) {
    bool currentFieldIsList;
    bool valid;
    if (ctx->decodeOffset >= sizeof(ctx->decodeBuffer)) {
        LOG("RLP decode buffer would overflow\n");
        THROW(0x6A8A);
    }
    SAFE_MEMMOVE(ctx->decodeBuffer,
                 sizeof(ctx->decodeBuffer),
                 ctx->decodeOffset,
                 APDU_DATA_PTR,
                 APDU_TOTAL_DATA_SIZE,
                 0,
                 1,
                 THROW(0x6A8A));
    ctx->decodeOffset++;
    ctx->listRemaining[ctx->listLevel] -= 1;
    if (rlpCanDecode(ctx->decodeBuffer, ctx->decodeOffset, &valid)) {
        // Can decode now, if valid
        if (!valid) {
            LOG("RLP pre-decode error\n");
            THROW(0x6A8A);
        } else {
            if (!rlpDecodeLength(ctx->decodeBuffer,
                                 &ctx->currentFieldLength,
                                 &ctx->offset,
                                 &currentFieldIsList)) {
                LOG("RLP decode error\n");
                THROW(0x6A8B);
            }

            LOG_N_CHARS('\t', ctx->listLevel);
            LOG("[I] listDepth: %d currentFieldLenght: %d offset: %d "
                "IsList: %d\n",
                ctx->listLevel,
                ctx->currentFieldLength,
                ctx->offset,
                currentFieldIsList);

            ctx->decodeOffset = 0;
            SET_APDU_FOR_RECEIPT();
            *tx = TX_FOR_TXLEN();
            if (currentFieldIsList) // List field
            {
                if (++ctx->listLevel ==
                    (sizeof(ctx->listSize) / sizeof(ctx->listSize[0])))
                    THROW(0x6A8C); // Max tree depth reached
                ctx->fieldCount = 0;
                ctx->listSize[ctx->listLevel] =
                    ctx->listRemaining[ctx->listLevel] =
                        ctx->currentFieldLength;
                SET_APDU_TXLEN(1); // Return 1 byte
                *state = S_RLP_HDR;
            } else { // Regular field
                ctx->fieldCount++;
                if (ctx->offset == 0) // Single-encoded byte
                {
                    SET_APDU_TXLEN(1); // Return 1 byte
                    *state = S_RLP_HDR;
                } else {
                    if (ctx->currentFieldLength <= RLP_MAX_TRANSFER)
                        SET_APDU_TXLEN(
                            ctx->currentFieldLength); // Return whole field
                    else
                        SET_APDU_TXLEN(
                            RLP_MAX_TRANSFER); // Return max amount possible
                    ctx->remainingFieldBytes = ctx->currentFieldLength;
                    *state = S_RLP_FIELD;
                }
            }
        }
    } else // cannot decode
    {
        SET_APDU_FOR_RECEIPT();
        SET_APDU_TXLEN(1); // Return 1 additional byte until we can decode
        *tx = TX_FOR_DATA_SIZE(1);
    }
}

// INIT parser
void SM_RLP_START(RLP_CTX *ctx,
                  PARSE_STM *state,
                  unsigned int rx,
                  unsigned int *tx) {
    LOG("[I] Starting RLP parsing\n");

    memset(ctx, 0, sizeof(RLP_CTX));
    SET_APDU_FOR_RECEIPT();
    SET_APDU_TXLEN(1); // Return TXLen + Version + in-counter
    *tx = TX_FOR_DATA_SIZE(1);
    *state = S_RLP_HDR;
}

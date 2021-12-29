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

#include <stdint.h>
#include <string.h>

#include "btcscript.h"

#include "svarint.h"

// Context pointer
static btcscript_ctx_t *ctx;

/*
 * Initialize the parser.
 *
 * @arg[in] ctx         the context to be used for this session
 * @arg[in] cb          the callback to be used for this session
 * @arg[in] script_size the total script size in bytes
 */
void btcscript_init(btcscript_ctx_t *_ctx,
                    btcscript_cb_t _cb,
                    uint32_t script_size) {
    ctx = _ctx;
    memset(ctx, 0, sizeof(btcscript_ctx_t));
    ctx->state = BTCSCRIPT_ST_OPCODE;
    ctx->callback = _cb;
    ctx->bytes_remaining = script_size;
}

/*
 * Tell whether parsing is finished, and
 * whether it triggered an error (and which one)
 * This should be checked after every call to btcscript_consume
 */
int8_t btcscript_result() {
    if (ctx->state < 0 || ctx->state == BTCSCRIPT_ST_DONE)
        return ctx->state;
    return BTCSCRIPT_ERR_NONE;
}

/*
 * Consume a chunk of bytes.
 *
 * @arg[in] buf: buffer holding bytes to be consumed
 * @arg[in] len: number of bytes to consume in buffer
 *
 * @return the number of bytes actually read and processed
 */
uint8_t btcscript_consume(uint8_t *buf, const uint8_t len) {
    for (uint8_t i = 0; i < len; i++) {
        ctx->bytes_remaining--;
        switch (ctx->state) {
        case BTCSCRIPT_ST_OPCODE:
            ctx->opcode = buf[i];
            // Push only - taken from
            // https://github.com/bitcoin/bitcoin/blob/v0.20.2/src/script/script.cpp#L242
            if (ctx->opcode > BTCSCRIPT_OP_16) {
                ctx->state = BTCSCRIPT_ERR_INVALID;
                return i + 1;
            }

            // Taken from
            // https://github.com/bitcoin/bitcoin/blob/v0.20.2/src/script/script.cpp#L278
            if (ctx->opcode > BTCSCRIPT_OP_0 &&
                ctx->opcode < BTCSCRIPT_OP_PUSHDATA1) {
                ctx->operand_size = ctx->opcode;
                ctx->callback(BTCSCRIPT_EV_OPCODE);
                ctx->state = BTCSCRIPT_ST_OPERAND;
            } else if (ctx->opcode == BTCSCRIPT_OP_0 ||
                       ctx->opcode >= BTCSCRIPT_OP_1NEGATE) {
                ctx->operand_size = 0;
                ctx->callback(BTCSCRIPT_EV_OPCODE);
            } else { // OP_PUSHDATA{1,2,4}
                ctx->operand_size = 0;
                ctx->size_offset = 0;
                ctx->state = BTCSCRIPT_ST_OPERAND_SIZE;
            }
            break;
        case BTCSCRIPT_ST_OPERAND_SIZE:
            ctx->operand_size += buf[i] << (8 * ctx->size_offset++);
            if ((ctx->opcode == BTCSCRIPT_OP_PUSHDATA1 &&
                 ctx->size_offset == 1) ||
                (ctx->opcode == BTCSCRIPT_OP_PUSHDATA2 &&
                 ctx->size_offset == 2) ||
                (ctx->opcode == BTCSCRIPT_OP_PUSHDATA4 &&
                 ctx->size_offset == 4)) {
                ctx->callback(BTCSCRIPT_EV_OPCODE);
                ctx->state = BTCSCRIPT_ST_OPERAND;
            }
            break;
        case BTCSCRIPT_ST_OPERAND:
            ctx->operand_byte = buf[i];
            ctx->callback(BTCSCRIPT_EV_OPERAND);
            if (!--ctx->operand_size) {
                ctx->callback(BTCSCRIPT_EV_OPERAND_END);
                ctx->state = BTCSCRIPT_ST_OPCODE;
            }
            break;
        default:
            return 0;
        }

        if (!ctx->bytes_remaining) {
            if (ctx->state == BTCSCRIPT_ST_OPCODE) {
                ctx->state = BTCSCRIPT_ST_DONE;
            } else {
                ctx->state = BTCSCRIPT_ERR_INVALID;
            }
            return i + 1;
        }
    }

    return len;
}

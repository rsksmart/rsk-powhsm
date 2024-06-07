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

#include "btctx.h"
#include "memutil.h"

#include "svarint.h"

// Context pointer
static btctx_ctx_t *ctx;

/*
 * Initialize the parser.
 *
 * @arg[in] ctx the context to be used for this session
 *          (should have its callback set)
 */
void btctx_init(btctx_ctx_t *_ctx, btctx_cb_t _cb) {
    ctx = _ctx;
    memset(ctx, 0, sizeof(btctx_ctx_t));
    ctx->state = BTCTX_ST_VERSION;
    ctx->callback = _cb;
}

/*
 * Tell whether parsing is finished, and
 * whether it triggered an error (and which one)
 * This should be checked after every call to btctx_consume
 */
int8_t btctx_result() {
    if (ctx->state < 0 || ctx->state == BTCTX_ST_DONE)
        return ctx->state;
    return BTCTX_ERR_NONE;
}

/*
 * Consume a chunk of bytes.
 *
 * @arg[in] buf: buffer holding bytes to be consumed
 * @arg[in] len: number of bytes to consume in buffer
 *
 * @return the number of bytes actually read and processed
 */
uint8_t btctx_consume(uint8_t *buf, const uint8_t len) {
    uint8_t processed;

    for (uint8_t i = 0; i < len; i++) {
        switch (ctx->state) {
        case BTCTX_ST_VERSION:
            // Read little endian TX version
            ctx->raw[ctx->offset] = buf[i];
            ctx->parsed.version += (uint32_t)buf[i] << (8 * ctx->offset++);
            if (ctx->offset == BTCTX_VERSION_SIZE) {
                ctx->raw_size = BTCTX_VERSION_SIZE;
                ctx->callback(BTCTX_EV_VERSION);
                ctx->state = BTCTX_ST_VIN_COUNT;
                svarint_init(&ctx->parsed.varint);
            }
            break;
        case BTCTX_ST_VIN_COUNT:
        case BTCTX_ST_VOUT_COUNT:
        case BTCTX_ST_VIN_SLENGTH:
        case BTCTX_ST_VOUT_SLENGTH:
            if (svarint_notstarted())
                ctx->raw_size = 0;
            processed = svarint_consume(buf + i, len - i);
            SAFE_MEMMOVE(ctx->raw,
                         sizeof(ctx->raw),
                         ctx->raw_size,
                         buf,
                         len,
                         i,
                         processed,
                         {
                             ctx->state = BTCTX_ERR_INVALID;
                             return processed;
                         });
            ctx->raw_size += processed;
            i += processed - 1;

            switch (svarint_result()) {
            case SVARINT_ERR_NONE:
                break;
            case SVARINT_ST_DONE:
                switch (ctx->state) {
                case BTCTX_ST_VIN_COUNT:
                    ctx->callback(BTCTX_EV_VIN_COUNT);
                    ctx->inout_total = ctx->parsed.varint.value;
                    ctx->inout_current = 0;
                    ctx->state = BTCTX_ST_VIN_TXH;
                    ctx->offset = 0;
                    break;
                case BTCTX_ST_VOUT_COUNT:
                    ctx->callback(BTCTX_EV_VOUT_COUNT);
                    ctx->inout_total = ctx->parsed.varint.value;
                    ctx->inout_current = 0;
                    ctx->state = BTCTX_ST_VOUT_VALUE;
                    ctx->offset = 0;
                    break;
                case BTCTX_ST_VIN_SLENGTH:
                    ctx->callback(BTCTX_EV_VIN_SLENGTH);
                    ctx->state = BTCTX_ST_VIN_SCRIPT;
                    ctx->script_remaining = ctx->parsed.varint.value;
                    break;
                case BTCTX_ST_VOUT_SLENGTH:
                    ctx->callback(BTCTX_EV_VOUT_SLENGTH);
                    ctx->state = BTCTX_ST_VOUT_SCRIPT;
                    ctx->script_remaining = ctx->parsed.varint.value;
                    break;
                }
                break;
            case SVARINT_ERR_UNSUPPORTED:
                ctx->state = BTCTX_ERR_UNSUPPORTED;
                return i + 1;
            case SVARINT_ERR_INVALID:
            default:
                ctx->state = BTCTX_ERR_INVALID;
                return i + 1;
            }

            break;
        case BTCTX_ST_VIN_TXH:
            if (ctx->offset == 0) {
                ctx->raw_size = 0;
                ctx->callback(BTCTX_EV_VIN_TXH_START);
            }
            ctx->parsed.value = ctx->raw[0] = buf[i];
            ctx->raw_size = 1;
            ctx->callback(BTCTX_EV_VIN_TXH_DATA);
            if (++ctx->offset == BTCTX_HASH_SIZE) {
                ctx->raw_size = 0;
                ctx->callback(BTCTX_EV_VIN_TXH_END);
                ctx->state = BTCTX_ST_VIN_TXIX;
                ctx->offset = 0;
            }
            break;
        case BTCTX_ST_VIN_TXIX:
            if (ctx->offset == 0)
                ctx->parsed.ptxo_index = 0;
            ctx->raw[ctx->offset] = buf[i];
            ctx->parsed.ptxo_index += (uint32_t)buf[i] << (8 * ctx->offset++);
            if (ctx->offset == BTCTX_INPUT_INDEX_SIZE) {
                ctx->raw_size = BTCTX_INPUT_INDEX_SIZE;
                ctx->callback(BTCTX_EV_VIN_TXIX);
                ctx->state = BTCTX_ST_VIN_SLENGTH;
                svarint_init(&ctx->parsed.varint);
            }
            break;
        case BTCTX_ST_VIN_SCRIPT:
        case BTCTX_ST_VOUT_SCRIPT:
            ctx->parsed.value = ctx->raw[0] = buf[i];
            ctx->raw_size = 1;
            ctx->script_remaining--;
            ctx->callback(ctx->state == BTCTX_ST_VIN_SCRIPT
                              ? BTCTX_EV_VIN_SCRIPT_DATA
                              : BTCTX_EV_VOUT_SCRIPT_DATA);
            if (ctx->script_remaining == 0) {
                if (ctx->state == BTCTX_ST_VIN_SCRIPT) {
                    ctx->state = BTCTX_ST_VIN_SEQNO;
                } else {
                    ctx->state = ++ctx->inout_current == ctx->inout_total
                                     ? BTCTX_ST_LOCK_TIME
                                     : BTCTX_ST_VOUT_VALUE;
                }
                ctx->offset = 0;
            }
            break;
        case BTCTX_ST_VIN_SEQNO:
            if (ctx->offset == 0)
                ctx->parsed.seqno = 0;
            ctx->raw[ctx->offset] = buf[i];
            ctx->parsed.seqno += (uint32_t)buf[i] << (8 * ctx->offset++);
            if (ctx->offset == BTCTX_INPUT_SEQNO_SIZE) {
                ctx->raw_size = BTCTX_INPUT_SEQNO_SIZE;
                ctx->callback(BTCTX_EV_VIN_SEQNO);
                if (++ctx->inout_current == ctx->inout_total) {
                    ctx->state = BTCTX_ST_VOUT_COUNT;
                    svarint_init(&ctx->parsed.varint);
                } else {
                    ctx->state = BTCTX_ST_VIN_TXH;
                    ctx->offset = 0;
                }
            }
            break;
        case BTCTX_ST_VOUT_VALUE:
            if (ctx->offset == 0)
                ctx->parsed.vout_value = 0L;
            ctx->raw[ctx->offset] = buf[i];
            ctx->parsed.vout_value += (uint64_t)buf[i] << 8 * ctx->offset++;
            if (ctx->offset == BTCTX_OUTPUT_VALUE_SIZE) {
                ctx->raw_size = BTCTX_OUTPUT_VALUE_SIZE;
                ctx->callback(BTCTX_EV_VOUT_VALUE);
                ctx->state = BTCTX_ST_VOUT_SLENGTH;
                svarint_init(&ctx->parsed.varint);
            }
            break;
        case BTCTX_ST_LOCK_TIME:
            if (ctx->offset == 0)
                ctx->parsed.locktime = 0;
            ctx->raw[ctx->offset] = buf[i];
            ctx->parsed.locktime += (uint32_t)buf[i] << (8 * ctx->offset++);
            if (ctx->offset == BTCTX_LOCKTIME_SIZE) {
                ctx->raw_size = BTCTX_LOCKTIME_SIZE;
                ctx->callback(BTCTX_EV_LOCKTIME);
                ctx->state = BTCTX_ST_DONE;
                return i + 1;
            }
            break;
        default:
            return 0;
        }
    }

    return len;
}

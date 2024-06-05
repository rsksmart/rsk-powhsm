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
#include "memutil.h"

#include "trie.h"
#include "svarint.h"
#include "util.h"

// Context pointer
static trie_ctx_t *ctx;

/*
 * Initialize the parser.
 *
 * @arg[in] ctx the context to be used for this session
 * @arg[in] cb  the callback to be used for this session
 * @arg[in] length  the length of the node in bytes
 */
void trie_init(trie_ctx_t *_ctx, trie_cb_t _cb, uint32_t length) {
    ctx = _ctx;
    memset(ctx, 0, sizeof(trie_ctx_t));
    ctx->state = TRIE_ST_FLAGS;
    ctx->callback = _cb;
    ctx->remaining_bytes = length;
}

/*
 * Tell whether parsing is finished, and
 * whether it triggered an error (and which one)
 * This should be checked after every call to trie_consume
 */
int8_t trie_result() {
    if (ctx->state < 0 || ctx->state == TRIE_ST_DONE)
        return ctx->state;
    return TRIE_ERR_NONE;
}

#define NEXT_STATE()                                           \
    {                                                          \
        if (ctx->state < TRIE_ST_SHARED_PREFIX_LENGTH &&       \
            TRIE_FG_SHARED_PREFIX_PRESENT(ctx->flags)) {       \
            ctx->state = TRIE_ST_SHARED_PREFIX_LENGTH;         \
        } else if (ctx->state < TRIE_ST_LEFT_NODE &&           \
                   TRIE_FG_NODE_PRESENT_LEFT(ctx->flags)) {    \
            ctx->offset = 0;                                   \
            if (TRIE_FG_NODE_IS_EMBEDDED_LEFT(ctx->flags))     \
                ctx->state = TRIE_ST_LEFT_NODE_EMBEDDED;       \
            else                                               \
                ctx->state = TRIE_ST_LEFT_NODE;                \
        } else if (ctx->state < TRIE_ST_RIGHT_NODE &&          \
                   TRIE_FG_NODE_PRESENT_RIGHT(ctx->flags)) {   \
            ctx->offset = 0;                                   \
            if (TRIE_FG_NODE_IS_EMBEDDED_RIGHT(ctx->flags))    \
                ctx->state = TRIE_ST_RIGHT_NODE_EMBEDDED;      \
            else                                               \
                ctx->state = TRIE_ST_RIGHT_NODE;               \
        } else if (ctx->state < TRIE_ST_CHILDREN_SIZE &&       \
                   (TRIE_FG_NODE_PRESENT_LEFT(ctx->flags) ||   \
                    TRIE_FG_NODE_PRESENT_RIGHT(ctx->flags))) { \
            svarint_init(&ctx->varint);                        \
            ctx->state = TRIE_ST_CHILDREN_SIZE;                \
        } else if (ctx->state < TRIE_ST_VALUE) {               \
            ctx->offset = 0;                                   \
            if (TRIE_FG_HAS_LONG_VALUE(ctx->flags))            \
                ctx->state = TRIE_ST_LONG_VALUE;               \
            else if (ctx->remaining_bytes == 0) {              \
                ctx->state = TRIE_ERR_INVALID;                 \
                return i + 1;                                  \
            } else                                             \
                ctx->state = TRIE_ST_VALUE;                    \
        } else {                                               \
            ctx->state = TRIE_ERR_INVALID;                     \
            return i + 1;                                      \
        }                                                      \
    }

#define SHARED_PREFIX_TO_BYTES() \
    { ctx->length = (ctx->length - 1) / 8 + 1; }

/*
 * Consume a chunk of bytes.
 *
 * @arg[in] buf: buffer holding bytes to be consumed
 * @arg[in] len: number of bytes to consume in buffer
 *
 * @return the number of bytes actually read and processed
 */
uint8_t trie_consume(uint8_t *buf, const uint8_t len) {
    uint8_t processed;

    for (uint8_t i = 0; i < len; i++) {
        switch (ctx->state) {
        case TRIE_ST_FLAGS:
            ctx->raw[0] = buf[i];
            ctx->raw_size = 1;
            --ctx->remaining_bytes;
            ctx->flags = buf[i];
            ctx->callback(TRIE_EV_FLAGS);
            NEXT_STATE();
            break;
        case TRIE_ST_SHARED_PREFIX_LENGTH:
            ctx->raw[0] = buf[i];
            ctx->raw_size = 1;
            --ctx->remaining_bytes;
            ctx->state = TRIE_ST_SHARED_PREFIX;
            if (buf[i] >= 0 && buf[i] <= 31) {
                ctx->length = buf[i] + 1;
                ctx->callback(TRIE_EV_SHARED_PREFIX_LENGTH);
                SHARED_PREFIX_TO_BYTES();
            } else if (buf[i] >= 32 && buf[i] <= 254) {
                ctx->length = buf[i] + 128;
                ctx->callback(TRIE_EV_SHARED_PREFIX_LENGTH);
                SHARED_PREFIX_TO_BYTES();
            } else {
                ctx->state = TRIE_ST_SHARED_PREFIX_LENGTH_VAR;
                svarint_init(&ctx->varint);
            }
            break;
        case TRIE_ST_SHARED_PREFIX_LENGTH_VAR:
            processed = svarint_consume(buf + i, len - i);
            SAFE_MEMMOVE(ctx->raw,
                         sizeof(ctx->raw),
                         ctx->raw_size,
                         buf,
                         len,
                         i,
                         processed,
                         {
                             ctx->state = TRIE_ERR_INVALID;
                             return processed;
                         });
            ctx->raw_size += processed;
            i += processed - 1;
            ctx->remaining_bytes -= processed;

            switch (svarint_result()) {
            case SVARINT_ST_DONE:
                ctx->length = ctx->varint.value;
                ctx->callback(TRIE_EV_SHARED_PREFIX_LENGTH);
                SHARED_PREFIX_TO_BYTES();
                ctx->state = TRIE_ST_SHARED_PREFIX;
                break;
            case SVARINT_ERR_UNSUPPORTED:
                ctx->state = TRIE_ERR_UNSUPPORTED;
                return i + 1;
            case SVARINT_ERR_INVALID:
                ctx->state = TRIE_ERR_INVALID;
                return i + 1;
            }
            break;
        case TRIE_ST_SHARED_PREFIX:
            ctx->raw_size = 1;
            ctx->raw[0] = buf[i];
            --ctx->remaining_bytes;
            ctx->callback(TRIE_EV_SHARED_PREFIX);
            if (--ctx->length == 0) {
                NEXT_STATE();
            }
            break;
        case TRIE_ST_LEFT_NODE:
        case TRIE_ST_RIGHT_NODE:
            if (ctx->offset == 0) {
                ctx->raw_size = 0;
                ctx->callback(ctx->state == TRIE_ST_LEFT_NODE
                                  ? TRIE_EV_LEFT_NODE_START
                                  : TRIE_EV_RIGHT_NODE_START);
            }
            ctx->raw[0] = buf[i];
            ctx->raw_size = 1;
            --ctx->remaining_bytes;
            ctx->callback(ctx->state == TRIE_ST_LEFT_NODE
                              ? TRIE_EV_LEFT_NODE_DATA
                              : TRIE_EV_RIGHT_NODE_DATA);
            if (++ctx->offset == NON_EMBEDDED_NODE_SIZE) {
                ctx->raw_size = 0;
                ctx->callback(ctx->state == TRIE_ST_LEFT_NODE
                                  ? TRIE_EV_LEFT_NODE_END
                                  : TRIE_EV_RIGHT_NODE_END);
                NEXT_STATE();
            }
            break;
        case TRIE_ST_LEFT_NODE_EMBEDDED:
        case TRIE_ST_RIGHT_NODE_EMBEDDED:
            ctx->raw[0] = buf[i];
            ctx->raw_size = 1;
            --ctx->remaining_bytes;
            if (ctx->offset == 0) {
                ctx->offset = MIN(buf[i], MAX_EMBEDDED_SIZE);
                ctx->length = (uint32_t)ctx->offset;
                ctx->callback(ctx->state == TRIE_ST_LEFT_NODE_EMBEDDED
                                  ? TRIE_EV_LEFT_NODE_EMBEDDED_START
                                  : TRIE_EV_RIGHT_NODE_EMBEDDED_START);
            } else {
                ctx->callback(ctx->state == TRIE_ST_LEFT_NODE_EMBEDDED
                                  ? TRIE_EV_LEFT_NODE_EMBEDDED_DATA
                                  : TRIE_EV_RIGHT_NODE_EMBEDDED_DATA);
                if (--ctx->offset == 0) {
                    ctx->raw_size = 0;
                    ctx->callback(ctx->state == TRIE_ST_LEFT_NODE_EMBEDDED
                                      ? TRIE_EV_LEFT_NODE_EMBEDDED_END
                                      : TRIE_EV_RIGHT_NODE_EMBEDDED_END);
                    NEXT_STATE();
                }
            }
            break;
        case TRIE_ST_CHILDREN_SIZE:
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
                             ctx->state = TRIE_ERR_INVALID;
                             return processed;
                         });
            ctx->raw_size += processed;
            i += processed - 1;
            ctx->remaining_bytes -= processed;

            switch (svarint_result()) {
            case SVARINT_ST_DONE:
                ctx->children_size = ctx->varint.value;
                ctx->callback(TRIE_EV_CHILDREN_SIZE);
                if (ctx->remaining_bytes == 0 &&
                    !TRIE_FG_HAS_LONG_VALUE(ctx->flags)) {
                    ctx->state = TRIE_ST_DONE;
                    return i + 1;
                } else {
                    NEXT_STATE();
                }
                break;
            case SVARINT_ERR_UNSUPPORTED:
                ctx->state = TRIE_ERR_UNSUPPORTED;
                return i + 1;
            case SVARINT_ERR_INVALID:
                ctx->state = TRIE_ERR_INVALID;
                return i + 1;
            }
            break;
        case TRIE_ST_VALUE:
            if (ctx->offset == 0)
                ctx->callback(TRIE_EV_VALUE_START);
            ctx->raw[0] = buf[i];
            ctx->raw_size = 1;
            --ctx->remaining_bytes;
            ++ctx->offset;
            ctx->callback(TRIE_EV_VALUE_DATA);
            if (ctx->remaining_bytes == 0) {
                ctx->callback(TRIE_EV_VALUE_END);
                ctx->state = TRIE_ST_DONE;
                return i + 1;
            }
            break;
        case TRIE_ST_LONG_VALUE:
            --ctx->remaining_bytes;
            if (ctx->offset == 0) {
                ctx->raw_size = 0;
                ctx->callback(TRIE_EV_VALUE_HASH_START);
            }
            if (ctx->offset < VALUE_HASH_SIZE) {
                ctx->raw[0] = buf[i];
                ctx->raw_size = 1;
                ctx->callback(TRIE_EV_VALUE_HASH_DATA);
                ++ctx->offset;
                ctx->value_size = 0;
                ctx->raw_size = 0;
            } else {
                ctx->value_size = (ctx->value_size << 8) + buf[i];
                ctx->raw[ctx->raw_size++] = buf[i];
                if (++ctx->offset == VALUE_HASH_SIZE + VALUE_LENGTH_SIZE) {
                    ctx->callback(TRIE_EV_VALUE_HASH_END);
                    ctx->state = ctx->remaining_bytes == 0 ? TRIE_ST_DONE
                                                           : TRIE_ERR_INVALID;
                    return i + 1;
                }
            }
            break;
        default:
            return 0;
        }
    }

    return len;
}

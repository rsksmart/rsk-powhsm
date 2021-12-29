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

#include <stddef.h>
#include <stdint.h>

#include "srlp.h"

#include "os.h"

#include "dbg.h"

// This code tinkers with function pointers referenced from
// const data structures, so we need to use the PIC macro.
// See:
// https://ledger.readthedocs.io/en/latest/userspace/memory.html?highlight=PIC#pic-and-model-implications

// Parser state is modeled as a stack of context items of the form:
//
//  { state, size, cursor }, where:
//
//  - state: signals what the parser is currently parsing
//  - size: size in bytes of the structure being parsed
//  - cursor: number of bytes consumed for the structure being parsed
//
// At the bottom of the stack there's always a mark used to prevent a
// stack underflow. The stack size is limited to MAX_RLP_CTX_DEPTH
// items (see srlp.h).

// Context item stack and stack pointer
static uint8_t rlp_ctx_ptr;
static rlp_ctx_t rlp_ctx[MAX_RLP_CTX_DEPTH + 1];

// Pointer to the beginning of the next chunk to report
static uint8_t* rlp_frame_start;

// User callbacks
static const rlp_callbacks_t* rlp_callbacks;

/*
 * Initialize the parser.
 *
 * @arg[in] cbs struct holding callbacks to be called by the parser
 */
void rlp_start(const rlp_callbacks_t* cbs) {
    rlp_callbacks = cbs;
    rlp_ctx_ptr = 0;
    rlp_ctx[rlp_ctx_ptr].state = RLP_BOTTOM;
}

// Notify the user about a trivial bytearray (length = 0 or 1).
// Defined as a macro to save stack space.
#define TRIVIAL_BYTEARRAY(bytearray, len)                                      \
    {                                                                          \
        ((rlp_start_cb_t)PIC(rlp_callbacks->bytearray_start))(len);            \
        ((rlp_chunk_cb_t)PIC(rlp_callbacks->bytearray_chunk))(bytearray, len); \
        ((rlp_end_cb_t)PIC(rlp_callbacks->bytearray_end))();                   \
    }

// Push a context item to the stack. Defined as a macro to save stack.
// NOTE: Returns if stack overflow.
//
//   @arg st state of context item to push
//   @arg sz size in bytes of the item top parse
//
#define RLP_PUSH_CTX(st, sz)                    \
    {                                           \
        if (rlp_ctx_ptr == MAX_RLP_CTX_DEPTH) { \
            return RLP_STACK_OVERFLOW;          \
        }                                       \
        ++rlp_ctx_ptr;                          \
        rlp_ctx[rlp_ctx_ptr].state = (st);      \
        rlp_ctx[rlp_ctx_ptr].size = (sz);       \
        rlp_ctx[rlp_ctx_ptr].cursor = 0;        \
    }

// Pop current context. Defined as a macro to save stack space.
// NOTE: Returns if stack underflow.
//
#define RLP_POP_CTX()                                            \
    {                                                            \
        if (rlp_ctx_ptr == 0) {                                  \
            return RLP_STACK_UNDERFLOW;                          \
        }                                                        \
        rlp_state_t state = rlp_ctx[rlp_ctx_ptr].state;          \
        if (state == RLP_LIST) {                                 \
            ((rlp_end_cb_t)PIC(rlp_callbacks->list_end))();      \
        } else if (state == RLP_STR) {                           \
            ((rlp_end_cb_t)PIC(rlp_callbacks->bytearray_end))(); \
        }                                                        \
        --rlp_ctx_ptr;                                           \
    }

// Called for every consumed byte of the input buffer. Traverse stack from
// top to bottom, incrementing the number of consumed bytes for each list
// context.
// If consumed bytes reaches list size on the top context, pop it.
// If consumed bytes reaches list size on a non-top context, fail due to
// inconsistency.
//
// Defined as a macro to save stack.
// NOTE: Returns if stack underflow
//
#define RLP_UPDATE_LISTS()                                    \
    {                                                         \
        int __ix;                                             \
        for (__ix = rlp_ctx_ptr; __ix >= 0; --__ix) {         \
            if (rlp_ctx[__ix].state != RLP_LIST) {            \
                continue;                                     \
            }                                                 \
            ++rlp_ctx[__ix].cursor;                           \
            if (rlp_ctx[__ix].cursor == rlp_ctx[__ix].size) { \
                if (__ix == rlp_ctx_ptr) {                    \
                    RLP_POP_CTX();                            \
                } else {                                      \
                    return RLP_MALFORMED;                     \
                }                                             \
            }                                                 \
        }                                                     \
    }

// Handle beginning of list. Defined as  a macro to save stack space.
#define HANDLE_RLP_LIST(b)                                                    \
    {                                                                         \
        if (*b <= 0x7F) {                                                     \
            TRIVIAL_BYTEARRAY(rlp_frame_start, 1);                            \
        } else if (*b == 0x80) {                                              \
            TRIVIAL_BYTEARRAY(rlp_frame_start, 0);                            \
        } else if (*b <= 0xB7) {                                              \
            RLP_PUSH_CTX(RLP_STR, *b - 0x80);                                 \
            ((rlp_start_cb_t)PIC(rlp_callbacks->bytearray_start))(*b - 0x80); \
        } else if (*b <= 0xBF) {                                              \
            if (*b - 0xB7 > sizeof(uint16_t)) {                               \
                return RLP_TOO_LONG;                                          \
            }                                                                 \
            RLP_PUSH_CTX(RLP_STR_LEN, *b - 0xB7);                             \
        } else if (*b <= 0xF7) {                                              \
            RLP_PUSH_CTX(RLP_LIST, *b - 0xC0 + 1);                            \
            ((rlp_start_cb_t)PIC(rlp_callbacks->list_start))(*b - 0xC0);      \
        } else {                                                              \
            if (*b - 0xF7 > sizeof(uint16_t)) {                               \
                return RLP_TOO_LONG;                                          \
            }                                                                 \
            RLP_PUSH_CTX(RLP_LIST_LEN, *b - 0xF7);                            \
        }                                                                     \
        rlp_frame_start = b + 1;                                              \
    }

// Handle beginning of byte array. Defined as a macero to save space.
#define HANDLE_RLP_STR(b)                                               \
    {                                                                   \
        ++rlp_ctx[rlp_ctx_ptr].cursor;                                  \
        if (rlp_ctx[rlp_ctx_ptr].size == rlp_ctx[rlp_ctx_ptr].cursor) { \
            ((rlp_chunk_cb_t)PIC(rlp_callbacks->bytearray_chunk))(      \
                rlp_frame_start, b - rlp_frame_start + 1);              \
            RLP_POP_CTX();                                              \
            rlp_frame_start = b + 1;                                    \
        }                                                               \
    }

/*
 * Consume a chunk of bytes.
 *
 * @arg[in] buf: buffer holdoing bytes to be consumed
 * @arg[in] len: number of bytes to consume in buffer
 *
 * @return
 *    RLP_OK if bytes were consumed successfully
 *    RLP_TOO_LONG if len greater than RLP_BUFFER_SIZE
 *    RLP_STACK_OVERFLOW if list nesting level is greater than MAX_RLP_CTX_DEPTH
 *    RLP_STACK_UNDERFLOW if RLP to parse is ill-formed (e.g., [[a])
 *    RLP_MALFORMED if RLP to parse is ill-formed wrt reported sizes
 */
int rlp_consume(uint8_t* buf, const uint8_t len) {
    if (len > RLP_BUFFER_SIZE) {
        return RLP_TOO_LONG;
    }

    rlp_frame_start = buf;
    for (uint8_t i = 0; i < len; ++i) {
        uint8_t* b = buf + i;

        LOG_SRLP_CTX(*b, rlp_ctx, rlp_ctx_ptr);

        switch (rlp_ctx[rlp_ctx_ptr].state) {
        case RLP_BOTTOM:
        case RLP_LIST:
            HANDLE_RLP_LIST(b);
            break;
        case RLP_LIST_LEN:
            if (rlp_ctx[rlp_ctx_ptr].size == 0) {
                rlp_ctx[rlp_ctx_ptr].state = RLP_LIST;
                rlp_ctx[rlp_ctx_ptr].size = rlp_ctx[rlp_ctx_ptr].cursor;
                rlp_ctx[rlp_ctx_ptr].cursor = 0;
                rlp_frame_start = b;
                ((rlp_start_cb_t)PIC(rlp_callbacks->list_start))(
                    rlp_ctx[rlp_ctx_ptr].size);
                HANDLE_RLP_LIST(b);
            } else {
                rlp_ctx[rlp_ctx_ptr].size -= 1;
                rlp_ctx[rlp_ctx_ptr].cursor =
                    (rlp_ctx[rlp_ctx_ptr].cursor << 8) | *b;
            }
            break;
        case RLP_STR:
            HANDLE_RLP_STR(b);
            break;
        case RLP_STR_LEN:
            if (rlp_ctx[rlp_ctx_ptr].size == 0) {
                rlp_ctx[rlp_ctx_ptr].state = RLP_STR;
                rlp_ctx[rlp_ctx_ptr].size = rlp_ctx[rlp_ctx_ptr].cursor;
                rlp_ctx[rlp_ctx_ptr].cursor = 0;
                rlp_frame_start = b;
                ((rlp_start_cb_t)PIC(rlp_callbacks->bytearray_start))(
                    rlp_ctx[rlp_ctx_ptr].size);
                HANDLE_RLP_STR(b);
            } else {
                rlp_ctx[rlp_ctx_ptr].size -= 1;
                rlp_ctx[rlp_ctx_ptr].cursor =
                    (rlp_ctx[rlp_ctx_ptr].cursor << 8) | *b;
            }
            break;
        }

        // Increment consumed bytes for all lists in the context
        RLP_UPDATE_LISTS();
    }

    // If the item being parsed is a byte array, notify about the seen chunk.
    if (rlp_ctx[rlp_ctx_ptr].state == RLP_STR) {
        ((rlp_chunk_cb_t)PIC(rlp_callbacks->bytearray_chunk))(
            rlp_frame_start, buf + len - rlp_frame_start);
    }

    return RLP_OK;
}

/*
 * Guess the length in bytes of the RLP prefix for str of the given size.
 *
 * NOTE: This guessing because for single byte strings we need the str
 * value to determine accurately. For single byte strings, this method
 * always return one. It's up to the caller to take this into account.
 *
 * @arg[in] str_size string size
 */
uint8_t guess_rlp_str_prefix_size(uint16_t str_size) {
    if (str_size == 0)
        return 1;
    else if (str_size == 1)
        // Guessing happens here: we should return zero if
        // the string's single byte is less or equals 0x7F.
        return 1;
    else if (str_size <= 55)
        return 1;
    else {
        uint8_t n;
        for (n = 0; str_size != 0; str_size >>= 8, ++n)
            ;
        return n + 1;
    }
}

/*
 * Get the length in bytes of the (minimal) RLP prefix for a list of the
 * given size (max size for any given list is 2^16-1 in this
 * implementation)
 *
 * @arg[in] list_size list size
 */
uint8_t rlp_list_prefix_size(uint16_t list_size) {
    if (list_size <= 55)
        return 1;

    uint8_t n;
    for (n = 0; list_size != 0; list_size >>= 8, ++n)
        ;
    return n + 1;
}

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

#ifndef __BC_ANCESTOR_H
#define __BC_ANCESTOR_H

/*
 * Blockchain update ancestor protocol definitions. These messages
 * define the protocol for updating the ancestor block.
 */

// Operation selectors for update ancestor protocol
typedef enum {
    OP_UPD_ANCESTOR_INIT = 0x02,
    OP_UPD_ANCESTOR_HEADER_META = 0x03,
    OP_UPD_ANCESTOR_HEADER_CHUNK = 0x04,
    OP_UPD_ANCESTOR_SUCCESS = 0x05,
} op_code_updancestor_t;

/*
 * Initialize Blockchain update ancestor protocol state.
 */
void bc_init_upd_ancestor();

/*
 * Update blockchain ancestor.
 *
 * @arg[in] rx number of received bytes from the Host
 * @ret     number of transmited bytes to the host
 */
unsigned int bc_upd_ancestor(volatile unsigned int rx);

#endif // __BC_ANCESTOR_H

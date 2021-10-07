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

/****************************************************************************
 *   powHSM
 *   Ledger Nano S BOLOS simulator layer
 *
 *   Network-upgrade related functions
 *****************************************************************************/

#ifndef __SIMULATOR_NU
#define __SIMULATOR_NU

#include <stdint.h>

#include "bc_nu.h"

void hsmsim_set_network_upgrade(uint32_t block_number,
                                uint8_t* dst_network_upgrade);

uint8_t hsmsim_get_network_identifier();

const char* get_network_name(uint8_t netid);

uint8_t get_network_identifier_by_name(char* name);

bool hsmsim_set_network(uint8_t netid);

#endif // __SIMULATOR_NU
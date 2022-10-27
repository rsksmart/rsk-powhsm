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

#include "apdu.h"
#include "os.h"
#include "string.h"
#include "unlock.h"

/*
 * Implements RSK UNLOCK command.
 *
 * Unlocks the device.
 *
 * @arg[in] rx      number of received bytes from the Host
 * @arg[in] pin_ctx pin context
 * @ret             number of transmited bytes to the host
 */
unsigned int unlock(volatile unsigned int rx, pin_t *pin_ctx) {
    // Unlock command does not use any input from apdu buffer
    UNUSED(rx);

    unsigned char output_index = OP;
    SET_APDU_AT(output_index++,
                os_global_pin_check(pin_ctx->pin_buffer,
                                    strlen((const char *)pin_ctx->pin_buffer)));
    return output_index;
}

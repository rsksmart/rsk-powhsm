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

#include <string.h>

#include "apdu.h"
#include "os.h"
#include "err.h"
#include "pin.h"

// Helper macros for pin validation
#define IS_IN_RANGE(c, begin, end) (((c) >= (begin)) && ((c) <= (end)))
#define IS_ALPHA(c) (IS_IN_RANGE(c, 'a', 'z') || IS_IN_RANGE(c, 'A', 'Z'))
#define IS_NUM(c) IS_IN_RANGE(c, '0', '9')
#define IS_ALPHANUM(c) (IS_ALPHA(c) || IS_NUM(c))

/*
 * Validates that the pin has exactly PIN_LENGTH alphanumeric characters
 * with at least one alphabetic character.
 *
 * @arg[in] pin_ctx pin context (with prepended length)
 * @ret     true if pin is valid, false otherwise
 */
bool is_pin_valid(pin_t* pin_ctx) {
    // PIN_LENGTH is the only length accepted
    if (GET_PIN_LENGTH(pin_ctx) != PIN_LENGTH) {
        return false;
    }
    // Check if PIN is alphanumeric
    bool hasAlpha = false;
    for (int i = 0; i < PIN_LENGTH; i++) {
        if (!IS_ALPHANUM(GET_PIN(pin_ctx)[i])) {
            return false;
        }
        if (hasAlpha || IS_ALPHA(GET_PIN(pin_ctx)[i])) {
            hasAlpha = true;
        }
    }

    return hasAlpha;
}

/*
 * Reset the given pin context to point to a target buffer
 *
 * @arg[out] pin_ctx    pin context
 * @arg[in]  pin_buffer pin buffer to which the pin context should point
 */
void init_pin_ctx(pin_t* pin_ctx, unsigned char* pin_buffer) {
    pin_ctx->pin_buffer = pin_buffer;
}

/*
 * Reset the given pin context
 *
 * @arg[in] pin_ctx pin context
 */
void reset_pin_ctx(pin_t* pin_ctx) {
    explicit_bzero(pin_ctx, sizeof(pin_t));
}

/*
 * Implements RSK PIN command.
 *
 * Receives one byte at a time and updates the pin context, adding a null byte
 * at the end.
 *
 * @arg[in] rx      number of received bytes from the Host
 * @arg[in] pin_ctx pin context
 * @ret             number of transmited bytes to the host
 */
unsigned int update_pin_buffer(volatile unsigned int rx, pin_t* pin_ctx) {
    // Should receive 1 byte per call
    if (APDU_DATA_SIZE(rx) != 1) {
        THROW(PROT_INVALID);
    }

    unsigned char index = APDU_OP();
    if ((index >= 0) && (index <= PIN_LENGTH)) {
        pin_ctx->pin_buffer[index] = APDU_AT(DATA);
        pin_ctx->pin_buffer[index + 1] = 0;
    }

    return 3;
}

/*
 * Implements RSK NEW PIN command.
 *
 * Sets the device pin.
 *
 * @arg[in] rx      number of received bytes from the Host
 * @arg[in] pin_ctx pin context
 * @ret             number of transmited bytes to the host
 */
unsigned int set_device_pin(volatile unsigned int rx, pin_t* pin_ctx) {
    // NEW_PIN command does not use any input from apdu buffer
    UNUSED(rx);

#ifndef DEBUG_BUILD
    if (!is_pin_valid(pin_ctx)) {
        THROW(ERR_INVALID_PIN);
    }
#endif
    // Set PIN
    os_perso_set_pin(0, GET_PIN(pin_ctx), GET_PIN_LENGTH(pin_ctx));
    // check PIN
    os_global_pin_invalidate();
    unsigned char output_index = CMDPOS;
    SET_APDU_AT(output_index++, 2);
    SET_APDU_AT(output_index++,
                os_global_pin_check(GET_PIN(pin_ctx), GET_PIN_LENGTH(pin_ctx)));
    return output_index;
}
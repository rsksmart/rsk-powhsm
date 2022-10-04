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

#include "defs.h"
#include "err.h"
#include "os.h"
#include "pin.h"

// Helper macros for pin validation
#define IS_IN_RANGE(c, begin, end) (((c) >= (begin)) && ((c) <= (end)))
#define IS_ALPHA(c) (IS_IN_RANGE(c, 'a', 'z') || IS_IN_RANGE(c, 'A', 'Z'))
#define IS_NUM(c) IS_IN_RANGE(c, '0', '9')
#define IS_ALPHANUM(c) (IS_ALPHA(c) || IS_NUM(c))

bool is_pin_valid(unsigned char *pin) {
    // PIN_LENGTH is the only length accepted
    size_t length = strnlen((const char *)pin, PIN_LENGTH + 1);
    if (length != PIN_LENGTH) {
        return false;
    }
    // Check if PIN is alphanumeric
    bool hasAlpha = false;
    for (int i = 0; i < PIN_LENGTH; i++) {
        if (!IS_ALPHANUM(pin[i])) {
            return false;
        }
        if (hasAlpha || IS_ALPHA(pin[i])) {
            hasAlpha = true;
        }
    }

    return hasAlpha;
}

void do_rsk_pin_cmd(unsigned char *pin_buffer) {
    unsigned char index = APDU_AT(2);
    if ((index >= 0) && (index <= PIN_LENGTH)) {
        pin_buffer[index] = APDU_AT(3);
        pin_buffer[index + 1] = 0;
    }
}

unsigned char do_rsk_new_pin(unsigned char *pin_buffer) {
#ifndef DEBUG_BUILD
    if (!is_pin_valid(pin_buffer)) {
        THROW(ERR_INVALID_PIN);
    }
#endif
    // Set PIN
    os_perso_set_pin(0, pin_buffer, strlen((const char *)pin_buffer));
    // check PIN
    os_global_pin_invalidate();
    unsigned char output_index = CMDPOS;
    SET_APDU_AT(output_index++, 2);
    SET_APDU_AT(
        output_index++,
        os_global_pin_check(pin_buffer, strlen((const char *)pin_buffer)));
    return output_index;
}
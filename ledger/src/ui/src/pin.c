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
#include "ui_err.h"
#include "pin.h"

// Helper macros for pin validation
#define IS_IN_RANGE(c, begin, end) (((c) >= (begin)) && ((c) <= (end)))
#define IS_ALPHA(c) (IS_IN_RANGE(c, 'a', 'z') || IS_IN_RANGE(c, 'A', 'Z'))
#define IS_NUM(c) IS_IN_RANGE(c, '0', '9')
#define IS_ALPHANUM(c) (IS_ALPHA(c) || IS_NUM(c))

#define PIN_LENGTH 8
#define PIN_BUFFER_LENGTH (PIN_LENGTH + 2)
// Internal PIN buffer used for authenticated operations
unsigned char G_pin_buffer[PIN_BUFFER_LENGTH];
// Helper macros for pin manipulation when prepended length is used
#define GET_PIN() ((unsigned char *)(G_pin_buffer + 1))
#define GET_PIN_LENGTH() strlen((const char *)GET_PIN())

/*
 * Implements RSK PIN command.
 *
 * Receives one byte at a time and updates the pin context, adding a null byte
 * at the end.
 *
 * @arg[in] rx      number of received bytes from the Host
 * @ret             number of transmited bytes to the host
 */
unsigned int update_pin_buffer(volatile unsigned int rx) {
    // Should receive 1 byte per call
    if (APDU_DATA_SIZE(rx) != 1) {
        THROW(ERR_UI_PROT_INVALID);
    }

    unsigned char index = APDU_OP();
    if ((index >= 0) && (index <= PIN_LENGTH)) {
        G_pin_buffer[index] = APDU_AT(DATA);
        G_pin_buffer[index + 1] = 0;
    }

    return 3;
}

/*
 * Implements RSK NEW PIN command.
 *
 * Sets and checks the device pin.
 *
 * @ret number of transmited bytes to the host
 */
unsigned int set_pin() {
#ifndef DEBUG_BUILD
    if (!is_pin_valid()) {
        THROW(ERR_UI_INVALID_PIN);
    }
#endif
    // Set PIN
    os_perso_set_pin(0, GET_PIN(), GET_PIN_LENGTH());
    // check PIN
    os_global_pin_invalidate();
    unsigned char output_index = CMDPOS;
    SET_APDU_AT(output_index++, 2);
    SET_APDU_AT(output_index++,
                os_global_pin_check(GET_PIN(), GET_PIN_LENGTH()));
    return output_index;
}

/*
 * Validates that the pin curently saved to the internal buffer has exactly
 * PIN_LENGTH alphanumeric characters with at least one alphabetic character.
 *
 * @ret     true if pin is valid, false otherwise
 */
bool is_pin_valid() {
    // PIN_LENGTH is the only length accepted
    if (GET_PIN_LENGTH() != PIN_LENGTH) {
        return false;
    }
    // Check if PIN is alphanumeric
    bool hasAlpha = false;
    for (int i = 0; i < PIN_LENGTH; i++) {
        if (!IS_ALPHANUM(GET_PIN()[i])) {
            return false;
        }
        if (hasAlpha || IS_ALPHA(GET_PIN()[i])) {
            hasAlpha = true;
        }
    }

    return hasAlpha;
}

/*
 * Fills the internal pin buffer with zeroes
 */
void clear_pin() {
    explicit_bzero(G_pin_buffer, sizeof(G_pin_buffer));
}

/*
 * Uses the pin currently saved to the internal pin buffer to unlock the device
 *
 * @arg[in] prepended_length true if the internal buffer includes a prepended
 *                           length byte, false otherwise
 * @ret                      1 if pin validated successfully, 0 otherwise
 */
unsigned int unlock_with_pin(bool prepended_length) {
    if (prepended_length) {
        return os_global_pin_check(GET_PIN(), GET_PIN_LENGTH());
    } else {
        return os_global_pin_check(G_pin_buffer,
                                   strlen((const char *)G_pin_buffer));
    }
}

/*
 * Sets the pin currently saved to the internal pin buffer as the device's pin.
 * This function assumes the pin is saved with a prepended length byte.
 */
void set_device_pin() {
    os_perso_set_pin(0, GET_PIN(), GET_PIN_LENGTH());
}
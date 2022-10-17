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

#ifndef __PIN
#define __PIN

#include <stdbool.h>

#define MAX_PIN_LENGTH 8
#define MIN_PIN_LENGTH 4

// Pin context
typedef struct {
    union {
        struct {
            unsigned char length;
            unsigned char payload[MAX_PIN_LENGTH + 1];
        } pin_buffer;
        unsigned char pin_raw[MAX_PIN_LENGTH + 2];
    };
} pin_t;

/*
 * Reset the given pin context
 *
 * @arg[in] pin_ctx pin context
 */
void reset_pin(pin_t* pin_ctx);

// -----------------------------------------------------------------------
// RSK protocol implementation
// -----------------------------------------------------------------------

/*
 * Implements RSK PIN command.
 *
 * Receives one byte at a time and updates the pin context, adding a null byte
 * at the end.
 *
 * @arg[in] pin_ctx pin context
 * @ret             number of transmited bytes to the host
 */
unsigned int pin_cmd(pin_t* pin_ctx);

/*
 * Implements RSK NEW PIN command.
 *
 * Sets the device pin.
 *
 * @arg[in] pin_ctx pin context
 * @ret             number of transmited bytes to the host
 */
unsigned int new_pin_cmd(pin_t* pin_ctx);

// -----------------------------------------------------------------------
// Pin manipulation utilities
// -----------------------------------------------------------------------

/*
 * Validates that the pin has exactly PIN_LENGTH alphanumeric characters
 * with at least one alphabetic character.
 *
 * @arg[in] pin_ctx pin context (with prepended length)
 * @ret     true if pin is valid, false otherwise
 */
bool is_pin_valid(pin_t* pin_ctx);

/*
 * Retrieves the pin currently saved on pin_ctx to pin_buffer
 *
 * @arg[in]  pin_ctx    pin context
 * @arg[out] pin_buffer output buffer where the pin should be copied
 */
void get_pin_ctx(pin_t* pin_ctx, unsigned char* pin_buffer);

/*
 * Saves the pin in pin_buffer to pin_ctx.
 *
 * @arg[out] pin_ctx    pin context
 * @arg[in]  pin_buffer input buffer that holds the pin
 */
void set_pin_ctx(pin_t* pin_ctx, unsigned char* pin_buffer);

#endif
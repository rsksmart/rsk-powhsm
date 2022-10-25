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

#define PIN_LENGTH 8

// Pin context
typedef struct {
    unsigned char* pin_buffer;
} pin_t;

// Helper macros for pin context manipulation
#define PIN_CTX_PAYLOAD(pin_ctx) ((unsigned char*)((pin_ctx)->pin_buffer + 1))
#define PIN_CTX_PAYLOAD_LEN(pin_ctx) \
    strlen((const char*)PIN_CTX_PAYLOAD(pin_ctx))

/*
 * Reset the given pin context
 *
 * @arg[in] pin_ctx pin context
 */
void reset_pin_ctx(pin_t* pin_ctx);

/*
 * Reset the given pin context to point to a target buffer
 *
 * @arg[out] pin_ctx    pin context
 * @arg[in]  pin_buffer pin buffer to which the pin context should point
 */
void init_pin_ctx(pin_t* pin_ctx, unsigned char* pin_buffer);

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
unsigned int update_pin_buffer(pin_t* pin_ctx);

/*
 * Implements RSK NEW PIN command.
 *
 * Sets the device pin.
 *
 * @arg[in] pin_ctx pin context
 * @ret             number of transmited bytes to the host
 */
unsigned int set_device_pin(pin_t* pin_ctx);

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

#endif
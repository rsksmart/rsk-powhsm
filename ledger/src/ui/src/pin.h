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

#ifndef __PIN_H
#define __PIN_H

#include <stdbool.h>

// -----------------------------------------------------------------------
// RSK protocol implementation
// -----------------------------------------------------------------------

/*
 * Implements RSK PIN command.
 *
 * Receives one byte at a time and updates the pin context, adding a null byte
 * at the end.
 *
 * @arg[in] rx      number of received bytes from the Host
 * @ret             number of transmited bytes to the host
 */
unsigned int update_pin_buffer(volatile unsigned int rx);

/*
 * Implements RSK NEW PIN command.
 *
 * Sets and checks the device pin.
 *
 * @ret number of transmited bytes to the host
 */
unsigned int set_pin();

// -----------------------------------------------------------------------
// Pin manipulation utilities
// -----------------------------------------------------------------------

/*
 * Validates that the pin curently saved to the internal buffer has exactly
 * PIN_LENGTH alphanumeric characters with at least one alphabetic character.
 *
 * @ret     true if pin is valid, false otherwise
 */
bool is_pin_valid();

/*
 * Fills the internal pin buffer with zeroes
 */
void clear_pin();

/*
 * Uses the pin currently saved to the internal pin buffer to unlock the device
 *
 * @arg[in] prepended_length true if the internal buffer includes a prepended
 *                           length byte, false otherwise
 * @ret                      1 if pin validated successfully, 0 otherwise
 */
unsigned int unlock_with_pin(bool prepended_length);

/*
 * Sets the pin currently saved to the internal pin buffer as the device's pin.
 * This function assumes the pin is saved with a prepended length byte.
 */
void set_device_pin();

#endif // __PIN_H

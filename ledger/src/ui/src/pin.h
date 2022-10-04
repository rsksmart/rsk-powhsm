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

/*
 * Validates that the pin has exactly PIN_LENGTH alphanumeric characters
 * with at least one alphabetic character.
 *
 * @arg[in] pin null-terminated string representing the pin to validate
 * @ret     true if pin is valid, false otherwise
 */
bool is_pin_valid(unsigned char *pin);

/*
 * Implements RSK PIN command.
 *
 * Receives one byte at a time and fills the buffer pointed by pin_buffer,
 * adding a null byte after the new byte.
 *
 * @arg[in] pin_buffer Buffer that will hold the null-terminated pin (with a
 *                     1-byte prepended length). The buffer is required to
 *                     have a lentgh of (PIN_LENGTH + 2).
 */
void do_rsk_pin_cmd(unsigned char *pin_buffer);

/*
 * Implements RSK NEW PIN command.
 *
 * Sets the device pin.
 *
 * @arg[in] pin_buffer Buffer that holds the new pin.
 * @ret                Number of transmited bytes to the host.
 */
unsigned char do_rsk_new_pin(unsigned char *pin_buffer);

#endif
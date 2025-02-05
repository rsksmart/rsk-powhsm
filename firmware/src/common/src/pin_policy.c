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

#include "pin_policy.h"

// Helper macros for pin validation
#define IS_IN_RANGE(c, begin, end) (((c) >= (begin)) && ((c) <= (end)))
#define IS_ALPHA(c) (IS_IN_RANGE(c, 'a', 'z') || IS_IN_RANGE(c, 'A', 'Z'))
#define IS_NUM(c) IS_IN_RANGE(c, '0', '9')
#define IS_ALPHANUM(c) (IS_ALPHA(c) || IS_NUM(c))

bool pin_policy_is_valid_pin(const char* pin, size_t pin_length) {
    // Pin should be exactly MAX_PIN_LENGTH characters long
    if (pin_length != MAX_PIN_LENGTH) {
        return false;
    }

    // Pin should:
    // - Be entirely alphanumeric and;
    // - Contain at least one alphabetic character
    bool hasAlpha = false;
    for (size_t i = 0; i < pin_length; i++) {
        if (!IS_ALPHANUM(pin[i])) {
            return false;
        }
        hasAlpha |= IS_ALPHA(pin[i]);
    }

    return hasAlpha;
}

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

/*******************************************************************************
 *   Ledger Blue - Secure firmware
 *   (c) 2016, 2017 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include "os.h"
#include "cx.h"

#include "os_io_seproxyhal.h"
#include "string.h"

#include "bolos_ux.h"

#ifdef OS_IO_SEPROXYHAL

#define COLOR_BG_1 0xF9F9F9

#define KEYCODE_SWITCH '\1'
#define KEYCODE_BACKSPACE '\r'

// avoid typing the size each time
#define SPRINTF(strbuf, ...) snprintf(strbuf, sizeof(strbuf), __VA_ARGS__)

#define ONBOARDING_CONFIRM_WORD_COUNT 2
#define ONBOARDING_WORD_COMPLETION_MAX_ITEMS 8
#define BOLOS_UX_HASH_LENGTH 4 // as on the blue

#define CONSENT_INTERVAL_MS 3000

#define ARRAYLEN(array) (sizeof(array) / sizeof(array[0]))
#define INARRAY(elementptr, array)                      \
    ((unsigned int)elementptr >= (unsigned int)array && \
     (unsigned int)elementptr < ((unsigned int)array) + sizeof(array))

extern bolos_ux_context_t G_bolos_ux_context;

extern const unsigned char hex_digits[];

unsigned char rng_u8_modulo(unsigned char modulo);
// common code for all screens
// reset the screen asynch display machine
void screen_state_init(unsigned int stack_slot);

// common code for all screens
// start display of first declared element
void screen_display_init(unsigned int stack_slot);

// request display of the element (taking care of calling screen displayed
// preprocessors)
void screen_display_element(const bagl_element_t *element);

// all screens
void screen_dashboard_init(void);
void screen_dashboard_prepare(void);
void screen_not_personalized_init(void);
void screen_processing_init(void);

// apply settings @ boot time
void screen_settings_apply(void);

#define COMMON_KEYBOARD_INDEX_UNCHANGED (-1UL)

void debug(unsigned int id, unsigned char *msg);

#endif // OS_IO_SEPROXYHAL

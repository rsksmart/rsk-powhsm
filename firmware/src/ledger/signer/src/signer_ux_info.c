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

#include <stddef.h>
#include "os_io_seproxyhal.h"
#include "defs.h"
#include "signer_ux.h"

// This 2-step expansion is necessary to force the preprocessor to expand the
// numeric macros before stringifying them
#define STRINGIFY(x) #x
#define INT2STR(x) STRINGIFY(x)

#define SIGNER_VERSION_STRING \
    INT2STR(VERSION_MAJOR)    \
    "." INT2STR(VERSION_MINOR) "." INT2STR(VERSION_PATCH)

// clang-format off
static const bagl_element_t bagl_ui_info_nanos[] = {
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000,
         0xFFFFFF, 0, 0},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_LABELINE, 0x02, 0, 12, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000,
         BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
        "Signer running...",
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_LABELINE, 0x03, 0, 26, 128, 11, 0, 0, 0, 0xFFFFFF, 0x000000,
         BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
        "Version: " SIGNER_VERSION_STRING,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    }
};
// clang-format on

static unsigned int bagl_ui_info_nanos_button(
    unsigned int button_mask, unsigned int button_mask_counter) {
    // no-op - button presses are handled directly in the event loop
    return 0;
}

void signer_ux_info(void) {
    UX_DISPLAY(bagl_ui_info_nanos, NULL);
}

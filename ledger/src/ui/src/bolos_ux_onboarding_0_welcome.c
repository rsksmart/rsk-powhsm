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

#include "bolos_ux_common.h"

#ifdef OS_IO_SEPROXYHAL

#define HELP_MSG_INTERVAL_MS 3000

const bagl_element_t screen_onboarding_0_welcome_elements[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE,
      0x00,
      0,
      0,
      128,
      32,
      0,
      0,
      BAGL_FILL,
      0x000000,
      0xFFFFFF,
      0,
      0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE,
      0x01,
      0,
      21,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_LIGHT_16px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "Welcome",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE,
      0x02,
      11,
      12,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px,
      0},
     "to RSK",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x02,
      42,
      12,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px,
      0},
     "both buttons",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x02,
      0,
      26,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "to begin",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

const bagl_element_t screen_onboarding_0_welcome_tuto_elements[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE,
      0x00,
      0,
      0,
      128,
      32,
      0,
      0,
      BAGL_FILL,
      0x000000,
      0xFFFFFF,
      0,
      0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE,
      0x01,
      0,
      12,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "With Ledger Nano S,",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x01,
      0,
      26,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "side buttons are used",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE,
      0x02,
      0,
      12,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "to interact and control",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x02,
      0,
      26,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "the user interface.",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE,
      0x03,
      3,
      12,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px,
      0},
     "Use",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x03,
      25,
      12,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px,
      0},
     "left/right buttons",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x03,
      0,
      26,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "to change values",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE,
      0x04,
      0,
      12,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "and navigate through",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x04,
      0,
      26,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "multiple-choice lists.",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE,
      0x05,
      11,
      12,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px,
      0},
     "Press",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x05,
      42,
      12,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px,
      0},
     "both buttons",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x05,
      0,
      26,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "when you wish to",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE,
      0x06,
      0,
      12,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "confirm/continue or",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x06,
      0,
      26,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "open an application.",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE,
      0x07,
      0,
      12,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "To begin configuration,",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x07,
      12,
      26,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px,
      0},
     "press",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x07,
      42,
      26,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px,
      0},
     "both buttons.",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

};

const bagl_element_t screen_onboarding_0_welcome_new_elements[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE,
      0x00,
      0,
      0,
      128,
      32,
      0,
      0,
      BAGL_FILL,
      0x000000,
      0xFFFFFF,
      0,
      0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x00,
      0,
      12,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "Configure as",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x00,
      0,
      26,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "new device?",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON,
      0x00,
      3,
      12,
      7,
      7,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON,
      0x00,
      117,
      13,
      8,
      6,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

const bagl_element_t screen_onboarding_0_welcome_restore_elements[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE,
      0x00,
      0,
      0,
      128,
      32,
      0,
      0,
      BAGL_FILL,
      0x000000,
      0xFFFFFF,
      0,
      0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x00,
      0,
      12,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "Restore",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x00,
      0,
      26,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "configuration?",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON,
      0x00,
      3,
      12,
      7,
      7,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON,
      0x00,
      117,
      13,
      8,
      6,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

#ifdef HAVE_ELECTRUM

const bagl_element_t screen_onboarding_0_welcome_electrum_elements[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE,
      0x00,
      0,
      0,
      128,
      32,
      0,
      0,
      BAGL_FILL,
      0x000000,
      0xFFFFFF,
      0,
      0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x00,
      0,
      12,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "Configure for",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x00,
      0,
      26,
      128,
      32,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "Electrum?",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON,
      0x00,
      3,
      12,
      7,
      7,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON,
      0x00,
      117,
      13,
      8,
      6,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

#endif

unsigned int screen_onboarding_0_welcome_new_button(
    unsigned int button_mask, unsigned int button_mask_counter);

#ifdef HAVE_ELECTRUM

unsigned int screen_onboarding_0_welcome_electrum_button(
    unsigned int button_mask, unsigned int button_mask_counter);

#endif

unsigned int screen_onboarding_0_welcome_restore_button(
    unsigned int button_mask, unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        // ask for new
        G_bolos_ux_context.screen_stack[0].element_arrays[0].element_array =
            screen_onboarding_0_welcome_new_elements;
        G_bolos_ux_context.screen_stack[0]
            .element_arrays[0]
            .element_array_count =
            ARRAYLEN(screen_onboarding_0_welcome_new_elements);
        G_bolos_ux_context.screen_stack[0].element_arrays_count = 1;
        G_bolos_ux_context.screen_stack[0].button_push_callback =
            screen_onboarding_0_welcome_new_button;
        screen_display_init(0);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        G_bolos_ux_context.onboarding_kind = BOLOS_UX_ONBOARDING_RESTORE;
#ifdef HAVE_ELECTRUM
        G_bolos_ux_context.screen_stack[0].element_arrays[0].element_array =
            screen_onboarding_0_welcome_electrum_elements;
        G_bolos_ux_context.screen_stack[0]
            .element_arrays[0]
            .element_array_count =
            ARRAYLEN(screen_onboarding_0_welcome_electrum_elements);
        G_bolos_ux_context.screen_stack[0].element_arrays_count = 1;
        G_bolos_ux_context.screen_stack[0].button_push_callback =
            screen_onboarding_0_welcome_electrum_button;
        screen_display_init(0);
#else
        screen_onboarding_1_2_pin_init(1);
#endif

        break;
    }
    return 0;
}

unsigned int screen_onboarding_0_welcome_new_button(
    unsigned int button_mask, unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        // ask for restore
        G_bolos_ux_context.screen_stack[0].element_arrays[0].element_array =
            screen_onboarding_0_welcome_restore_elements;
        G_bolos_ux_context.screen_stack[0]
            .element_arrays[0]
            .element_array_count =
            ARRAYLEN(screen_onboarding_0_welcome_restore_elements);
        G_bolos_ux_context.screen_stack[0].element_arrays_count = 1;
        G_bolos_ux_context.screen_stack[0].button_push_callback =
            screen_onboarding_0_welcome_restore_button;
        screen_display_init(0);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        G_bolos_ux_context.onboarding_kind = BOLOS_UX_ONBOARDING_NEW;
#ifdef HAVE_ELECTRUM
        G_bolos_ux_context.screen_stack[0].element_arrays[0].element_array =
            screen_onboarding_0_welcome_electrum_elements;
        G_bolos_ux_context.screen_stack[0]
            .element_arrays[0]
            .element_array_count =
            ARRAYLEN(screen_onboarding_0_welcome_electrum_elements);
        G_bolos_ux_context.screen_stack[0].element_arrays_count = 1;
        G_bolos_ux_context.screen_stack[0].button_push_callback =
            screen_onboarding_0_welcome_electrum_button;
        screen_display_init(0);
#else
        screen_onboarding_1_2_pin_init(1);
#endif
        break;
    }
    return 0;
}

#ifdef HAVE_ELECTRUM
unsigned int screen_onboarding_0_welcome_electrum_button(
    unsigned int button_mask, unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
        G_bolos_ux_context.onboarding_algorithm =
            BOLOS_UX_ONBOARDING_ALGORITHM_BIP39;
        screen_onboarding_1_2_pin_init(1);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
        G_bolos_ux_context.onboarding_algorithm =
            BOLOS_UX_ONBOARDING_ALGORITHM_ELECTRUM;
        screen_onboarding_1_2_pin_init(1);
        break;
    }
    return 0;
}
#endif

const bagl_element_t *screen_onboarding_0_welcome_prepro(
    const bagl_element_t *element) {
    if (element->component.userid > 0) {
        return (G_bolos_ux_context.onboarding_index ==
                (unsigned int)(element->component.userid - 1))
                   ? element
                   : NULL;
    }
    return element;
}

unsigned int screen_onboarding_0_welcome_ticker(unsigned int ignored) {
    UNUSED(ignored);
    // switch display if multiple steps defined
    if (G_bolos_ux_context.onboarding_step) {
        // prepare displaying next screen
        G_bolos_ux_context.onboarding_index =
            (G_bolos_ux_context.onboarding_index + 1) %
            G_bolos_ux_context.onboarding_step;

        screen_display_init(0);
    }
    return 0;
}

unsigned int screen_onboarding_0_welcome_tuto_button(
    unsigned int button_mask, unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
        // reset ticker interval
        G_bolos_ux_context.screen_stack[0].ticker_interval = 0;

        // display new/restore switcher
        G_bolos_ux_context.onboarding_index = 0;
        G_bolos_ux_context.onboarding_step = 0;

        G_bolos_ux_context.screen_stack[0].element_arrays[0].element_array =
            screen_onboarding_0_welcome_new_elements;
        G_bolos_ux_context.screen_stack[0]
            .element_arrays[0]
            .element_array_count =
            ARRAYLEN(screen_onboarding_0_welcome_new_elements);
        G_bolos_ux_context.screen_stack[0].element_arrays_count = 1;
        G_bolos_ux_context.screen_stack[0].button_push_callback =
            screen_onboarding_0_welcome_new_button;
        screen_display_init(0);
        break;
    }
    return 0;
}

unsigned int screen_onboarding_0_welcome_button(
    unsigned int button_mask, unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
        // display tutorial
        G_bolos_ux_context.onboarding_index = 0;
        G_bolos_ux_context.onboarding_step = 7;

        // reset the delay
        G_bolos_ux_context.screen_stack[0].ticker_value = HELP_MSG_INTERVAL_MS;

        G_bolos_ux_context.screen_stack[0].element_arrays[0].element_array =
            screen_onboarding_0_welcome_tuto_elements;
        G_bolos_ux_context.screen_stack[0]
            .element_arrays[0]
            .element_array_count =
            ARRAYLEN(screen_onboarding_0_welcome_tuto_elements);
        G_bolos_ux_context.screen_stack[0].element_arrays_count = 1;
        G_bolos_ux_context.screen_stack[0].button_push_callback =
            screen_onboarding_0_welcome_tuto_button;
        screen_display_init(0);
        break;
    }
    return 0;
}

void screen_onboarding_0_welcome_init(void) {
    screen_state_init(0);

    // neither new nor restore for now
    G_bolos_ux_context.onboarding_kind = 0;

    // register action callbacks
    G_bolos_ux_context.screen_stack[0].screen_before_element_display_callback =
        screen_onboarding_0_welcome_prepro;

    // start ticker for first screen
    G_bolos_ux_context.screen_stack[0].ticker_value = HELP_MSG_INTERVAL_MS;
    G_bolos_ux_context.screen_stack[0].ticker_interval = HELP_MSG_INTERVAL_MS;
    G_bolos_ux_context.screen_stack[0].ticker_callback =
        screen_onboarding_0_welcome_ticker;
    G_bolos_ux_context.onboarding_index = 0;
    G_bolos_ux_context.onboarding_step = 2;

    // display the welcome screen first
    G_bolos_ux_context.screen_stack[0].element_arrays[0].element_array =
        screen_onboarding_0_welcome_elements;
    G_bolos_ux_context.screen_stack[0].element_arrays[0].element_array_count =
        ARRAYLEN(screen_onboarding_0_welcome_elements);
    G_bolos_ux_context.screen_stack[0].element_arrays_count = 1;
    G_bolos_ux_context.screen_stack[0].button_push_callback =
        screen_onboarding_0_welcome_button;
    screen_display_init(0);
}

#endif // OS_IO_SEPROXYHAL

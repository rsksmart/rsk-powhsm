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

const bagl_element_t screen_boot_unsafe_wipe_1_elements[] = {
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

    {{BAGL_ICON,
      0x00,
      13,
      9,
      14,
      14,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      0,
      BAGL_GLYPH_ICON_WARNING_BADGE},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE,
      0x00,
      34,
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
     "MCU firmware",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x00,
      34,
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
     "is genuine ja",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

const bagl_element_t screen_boot_unsafe_wipe_2_elements[] = {
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
      0x11,
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
     "Identifier",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE,
      0x31,
      0,
      26,
      128,
      11,
      0,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     G_bolos_ux_context.string_buffer,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

};

const struct screen_boot_unsafe_strings_s {
    const char *line1;
    const char *line2;
} const screen_boot_unsafe_strings[] = {
    {"The device will run", "in unsafe mode."},
    {"The configuration of", " your Nano S will be"},
    {"erased, but apps", "will remain accessible."},
    {"To return to safe mode,", "connect the device"},
    {"to your computer,", "enter your PIN code"},
    {"and open the", "Ledger Manager app."},
    {"Unplug the device", "now to abort."},
};

const bagl_element_t screen_boot_unsafe_wipe_x_elements[] = {
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
     G_bolos_ux_context.string_buffer,
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
     G_bolos_ux_context.string_buffer,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

const bagl_element_t *screen_boot_unsafe_before_element_display_callback(
    const bagl_element_t *element) {
    switch (element->component.userid) {
    case 0x01:
        strcpy(
            G_bolos_ux_context.string_buffer,
            (const char *)PIC(
                screen_boot_unsafe_strings[G_bolos_ux_context.onboarding_index]
                    .line1));
        break;

    case 0x02:
        strcpy(
            G_bolos_ux_context.string_buffer,
            (const char *)PIC(
                screen_boot_unsafe_strings[G_bolos_ux_context.onboarding_index]
                    .line2));
        break;

    case 0x31:
        screen_hex_identifier_string_buffer(
            G_bolos_ux_context.parameters.u.boot_unsafe.hash, 32);
        break;
    }
    return element;
}

unsigned int screen_boot_unsafe_wipe_x_button(
    unsigned int button_mask, unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
        if ((!G_bolos_ux_context.parameters.u.boot_unsafe.currently_onboarded &&
             G_bolos_ux_context.onboarding_index == 0) ||
            G_bolos_ux_context.onboarding_index ==
                ARRAYLEN(screen_boot_unsafe_strings) - 1) {
            G_bolos_ux_context.exit_code = BOLOS_UX_OK;
        } else {
            G_bolos_ux_context.onboarding_index++;
            screen_display_init(0);
        }
        break;
    }
    return 0;
}

unsigned int screen_boot_unsafe_wipe_2_button(
    unsigned int button_mask, unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
        G_bolos_ux_context.onboarding_index = 0;
        G_bolos_ux_context.screen_stack[0].element_arrays[0].element_array =
            screen_boot_unsafe_wipe_x_elements;
        G_bolos_ux_context.screen_stack[0]
            .element_arrays[0]
            .element_array_count = ARRAYLEN(screen_boot_unsafe_wipe_x_elements);
        G_bolos_ux_context.screen_stack[0].button_push_callback =
            screen_boot_unsafe_wipe_x_button;
        screen_display_init(0);
        break;
    }
    return 0;
}

unsigned int screen_boot_unsafe_wipe_1_button(
    unsigned int button_mask, unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
        G_bolos_ux_context.screen_stack[0].element_arrays[0].element_array =
            screen_boot_unsafe_wipe_2_elements;
        G_bolos_ux_context.screen_stack[0]
            .element_arrays[0]
            .element_array_count = ARRAYLEN(screen_boot_unsafe_wipe_2_elements);
        G_bolos_ux_context.screen_stack[0].button_push_callback =
            screen_boot_unsafe_wipe_2_button;
        screen_display_init(0);
        break;
    }
    return 0;
}

void screen_boot_unsafe_wipe_init(void) {
    screen_state_init(0);
    G_bolos_ux_context.screen_stack[0].element_arrays[0].element_array =
        screen_boot_unsafe_wipe_1_elements;
    G_bolos_ux_context.screen_stack[0].element_arrays[0].element_array_count =
        ARRAYLEN(screen_boot_unsafe_wipe_1_elements);
    G_bolos_ux_context.screen_stack[0].element_arrays_count = 1;
    G_bolos_ux_context.screen_stack[0].button_push_callback =
        screen_boot_unsafe_wipe_1_button;
    G_bolos_ux_context.screen_stack[0].screen_before_element_display_callback =
        screen_boot_unsafe_before_element_display_callback;
    screen_display_init(0);
}

#endif // OS_IO_SEPROXYHAL

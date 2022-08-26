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

const struct screen_help_strings_s {
    const char *line1;
    const char *line2;
} const screen_help_strings[] = {
    {"Website", "help.ledgerwallet.com"},
    {"Email", "help@ledgerwallet.com"},
};

const bagl_element_t screen_help_x_elements[] = {
    // erase
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
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER,
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

const bagl_element_t screen_help_0_elements[] = {
    // erase
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
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "To get assistance,",
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
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER,
      0},
     "contact Ledger support.",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

const bagl_element_t *screen_help_before_element_display_callback(
    const bagl_element_t *element) {
    switch (element->component.userid) {
    case 0x01:
        strcpy(
            G_bolos_ux_context.string_buffer,
            (const char *)PIC(
                screen_help_strings[G_bolos_ux_context.help_screen_idx].line1));
        break;

    case 0x02:
        strcpy(
            G_bolos_ux_context.string_buffer,
            (const char *)PIC(
                screen_help_strings[G_bolos_ux_context.help_screen_idx].line2));
        break;
    }
    return element;
}

unsigned int screen_help_x_button(unsigned int button_mask,
                                  unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
        // help flow ended
        if (G_bolos_ux_context.help_screen_idx ==
            ARRAYLEN(screen_help_strings) - 1) {
            // never called from an app
            screen_stack_pop();
            G_bolos_ux_context.help_ended_callback();
        } else {
            G_bolos_ux_context.help_screen_idx++;
            screen_display_init(G_bolos_ux_context.screen_stack_count - 1);
        }
        break;
    }
    return 1;
}

unsigned int screen_help_0_button(unsigned int button_mask,
                                  unsigned int button_mask_counter) {
    UNUSED(button_mask_counter);
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
        G_bolos_ux_context
            .screen_stack[G_bolos_ux_context.screen_stack_count - 1]
            .button_push_callback = screen_help_x_button;
        G_bolos_ux_context
            .screen_stack[G_bolos_ux_context.screen_stack_count - 1]
            .element_arrays[0]
            .element_array = screen_help_x_elements;
        G_bolos_ux_context
            .screen_stack[G_bolos_ux_context.screen_stack_count - 1]
            .element_arrays[0]
            .element_array_count = ARRAYLEN(screen_help_x_elements);
        G_bolos_ux_context.help_screen_idx = 0;
        screen_display_init(G_bolos_ux_context.screen_stack_count - 1);
        break;
    }
    return 1;
}

void screen_help_init(appmain_t help_ended_callback) {
    // this is a modal
    unsigned int stack_slot =
        screen_stack_is_element_array_present(screen_help_0_elements);

    // screen already present, can't be redisplayed
    if (stack_slot &&
        (stack_slot - 1 != G_bolos_ux_context.screen_stack_count - 1)) {
        screen_stack_remove(stack_slot - 1);
    }

    stack_slot = screen_stack_is_element_array_present(screen_help_x_elements);

    // screen already present, can't be redisplayed
    if (stack_slot &&
        (stack_slot - 1 != G_bolos_ux_context.screen_stack_count - 1)) {
        screen_stack_remove(stack_slot - 1);
    }

    stack_slot = screen_stack_push();

    screen_state_init(stack_slot);

    if (help_ended_callback) {
        G_bolos_ux_context.help_ended_callback = help_ended_callback;
    }

    // static dashboard content
    G_bolos_ux_context.screen_stack[stack_slot]
        .element_arrays[0]
        .element_array = screen_help_0_elements;
    G_bolos_ux_context.screen_stack[stack_slot]
        .element_arrays[0]
        .element_array_count = ARRAYLEN(screen_help_0_elements);
    G_bolos_ux_context.screen_stack[stack_slot].element_arrays_count = 1;

    // ensure the string_buffer will be set before each button is displayed
    G_bolos_ux_context.screen_stack[stack_slot]
        .screen_before_element_display_callback =
        screen_help_before_element_display_callback;
    G_bolos_ux_context.screen_stack[stack_slot].button_push_callback =
        screen_help_0_button;

    screen_display_init(stack_slot);
}

#endif // OS_IO_SEPROXYHAL

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

#ifdef BOLOS_RELEASE
#define DASHBOARD_SETTINGS_APPNAME "Settings"
#else
#define DASHBOARD_SETTINGS_APPNAME "NOT A RELEASE"
#endif // BOLOS_RELEASE

#ifdef OS_IO_SEPROXYHAL

// DESIGN NOTE: index 0 of the slider is the settings

// draw screen
static const bagl_element_t screen_dashboard_elements[] = {
    {
        {BAGL_RECTANGLE,
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
        NULL,
    },
    {
        {BAGL_LABELINE,
         0x02,
         0,
         12,
         128,
         11,
         0,
         0,
         0,
         0xFFFFFF,
         0x000000,
         BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER,
         0},
        "UI waiting for update",
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    }};

unsigned int screen_dashboard_displayed(unsigned int i) {
    UNUSED(i);

    if (G_bolos_ux_context.dashboard_redisplayed) {
        G_bolos_ux_context.dashboard_redisplayed = 0;

        G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_SCREEN_ANIMATION_STATUS;
        G_io_seproxyhal_spi_buffer[1] = 0;
        G_io_seproxyhal_spi_buffer[2] = 5;
        G_io_seproxyhal_spi_buffer[3] =
            SEPROXYHAL_TAG_SCREEN_ANIMATION_STATUS_VERTICAL_SPLIT_SLIDE;
        G_io_seproxyhal_spi_buffer[4] = 0;   // split y coordinate
        G_io_seproxyhal_spi_buffer[5] = 19;  // split y coordinate
        G_io_seproxyhal_spi_buffer[6] = 0;   // duration of the animation in ms
        G_io_seproxyhal_spi_buffer[7] = 200; // duration of the animation in ms
        io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 8);
        return 0; // don't consider screen ended, more data sent
    }
    return 1;
}

void screen_dashboard_prepare(void) {
    screen_state_init(0);

    // static dashboard content
    G_bolos_ux_context.screen_stack[0].element_arrays[0].element_array =
        screen_dashboard_elements;
    G_bolos_ux_context.screen_stack[0].element_arrays[0].element_array_count =
        ARRAYLEN(screen_dashboard_elements);
    G_bolos_ux_context.screen_stack[0].element_arrays_count = 1;

    // dashboard says ok when done displaying
    G_bolos_ux_context.screen_stack[0].exit_code_after_elements_displayed =
        BOLOS_UX_OK;
    G_bolos_ux_context.screen_stack[0].displayed_callback =
        screen_dashboard_displayed;
}

void screen_dashboard_init(void) {
    screen_dashboard_prepare();

    screen_display_init(0);
}

#endif // OS_IO_SEPROXYHAL

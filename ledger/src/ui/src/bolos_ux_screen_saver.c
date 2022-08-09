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

#include "glyphs.h"

#ifdef OS_IO_SEPROXYHAL

#define KONAMI_CODE_ENABLED 5

const bagl_element_t screen_saver_elements[] = {
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
      0x02,
      23,
      21,
      82,
      17,
      /*0x80|*/ 1,
      0,
      0,
      0xFFFFFF,
      0x000000,
      BAGL_FONT_OPEN_SANS_LIGHT_16px | BAGL_FONT_ALIGNMENT_CENTER,
      26},
     "                        vires in numeris                        ",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

void screen_saver_deinit(void) {
    unsigned int stack_slot = 0;
    // will push back the poweroff on top of screen stack
    stack_slot = screen_stack_is_element_array_present(screen_saver_elements);
    if (stack_slot) {
        G_bolos_ux_context.screen_stack[stack_slot - 1]
            .exit_code_after_elements_displayed = BOLOS_UX_OK;
        screen_stack_remove(stack_slot - 1);
        screen_display_init(G_bolos_ux_context.screen_stack_count - 1);
    }
}

#endif // OS_IO_SEPROXYHAL

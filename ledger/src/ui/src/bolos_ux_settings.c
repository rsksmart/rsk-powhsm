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

#define BRIGHTNESS_DEFAULT 3
#define ROTATION_DEFAULT 0
#define INVERSION_DEFAULT 0
#define SHUFFLE_PIN_DEFAULT 0

#define AUTO_LOCK_DEFAULT 600000

void screen_settings_apply_internal(unsigned int use_persisted,
                                    unsigned int brightness,
                                    unsigned int rotation,
                                    unsigned int invert) {
    // apply default settings
    if (!os_perso_isonboarded()) {
        brightness = BRIGHTNESS_DEFAULT;
        rotation = ROTATION_DEFAULT;
        invert = INVERSION_DEFAULT;
        G_bolos_ux_context.setting_auto_lock_delay_ms = AUTO_LOCK_DEFAULT;
    }

    if (os_perso_isonboarded() && use_persisted) {
        brightness = os_setting_get(OS_SETTING_BRIGHTNESS);
        rotation = os_setting_get(OS_SETTING_ROTATION);
        invert = os_setting_get(OS_SETTING_INVERT);

        // load
        G_bolos_ux_context.setting_auto_lock_delay_ms = AUTO_LOCK_DEFAULT;
        if (os_setting_get(OS_SETTING_AUTO_LOCK_DELAY)) {
            G_bolos_ux_context.setting_auto_lock_delay_ms =
                os_setting_get(OS_SETTING_AUTO_LOCK_DELAY);
        }
    }

#ifdef ALWAYS_INVERT // fast discriminant for UX trigger check // debug
    invert = 1;
#endif // ALWAYS_INVERT

    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_SET_SCREEN_CONFIG;
    G_io_seproxyhal_spi_buffer[1] = 0;
    G_io_seproxyhal_spi_buffer[2] = 2;
    G_io_seproxyhal_spi_buffer[3] = 0x80 /*power on screen*/
                                    | (rotation ? 4 : 0) | (invert ? 1 : 0);
    switch (brightness) {
    case 1:
        G_io_seproxyhal_spi_buffer[4] = 0;
        break;
    case 2:
        G_io_seproxyhal_spi_buffer[4] = 10;
        break;
    default:
    case 3:
        G_io_seproxyhal_spi_buffer[4] = 20;
        break;
    case 4:
        G_io_seproxyhal_spi_buffer[4] = 30;
        break;
    case 5:
        G_io_seproxyhal_spi_buffer[4] = 50;
        break;
    case 6:
        G_io_seproxyhal_spi_buffer[4] = 100;
        break;
    }
    io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 5);
}

void screen_settings_apply(void) {
    // use NVRAM values
    screen_settings_apply_internal(1, 0, 0, 0);
}

#endif // OS_IO_SEPROXYHAL

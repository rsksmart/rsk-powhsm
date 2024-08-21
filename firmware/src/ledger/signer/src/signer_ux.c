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

#include "signer_ux.h"

// UI currently displayed
enum UI_STATE { UI_INFO, UI_SCREENSAVER };
enum UI_STATE G_ui_state;
// Time spent since the last button press
static unsigned int G_idle_time_ms;
// The time in milliseconds after which the screen saver is displayed if no
// button is pressed
static unsigned int G_screensaver_timeout_ms;

// Local functions
static void signer_ux_update(void) {
    switch (G_ui_state) {
    case UI_INFO:
        if (G_idle_time_ms >= G_screensaver_timeout_ms) {
            G_ui_state = UI_SCREENSAVER;
            signer_ux_screensaver();
        }
        break;
    case UI_SCREENSAVER:
        if (G_idle_time_ms < G_screensaver_timeout_ms) {
            G_ui_state = UI_INFO;
            signer_ux_info();
        }
        break;
    default:
        break;
    }
}

// Public interface
void signer_ux_init(unsigned int screensaver_timeout_ms) {
    G_idle_time_ms = 0;
    G_ui_state = UI_INFO;
    G_screensaver_timeout_ms = screensaver_timeout_ms;
    signer_ux_info();
}

void signer_ux_handle_button_press(void) {
    G_idle_time_ms = 0;
    signer_ux_update();
}

void signer_ux_handle_ticker_event(unsigned int interval_ms) {
    unsigned int last_idle_time_ms = G_idle_time_ms;
    G_idle_time_ms += interval_ms;
    // Handle overflow
    if (G_idle_time_ms < last_idle_time_ms) {
        G_idle_time_ms = last_idle_time_ms;
    }
    signer_ux_update();
}

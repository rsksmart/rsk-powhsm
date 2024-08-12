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
 *   Ledger Blue
 *   (c) 2016 Ledger
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
#include "os_io_seproxyhal.h"

#include "hsm.h"

// HAL includes
#include "hal/communication.h"

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

// UI currently displayed
enum UI_STATE { UI_IDLE, UI_SCREENSAVER };
enum UI_STATE uiState;
ux_state_t ux;

#define SCREEN_SAVER_TIMEOUT_MS 30000
// The interval between two subsequent ticker events in milliseconds. This is
// assumed to be 100ms according to the nanos-secure-sdk documentation.
#define TICKER_INTERVAL_MS 100
// Time spent in idle state. This timer is reset when a button is pressed.
static unsigned int G_idle_time_ms;

// clang-format off
static const bagl_element_t bagl_ui_idle_nanos[] = {
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
    }
};

static const bagl_element_t bagl_ui_screensaver_nanos[] = {
    {
        {BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000,
         0x000000, 0, 0},
        NULL,
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
};
// clang-format on

static unsigned int bagl_ui_idle_nanos_button(
    unsigned int button_mask, unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
        //     We removed this function, but leave it in src in case its needed
        //     for debug. io_seproxyhal_touch_exit(NULL);
        break;
    }

    return 0;
}

static unsigned int bagl_ui_screensaver_nanos_button(
    unsigned int button_mask, unsigned int button_mask_counter) {
    // no-op - button presses are handled directly in the event loop
    return 0;
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        } else {
            return io_seproxyhal_spi_recv(
                G_io_apdu_buffer, sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t *)element);
}

static void ui_idle(void) {
    uiState = UI_IDLE;
    UX_DISPLAY(bagl_ui_idle_nanos, NULL);
}

static void ui_screensaver(void) {
    uiState = UI_SCREENSAVER;
    UX_DISPLAY(bagl_ui_screensaver_nanos, NULL);
}

static void handle_button_press(void) {
    G_idle_time_ms = 0;
}

static void handle_ticker_event(void) {
    unsigned int last_idle_time_ms = G_idle_time_ms;
    G_idle_time_ms += TICKER_INTERVAL_MS;
    // Handle overflow
    if (G_idle_time_ms < last_idle_time_ms) {
        G_idle_time_ms = last_idle_time_ms;
    }
}

static void handle_ui_state(void) {
    switch (uiState) {
    case UI_IDLE:
        if (G_idle_time_ms >= SCREEN_SAVER_TIMEOUT_MS) {
            ui_screensaver();
        }
        break;
    case UI_SCREENSAVER:
        if (G_idle_time_ms < SCREEN_SAVER_TIMEOUT_MS) {
            ui_idle();
        }
        break;
    default:
        break;
    }
}

unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT: // for Nano S
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        handle_button_press();
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        UX_DISPLAYED_EVENT();
        break;
    case SEPROXYHAL_TAG_TICKER_EVENT:
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
            // defaulty retrig very soon (will be overriden during
            // stepper_prepro)
            UX_CALLBACK_SET_INTERVAL(500);
            handle_ui_state();
        });
        handle_ticker_event();
        break;

    // unknown events are acknowledged
    default:
        UX_DEFAULT_EVENT();
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

static bool do_io_exchange(volatile unsigned int *rtx) {
    BEGIN_TRY {
        TRY {
            *rtx = io_exchange(CHANNEL_APDU, *rtx);
            return true;
        }
        CATCH_OTHER(e) {
            *rtx = 0;
            G_io_apdu_buffer[(*rtx)++] = 0x68;
            G_io_apdu_buffer[(*rtx)++] = e & 0xFF;
            return false;
        }
        FINALLY {
        }
    }
    END_TRY;
}

static void main_loop() {
    volatile unsigned int rtx = 0;

    while (!hsm_exit_requested()) {
        if (!do_io_exchange(&rtx))
            continue;
        rtx = hsm_process_apdu(rtx);
    }
}

__attribute__((section(".boot"))) int main(int argc, char **argv) {
    __asm volatile("cpsie i");

    // ensure exception will work as planned
    os_boot();

    UX_INIT();

    BEGIN_TRY {
        TRY {
            io_seproxyhal_init();

#ifdef LISTEN_BLE
            if (os_seph_features() &
                SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_BLE) {
                BLE_power(0, NULL);
                // restart IOs
                BLE_power(1, NULL);
            }
#endif

            USB_power(0);
            USB_power(1);

            ui_idle();
            G_idle_time_ms = 0;

            // next timer callback in 500 ms
            UX_CALLBACK_SET_INTERVAL(500);

            // APDU buffer initialization
            os_memset(G_io_apdu_buffer, 0, sizeof(G_io_apdu_buffer));

            // HAL modules initialization
            communication_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));

            // HSM context initialization
            hsm_init();

            // Main loop
            main_loop();

            // HAL modules finalisation
            // Nothing for now
        }
        CATCH_OTHER(e) {
        }
        FINALLY {
        }
    }
    END_TRY;
}

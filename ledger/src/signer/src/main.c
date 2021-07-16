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

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

static unsigned int current_text_pos; // parsing cursor in the text to display

// UI currently displayed
enum UI_STATE { UI_IDLE, UI_TEXT, UI_APPROVAL };
enum UI_STATE uiState;
ux_state_t ux;

static void ui_idle(void);
static unsigned char display_text_part(void);

#define MAX_CHARS_PER_LINE 19
#define DEFAULT_FONT BAGL_FONT_OPEN_SANS_LIGHT_16px | BAGL_FONT_ALIGNMENT_LEFT
#define TEXT_HEIGHT 15
#define TEXT_SPACE 4

static char lineBuffer[MAX_CHARS_PER_LINE + 1];

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
        "RSK: Waiting for msg",
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    }
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

// Pick the text elements to display
static unsigned char display_text_part() {
    unsigned int i;
    WIDE char *text = (char *)G_io_apdu_buffer + 5;
    if (text[current_text_pos] == '\0') {
        return 0;
    }
    i = 0;
    while ((text[current_text_pos] != 0) && (text[current_text_pos] != '\n') &&
           (i < MAX_CHARS_PER_LINE)) {
        lineBuffer[i++] = text[current_text_pos];
        current_text_pos++;
    }
    if (text[current_text_pos] == '\n') {
        current_text_pos++;
    }
    lineBuffer[i] = '\0';
    return 1;
}

static void ui_idle(void) {
    uiState = UI_IDLE;
    UX_DISPLAY(bagl_ui_idle_nanos, NULL);
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
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        if ((uiState == UI_TEXT) &&
            (os_seph_features() &
             SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG)) {
            if (!display_text_part()) {
                // ui_approval();
            } else {
                UX_REDISPLAY();
            }
        } else {
            UX_DISPLAYED_EVENT();
        }
        break;
    case SEPROXYHAL_TAG_TICKER_EVENT:
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
            // defaulty retrig very soon (will be overriden during
            // stepper_prepro)
            UX_CALLBACK_SET_INTERVAL(500);
            UX_REDISPLAY();
        });
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

static void hsm_main_loop() {
    volatile unsigned int rx = 0;
    unsigned int tx = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        BEGIN_TRY {
            TRY {
                // ensure no race in catch_other if io_exchange throws
                // an error
                rx = tx;
                tx = 0; 
                rx = io_exchange(CHANNEL_APDU, rx);

                tx = hsm_process_apdu(rx);
                THROW(0x9000);
            }
            CATCH_OTHER(e) {
                tx = hsm_process_exception(e, tx);
            }
            FINALLY {
            }
        }
        END_TRY;
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

            // next timer callback in 500 ms
            UX_CALLBACK_SET_INTERVAL(500);

            // APDU buffer initialization
            memset(G_io_apdu_buffer, 0, sizeof(G_io_apdu_buffer));

            // HSM context initialization
            hsm_init();

            // HSM main loop 
            // (separate function to allow for nested TRY...CATCH)
            hsm_main_loop();
        }
        CATCH_OTHER(e) {
        }
        FINALLY {
        }
    }
    END_TRY;
}

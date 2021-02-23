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
#include <string.h>

#include "os_io_seproxyhal.h"

#undef FEDHM_EMULATOR

#ifdef FEDHM_EMULATOR
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void init_perso(char *persoFile);

#else

// Crypto_cleanup() not needed on real hardware
void moxie_swi_crypto_cleanup(void){};

#endif

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

static unsigned int current_text_pos; // parsing cursor in the text to display

// UI currently displayed
enum UI_STATE { UI_IDLE, UI_TEXT, UI_APPROVAL };
enum UI_STATE uiState;
ux_state_t ux;

// avoid including stdbool.h
typedef unsigned char bool;
#define true 1
#define false 0

static void ui_idle(void);
static unsigned char display_text_part(void);

#define MAX_CHARS_PER_LINE 19
#define DEFAULT_FONT BAGL_FONT_OPEN_SANS_LIGHT_16px | BAGL_FONT_ALIGNMENT_LEFT
#define TEXT_HEIGHT 15
#define TEXT_SPACE 4

#define CLA 0x80
#define INS_SIGN 0x02
#define INS_GET_PUBLIC_KEY 0x04
#define RSK_IS_ONBOARD 0x06

#include "mem.h"

// Simulation of cx_hash()
#include "sha256.h"

// local definitions
//#include "defs.h"

// BTC TX-parsing code
#include "txparser.h"

// rlp-parsing code
#include "rlp.h"

// Path auth definitions
#include "pathAuth.h"

// Hardcoded contract values
#include "contractValues.h"

#include "bc_state.h"
#include "bc_advance.h"
#include "bc_ancestor.h"

#include "attestation.h"

#define RSK_MODE_CMD 0x43
#define RSK_MODE_APP 0x03
#define RSK_END_CMD 0xff

// Version and patchlevel
#define VERSION_MAJOR 0x02
#define VERSION_MINOR 0x00
#define VERSION_PATCH 0x00

// private key in flash. const and N_ variable name are mandatory here
// static const cx_ecfp_private_key_t N_privateKey;
// initialization marker in flash. const and N_ variable name are mandatory here
static const unsigned char N_initialized;

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

// Key definitions
unsigned int path[5];
cx_ecfp_public_key_t publicKey;
cx_ecfp_private_key_t privateKey;

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

// Make state variables used by signer global static, so they can be reset
static PARSE_STM state;
// Receipt keccak256 hash
unsigned char ReceiptHashBuf[HASHLEN];
// Receipts trie root (from block headers)
unsigned char ReceiptsRootBuf[HASHLEN];

/*
 * Reset signer state.
 *
 * TODO: (ppedemon) Not sure this is correct, Alfredo should check.
 */
void reset_signer() {
    state = S_CMD_START;
}

// Operation being currently executed
static unsigned char curr_cmd;

/*
 * Reset all reseteable operations, only if the given operation is starting.
 *
 * @arg[in] cmd operation code
 */
static void reset_if_starting(unsigned char cmd) {
    // Reset only if starting new operation (cmd != curr_cmd).
    // Otherwise we already reset when curr_cmd started.
    if (cmd != curr_cmd) {
        curr_cmd = cmd;
        reset_signer();
        bc_init_advance();
        bc_init_upd_ancestor();
    }
}

static void hsm_main(void) {
    volatile unsigned int rx = 0;
    unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // next timer callback in 500 ms
    UX_CALLBACK_SET_INTERVAL(500);

    // Buffer cleanup
    memset(G_io_apdu_buffer, 0, sizeof(G_io_apdu_buffer));

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;
        unsigned int index;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                if ((G_io_apdu_buffer[1] == INS_SIGN) &&
                    (G_io_apdu_buffer[TXLEN] == 0))
                    rx = 3;
                else
                    rx = io_exchange(CHANNEL_APDU | flags, rx);

                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                    THROW(0x6982);
                }

                if (G_io_apdu_buffer[0] != CLA) {
                    THROW(0x6E11);
                }

                switch (G_io_apdu_buffer[1]) {
// Include HSM 1.1 Legacy commands
#include "hsmLegacy.h"

// Include HSM 2 commands
#include "hsmCommands.h"

                case INS_ATTESTATION:
                    reset_if_starting(INS_ATTESTATION);
                    tx = get_attestation(rx, &attestation);
                    break;

                // Get blockchain state
                case INS_GET_STATE:
                    reset_if_starting(INS_GET_STATE);
                    tx = bc_get_state(rx);
                    break;

                // Reset blockchain state
                case INS_RESET_STATE:
                    reset_if_starting(INS_RESET_STATE);
                    tx = bc_reset_state(rx);
                    break;

                // Advance blockchain
                case INS_ADVANCE:
                    reset_if_starting(INS_ADVANCE);
                    tx = bc_advance(rx);
                    break;

                // Advance blockchain precompiled parameters
                case INS_ADVANCE_PARAMS:
                    reset_if_starting(INS_ADVANCE_PARAMS);
                    tx = bc_advance_get_params();
                    break;

                // Update ancestor
                case INS_UPD_ANCESTOR:
                    reset_if_starting(INS_UPD_ANCESTOR);
                    tx = bc_upd_ancestor(rx);
                    break;

                default: // Unknown command
                    THROW(0x6D00);
                    break;
                }
                THROW(0x9000);
            }
            CATCH_OTHER(e) {
                switch (e & 0xF000) {
                case 0x6000:
                case 0x9000:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
                }
                // Unexpected exception => report
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }

    return;
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

__attribute__((section(".boot"))) int main(int argc, char **argv) {
    __asm volatile("cpsie i");

    // ensure exception will work as planned
    os_boot();

    UX_INIT();

    BEGIN_TRY {
        TRY {
            unsigned char canary;
            io_seproxyhal_init();

            // Initialize current operation
            curr_cmd = 0; // 0 = no operation being executed

            // Blockchain state initialization
            bc_init_state();

            // DEBUG
            canary = 0x00;
            nvm_write((void *)&N_initialized, &canary, sizeof(canary));

            // Create the private key if not initialized
            if (N_initialized != 0x01) {
                canary = 0x01;
                nvm_write((void *)&N_initialized, &canary, sizeof(canary));
            }

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

            hsm_main();
        }
        CATCH_OTHER(e) {
        }
        FINALLY {
        }
    }
    END_TRY;
}

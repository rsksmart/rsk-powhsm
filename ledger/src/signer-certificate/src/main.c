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
#include "cx.h"

#include "os_io_seproxyhal.h"

#undef FEDHM_EMULATOR

#ifdef FEDHM_EMULATOR
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static const bagl_element_t *io_seproxyhal_touch_exit(const bagl_element_t *e);
static const bagl_element_t *io_seproxyhal_touch_approve(
    const bagl_element_t *e);

static void ui_idle(void);
static unsigned char display_text_part(void);

#define MAX_CHARS_PER_LINE 49
#define DEFAULT_FONT BAGL_FONT_OPEN_SANS_LIGHT_16px | BAGL_FONT_ALIGNMENT_LEFT
#define TEXT_HEIGHT 15
#define TEXT_SPACE 4

#define CLA 0x80
#define INS_SIGN 0x02
#define INS_GET_PUBLIC_KEY 0x04
#define RSK_GET_LOG 0x05
#define RSK_IS_ONBOARD 0x06
#define RSK_GET_ATTESTATION 0x09
#define RSK_GET_ENDORSEMENT_PUBKEY 0x0A
#define RSK_GET_APP_HASH 0x0B
#define P1_LAST 0x80
#define P1_MORE 0x00
#define P1_PATH 0x70
#define RSK_MODE_CMD 0x43
#define RSK_MODE_APP 0x03
#define RSK_END_CMD 0xff

// private key in flash. const and N_ variable name are mandatory here
// static const cx_ecfp_private_key_t N_privateKey;
// initialization marker in flash. const and N_ variable name are mandatory here
static const unsigned char N_initialized;

//********** LOG ***********
#define MAX_LOGENTRIES 32
typedef struct {
    char *hash[32];
    char *signature[32];
    char *time[8];
} log_entry;

static const log_entry N_flash_log[MAX_LOGENTRIES];
static const unsigned int N_logcursor;

static char lineBuffer[50];
static unsigned char attestation[(1 + 1 + 2 * (1 + 1 + 33))];
unsigned char attestation_len = 0;

int write_log(char *hash, char *signature, char *time) {
    log_entry le;
    os_memmove(&le.hash, hash, sizeof(le.hash));
    os_memmove(&le.signature, signature, sizeof(le.signature));
    os_memmove(&le.time, time, sizeof(le.time));

    unsigned int newcursor = N_logcursor;
    newcursor = (newcursor + 1) % MAX_LOGENTRIES;
    nvm_write((void *)&N_flash_log[N_logcursor], &le, sizeof(log_entry));
    nvm_write((void *)&N_logcursor, &newcursor, sizeof(unsigned int));
    return 0;
}

int read_log(unsigned int index, log_entry *le) {
    unsigned int newcursor = (N_logcursor - index) % MAX_LOGENTRIES;
    os_memmove(le->hash, &N_flash_log[newcursor].hash, sizeof(le->hash));
    os_memmove(le->signature,
               &N_flash_log[newcursor].signature,
               sizeof(le->signature));
    os_memmove(le->time, &N_flash_log[newcursor].time, sizeof(le->time));
    return 0;
}

#ifdef TARGET_BLUE

// UI to approve or deny the signature proposal
static const bagl_element_t const bagl_ui_approval_blue[] = {
    {
        {BAGL_BUTTON | BAGL_FLAG_TOUCHABLE,
         0x00,
         190,
         215,
         120,
         40,
         0,
         6,
         BAGL_FILL,
         0x41ccb4,
         0xF9F9F9,
         BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
             BAGL_FONT_ALIGNMENT_MIDDLE,
         0},
        "Deny",
        0,
        0x37ae99,
        0xF9F9F9,
        io_seproxyhal_touch_deny,
        NULL,
        NULL,
    },
    {
        {BAGL_BUTTON | BAGL_FLAG_TOUCHABLE,
         0x00,
         190,
         265,
         120,
         40,
         0,
         6,
         BAGL_FILL,
         0x41ccb4,
         0xF9F9F9,
         BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
             BAGL_FONT_ALIGNMENT_MIDDLE,
         0},
        "Approve",
        0,
        0x37ae99,
        0xF9F9F9,
        io_seproxyhal_touch_approve,
        NULL,
        NULL,
    },
};

static unsigned int bagl_ui_approval_blue_button(
    unsigned int button_mask, unsigned int button_mask_counter) {
    return 0;
}

// UI displayed when no signature proposal has been received
static const bagl_element_t bagl_ui_idle_blue[] = {
    {
        {BAGL_RECTANGLE,
         0x00,
         0,
         60,
         320,
         420,
         0,
         0,
         BAGL_FILL,
         0xf9f9f9,
         0xf9f9f9,
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
        {BAGL_RECTANGLE,
         0x00,
         0,
         0,
         320,
         60,
         0,
         0,
         BAGL_FILL,
         0x1d2028,
         0x1d2028,
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
        {BAGL_LABEL,
         0x00,
         20,
         0,
         320,
         60,
         0,
         0,
         BAGL_FILL,
         0xFFFFFF,
         0x1d2028,
         BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE,
         0},
        "Sample Sign",
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    },
    {
        {BAGL_BUTTON | BAGL_FLAG_TOUCHABLE,
         0x00,
         190,
         215,
         120,
         40,
         0,
         6,
         BAGL_FILL,
         0x41ccb4,
         0xF9F9F9,
         BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
             BAGL_FONT_ALIGNMENT_MIDDLE,
         0},
        "Exit",
        0,
        0x37ae99,
        0xF9F9F9,
        io_seproxyhal_touch_exit,
        NULL,
        NULL,
    },
};

static unsigned int bagl_ui_idle_blue_button(unsigned int button_mask,
                                             unsigned int button_mask_counter) {
    return 0;
}

static bagl_element_t bagl_ui_text[1];

static unsigned int bagl_ui_text_button(unsigned int button_mask,
                                        unsigned int button_mask_counter) {
    return 0;
}

#else

static const bagl_element_t bagl_ui_idle_nanos[] = {
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
        "RSK: Waiting for msg",
        0,
        0,
        0,
        NULL,
        NULL,
        NULL,
    }};

static unsigned int bagl_ui_idle_nanos_button(
    unsigned int button_mask, unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT:
    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
        //     We removed this functio, but leave it in src in case its needed
        //     for debug. io_seproxyhal_touch_exit(NULL);
        break;
    }

    return 0;
}

#endif

cx_ecfp_public_key_t publicKey;
cx_ecfp_private_key_t privateKey;

static const bagl_element_t *io_seproxyhal_touch_exit(const bagl_element_t *e) {
    // Go back to the dashboard
    os_sched_exit(0);
    return NULL; // do not redraw the widget
}

static const bagl_element_t *io_seproxyhal_touch_approve(
    const bagl_element_t *e) {
    unsigned int tx = 0;
    unsigned char result[32];
    memcpy(result, G_io_apdu_buffer + 5, sizeof(result));
#if TARGET_ID == 0x31100003
    tx = cx_ecdsa_sign((void *)&privateKey,
                       CX_RND_RFC6979 | CX_LAST,
                       CX_SHA256,
                       result,
                       sizeof(result),
                       G_io_apdu_buffer,
                       NULL);
#else
    tx = cx_ecdsa_sign((void *)&privateKey,
                       CX_RND_RFC6979 | CX_LAST,
                       CX_SHA256,
                       result,
                       sizeof(result),
                       G_io_apdu_buffer);
#endif
    G_io_apdu_buffer[0] &= 0xF0; // discard the parity information

    // Sign output buffer with attestation key
    // attestation_len =
    // os_endorsement_key2_derive_sign_data(G_io_apdu_buffer,tx,attestation);

    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
    return 0; // do not redraw the widget
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

static void hsm_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // next timer callback in 500 ms
    UX_CALLBACK_SET_INTERVAL(500);

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
                case RSK_MODE_CMD: // print mode
                    G_io_apdu_buffer[1] = RSK_MODE_APP;
                    tx = 2;
                    THROW(0x9000);
                    break;
                case RSK_IS_ONBOARD: // Wheter it's onboarded or not
                    G_io_apdu_buffer[1] = os_perso_isonboarded();
                    tx = 2;
                    THROW(0x9000);
                    break;
                case RSK_GET_LOG:
                    if (rx != 4)
                        THROW(0x6A87); /// Wrong buffer size
                    index = G_io_apdu_buffer[3];
                    log_entry le;
                    read_log(index, &le);
                    switch (G_io_apdu_buffer[2]) {
                    case 0:
                        os_memmove(
                            &G_io_apdu_buffer[1], le.hash, sizeof(le.hash));
                        tx = 1 + sizeof(le.hash);
                        break;
                    case 1:
                        os_memmove(&G_io_apdu_buffer[1],
                                   le.signature,
                                   sizeof(le.signature));
                        tx = 1 + sizeof(le.signature);
                        break;
                    case 2:
                        os_memmove(
                            &G_io_apdu_buffer[1], le.time, sizeof(le.time));
                        tx = 1 + sizeof(le.time);
                        break;
                    }
                    THROW(0x9000);
                    break;

                case INS_SIGN: {
                    // Generate key with path
                    if (G_io_apdu_buffer[2] == P1_PATH) {
                        unsigned char privateKeyData[32];
                        if (rx != 4 + 20)
                            THROW(0x6A87); // Wrong buffer size (has to be 24)
                        moxie_swi_crypto_cleanup();

                        unsigned int path[5];
                        int pathlen = 5; // G_io_apdu_buffer[3];
                        os_memmove(path, &G_io_apdu_buffer[4], pathlen * 4);
                        os_perso_derive_node_bip32(CX_CURVE_256K1,
                                                   path,
                                                   pathlen,
                                                   privateKeyData,
                                                   NULL);
                        cx_ecdsa_init_private_key(
                            CX_CURVE_256K1, privateKeyData, 32, &privateKey);
                        cx_ecfp_generate_pair(
                            CX_CURVE_256K1, &publicKey, &privateKey, 1);
                        THROW(0x9000);
                    }
                    if ((G_io_apdu_buffer[2] != P1_MORE) &&
                        (G_io_apdu_buffer[2] != P1_LAST)) {
                        THROW(0x6A86);
                    }
                    if (rx != 5 + 32)
                        THROW(0x6A87); // Wrong buffer size (has to be 32)
                    io_seproxyhal_touch_approve(NULL);
                } break;

                case RSK_GET_APP_HASH:
                    os_endorsement_get_code_hash(G_io_apdu_buffer);
                    tx = 32;
                    THROW(0x9000);
                    break;

                case RSK_GET_ENDORSEMENT_PUBKEY:
                    os_endorsement_get_public_key(2, G_io_apdu_buffer);
                    tx = 65;
                    THROW(0x9000);
                    break;

                case RSK_GET_ATTESTATION:
                    tx = attestation_len;
                    os_memmove(G_io_apdu_buffer, attestation, tx);
                    THROW(0x9000);
                    break;

                case INS_GET_PUBLIC_KEY: {
                    cx_ecfp_public_key_t publicKey;
                    cx_ecfp_private_key_t privateKey;
                    unsigned char privateKeyData[32];
                    if (rx != 3 + 20)
                        THROW(0x6A87); // Wrong buffer size (has to be 32)
                    moxie_swi_crypto_cleanup();
                    unsigned int path[5];
                    int pathlen = 5; // G_io_apdu_buffer[2];
                    os_memmove(path, &G_io_apdu_buffer[3], pathlen * 4);
                    os_perso_derive_node_bip32(
                        CX_CURVE_256K1, path, pathlen, privateKeyData, NULL);
                    cx_ecdsa_init_private_key(
                        CX_CURVE_256K1, privateKeyData, 32, &privateKey);
                    cx_ecfp_generate_pair(
                        CX_CURVE_256K1, &publicKey, &privateKey, 1);
                    os_memmove(G_io_apdu_buffer, publicKey.W, 65);
                    tx = 65;
                    THROW(0x9000);
                } break;

                case RSK_END_CMD: // return to dashboard
                    os_sched_exit(0);
                    return;
                    // goto return_to_dashboard;

                default:
                    THROW(0x6D00);
                    break;
                }
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

return_to_dashboard:
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
#ifdef TARGET_BLUE
    os_memset(bagl_ui_text, 0, sizeof(bagl_ui_text));
    bagl_ui_text[0].component.type = BAGL_LABEL;
    bagl_ui_text[0].component.x = 4;
    bagl_ui_text[0].component.y = text_y;
    bagl_ui_text[0].component.width = 320;
    bagl_ui_text[0].component.height = TEXT_HEIGHT;
    // element.component.fill = BAGL_FILL;
    bagl_ui_text[0].component.fgcolor = 0x000000;
    bagl_ui_text[0].component.bgcolor = 0xf9f9f9;
    bagl_ui_text[0].component.font_id = DEFAULT_FONT;
    bagl_ui_text[0].text = lineBuffer;
    text_y += TEXT_HEIGHT + TEXT_SPACE;
#endif
    return 1;
}

static void ui_idle(void) {
    uiState = UI_IDLE;
#ifdef TARGET_BLUE
    UX_DISPLAY(bagl_ui_idle_blue, NULL);
#else
    UX_DISPLAY(bagl_ui_idle_nanos, NULL);
#endif
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
#ifdef TARGET_NANOS
        UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
            // defaulty retrig very soon (will be overriden during
            // stepper_prepro)
            UX_CALLBACK_SET_INTERVAL(500);
            UX_REDISPLAY();
        });
#endif
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
char SERVER_PATH[256];

__attribute__((section(".boot"))) int main(int argc, char **argv) {

#ifdef FEDHM_EMULATOR
    printf("[EMU] Emulator starting. Usage:\n[EMU] %s <comm socket> <privkey "
           "file>\n",
           argv[0]);
    // Socket name
    if (argc > 1)
        strncpy(SERVER_PATH, argv[1], sizeof(SERVER_PATH));
    else
        strncpy(SERVER_PATH, "/tmp/emuUSBSocket", sizeof(SERVER_PATH));

    current_text_pos = 0;
    text_y = 60;
    uiState = UI_IDLE;
    if (argc > 3)
        init_perso(argv[3]);
#else
    // exit critical section
    __asm volatile("cpsie i");
#endif

    // ensure exception will work as planned
    os_boot();

    UX_INIT();

    BEGIN_TRY {
        TRY {
            unsigned char canary;
            io_seproxyhal_init();
            // DEBUG
            canary = 0x00;
            nvm_write((void *)&N_initialized, &canary, sizeof(canary));

            // Create the private key if not initialized
            if (N_initialized != 0x01) {
#ifdef FEDHM_EMULATOR
                srand(time(NULL));
                //		platform_random(privateKeyData, sizeof(privateKeyData));
                FILE *pFile;
                if (argc > 2) {
                    pFile = fopen(argv[2], "r");
                    if (pFile != NULL) {
                        fread(
                            &privateKeyData, 1, sizeof(privateKeyData), pFile);
                        printf("[EMU] Loaded private key from %s \n", argv[2]);
                        fclose(pFile);
                    } else { // Key not found, save it
                        pFile = fopen(argv[2], "w");
                        fwrite(
                            &privateKeyData, 1, sizeof(privateKeyData), pFile);
                        printf("[EMU] Saved private key to %s \n", argv[2]);
                        fclose(pFile);
                    }
                }
#endif
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

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

#ifndef __BOLOS_UX_H
#define __BOLOS_UX_H

#include "os_io_seproxyhal.h"

#include "attestation.h"
#include "signer_authorization.h"
#include "pin.h"
#include "onboard.h"
#include "ui_heartbeat.h"

#ifdef HAVE_BOLOS_UX

typedef unsigned int (*callback_t)(unsigned int);

#define KEYBOARD_ITEM_VALIDATED \
    1 // callback is called with the entered item index, tmp_element is
      // precharged with element to be displayed and using the common string
      // buffer as string parameter
#define KEYBOARD_RENDER_ITEM \
    2 // callback is called the element index, tmp_element is precharged with
      // element to be displayed and using the common string buffer as string
      // parameter
#define KEYBOARD_RENDER_WORD \
    3 // callback is called with a -1 when requesting complete word, or the char
      // index else, returnin 0 implies no char is to be displayed
typedef const bagl_element_t *(*keyboard_callback_t)(unsigned int event,
                                                     unsigned int value);

// bolos ux context (not mandatory if redesigning a bolos ux)
typedef struct bolos_ux_context {
#define STATE_UNINITIALIZED 0
#ifndef STATE_INITIALIZED
#define STATE_INITIALIZED 0xB01055E5UL
#endif // STATE_INITIALIZED
    unsigned int state;

    // unified arrays
    struct {
        // arrays of element to be displayed (to automate when dealing with
        // static and dynamic elements)
        struct {
            const bagl_element_t *element_array;
            unsigned int element_array_count;
        } element_arrays[2]; // not more than 2 arrays of elements are in use
                             // for any screen
        unsigned int element_arrays_count;
        unsigned int element_index;

        unsigned int exit_code_after_elements_displayed;
        unsigned int displayed;
        callback_t displayed_callback;
        // callback called before the screen callback to change the keyboard
        // face
        bagl_element_callback_t screen_before_element_display_callback;
        button_push_callback_t button_push_callback;

        callback_t ticker_callback;
        unsigned int ticker_value;
        unsigned int ticker_interval;

        // [onboarding/dashboard/settings] | [pin] | [help] | [screensaver]
    } screen_stack[2];

    unsigned int
        screen_stack_count; // initialized @0 by the bolos ux initialize
    // a screen pop occured, the underlaying screen must optimize its drawing as
    // we've probably trashed the whole screen
    unsigned int screen_redraw;

    unsigned int ms;
    unsigned int setting_auto_lock_delay_ms;

#define IS_SETTING_PRE_POWER_OFF()                            \
    (G_bolos_ux_context.setting_auto_lock_delay_ms != -1UL && \
     G_bolos_ux_context.setting_auto_lock_delay_ms != 0)
#define INACTIVITY_MS_AUTO_LOCK (G_bolos_ux_context.setting_auto_lock_delay_ms)
    unsigned int ms_last_activity;

    enum {
        INACTIVITY_NONE,
        INACTIVITY_LOCK,
    } inactivity_state;

    bagl_element_t tmp_element;

    unsigned int exit_code;

    unsigned int last_ux_id;

    union {
        struct {
            unsigned int onboarding_step;
            unsigned int onboarding_index;
            unsigned int onboarding_words_checked;
            unsigned int onboarding_words_are_valid;
            unsigned int onboarding_step_checked_inc;
            unsigned int onboarding_step_checked;
        };

        union {
            att_t attestation;
            sigaut_t sigaut;
            onboard_t onboard;
            ui_heartbeat_t ui_heartbeat;
        };
    };

    // filled up during os_ux syscall when called by user or bolos.
    bolos_ux_params_t parameters;

    unsigned int settings_index;
    unsigned int settings_value;

    int saver_step_x;
    int saver_step_y;

    // slider management
    unsigned int hslider3_before;
    unsigned int hslider3_current;
    unsigned int hslider3_after;
    unsigned int hslider3_total;

    keyboard_callback_t keyboard_callback;

    // dashboard last selected item
    unsigned int dashboard_last_selected;
    unsigned int dashboard_redisplayed; // to trigger animation when all
                                        // elements are displayed
    // in case autostart is engaged, to avoid starting the app multiple times
    unsigned int app_auto_started;

    // to return to the current context after help screens have been validated
    appmain_t help_ended_callback;
    unsigned int help_screen_idx;

// detect stack/global variable overlap
// have a zero byte to avoid buffer overflow from strings in the ux (we never
// know)
#define CANARY_MAGIC 0x7600E9AB
    unsigned int canary;

} bolos_ux_context_t;

extern bolos_ux_context_t G_bolos_ux_context;

// update before, current, after index for horizontal slider with 3 positions
// slider distinguish handling from the data, to be more generic :)
#define BOLOS_UX_HSLIDER3_NONE (-1UL)
#define FAST_LIST_THRESHOLD_CS 8
#define FAST_LIST_ACTION_CS 2

unsigned int screen_stack_is_element_array_present(
    const bagl_element_t *element_array);
unsigned int screen_stack_push(void);
unsigned int screen_stack_pop(void);
void screen_stack_remove(unsigned int stack_slot);

// BIP39 helpers
#include "bolos_ux_onboarding_seed_rom_variables.h"

unsigned int bolos_ux_get_word_ptr(unsigned char **word,
                                   unsigned int max_length,
                                   unsigned int word_index);

/**
 * Bolos system app internal UX entry point (could be overriden by a further
 * loaded BOLOS_UX application)
 */
void bolos_ux_main(void);

void screen_display_init(unsigned int stack_slot);
void screen_state_init(unsigned int stack_slot);

#endif // HAVE_BOLOS_UX

#endif // __BOLOS_UX_H

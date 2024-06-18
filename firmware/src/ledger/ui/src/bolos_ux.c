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
#include "ux_handlers.h"
#include "defs.h"
#include "ui_err.h"
#include "bootloader.h"
#include "ui_heartbeat.h"
#include "memutil.h"

#ifdef OS_IO_SEPROXYHAL

#define ARRAYLEN(array) (sizeof(array) / sizeof(array[0]))
bolos_ux_context_t G_bolos_ux_context;

// common code for all screens
void screen_state_init(unsigned int stack_slot) {
    // reinit ux behavior (previous touched element, button push state)
    io_seproxyhal_init_ux(); // glitch upon screen_display_init for a button
                             // being pressed in a previous screen

    // wipe the slot to be displayed just in case
    os_memset(&G_bolos_ux_context.screen_stack[stack_slot],
              0,
              sizeof(G_bolos_ux_context.screen_stack[0]));

    // init current screen state
    G_bolos_ux_context.screen_stack[stack_slot]
        .exit_code_after_elements_displayed = BOLOS_UX_CONTINUE;
}

// check to process keyboard callback before screen generic callback
const bagl_element_t *screen_display_element_callback(
    const bagl_element_t *element) {
    const bagl_element_t *el;
    if (G_bolos_ux_context.screen_stack_count) {
        if (G_bolos_ux_context
                .screen_stack[G_bolos_ux_context.screen_stack_count - 1]
                .screen_before_element_display_callback) {
            el = G_bolos_ux_context
                     .screen_stack[G_bolos_ux_context.screen_stack_count - 1]
                     .screen_before_element_display_callback(element);
            if (!el) {
                return 0;
            }
            if ((unsigned int)el != 1) {
                element = el;
            }
        }
    }
    // consider good to be displayed by default
    return element;
}

// common code for all screens
void screen_display_init(unsigned int stack_slot) {
    // don't display any elements of a previous screen replacement
    if (G_bolos_ux_context.screen_stack_count > 0 &&
        stack_slot == G_bolos_ux_context.screen_stack_count - 1) {
        io_seproxyhal_init_ux();

        if (!io_seproxyhal_spi_is_status_sent() &&
            G_bolos_ux_context.screen_stack[stack_slot]
                .element_arrays[0]
                .element_array_count) {
            G_bolos_ux_context.screen_stack[stack_slot].element_index =
                1; // prepare displaying next element
            screen_display_element(&G_bolos_ux_context.screen_stack[stack_slot]
                                        .element_arrays[0]
                                        .element_array[0]);
        }
    }
    // asking to redraw below top screen (likely the app below the ux)
    else if (stack_slot == -1UL || G_bolos_ux_context.screen_stack_count == 0) {
        if (G_bolos_ux_context.exit_code == BOLOS_UX_OK) {
            G_bolos_ux_context.exit_code = BOLOS_UX_REDRAW;
        }
    }
}

// return true (stack slot +1) if an element
unsigned int screen_stack_is_element_array_present(
    const bagl_element_t *element_array) {
    unsigned int i, j;
    for (i = 0;
         i < /*ARRAYLEN(G_bolos_ux_context.screen_stack)*/ G_bolos_ux_context
                 .screen_stack_count;
         i++) {
        for (j = 0; j < G_bolos_ux_context.screen_stack[i].element_arrays_count;
             j++) {
            if (G_bolos_ux_context.screen_stack[i]
                    .element_arrays[j]
                    .element_array == element_array) {
                return i + 1;
            }
        }
    }
    return 0;
}

unsigned int screen_stack_push(void) {
    // only push if an available slot exists
    if (G_bolos_ux_context.screen_stack_count <
        ARRAYLEN(G_bolos_ux_context.screen_stack)) {
        os_memset(&G_bolos_ux_context
                       .screen_stack[G_bolos_ux_context.screen_stack_count],
                  0,
                  sizeof(G_bolos_ux_context.screen_stack[0]));
        G_bolos_ux_context.screen_stack_count++;
    }
    // return the stack top index
    return G_bolos_ux_context.screen_stack_count - 1;
}

unsigned int screen_stack_pop(void) {
    unsigned int exit_code = BOLOS_UX_OK;
    // only pop if more than two stack entry (0 and 1,top is an index not a
    // count)
    if (G_bolos_ux_context.screen_stack_count > 0) {
        G_bolos_ux_context.screen_stack_count--;
        exit_code = G_bolos_ux_context
                        .screen_stack[G_bolos_ux_context.screen_stack_count]
                        .exit_code_after_elements_displayed;
        // wipe popped slot
        os_memset(&G_bolos_ux_context
                       .screen_stack[G_bolos_ux_context.screen_stack_count],
                  0,
                  sizeof(G_bolos_ux_context.screen_stack[0]));
    }

    // prepare output code when popping the last stack screen
    if (G_bolos_ux_context.screen_stack_count == 0) {
        G_bolos_ux_context.exit_code = exit_code;
    }

    // ask for a complete redraw (optimisation due to blink must be avoided as
    // we're returning from a modal, and within the bolos ux screen stack)
    G_bolos_ux_context.screen_redraw = 1;
    // return the stack top index
    return G_bolos_ux_context.screen_stack_count - 1;
}

void screen_stack_remove(unsigned int stack_slot) {
    if (stack_slot > ARRAYLEN(G_bolos_ux_context.screen_stack) - 1) {
        stack_slot = ARRAYLEN(G_bolos_ux_context.screen_stack) - 1;
    }

    // removing something not in stack
    if (stack_slot >= G_bolos_ux_context.screen_stack_count) {
        return;
    }

    // before: | screenz | removed screen | other screenz |
    // after:  | screenz | other screenz |

    if (stack_slot != ARRAYLEN(G_bolos_ux_context.screen_stack) - 1) {
        os_memmove(
            &G_bolos_ux_context.screen_stack[stack_slot],
            &G_bolos_ux_context.screen_stack[stack_slot + 1],
            (ARRAYLEN(G_bolos_ux_context.screen_stack) - (stack_slot + 1)) *
                sizeof(G_bolos_ux_context.screen_stack[0]));
    }

    // wipe last slot
    screen_stack_pop();
}

void screen_display_element(const bagl_element_t *element) {
    const bagl_element_t *el = screen_display_element_callback(element);
    if (!el) {
        return;
    }
    if ((unsigned int)el != 1) {
        element = el;
    }
    // display current element
    io_seproxyhal_display(element);
}

void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t *)element);
}

void bolos_ux_main(void) {
    G_bolos_ux_context.exit_code = BOLOS_UX_CONTINUE;

    bootloader_init();
    ui_heartbeat_init(&G_bolos_ux_context.ui_heartbeat);

    switch (G_bolos_ux_context.state) {
    default:
        // init seproxyhal ux related globals
        io_seproxyhal_init_ux();
        // no button push so far
        io_seproxyhal_init_button();

        // init the ram context
        os_memset(&G_bolos_ux_context, 0, sizeof(G_bolos_ux_context));
        // setup the ram canary
        G_bolos_ux_context.canary = CANARY_MAGIC;
        // register the ux parameters pointer for the os side
        os_ux_register(&G_bolos_ux_context.parameters);
        G_bolos_ux_context.state = STATE_INITIALIZED;
        G_bolos_ux_context.dashboard_last_selected =
            -1UL; // initialize the current selected application to none., done
                  // only at boot

        // request animation when dashboard has finished displaying all the
        // elements (after onboarding OR the first time displayed)
        G_bolos_ux_context.dashboard_redisplayed = 1;

        // return, this should be the first and only call from the bolos task at
        // platform startup
        G_bolos_ux_context.exit_code = BOLOS_UX_OK;
        break;

    case STATE_INITIALIZED:
        // push the default screen to display the ux into it
        if (G_bolos_ux_context.screen_stack_count == 0
            // no need for a new stacked screen in the following cases (no
            // screen frame needed on top of apps for these calls)

            // BEGIN BOLOS MANAGER FLOW (use slot 0 implicitely)
            &&
            (G_bolos_ux_context.parameters.ux_id == BOLOS_UX_BOOT_ONBOARDING ||
             G_bolos_ux_context.parameters.ux_id == BOLOS_UX_DASHBOARD ||
             G_bolos_ux_context.parameters.ux_id == BOLOS_UX_PROCESSING
             // END BOLOS MANAGER FLOW
             )) {
            screen_stack_push();
        }

        switch (G_bolos_ux_context.parameters.ux_id) {
        default:
            // nothing to do yet
            G_bolos_ux_context.exit_code = BOLOS_UX_CANCEL;
            break;

        case BOLOS_UX_BOOT_ONBOARDING:
            G_bolos_ux_context.exit_code = handle_bolos_ux_boot_onboarding();
            break;

        case BOLOS_UX_DASHBOARD:
            handle_bolos_ux_boot_dashboard();
            break;

        case BOLOS_UX_VALIDATE_PIN:
            G_bolos_ux_context.exit_code = handle_bolos_ux_boot_validate_pin();
            break;

        case BOLOS_UX_CONSENT_APP_ADD:
            G_bolos_ux_context.exit_code = handle_bolos_ux_boot_consent_app_add(
                G_bolos_ux_context.parameters.u.appadd.appentry.hash);
            break;

        case BOLOS_UX_CONSENT_APP_DEL:
            G_bolos_ux_context.exit_code =
                handle_bolos_ux_boot_consent_app_del();
            break;

        case BOLOS_UX_CONSENT_FOREIGN_KEY:
            G_bolos_ux_context.exit_code =
                handle_bolos_ux_boot_consent_foreing_key();
            break;

        case BOLOS_UX_PROCESSING:
            handle_bolos_ux_boot_processing();
            break;

        case BOLOS_UX_WAKE_UP:
            // if a screen is drawn (like the PIN) onto the current screen, then
            // avoid allowing the app to erase or whatever the current screen
            goto continue_SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT;

        // continue processing of the current screen
        case BOLOS_UX_EVENT: {
            // retrieve the last message received by the application, cached by
            // the OS (to avoid complex and sluggish parameter copy interface in
            // syscall)
            io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer,
                                   sizeof(G_io_seproxyhal_spi_buffer),
                                   IO_CACHE);
            // process event
            // nothing done with the event, throw an error on the transport
            // layer if needed

            // just reply "amen"
            // add a "pairing ok" tag if necessary
            // can't have more than one tag in the reply, not supported yet.
            switch (G_io_seproxyhal_spi_buffer[0]) {
            case SEPROXYHAL_TAG_TICKER_EVENT: {
                unsigned int last_ms = G_bolos_ux_context.ms;
                unsigned int interval_ms = 0;
                if (G_io_seproxyhal_spi_buffer[2] == 4) {
                    G_bolos_ux_context.ms = U4BE(G_io_seproxyhal_spi_buffer, 3);
                } else {
                    G_bolos_ux_context.ms += 100; // ~ approx, just to avoid
                                                  // being stuck on blue dev
                                                  // edition
                }

                // compute time interval, handle overflow
                interval_ms = G_bolos_ux_context.ms - last_ms;
                if (G_bolos_ux_context.ms < last_ms) {
                    interval_ms = (-1UL) - interval_ms;
                }

                // request time extension of the MCU watchdog
                G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_MORE_TIME;
                G_io_seproxyhal_spi_buffer[1] = 0;
                G_io_seproxyhal_spi_buffer[2] = 0;
                io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 3);

                if (G_bolos_ux_context.screen_stack_count > 0 &&
                    G_bolos_ux_context
                        .screen_stack[G_bolos_ux_context.screen_stack_count - 1]
                        .ticker_callback &&
                    G_bolos_ux_context
                        .screen_stack[G_bolos_ux_context.screen_stack_count - 1]
                        .ticker_interval) {
                    G_bolos_ux_context
                        .screen_stack[G_bolos_ux_context.screen_stack_count - 1]
                        .ticker_value -=
                        MIN(G_bolos_ux_context
                                .screen_stack
                                    [G_bolos_ux_context.screen_stack_count - 1]
                                .ticker_value,
                            interval_ms);
                    if (G_bolos_ux_context
                            .screen_stack
                                [G_bolos_ux_context.screen_stack_count - 1]
                            .ticker_value == 0) {
                        // rearm, and call the registered function
                        G_bolos_ux_context
                            .screen_stack
                                [G_bolos_ux_context.screen_stack_count - 1]
                            .ticker_value =
                            G_bolos_ux_context
                                .screen_stack
                                    [G_bolos_ux_context.screen_stack_count - 1]
                                .ticker_interval;
                        G_bolos_ux_context
                            .screen_stack
                                [G_bolos_ux_context.screen_stack_count - 1]
                            .ticker_callback(/*ignored*/ 0);
                    }
                }

                if (G_bolos_ux_context.ms_last_activity == 0) {
                    // initializing with no user action (at boot time, the user
                    // just ... wait)
                    G_bolos_ux_context.ms_last_activity = G_bolos_ux_context.ms;
                }

                // in case more display to be finished (asynch timer during
                // display sequence)
                goto continue_SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT;
            }
            continue_SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
            case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT: {
                // display next screen element
                unsigned int elem_idx;
                unsigned int total_element_count;
                const bagl_element_t *element;
                unsigned int i;
            next_elem:
                i = 0;
                total_element_count = 0;
                if (G_bolos_ux_context.screen_stack_count) {
                    if (!G_bolos_ux_context
                             .screen_stack
                                 [G_bolos_ux_context.screen_stack_count - 1]
                             .displayed) {
                        elem_idx =
                            G_bolos_ux_context
                                .screen_stack
                                    [G_bolos_ux_context.screen_stack_count - 1]
                                .element_index;
                        while (i < G_bolos_ux_context
                                       .screen_stack[G_bolos_ux_context
                                                         .screen_stack_count -
                                                     1]
                                       .element_arrays_count) {
                            if (!io_seproxyhal_spi_is_status_sent()) {
                                // check if we're sending from this array or not
                                if (elem_idx <
                                    G_bolos_ux_context
                                        .screen_stack[G_bolos_ux_context
                                                          .screen_stack_count -
                                                      1]
                                        .element_arrays[i]
                                        .element_array_count) {
                                    const bagl_element_t *el;
                                    // pre inc before callback to allow callback
                                    // to change the next element to be drawn
                                    G_bolos_ux_context
                                        .screen_stack[G_bolos_ux_context
                                                          .screen_stack_count -
                                                      1]
                                        .element_index++;

                                    element =
                                        &G_bolos_ux_context
                                             .screen_stack
                                                 [G_bolos_ux_context
                                                      .screen_stack_count -
                                                  1]
                                             .element_arrays[i]
                                             .element_array[elem_idx];
                                    el = screen_display_element_callback(
                                        element);
                                    if (!el) {
                                        // skip display if requested to
                                        if (!io_seproxyhal_spi_is_status_sent() &&
                                            G_bolos_ux_context.exit_code ==
                                                BOLOS_UX_CONTINUE) {
                                            goto next_elem;
                                        }
                                        goto return_exit_code;
                                    }
                                    if ((unsigned int)el != 1) {
                                        element = el;
                                    }

                                    io_seproxyhal_display(element);
                                    goto return_exit_code;
                                }
                                //  prepare for next array comparison
                                elem_idx -=
                                    G_bolos_ux_context
                                        .screen_stack[G_bolos_ux_context
                                                          .screen_stack_count -
                                                      1]
                                        .element_arrays[i]
                                        .element_array_count;
                            }
                            total_element_count +=
                                G_bolos_ux_context
                                    .screen_stack[G_bolos_ux_context
                                                      .screen_stack_count -
                                                  1]
                                    .element_arrays[i]
                                    .element_array_count;
                            i++;
                        }

                        if (G_bolos_ux_context
                                .screen_stack
                                    [G_bolos_ux_context.screen_stack_count - 1]
                                .element_index >= total_element_count) {
                            // pop screen redisplay operation ended
                            G_bolos_ux_context.screen_redraw = 0;

                            // if screen has special stuff todo on exit
                            // G_bolos_ux_context.screen_stack[G_bolos_ux_context.screen_stack_count-1].displayed
                            // = 1; // to be tested first
                            if (G_bolos_ux_context
                                    .screen_stack[G_bolos_ux_context
                                                      .screen_stack_count -
                                                  1]
                                    .displayed_callback) {
                                // if screen displayed callback requested one
                                // more round, then set CONTINUE exit code
                                if (!G_bolos_ux_context
                                         .screen_stack[G_bolos_ux_context
                                                           .screen_stack_count -
                                                       1]
                                         .displayed_callback(0)) {
                                    G_bolos_ux_context
                                        .screen_stack[G_bolos_ux_context
                                                          .screen_stack_count -
                                                      1]
                                        .displayed = 0;
                                    G_bolos_ux_context.exit_code =
                                        BOLOS_UX_CONTINUE;
                                    break;
                                }
                            }
                            G_bolos_ux_context.exit_code =
                                G_bolos_ux_context
                                    .screen_stack[G_bolos_ux_context
                                                      .screen_stack_count -
                                                  1]
                                    .exit_code_after_elements_displayed;
                        }
                    }
                } else {
                    // nothing to be done here
                    G_bolos_ux_context.exit_code = BOLOS_UX_OK;
                }
                break;
            }
            }
            // process exit code
            break;
        }
        }
        break;
    }

return_exit_code:
    // remember the last displayed screen for blanking
    if (G_bolos_ux_context.parameters.ux_id != BOLOS_UX_EVENT) {
        G_bolos_ux_context.last_ux_id = G_bolos_ux_context.parameters.ux_id;
    }

    // kthx, but no
    if (G_bolos_ux_context.canary != CANARY_MAGIC) {
        reset();
    }

    // return to the caller
    os_sched_exit(G_bolos_ux_context.exit_code);
}

#endif // OS_IO_SEPROXYHAL

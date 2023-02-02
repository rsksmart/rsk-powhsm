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

#ifndef __TEST_UX_HANDLERS_H
#define __TEST_UX_HANDLERS_H

// Needed for signer_authorization.h
#define PARAM_SIGNERS_FILE testing
// Needed for bolos_ux.h
#define HAVE_BOLOS_UX 1

// Mock type definitions
typedef struct mock_application_t {
    unsigned int flags;
    unsigned char *hash;
} application_t;

typedef struct mock_struct bagl_element_t;
typedef struct mock_struct bagl_element_callback_t;
typedef struct mock_struct button_push_callback_t;
typedef struct mock_struct bolos_ux_params_t;
typedef struct mock_struct appmain_t;

// Mock internal os defines
#define APPLICATION_FLAG_BOLOS_UX 0x8
#define BOLOS_UX_OK 0xB0105011
#define BOLOS_UX_CANCEL 0xB0105022
#define BOLOS_UX_ERROR 0xB0105033

// Mock os function declarations
unsigned int os_registry_count(void);
void os_registry_get(unsigned int index, application_t *out_application_entry);
unsigned int os_sched_exec(unsigned int application_index);
void io_seproxyhal_setup_ticker(unsigned int interval_ms);
void io_seproxyhal_disable_io(void);
void io_seproxyhal_init(void);
void USB_power(unsigned char enabled);

// Mock bolos UX function definitions
void screen_settings_apply(void);
void screen_not_personalized_init(void);
void screen_dashboard_init(void);
void screen_dashboard_prepare(void);
void screen_processing_init(void);

#endif // __TEST_UX_HANDLERS_H

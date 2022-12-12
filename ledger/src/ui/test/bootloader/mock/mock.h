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

#ifndef _MOCK_H
#define _MOCK_H

#include <assert.h>
#include <stdint.h>

#include "os_exceptions.h"

#define APPLICATION_FLAG_BOLOS_UX 0x8
#define CHANNEL_APDU 0
#define BOLOS_UX_OK 0xB0105011
#define BOLOS_UX_CANCEL 0xB0105022
#define BOLOS_UX_ERROR 0xB0105033

#define IO_APDU_BUFFER_SIZE (5 + 255)
extern unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

// Assert helpers
#define ASSERT_EQUALS(a, b) assert((a) == (b))
#define ASSERT_TRUE(cond) assert(cond)
#define ASSERT_FALSE(cond) assert(!(cond))

#define APDU_RETURN(offset) \
    ((uint16_t)(G_io_apdu_buffer[offset] << 8) | (G_io_apdu_buffer[offset +1]))

// Empty struct used to mock data types
struct mock_struct {
    void *mock_data;
};

typedef struct mock_application_s {
    unsigned int flags;
    unsigned char hash[32];
} application_t;

typedef uint8_t cx_curve_t;
typedef struct mock_struct cx_sha3_t;
typedef struct mock_struct cx_ecfp_public_key_t;
typedef struct mock_struct cx_ecfp_private_key_t;

unsigned int screen_stack_pop(void);
void screen_settings_apply(void);
void screen_dashboard_init(void);
void screen_dashboard_prepare(void);
void screen_not_personalized_init(void);
void screen_processing_init(void);

void io_seproxyhal_init(void);
void io_seproxyhal_disable_io(void);
unsigned short io_exchange(unsigned char channel_and_flags,
                           unsigned short tx_len);
void io_seproxyhal_setup_ticker(unsigned int interval_ms);


void os_memmove(void *dst, const void *src, unsigned int length);
unsigned int os_registry_count(void);
void os_registry_get(unsigned int index, application_t *out_application_entry);
unsigned int os_sched_exec(unsigned int application_index);
unsigned int os_perso_isonboarded(void);

void USB_power(unsigned char enabled);

#endif
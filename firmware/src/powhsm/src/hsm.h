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

#ifndef __HSM_H
#define __HSM_H

#include <stdbool.h>

#include "hal/access.h"
#include "hal/seed.h"

#include "err.h"

typedef struct {
    bool handled;
    unsigned int tx;
} external_processor_result_t;

// Macro that throws an error unless
// the device is onboarded
#define REQUIRE_ONBOARDED() \
    if (!seed_available())  \
        THROW(ERR_DEVICE_NOT_ONBOARDED);

// Macro that throws an error unless
// the device is unlocked
#define REQUIRE_UNLOCKED()  \
    if (access_is_locked()) \
        THROW(ERR_DEVICE_LOCKED);

typedef external_processor_result_t (*external_processor_t)(unsigned int);

void hsm_init();

unsigned int hsm_process_apdu(unsigned int rx);

bool hsm_exit_requested();

void hsm_set_external_processor(external_processor_t external_processor);

#endif // __HSM_H

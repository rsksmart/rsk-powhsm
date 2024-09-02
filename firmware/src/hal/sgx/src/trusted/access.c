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

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "hal/access.h"
#include "hal/log.h"

#include "secret_store.h"

#define MIN_PASSWORD_LENGTH 4
#define MAX_PASSWORD_LENGTH 10
#define MAX_RETRIES 3

#define SEST_PASSWORD_KEY "password"
#define SEST_RETRIES_KEY "retries"

// Globals
static bool G_wiped;
static bool G_locked;
static uint8_t G_available_retries;
static char G_password[MAX_PASSWORD_LENGTH];
static uint8_t G_password_length;
static access_wiped_callback_t G_wiped_callback;

bool access_init(access_wiped_callback_t wiped_callback) {
    G_locked = true;
    G_wiped = true;
    G_wiped_callback = wiped_callback;

    if (!sest_exists(SEST_PASSWORD_KEY) && !sest_exists(SEST_RETRIES_KEY)) {
        // Module is in a wiped and locked state. Nothing left to do
        return true;
    }

    // Read password
    if (!(G_password_length = sest_read(
              SEST_PASSWORD_KEY, (uint8_t*)G_password, sizeof(G_password)))) {
        LOG("Could not load the current password\n");
        return false;
    }

    // Make sure password is sound
    if (G_password_length < MIN_PASSWORD_LENGTH ||
        G_password_length > MAX_PASSWORD_LENGTH) {
        LOG("Detected invalid password\n");
        return false;
    }

    // Read retries
    if (sest_read(SEST_RETRIES_KEY,
                  (uint8_t*)&G_available_retries,
                  sizeof(G_available_retries)) != sizeof(G_available_retries)) {
        LOG("Could not read the current retries\n");
        return false;
    }

    // Make sure number of retries read is sound
    if (!G_available_retries || G_available_retries > MAX_RETRIES) {
        LOG("Detected invalid retries\n");
        return false;
    }

    G_wiped = false;
    LOG("Password loaded. Access is locked\n");
    return true;
}

bool access_wipe() {
    G_wiped = true;
    G_locked = true;

    bool success = true;
    success &= sest_remove(SEST_PASSWORD_KEY);
    success &= sest_remove(SEST_RETRIES_KEY);

    return success;
}

bool access_unlock(char* password, uint8_t password_length) {
    if (G_wiped) {
        LOG("Access module is wiped\n");
        return false;
    }

    if (!G_locked) {
        LOG("Access module already unlocked\n");
        return true;
    }

    if (password_length != G_password_length ||
        memcmp(password, G_password, G_password_length)) {
        LOG("Invalid password\n");
        G_available_retries--;
        sest_write(SEST_RETRIES_KEY,
                   (uint8_t*)&G_available_retries,
                   sizeof(G_available_retries));
        if (G_available_retries == 0) {
            LOG("Too many unlock retries. Forcing wipe...\n");
            access_wipe();
            G_wiped_callback();
        }
        return false;
    }

    LOG("Access module unlocked\n");
    G_locked = false;
    G_available_retries = MAX_RETRIES;
    sest_write(SEST_RETRIES_KEY,
               (uint8_t*)&G_available_retries,
               sizeof(G_available_retries));
    return true;
}

uint8_t access_get_retries() {
    return G_available_retries;
}

bool access_is_wiped() {
    return G_wiped;
}

bool access_is_locked() {
    return G_locked;
}

bool access_set_password(char* password, uint8_t password_length) {
    if (G_locked && !G_wiped) {
        LOG("Access module is locked, password change not possible\n");
        return false;
    }

    if (password_length < MIN_PASSWORD_LENGTH ||
        password_length > MAX_PASSWORD_LENGTH) {
        LOG("Invalid password\n");
        return false;
    }

    if (!sest_write(SEST_PASSWORD_KEY, (uint8_t*)password, password_length)) {
        LOG("Error writing password\n");
        return false;
    }

    G_password_length = password_length;
    memcpy(G_password, password, password_length);
    G_wiped = false;
    G_available_retries = MAX_RETRIES;
    sest_write(SEST_RETRIES_KEY,
               (uint8_t*)&G_available_retries,
               sizeof(G_available_retries));
    G_locked = true;
    LOG("Password set, access locked\n");
    return true;
}

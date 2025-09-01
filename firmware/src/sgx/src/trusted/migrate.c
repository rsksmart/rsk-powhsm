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

#include "migrate.h"

#include <string.h>
#include <openenclave/corelibc/stdlib.h>
#include "hal/seed.h"
#include "hal/access.h"
#include "hal/log.h"
#include "pin_policy.h"
#include "defs.h"
#include "aes_gcm.h"

#define EXPORT_SIZE (SEED_LENGTH + MAX_PIN_LENGTH)

bool migrate_export(uint8_t* key,
                    size_t key_size,
                    uint8_t* out,
                    size_t* out_size) {
    bool retval = false;
    uint8_t* cleartext = NULL;

    // Sizes check
    if (!aes_gcm_get_encrypted_size(EXPORT_SIZE)) {
        LOG("Migration export error: export size too big\n");
        goto migrate_export_exit;
    }
    if (*out_size < aes_gcm_get_encrypted_size(EXPORT_SIZE)) {
        LOG("Migration export error: output buffer too small\n");
        goto migrate_export_exit;
    }

    // Buffers
    cleartext = oe_malloc(EXPORT_SIZE);
    if (!cleartext) {
        LOG("Migration export error: unable to allocate memory\n");
        goto migrate_export_exit;
    }

    // Export
    explicit_bzero(cleartext, EXPORT_SIZE);
    uint8_t* tmp = cleartext;
    size_t tmp_size = EXPORT_SIZE;
    size_t exp_size = 0;
    if (!seed_output_USE_FROM_EXPORT_ONLY(tmp, &tmp_size)) {
        LOG("Migration export error: unable to export seed\n");
        goto migrate_export_exit;
    }
    tmp += tmp_size;
    exp_size += tmp_size;
    tmp_size = EXPORT_SIZE - tmp_size;
    if (!access_output_password_USE_FROM_EXPORT_ONLY(tmp, &tmp_size)) {
        LOG("Migration export error: unable to export password\n");
        goto migrate_export_exit;
    }
    exp_size += tmp_size;
    if (exp_size != EXPORT_SIZE) {
        LOG("Migration export error: unexpected exported size\n");
        goto migrate_export_exit;
    }

    // Encrypt and output
    explicit_bzero(out, *out_size);
    if (!aes_gcm_encrypt(
            key, key_size, cleartext, EXPORT_SIZE, out, out_size)) {
        LOG("Migration export error: error encrypting DB\n");
        goto migrate_export_exit;
    }
    if (*out_size != aes_gcm_get_encrypted_size(EXPORT_SIZE)) {
        LOG("Migration export error: unexpected encrypted DB size\n");
        goto migrate_export_exit;
    }
    explicit_bzero(cleartext, EXPORT_SIZE);
    retval = true;

    LOG("Migration exported DB\n");

migrate_export_exit:
    if (cleartext) {
        explicit_bzero(cleartext, EXPORT_SIZE);
        oe_free(cleartext);
        cleartext = NULL;
    }
    return retval;
}

bool migrate_import(uint8_t* key,
                    size_t key_size,
                    uint8_t* in,
                    size_t in_size) {
    bool retval = false;
    uint8_t* cleartext = NULL;
    size_t cleartext_size;

    // Sizes check
    if (!aes_gcm_get_encrypted_size(EXPORT_SIZE)) {
        LOG("Migration import error: export size too big\n");
        goto migrate_import_exit;
    }
    if (in_size < aes_gcm_get_encrypted_size(EXPORT_SIZE)) {
        LOG("Migration import error: input buffer too small\n");
        goto migrate_import_exit;
    }

    // Buffers
    cleartext_size = EXPORT_SIZE;
    cleartext = oe_malloc(cleartext_size);
    if (!cleartext) {
        LOG("Migration import error: unable to allocate memory\n");
        goto migrate_import_exit;
    }

    // Decrypt
    if (!aes_gcm_decrypt(
            key, key_size, in, in_size, cleartext, &cleartext_size)) {
        LOG("Migration import error: error decrypting DB\n");
        goto migrate_import_exit;
    }
    if (cleartext_size != EXPORT_SIZE) {
        LOG("Migration import error: invalid DB\n");
        goto migrate_import_exit;
    }

    // Import
    if (!seed_set_USE_FROM_EXPORT_ONLY(cleartext, SEED_LENGTH)) {
        LOG("Migration import error: unable to import seed\n");
        goto migrate_import_exit;
    }
    if (!access_set_password((char*)(cleartext + SEED_LENGTH),
                             cleartext_size - SEED_LENGTH)) {
        LOG("Migration import error: unable to import password\n");
        goto migrate_import_exit;
    }

    explicit_bzero(cleartext, cleartext_size);
    retval = true;
    LOG("Migration imported DB\n");

migrate_import_exit:
    // Wipe everything in case something fails
    if (!retval) {
        LOG("Migration import: preemptively wiping system\n");
        seed_wipe();
        access_wipe();
    }
    if (cleartext) {
        explicit_bzero(cleartext, EXPORT_SIZE);
        oe_free(cleartext);
        cleartext = NULL;
    }
    return retval;
}

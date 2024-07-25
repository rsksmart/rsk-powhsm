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

#include <string.h>

#include "hal/constants.h"
#include "hal/seed.h"
#include "hal/endorsement.h"
#include "hal/communication.h"
#include "hal/exceptions.h"
#include "hal/log.h"

#include "hsmsim_io.h"
#include "ui_deps.h"
#include "ui_err.h"
#include "sha256.h"
#include "hmac_sha256.h"

#define UI_DEPS_PIN_RETRIES (3)

unsigned int os_endorsement_key2_derive_sign_data(unsigned char *src,
                                                  unsigned int srcLength,
                                                  unsigned char *signature) {
    uint8_t signature_length = MAX_SIGNATURE_LENGTH;
    if (!endorsement_sign(src, srcLength, signature, &signature_length)) {
        LOG("UI error endorsing message\n");
        THROW(ERR_UI_INTERNAL);
    }
    return signature_length;
}

unsigned int os_endorsement_get_code_hash(unsigned char *buffer) {
    memmove(buffer, attestation_id.code_hash, sizeof(attestation_id.code_hash));
    return sizeof(attestation_id.code_hash);
}

unsigned int os_endorsement_get_public_key(unsigned char index,
                                           unsigned char *buffer) {
    uint8_t tempbuf[PUBKEY_UNCMP_LENGTH];
    size_t tempbuf_size =
        seed_derive_pubkey_format(attestation_id.key, tempbuf, false);
    memcpy(buffer, tempbuf, tempbuf_size);
    return tempbuf_size;
}

unsigned int os_global_pin_retries() {
    return UI_DEPS_PIN_RETRIES;
}

unsigned short io_exchange(unsigned char channel_and_flags, unsigned short tx) {
    return hsmsim_io_exchange(tx);
}
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

#include "os.h"
#include "string.h"

static mock_func_call_t mock_func_call_list[128];
static size_t mock_func_call_count = 0;

/**
 * Mocks pin currently loaded to device
 */
unsigned char current_pin[10];

/**
 * Helper functions to handle call list
 */
void reset_mock_func_call_list() {
    explicit_bzero(mock_func_call_list, sizeof(mock_func_call_list));
    mock_func_call_count = 0;
}

void add_mock_func_call(mock_func_call_t func) {
    mock_func_call_list[mock_func_call_count++] = func;
}

mock_func_call_t get_mock_func_call(int order) {
    return mock_func_call_list[order];
}

int get_mock_func_call_count() {
    return mock_func_call_count;
}

/**
 * APDU buffer
 */
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

void explicit_bzero(void *s, size_t len) {
    memset(s, '\0', len);
    /* Compiler barrier.  */
    asm volatile("" ::: "memory");
}

unsigned int os_global_pin_check(unsigned char *pin_buffer,
                                 unsigned char pin_length) {
    add_mock_func_call(MOCK_FUNC_OS_GLOBAL_PIN_CHECK);
    return !strncmp(
        (const char *)pin_buffer, (const char *)current_pin, pin_length);
}

void os_perso_set_pin(unsigned int identity,
                      unsigned char *pin,
                      unsigned int length) {
    add_mock_func_call(MOCK_FUNC_OS_PERSO_SET_PIN);
    strncpy((char *)current_pin, (char *)pin, length);
}

void os_global_pin_invalidate(void) {
    add_mock_func_call(MOCK_FUNC_OS_GLOBAL_PIN_INVALIDATE);
}

void os_memset(void *dst, unsigned char c, unsigned int length) {
    memset(dst, c, length);
}

void mock_set_pin(unsigned char *pin, size_t n) {
    memcpy(current_pin, pin, n);
}

void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len) {
    add_mock_func_call(MOCK_FUNC_NVM_WRITE);
    if (src_adr == NULL) {
        // Treat as memory reset
        memset(dst_adr, 0, src_len);
    } else {
        // Treat as normal copy
        memmove(dst_adr, src_adr, src_len);
    }
}

void os_perso_wipe() {
    add_mock_func_call(MOCK_FUNC_OS_PERSO_WIPE);
}

void os_perso_derive_and_set_seed(unsigned char identity,
                                  const char *prefix,
                                  unsigned int prefix_length,
                                  const char *passphrase,
                                  unsigned int passphrase_length,
                                  const char *words,
                                  unsigned int words_length) {
    add_mock_func_call(MOCK_FUNC_OS_PERSO_DERIVE_AND_SET_SEED);
}

void os_perso_finalize(void) {
    add_mock_func_call(MOCK_FUNC_OS_PERSO_FINALIZE);
}

unsigned int os_perso_isonboarded(void) {
    add_mock_func_call(MOCK_FUNC_OS_PERSO_ISONBOARDED);
    return 1;
}

unsigned int os_global_pin_retries(void) {
    add_mock_func_call(MOCK_FUNC_OS_GLOBAL_PIN_RETRIES);
    return 0;
}

unsigned int bolos_ux_mnemonic_from_data(unsigned char *in,
                                         unsigned int inLength,
                                         unsigned char *out,
                                         unsigned int outLength) {
    add_mock_func_call(MOCK_FUNC_BOLOS_UX_MNEMONIC_FROM_DATA);
    const char mnemonic[] = "the-mnemonics";
    strcpy((char *)out, mnemonic);
    return strlen(mnemonic);
}
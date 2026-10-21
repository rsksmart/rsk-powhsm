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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "sig_utils.h"

// Taken from the secp256k1 curve parameters
// https://github.com/bitcoin-core/secp256k1/blob/master/src/scalar_4x64_impl.h#L15
static const uint8_t ORDER[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
    0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

static uint8_t G_sig[80];
static size_t G_sig_length;

// Append a DER integer with the given value bytes (as is, no padding added)
static void append_int(const uint8_t* value, size_t length) {
    G_sig[G_sig_length++] = 0x02;
    G_sig[G_sig_length++] = (uint8_t)length;
    memcpy(G_sig + G_sig_length, value, length);
    G_sig_length += length;
}

// Build a signature with the given r and s encodings
static void build_sig(const uint8_t* r,
                      size_t r_length,
                      const uint8_t* s,
                      size_t s_length) {
    G_sig_length = 2;
    append_int(r, r_length);
    append_int(s, s_length);
    G_sig[0] = 0x30;
    G_sig[1] = (uint8_t)(G_sig_length - 2);
}

// A 32-byte value with the high bit set, padded with a leading zero
static void padded_value(uint8_t* out, uint8_t fill) {
    out[0] = 0x00;
    memset(out + 1, fill, 32);
}

void test_sound_max_length() {
    printf("Testing max length signature is sound...\n");
    uint8_t r[33], s[33];
    padded_value(r, 0xBB);
    padded_value(s, 0xCC);
    build_sig(r, sizeof(r), s, sizeof(s));
    assert(G_sig_length == 72);
    assert(sig_der_is_sound(G_sig, G_sig_length));
}

void test_sound_short_components() {
    printf("Testing signature with short components is sound...\n");
    uint8_t r[] = {0x01};
    uint8_t s[31];
    memset(s, 0x7F, sizeof(s));
    build_sig(r, sizeof(r), s, sizeof(s));
    assert(sig_der_is_sound(G_sig, G_sig_length));
}

void test_sound_order_minus_one() {
    printf("Testing signature with r = s = n-1 is sound...\n");
    uint8_t v[33];
    v[0] = 0x00;
    memcpy(v + 1, ORDER, 32);
    v[32] -= 1;
    build_sig(v, sizeof(v), v, sizeof(v));
    assert(sig_der_is_sound(G_sig, G_sig_length));
}

void test_sound_parity_tag() {
    printf("Testing signature with parity bit on sequence tag is sound...\n");
    uint8_t r[] = {0x01}, s[] = {0x02};
    build_sig(r, sizeof(r), s, sizeof(s));
    G_sig[0] = 0x31;
    assert(sig_der_is_sound(G_sig, G_sig_length));
}

void test_sound_superfluous_zeroes() {
    printf("Testing signature with superfluous leading zeroes is sound...\n");
    uint8_t r[] = {0x00, 0x00, 0x01}, s[] = {0x00, 0x7F};
    build_sig(r, sizeof(r), s, sizeof(s));
    assert(sig_der_is_sound(G_sig, G_sig_length));
}

void test_unsound_null_and_lengths() {
    printf("Testing NULL and out of bounds lengths are unsound...\n");
    uint8_t r[] = {0x01}, s[] = {0x02};
    build_sig(r, sizeof(r), s, sizeof(s));
    assert(sig_der_is_sound(G_sig, G_sig_length));
    assert(!sig_der_is_sound(NULL, G_sig_length));
    assert(!sig_der_is_sound(G_sig, 0));
    assert(!sig_der_is_sound(G_sig, 7));
    assert(!sig_der_is_sound(G_sig, 73));
}

void test_unsound_tags() {
    printf("Testing invalid tags are unsound...\n");
    uint8_t r[] = {0x01}, s[] = {0x02};

    uint8_t bad_seq_tags[] = {0x00, 0x20, 0x32, 0x70, 0xB0};
    for (size_t i = 0; i < sizeof(bad_seq_tags); i++) {
        build_sig(r, sizeof(r), s, sizeof(s));
        G_sig[0] = bad_seq_tags[i];
        assert(!sig_der_is_sound(G_sig, G_sig_length));
    }

    build_sig(r, sizeof(r), s, sizeof(s));
    G_sig[2] = 0x03; // r tag
    assert(!sig_der_is_sound(G_sig, G_sig_length));

    build_sig(r, sizeof(r), s, sizeof(s));
    G_sig[5] = 0x03; // s tag
    assert(!sig_der_is_sound(G_sig, G_sig_length));
}

void test_unsound_length_mismatches() {
    printf("Testing length mismatches are unsound...\n");
    uint8_t r[] = {0x01}, s[] = {0x02};

    // Sequence length too long and too short
    build_sig(r, sizeof(r), s, sizeof(s));
    G_sig[1]++;
    assert(!sig_der_is_sound(G_sig, G_sig_length));
    G_sig[1] -= 2;
    assert(!sig_der_is_sound(G_sig, G_sig_length));

    // Trailing data
    build_sig(r, sizeof(r), s, sizeof(s));
    G_sig[G_sig_length++] = 0x00;
    G_sig[1]++;
    assert(!sig_der_is_sound(G_sig, G_sig_length));

    // r length overruns the buffer
    build_sig(r, sizeof(r), s, sizeof(s));
    G_sig[3] = 0x10;
    assert(!sig_der_is_sound(G_sig, G_sig_length));

    // s length overruns the buffer
    build_sig(r, sizeof(r), s, sizeof(s));
    G_sig[6] = 0x02;
    assert(!sig_der_is_sound(G_sig, G_sig_length));

    // Missing s
    G_sig_length = 2;
    append_int(r, sizeof(r));
    G_sig[0] = 0x30;
    G_sig[1] = (uint8_t)(G_sig_length - 2);
    G_sig[G_sig_length++] = 0x00;
    G_sig[G_sig_length++] = 0x00;
    G_sig[G_sig_length++] = 0x00;
    G_sig[1] = (uint8_t)(G_sig_length - 2);
    assert(!sig_der_is_sound(G_sig, G_sig_length));
}

void test_unsound_component_lengths() {
    printf("Testing invalid component lengths are unsound...\n");
    uint8_t s[] = {0x02};

    // Zero length r
    build_sig(NULL, 0, s, sizeof(s));
    assert(!sig_der_is_sound(G_sig, G_sig_length));

    // 34 byte r (padded), even if the value is small
    uint8_t r[34];
    memset(r, 0, sizeof(r));
    r[33] = 0x01;
    build_sig(r, sizeof(r), s, sizeof(s));
    assert(!sig_der_is_sound(G_sig, G_sig_length));

    // 33 byte r without a leading zero (value > 32 bytes)
    uint8_t r33[33];
    memset(r33, 0x01, sizeof(r33));
    build_sig(r33, sizeof(r33), s, sizeof(s));
    assert(!sig_der_is_sound(G_sig, G_sig_length));
}

void test_unsound_negative() {
    printf("Testing negative components are unsound...\n");
    uint8_t neg[32], pos[] = {0x01};
    memset(neg, 0xBB, sizeof(neg));
    build_sig(neg, sizeof(neg), pos, sizeof(pos));
    assert(!sig_der_is_sound(G_sig, G_sig_length));
    build_sig(pos, sizeof(pos), neg, sizeof(neg));
    assert(!sig_der_is_sound(G_sig, G_sig_length));
}

void test_unsound_out_of_range() {
    printf("Testing out of range components are unsound...\n");
    uint8_t one[] = {0x01};
    uint8_t zero[] = {0x00};
    uint8_t zeroes[] = {0x00, 0x00, 0x00};
    uint8_t v[33];

    // Zero
    build_sig(zero, sizeof(zero), one, sizeof(one));
    assert(!sig_der_is_sound(G_sig, G_sig_length));
    build_sig(one, sizeof(one), zero, sizeof(zero));
    assert(!sig_der_is_sound(G_sig, G_sig_length));
    build_sig(zeroes, sizeof(zeroes), one, sizeof(one));
    assert(!sig_der_is_sound(G_sig, G_sig_length));

    // n
    v[0] = 0x00;
    memcpy(v + 1, ORDER, 32);
    build_sig(v, sizeof(v), one, sizeof(one));
    assert(!sig_der_is_sound(G_sig, G_sig_length));
    build_sig(one, sizeof(one), v, sizeof(v));
    assert(!sig_der_is_sound(G_sig, G_sig_length));

    // n+1
    v[32] += 1;
    build_sig(v, sizeof(v), one, sizeof(one));
    assert(!sig_der_is_sound(G_sig, G_sig_length));
    build_sig(one, sizeof(one), v, sizeof(v));
    assert(!sig_der_is_sound(G_sig, G_sig_length));

    // Max 32-byte value
    padded_value(v, 0xFF);
    build_sig(v, sizeof(v), one, sizeof(one));
    assert(!sig_der_is_sound(G_sig, G_sig_length));
    build_sig(one, sizeof(one), v, sizeof(v));
    assert(!sig_der_is_sound(G_sig, G_sig_length));
}

int main() {
    test_sound_max_length();
    test_sound_short_components();
    test_sound_order_minus_one();
    test_sound_parity_tag();
    test_sound_superfluous_zeroes();

    test_unsound_null_and_lengths();
    test_unsound_tags();
    test_unsound_length_mismatches();
    test_unsound_component_lengths();
    test_unsound_negative();
    test_unsound_out_of_range();

    printf("All sig_utils tests passed!\n");
    return 0;
}

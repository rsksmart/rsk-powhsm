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
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <mbedtls/bignum.h>

#include "bigdigits.h"
#include "bigdigits_helper.h"

#define DEBUG 0
#define MAX_TEST_DIGITS 12
#define INDIVIDUAL_CASES 200

#define DECLARE_AND_INIT(var, digits)                   \
    DIGIT_T var[(digits)];                              \
    for (size_t __i__ = 0; __i__ < (digits); __i__++) { \
        var[__i__] = 0;                                 \
    }

void test_set_zero(size_t ndigits) {
    printf("Testing mpSetZero with %lu digits...\n", ndigits);
    DIGIT_T a[ndigits];

    for (size_t i = 0; i < ndigits; i++)
        a[i] = 123;
    mpSetZero(a, ndigits);
    for (size_t i = 0; i < ndigits; ++i)
        assert(a[i] == 0);
}

void test_set_digit(size_t ndigits) {
    printf("Testing mpSetDigit with %lu digits...\n", ndigits);
    DIGIT_T a[ndigits];
    DECLARE_AND_INIT(b, ndigits);
    b[0] = 0x11223344;
    DECLARE_AND_INIT(c, ndigits);
    c[0] = 0x11223345;

    for (size_t i = 0; i < ndigits; i++)
        a[i] = 456;
    mpSetDigit(a, 0x11223344, ndigits);
    for (size_t i = 1; i < ndigits; ++i)
        assert(a[i] == 0);
    assert(a[0] == 0x11223344);
    assert(mpCompare_ct(a, b, ndigits) == 0);
    assert(mpCompare_ct(a, c, ndigits) != 0);
}

void test_set_equal(size_t ndigits) {
    printf("Testing mpSetEqual with %lu digits...\n", ndigits);
    DECLARE_AND_INIT(a, ndigits);
    DECLARE_AND_INIT(b, ndigits);

    for (size_t i = 0; i < ndigits; ++i)
        b[i] = 0x11111100 + i;

    assert(mpCompare_ct(a, b, ndigits) != 0);
    mpSetEqual(a, b, ndigits);
    assert(mpCompare_ct(a, b, ndigits) == 0);

    for (size_t i = 0; i < ndigits; ++i)
        assert(a[i] == 0x11111100 + i);
}

void assert_compare(DIGIT_T a[], DIGIT_T b[], size_t ndigits, int expected) {
    assert(mpCompare(a, b, ndigits) == expected);
    assert(mpCompare_ct(a, b, ndigits) == expected);
}

#define ASSERT_EQ(a, b) assert_compare(a, b, ndigits, 0);
#define ASSERT_LT(a, b) assert_compare(a, b, ndigits, -1);
#define ASSERT_GT(a, b) assert_compare(a, b, ndigits, 1);

void test_compare(size_t ndigits) {
    printf("Testing mpCompare and mpCompare_ct with %lu digits...\n", ndigits);
    DECLARE_AND_INIT(a, ndigits);
    DECLARE_AND_INIT(b, ndigits);

    ASSERT_EQ(a, b);

    for (size_t i = 0; i < ndigits; i++)
        a[i] = 0x12345678;
    mpSetEqual(a, b, ndigits);

    ASSERT_EQ(a, b);

    mpSetDigit(a, 100, ndigits);
    mpSetDigit(b, 101, ndigits);
    ASSERT_LT(a, b);
    mpSetDigit(b, 99, ndigits);
    ASSERT_GT(a, b);

    for (size_t i = 0; i < ndigits - 1; i++) {
        mpSetZero(a, ndigits);
        mpSetZero(b, ndigits);
        ASSERT_EQ(a, b);
        a[i] = 0xffffffff;
        b[i + 1] = 1;
        ASSERT_LT(a, b);
        ASSERT_GT(b, a);
    }

    mpSetZero(b, ndigits);
    b[ndigits - 1] = 0xffffffff;
    for (size_t i = 0; i < ndigits - 1; i++) {
        mpSetZero(a, ndigits);
        a[i] = 0xffffffff;
        ASSERT_LT(a, b);
        ASSERT_GT(b, a);
    }
    mpSetZero(a, ndigits);
    a[ndigits - 1] = 0xffffffff;
    ASSERT_EQ(a, b);
}

void test_sizeof(size_t ndigits) {
    printf("Testing mpSizeof with %lu digits...\n", ndigits);

    DECLARE_AND_INIT(a, ndigits);

    assert(mpSizeof(a, ndigits) == 0);
    for (size_t i = 0; i < ndigits; i++) {
        mpSetZero(a, ndigits);
        a[i] = 1;
        assert(mpSizeof(a, ndigits) == i + 1);
    }
}

void random_bytes(uint8_t* buf, size_t num_bytes) {
    buf[0] = (uint8_t)((rand() & 0xFF) | 0x01); // No leading zero
    for (size_t i = 1; i < num_bytes; i++)
        buf[i] = (uint8_t)(rand() & 0xFF);
}

void assert_eq_bigd_mbed(DIGIT_T* bd_var, mbedtls_mpi* mt_var, size_t ndigits) {
    char out_bd[100], out_mt[100];
    size_t aux, offset;
    mbedtls_mpi_write_string(mt_var, 16, out_mt, sizeof(out_mt), &aux);
    aux = ndigits;
    offset = 0;
    int skip = 1;
    int lzeroes = 0;
    while (aux--) {
        unsigned i = sizeof(DIGIT_T);
        while (i-- > 0) {
            uint8_t __b__ =
                (uint8_t)((bd_var[aux] & (0xFF << (8 * i))) >> (8 * i));
            if (!skip || __b__ > 0) {
                skip = 0;
                sprintf(out_bd + offset, "%02" PRIX8, __b__);
                offset += 2;
            } else {
                lzeroes++;
            }
        }
    }
    // Special zero case handling
    if (skip) {
        sprintf(out_bd, "00");
        lzeroes = ndigits * sizeof(DIGIT_T) - 1;
    }
    if (DEBUG)
        printf("MBED: %s\n", out_mt);
    if (DEBUG)
        printf("BIGD: %s\n", out_bd);
    assert(strlen(out_mt) == (ndigits * sizeof(DIGIT_T) - lzeroes) * 2);
    assert(strcmp(out_bd, out_mt) == 0);
}

void assert_randomize(DIGIT_T* bd_var, mbedtls_mpi* mt_var, size_t ndigits) {
    uint8_t buf[ndigits * sizeof(DIGIT_T)];

    random_bytes(buf, sizeof(buf));
    parse_bigint_be(buf, sizeof(buf), bd_var, ndigits);
    mbedtls_mpi_read_binary(mt_var, buf, sizeof(buf));

    assert_eq_bigd_mbed(bd_var, mt_var, ndigits);
}

void test_addition(size_t ndigits) {
    printf("Testing mpAdd with %lu digits...\n", ndigits);

    DECLARE_AND_INIT(a, ndigits);
    DECLARE_AND_INIT(b, ndigits);
    DECLARE_AND_INIT(sum, ndigits);

    mbedtls_mpi ref_a, ref_b, ref_sum;

    mbedtls_mpi_init(&ref_a);
    mbedtls_mpi_init(&ref_b);
    mbedtls_mpi_init(&ref_sum);

    for (unsigned i = 0; i < INDIVIDUAL_CASES; i++) {
        if (DEBUG)
            printf("mpAdd new case with %lu digits\n", ndigits);
        assert_randomize(a, &ref_a, ndigits);
        assert_randomize(b, &ref_b, ndigits);

        DIGIT_T carry = mpAdd(sum, a, b, ndigits);
        assert(carry == 0 || carry == 1);
        mbedtls_mpi_add_mpi(&ref_sum, &ref_a, &ref_b);
        DIGIT_T carry_ref =
            mbedtls_mpi_size(&ref_sum) - mbedtls_mpi_size(&ref_a);
        assert(carry_ref <= 1);
        if (carry_ref)
            mbedtls_mpi_set_bit(
                &ref_sum, (mbedtls_mpi_size(&ref_sum) - 1) * 8, 0);
        assert_eq_bigd_mbed(sum, &ref_sum, ndigits);
        assert(carry == carry_ref);
    }

    mbedtls_mpi_free(&ref_a);
    mbedtls_mpi_free(&ref_b);
    mbedtls_mpi_free(&ref_sum);
}

void test_division(size_t ndigits) {
    printf("Testing mpDivide with %lu digits...\n", ndigits);

    DECLARE_AND_INIT(a, ndigits);
    DECLARE_AND_INIT(q, ndigits);
    DECLARE_AND_INIT(r, ndigits);

    mbedtls_mpi ref_a, ref_b, ref_q, ref_r;

    mbedtls_mpi_init(&ref_a);
    mbedtls_mpi_init(&ref_b);
    mbedtls_mpi_init(&ref_q);
    mbedtls_mpi_init(&ref_r);

    for (unsigned divdig = 1; divdig <= ndigits; divdig++) {
        DECLARE_AND_INIT(b, divdig);

        mpSetZero(b, divdig);
        assert(mpDivide(q, r, a, ndigits, b, divdig) == -1);

        for (unsigned i = 0; i < INDIVIDUAL_CASES; i++) {
            if (DEBUG)
                printf("mpDivide new case with %lu digits and %lu digits "
                       "divisor\n",
                       ndigits,
                       divdig);

            assert_randomize(a, &ref_a, ndigits);
            assert_randomize(b, &ref_b, divdig);

            assert(mpDivide(q, r, a, ndigits, b, divdig) == 0);
            assert(mbedtls_mpi_div_mpi(&ref_q, &ref_r, &ref_a, &ref_b) == 0);

            assert_eq_bigd_mbed(q, &ref_q, ndigits);
            assert_eq_bigd_mbed(r, &ref_r, divdig);
        }
    }

    mbedtls_mpi_free(&ref_a);
    mbedtls_mpi_free(&ref_b);
    mbedtls_mpi_free(&ref_q);
    mbedtls_mpi_free(&ref_r);
}

void test_shift(size_t ndigits) {
    printf("Testing mpShiftLeft and mpShiftRight with %lu digits...\n",
           ndigits);

    DECLARE_AND_INIT(a, ndigits);
    DECLARE_AND_INIT(sh, ndigits);

    mbedtls_mpi ref_a, ref_sh;

    mbedtls_mpi_init(&ref_a);
    mbedtls_mpi_init(&ref_sh);

    for (size_t bits = 0; bits <= ndigits * 8; bits++) {
        for (unsigned i = 0; i < INDIVIDUAL_CASES; i++) {
            if (DEBUG)
                printf("mpShiftLeft and mpShiftRight new case with %lu digits "
                       "and %lu bits shifts\n",
                       ndigits,
                       bits);

            assert_randomize(a, &ref_a, ndigits);

            mpShiftLeft(sh, a, bits, ndigits);
            mbedtls_mpi_shift_l(&ref_a, bits);
            for (unsigned b = 0; b < bits; b++)
                mbedtls_mpi_set_bit(
                    &ref_a, ndigits * sizeof(DIGIT_T) * 8 + b, 0);
            assert_eq_bigd_mbed(sh, &ref_a, ndigits);

            assert_randomize(a, &ref_a, ndigits);

            mpShiftRight(sh, a, bits, ndigits);
            mbedtls_mpi_shift_r(&ref_a, bits);
            assert_eq_bigd_mbed(sh, &ref_a, ndigits);
        }
    }

    mbedtls_mpi_free(&ref_a);
    mbedtls_mpi_free(&ref_sh);
}

int main(void) {
    time_t rseed = time(NULL);
    srand(rseed);
    printf("Test seed: %lu\n", rseed);

    for (size_t d = 1; d <= MAX_TEST_DIGITS; ++d) {
        test_set_zero(d);
        test_set_digit(d);
        test_set_equal(d);
        test_compare(d);
        test_sizeof(d);
        test_addition(d);
        test_division(d);
        test_shift(d);
    }
    return 0;
}

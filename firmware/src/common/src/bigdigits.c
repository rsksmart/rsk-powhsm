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

/* $Id: bigdigits.c $ */

/***** BEGIN LICENSE BLOCK *****
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2001-16 David Ireland, D.I. Management Services Pty Limited
 * <http://www.di-mgt.com.au/bigdigits.html>. All rights reserved.
 *
 ***** END LICENSE BLOCK *****/
/*
 * Last updated:
 * $Date: 2016-03-31 09:51:00 $
 * $Revision: 2.6.1 $
 * $Author: dai $
 */

/* Core code for BigDigits library "mp" functions */

/* No asserts in stripped down version of this library */
#define assert(x)

#include "bigdigits.h"

#define BITS_PER_HALF_DIGIT (BITS_PER_DIGIT / 2)
#define LOHALF(x) ((DIGIT_T)((x) & MAX_HALF_DIGIT))
#define HIHALF(x) ((DIGIT_T)((x) >> BITS_PER_HALF_DIGIT & MAX_HALF_DIGIT))
#define TOHIGH(x) ((DIGIT_T)((x) << BITS_PER_HALF_DIGIT))

DIGIT_T mpSetZero(volatile DIGIT_T a[], size_t ndigits)
{    /* Sets a = 0 */

    /* Prevent optimiser ignoring this */
    volatile DIGIT_T optdummy;
    volatile DIGIT_T *p = a;

    while (ndigits--)
        a[ndigits] = 0;
    
    optdummy = *p;
    return optdummy;
}

void mpSetDigit(DIGIT_T a[], DIGIT_T d, size_t ndigits)
{    /* Sets a = d where d is a single digit */
    size_t i;
    
    for (i = 1; i < ndigits; i++)
    {
        a[i] = 0;
    }
    a[0] = d;
}

/** Returns number of significant digits in a */
size_t mpSizeof(const DIGIT_T a[], size_t ndigits)
{        
    while(ndigits--)
    {
        if (a[ndigits] != 0)
            return (++ndigits);
    }
    return 0;
}

void mpSetEqual(DIGIT_T a[], const DIGIT_T b[], size_t ndigits)
{    /* Sets a = b */
    size_t i;
    
    for (i = 0; i < ndigits; i++)
    {
        a[i] = b[i];
    }
}

DIGIT_T mpAdd(DIGIT_T w[], const DIGIT_T u[], const DIGIT_T v[], size_t ndigits)
{
    /*    Calculates w = u + v
        where w, u, v are multiprecision integers of ndigits each
        Returns carry if overflow. Carry = 0 or 1.

        Ref: Knuth Vol 2 Ch 4.3.1 p 266 Algorithm A.
    */

    DIGIT_T k;
    size_t j;

    /*     w can't be the same as v
        Stop if assert is working, else return error (overflow = -1)
    */
    if (w == v) {
        assert(w != v);
        return MAX_DIGIT;
    }

    /* Step A1. Initialise */
    k = 0;

    for (j = 0; j < ndigits; j++)
    {
        /*    Step A2. Add digits w_j = (u_j + v_j + k)
            Set k = 1 if carry (overflow) occurs
        */
        w[j] = u[j] + k;
        if (w[j] < k)
            k = 1;
        else
            k = 0;
        
        w[j] += v[j];
        if (w[j] < v[j])
            k++;

    }    /* Step A3. Loop on j */

    return k;    /* w_n = k */
}

static int QhatTooBig(DIGIT_T qhat, DIGIT_T rhat,
                      DIGIT_T vn2, DIGIT_T ujn2)
{    /*    Returns true if Qhat is too big
        i.e. if (Qhat * Vn-2) > (b.Rhat + Uj+n-2)
    */
    DIGIT_T t[2];

    spMultiply(t, qhat, vn2);
    if (t[1] < rhat)
        return 0;
    else if (t[1] > rhat)
        return 1;
    else if (t[0] > ujn2)
        return 1;

    return 0;
}

static DIGIT_T mpMultSub(DIGIT_T wn, DIGIT_T w[], const DIGIT_T v[],
                       DIGIT_T q, size_t n)
{    /*    Compute w = w - qv
        where w = (WnW[n-1]...W[0])
        return modified Wn.
    */
    DIGIT_T k, t[2];
    size_t i;

    if (q == 0)    /* No change */
        return wn;

    k = 0;

    for (i = 0; i < n; i++)
    {
        spMultiply(t, q, v[i]);
        w[i] -= k;
        if (w[i] > MAX_DIGIT - k)
            k = 1;
        else
            k = 0;
        w[i] -= t[0];
        if (w[i] > MAX_DIGIT - t[0])
            k++;
        k += t[1];
    }

    /* Cope with Wn not stored in array w[0..n-1] */
    wn -= k;

    return wn;
}

int mpDivide(DIGIT_T q[], DIGIT_T r[], const DIGIT_T u[],
    size_t udigits, DIGIT_T v[], size_t vdigits)
{    /*    Computes quotient q = u / v and remainder r = u mod v
        where q, r, u are multiple precision digits
        all of udigits and the divisor v is vdigits.

        Ref: Knuth Vol 2 Ch 4.3.1 p 272 Algorithm D.

        Do without extra storage space, i.e. use r[] for
        normalised u[], unnormalise v[] at end, and cope with
        extra digit Uj+n added to u after normalisation.

        WARNING: this trashes q and r first, so cannot do
        u = u / v or v = u mod v.
        It also changes v temporarily so cannot make it const.
    */
    size_t shift;
    int n, m, j;
    DIGIT_T bitmask, overflow;
    DIGIT_T qhat, rhat, t[2];
    DIGIT_T *uu, *ww;
    int qhatOK, cmp;

    /* Clear q and r */
    mpSetZero(q, udigits);
    mpSetZero(r, udigits);

    /* Work out exact sizes of u and v */
    n = (int)mpSizeof(v, vdigits);
    m = (int)mpSizeof(u, udigits);
    m -= n;

    /* Catch special cases */
    if (n == 0)
        return -1;    /* Error: divide by zero */

    if (n == 1)
    {    /* Use short division instead */
        r[0] = mpShortDiv(q, u, v[0], udigits);
        return 0;
    }

    if (m < 0)
    {    /* v > u, so just set q = 0 and r = u */
        mpSetEqual(r, u, udigits);
        return 0;
    }

    if (m == 0)
    {    /* u and v are the same length */
        cmp = mpCompare(u, v, (size_t)n);
        if (cmp < 0)
        {    /* v > u, as above */
            mpSetEqual(r, u, udigits);
            return 0;
        }
        else if (cmp == 0)
        {    /* v == u, so set q = 1 and r = 0 */
            mpSetDigit(q, 1, udigits);
            return 0;
        }
    }

    /*    In Knuth notation, we have:
        Given
        u = (Um+n-1 ... U1U0)
        v = (Vn-1 ... V1V0)
        Compute
        q = u/v = (QmQm-1 ... Q0)
        r = u mod v = (Rn-1 ... R1R0)
    */

    /*    Step D1. Normalise */
    /*    Requires high bit of Vn-1
        to be set, so find most signif. bit then shift left,
        i.e. d = 2^shift, u' = u * d, v' = v * d.
    */
    bitmask = HIBITMASK;
    for (shift = 0; shift < BITS_PER_DIGIT; shift++)
    {
        if (v[n-1] & bitmask)
            break;
        bitmask >>= 1;
    }

    /* Normalise v in situ - NB only shift non-zero digits */
    overflow = mpShiftLeft(v, v, shift, n);

    /* Copy normalised dividend u*d into r */
    overflow = mpShiftLeft(r, u, shift, n + m);
    uu = r;    /* Use ptr to keep notation constant */

    t[0] = overflow;    /* Extra digit Um+n */

    /* Step D2. Initialise j. Set j = m */
    for (j = m; j >= 0; j--)
    {
        /* Step D3. Set Qhat = [(b.Uj+n + Uj+n-1)/Vn-1] 
           and Rhat = remainder */
        qhatOK = 0;
        t[1] = t[0];    /* This is Uj+n */
        t[0] = uu[j+n-1];
        overflow = spDivide(&qhat, &rhat, t, v[n-1]);

        /* Test Qhat */
        if (overflow)
        {    /* Qhat == b so set Qhat = b - 1 */
            qhat = MAX_DIGIT;
            rhat = uu[j+n-1];
            rhat += v[n-1];
            if (rhat < v[n-1])    /* Rhat >= b, so no re-test */
                qhatOK = 1;
        }
        /* [VERSION 2: Added extra test "qhat && "] */
        if (qhat && !qhatOK && QhatTooBig(qhat, rhat, v[n-2], uu[j+n-2]))
        {    /* If Qhat.Vn-2 > b.Rhat + Uj+n-2 
               decrease Qhat by one, increase Rhat by Vn-1
            */
            qhat--;
            rhat += v[n-1];
            /* Repeat this test if Rhat < b */
            if (!(rhat < v[n-1]))
                if (QhatTooBig(qhat, rhat, v[n-2], uu[j+n-2]))
                    qhat--;
        }


        /* Step D4. Multiply and subtract */
        ww = &uu[j];
        overflow = mpMultSub(t[1], ww, v, qhat, (size_t)n);

        /* Step D5. Test remainder. Set Qj = Qhat */
        q[j] = qhat;
        if (overflow)
        {    /* Step D6. Add back if D4 was negative */
            q[j]--;
            overflow = mpAdd(ww, ww, v, (size_t)n);
        }

        t[0] = uu[j+n-1];    /* Uj+n on next round */

    }    /* Step D7. Loop on j */

    /* Clear high digits in uu */
    for (j = n; j < m+n; j++)
        uu[j] = 0;

    /* Step D8. Unnormalise. */

    mpShiftRight(r, r, shift, n);
    mpShiftRight(v, v, shift, n);

    return 0;
}

DIGIT_T mpShortDiv(DIGIT_T q[], const DIGIT_T u[], DIGIT_T v, 
                   size_t ndigits)
{
    /*    Calculates quotient q = u div v
        Returns remainder r = u mod v
        where q, u are multiprecision integers of ndigits each
        and r, v are single precision digits.

        Makes no assumptions about normalisation.
        
        Ref: Knuth Vol 2 Ch 4.3.1 Exercise 16 p625
    */
    size_t j;
    DIGIT_T t[2], r;
    size_t shift;
    DIGIT_T bitmask, overflow, *uu;

    if (ndigits == 0) return 0;
    if (v == 0)    return 0;    /* Divide by zero error */

    /*    Normalise first */
    /*    Requires high bit of V
        to be set, so find most signif. bit then shift left,
        i.e. d = 2^shift, u' = u * d, v' = v * d.
    */
    bitmask = HIBITMASK;
    for (shift = 0; shift < BITS_PER_DIGIT; shift++)
    {
        if (v & bitmask)
            break;
        bitmask >>= 1;
    }

    v <<= shift;
    overflow = mpShiftLeft(q, u, shift, ndigits);
    uu = q;
    
    /* Step S1 - modified for extra digit. */
    r = overflow;    /* New digit Un */
    j = ndigits;
    while (j--)
    {
        /* Step S2. */
        t[1] = r;
        t[0] = uu[j];
        overflow = spDivide(&q[j], &r, t, v);
    }

    /* Unnormalise */
    r >>= shift;
    
    return r;
}

DIGIT_T mpShiftLeft(DIGIT_T a[], const DIGIT_T *b,
    size_t shift, size_t ndigits)
{    /* Computes a = b << shift */
    /* [v2.1] Modified to cope with shift > BITS_PERDIGIT */
    size_t i, y, nw, bits;
    DIGIT_T mask, carry, nextcarry;

    /* Do we shift whole digits? */
    if (shift >= BITS_PER_DIGIT)
    {
        nw = shift / BITS_PER_DIGIT;
        i = ndigits;
        while (i--)
        {
            if (i >= nw)
                a[i] = b[i-nw];
            else
                a[i] = 0;
        }
        /* Call again to shift bits inside digits */
        bits = shift % BITS_PER_DIGIT;
        carry = b[ndigits-nw] << bits;
        if (bits) 
            carry |= mpShiftLeft(a, a, bits, ndigits);
        return carry;
    }
    else
    {
        bits = shift;
    }

    /* Construct mask = high bits set */
    mask = ~(~(DIGIT_T)0 >> bits);
    
    y = BITS_PER_DIGIT - bits;
    carry = 0;
    for (i = 0; i < ndigits; i++)
    {
        nextcarry = (b[i] & mask) >> y;
        a[i] = b[i] << bits | carry;
        carry = nextcarry;
    }

    return carry;
}

DIGIT_T mpShiftRight(DIGIT_T a[], const DIGIT_T b[], size_t shift, size_t ndigits)
{    /* Computes a = b >> shift */
    /* [v2.1] Modified to cope with shift > BITS_PERDIGIT */
    size_t i, y, nw, bits;
    DIGIT_T mask, carry, nextcarry;

    /* Do we shift whole digits? */
    if (shift >= BITS_PER_DIGIT)
    {
        nw = shift / BITS_PER_DIGIT;
        for (i = 0; i < ndigits; i++)
        {
            if ((i+nw) < ndigits)
                a[i] = b[i+nw];
            else
                a[i] = 0;
        }
        /* Call again to shift bits inside digits */
        bits = shift % BITS_PER_DIGIT;
        carry = b[nw-1] >> bits;
        if (bits) 
            carry |= mpShiftRight(a, a, bits, ndigits);
        return carry;
    }
    else
    {
        bits = shift;
    }

    /* Construct mask to set low bits */
    /* (thanks to Jesse Chisholm for suggesting this improved technique) */
    mask = ~(~(DIGIT_T)0 << bits);
    
    y = BITS_PER_DIGIT - bits;
    carry = 0;
    i = ndigits;
    while (i--)
    {
        nextcarry = (b[i] & mask) << y;
        a[i] = b[i] >> bits | carry;
        carry = nextcarry;
    }

    return carry;
}

/** Returns sign of (a - b) as 0, +1 or -1 (constant-time) */
int mpCompare_ct(const DIGIT_T a[], const DIGIT_T b[], size_t ndigits)
{
    /* All these vars are either 0 or 1 */
    unsigned int gt = 0;
    unsigned int lt = 0;
    unsigned int mask = 1;    /* Set to zero once first inequality found */
    unsigned int c;

    while (ndigits--) {
        gt |= (a[ndigits] > b[ndigits]) & mask;
        lt |= (a[ndigits] < b[ndigits]) & mask;
        c = (gt | lt);
        mask &= (c-1);    /* Unchanged if c==0 or mask==0, else mask=0 */
    }

    return (int)gt - (int)lt;    /* EQ=0 GT=+1 LT=-1 */
}

/** Returns sign of (a - b) as 0, +1 or -1. Not constant-time. */
int mpCompare(const DIGIT_T a[], const DIGIT_T b[], size_t ndigits)
{
    /* if (ndigits == 0) return 0; // deleted [v2.5] */

    while (ndigits--)
    {
        if (a[ndigits] > b[ndigits])
            return 1;    /* GT */
        if (a[ndigits] < b[ndigits])
            return -1;    /* LT */
    }

    return 0;    /* EQ */
}

int spMultiply(DIGIT_T p[2], DIGIT_T x, DIGIT_T y)
{    /*    Computes p = x * y */
    /*    Ref: Arbitrary Precision Computation
    http://numbers.computation.free.fr/Constants/constants.html

         high    p1                p0     low
        +--------+--------+--------+--------+
        |      x1*y1      |      x0*y0      |
        +--------+--------+--------+--------+
               +-+--------+--------+
               |1| (x0*y1 + x1*y1) |
               +-+--------+--------+
                ^carry from adding (x0*y1+x1*y1) together
                        +-+
                        |1|< carry from adding LOHALF t
                        +-+  to high half of p0
    */
    DIGIT_T x0, y0, x1, y1;
    DIGIT_T t, u, carry;

    /*    Split each x,y into two halves
        x = x0 + B*x1
        y = y0 + B*y1
        where B = 2^16, half the digit size
        Product is
        xy = x0y0 + B(x0y1 + x1y0) + B^2(x1y1)
    */

    x0 = LOHALF(x);
    x1 = HIHALF(x);
    y0 = LOHALF(y);
    y1 = HIHALF(y);

    /* Calc low part - no carry */
    p[0] = x0 * y0;

    /* Calc middle part */
    t = x0 * y1;
    u = x1 * y0;
    t += u;
    if (t < u)
        carry = 1;
    else
        carry = 0;

    /*    This carry will go to high half of p[1]
        + high half of t into low half of p[1] */
    carry = TOHIGH(carry) + HIHALF(t);

    /* Add low half of t to high half of p[0] */
    t = TOHIGH(t);
    p[0] += t;
    if (p[0] < t)
        carry++;

    p[1] = x1 * y1;
    p[1] += carry;


    return 0;
}

/* spDivide */

#define B (MAX_HALF_DIGIT + 1)

static void spMultSub(DIGIT_T uu[2], DIGIT_T qhat, DIGIT_T v1, DIGIT_T v0)
{
    /*    Compute uu = uu - q(v1v0) 
        where uu = u3u2u1u0, u3 = 0
        and u_n, v_n are all half-digits
        even though v1, v2 are passed as full digits.
    */
    DIGIT_T p0, p1, t;

    p0 = qhat * v0;
    p1 = qhat * v1;
    t = p0 + TOHIGH(LOHALF(p1));
    uu[0] -= t;
    if (uu[0] > MAX_DIGIT - t)
        uu[1]--;    /* Borrow */
    uu[1] -= HIHALF(p1);
}

DIGIT_T spDivide(DIGIT_T *q, DIGIT_T *r, const DIGIT_T u[2], DIGIT_T v)
{    /*    Computes quotient q = u / v, remainder r = u mod v
        where u is a double digit
        and q, v, r are single precision digits.
        Returns high digit of quotient (max value is 1)
        CAUTION: Assumes normalised such that v1 >= b/2
        where b is size of HALF_DIGIT
        i.e. the most significant bit of v should be one

        In terms of half-digits in Knuth notation:
        (q2q1q0) = (u4u3u2u1u0) / (v1v0)
        (r1r0) = (u4u3u2u1u0) mod (v1v0)
        for m = 2, n = 2 where u4 = 0
        q2 is either 0 or 1.
        We set q = (q1q0) and return q2 as "overflow"
    */
    DIGIT_T qhat, rhat, t, v0, v1, u0, u1, u2, u3;
    DIGIT_T uu[2], q2;

    /* Check for normalisation */
    if (!(v & HIBITMASK))
    {    /* Stop if assert is working, else return error */
        assert(v & HIBITMASK);
        *q = *r = 0;
        return MAX_DIGIT;
    }
    
    /* Split up into half-digits */
    v0 = LOHALF(v);
    v1 = HIHALF(v);
    u0 = LOHALF(u[0]);
    u1 = HIHALF(u[0]);
    u2 = LOHALF(u[1]);
    u3 = HIHALF(u[1]);

    /* Do three rounds of Knuth Algorithm D Vol 2 p272 */

    /*    ROUND 1. Set j = 2 and calculate q2 */
    /*    Estimate qhat = (u4u3)/v1  = 0 or 1 
        then set (u4u3u2) -= qhat(v1v0)
        where u4 = 0.
    */
/* [Replaced in Version 2] -->
    qhat = u3 / v1;
    if (qhat > 0)
    {
        rhat = u3 - qhat * v1;
        t = TOHIGH(rhat) | u2;
        if (qhat * v0 > t)
            qhat--;
    }
<-- */
    qhat = (u3 < v1 ? 0 : 1);
    if (qhat > 0)
    {    /* qhat is one, so no need to mult */
        rhat = u3 - v1;
        /* t = r.b + u2 */
        t = TOHIGH(rhat) | u2;
        if (v0 > t)
            qhat--;
    }

    uu[1] = 0;        /* (u4) */
    uu[0] = u[1];    /* (u3u2) */
    if (qhat > 0)
    {
        /* (u4u3u2) -= qhat(v1v0) where u4 = 0 */
        spMultSub(uu, qhat, v1, v0);
        if (HIHALF(uu[1]) != 0)
        {    /* Add back */
            qhat--;
            uu[0] += v;
            uu[1] = 0;
        }
    }
    q2 = qhat;

    /*    ROUND 2. Set j = 1 and calculate q1 */
    /*    Estimate qhat = (u3u2) / v1 
        then set (u3u2u1) -= qhat(v1v0)
    */
    t = uu[0];
    qhat = t / v1;
    rhat = t - qhat * v1;
    /* Test on v0 */
    t = TOHIGH(rhat) | u1;
    if ((qhat == B) || (qhat * v0 > t))
    {
        qhat--;
        rhat += v1;
        t = TOHIGH(rhat) | u1;
        if ((rhat < B) && (qhat * v0 > t))
            qhat--;
    }

    /*    Multiply and subtract 
        (u3u2u1)' = (u3u2u1) - qhat(v1v0)    
    */
    uu[1] = HIHALF(uu[0]);    /* (0u3) */
    uu[0] = TOHIGH(LOHALF(uu[0])) | u1;    /* (u2u1) */
    spMultSub(uu, qhat, v1, v0);
    if (HIHALF(uu[1]) != 0)
    {    /* Add back */
        qhat--;
        uu[0] += v;
        uu[1] = 0;
    }

    /* q1 = qhat */
    *q = TOHIGH(qhat);

    /* ROUND 3. Set j = 0 and calculate q0 */
    /*    Estimate qhat = (u2u1) / v1
        then set (u2u1u0) -= qhat(v1v0)
    */
    t = uu[0];
    qhat = t / v1;
    rhat = t - qhat * v1;
    /* Test on v0 */
    t = TOHIGH(rhat) | u0;
    if ((qhat == B) || (qhat * v0 > t))
    {
        qhat--;
        rhat += v1;
        t = TOHIGH(rhat) | u0;
        if ((rhat < B) && (qhat * v0 > t))
            qhat--;
    }

    /*    Multiply and subtract 
        (u2u1u0)" = (u2u1u0)' - qhat(v1v0)
    */
    uu[1] = HIHALF(uu[0]);    /* (0u2) */
    uu[0] = TOHIGH(LOHALF(uu[0])) | u0;    /* (u1u0) */
    spMultSub(uu, qhat, v1, v0);
    if (HIHALF(uu[1]) != 0)
    {    /* Add back */
        qhat--;
        uu[0] += v;
        uu[1] = 0;
    }

    /* q0 = qhat */
    *q |= LOHALF(qhat);

    /* Remainder is in (u1u0) i.e. uu[0] */
    *r = uu[0];
    return q2;
}

// Platform-dependent code
#ifndef HSM_PLATFORM_LEDGER

#include "hal/log.h"

void LOG_BIGD_HEX(const char *prefix,
                  const DIGIT_T *a,
                  size_t len,
                  const char *suffix) {
    if (prefix) {
        LOG("%s", prefix);
    }
    /* Trim leading digits which are zero */
    while (len--) {
        if (a[len] != 0)
            break;
    }
    len++;
    if (0 == len)
        len = 1;
    /* print first digit without leading zeros */
    LOG("0x%" PRIxBIGD, a[--len]);
    while (len--) {
        LOG("%08" PRIxBIGD, a[len]);
    }
    if (suffix) {
        LOG("%s", suffix);
    }
}

#endif
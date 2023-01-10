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

/* $Id: bigdigits.h $ */

/** @file
    Interface to core BigDigits "mp" functions using fixed-length arrays 
*/

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

#ifndef __BIGDIGITS_H
#define __BIGDIGITS_H 1

#include <stdlib.h>
#include "bigdtypes.h"

/**** USER CONFIGURABLE SECTION ****/

/* Define type and size of DIGIT */

/* [v2.1] Changed to use C99 exact-width types. */
/* [v2.2] Put macros for exact-width types in separate file "bigdtypes.h" */

/** The basic BigDigit element, an unsigned 32-bit integer */
typedef uint32_t DIGIT_T;

/* Sizes to match */
#define MAX_DIGIT 0xFFFFFFFFUL
#define MAX_HALF_DIGIT 0xFFFFUL    /* NB 'L' */
#define BITS_PER_DIGIT 32
#define HIBITMASK 0x80000000UL

#ifdef __cplusplus
extern "C" {
#endif

/*************************/
/* ASSIGNMENT OPERATIONS */
/*************************/

/** Sets a = 0 */
DIGIT_T mpSetZero(volatile DIGIT_T a[], size_t ndigits);

/** Sets a = d where d is a single digit */
void mpSetDigit(DIGIT_T a[], DIGIT_T d, size_t ndigits);

/** Sets a = b */
void mpSetEqual(DIGIT_T a[], const DIGIT_T b[], size_t ndigits);

/*************************/
/* ARITHMETIC OPERATIONS */
/*************************/

/** Computes w = u + v, returns carry 
@pre `w` and `v` must not overlap. 
*/
DIGIT_T mpAdd(DIGIT_T w[], const DIGIT_T u[], const DIGIT_T v[], size_t ndigits);

/** Computes integer division of u by v such that u=qv+r
@param[out] q to receive quotient = u div v, an array of size `udigits`
@param[out] r to receive divisor = u mod v, an array of size `udigits` 
@param[in]  u dividend of size `udigits`
@param[in] udigits size of arrays `q` `r` and `u`
@param[in]  v divisor of size `vdigits`
@param[in] vdigits size of array `v`
@pre `q` and `r` must be independent of `u` and `v`. 
@warning Trashes q and r first
*/
int mpDivide(DIGIT_T q[], DIGIT_T r[], const DIGIT_T u[], 
    size_t udigits, DIGIT_T v[], size_t vdigits);

/*************************/
/* COMPARISON OPERATIONS */
/*************************/

/** Returns sign of `(a-b)` as `{-1,0,+1}`
 *  @remark Not constant-time.
 */
int mpCompare(const DIGIT_T a[], const DIGIT_T b[], size_t ndigits);

/***************************************/
/* CONSTANT-TIME COMPARISON ALGORITHMS */
/***************************************/
/* -- added [v2.5] to replace originals. Renamed as "_ct" in [v2.6] */

/** Returns sign of `(a-b)` as `{-1,0,+1}` using constant-time algorithm */
int mpCompare_ct(const DIGIT_T a[], const DIGIT_T b[], size_t ndigits);

/**********************/
/* BITWISE OPERATIONS */
/**********************/

/** Computes a = b << x */
DIGIT_T mpShiftLeft(DIGIT_T a[], const DIGIT_T b[], size_t x, size_t ndigits);

/** Computes a = b >> x */
DIGIT_T mpShiftRight(DIGIT_T a[], const DIGIT_T b[], size_t x, size_t ndigits);

/**********************/
/* OTHER MP UTILITIES */
/**********************/

/** Returns number of significant non-zero digits in a */
size_t mpSizeof(const DIGIT_T a[], size_t ndigits);

/** Computes p = x * y, where x and y are single digits */
int spMultiply(DIGIT_T p[2], DIGIT_T x, DIGIT_T y);

/** Computes quotient q = u div v, remainder r = u mod v, where q, r and v are single digits */
DIGIT_T spDivide(DIGIT_T *q, DIGIT_T *r, const DIGIT_T u[2], DIGIT_T v);

/**********************************************/
/* FUNCTIONS THAT OPERATE WITH A SINGLE DIGIT */
/**********************************************/

/** Computes quotient q = u div d, returns remainder */
DIGIT_T mpShortDiv(DIGIT_T q[], const DIGIT_T u[], DIGIT_T d, size_t ndigits);

#ifdef __cplusplus
}
#endif

#endif  // __BIGDIGITS_H

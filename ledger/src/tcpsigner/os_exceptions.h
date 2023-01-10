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

/*****************************************************************************
 *   Ledger Nano S - Secure firmware
 *   (c) 2016, 2017 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

/**
 * Modified try...catch exception implementation (taken from nanos-secure-sdk)
 * (https://github.com/LedgerHQ/nanos-secure-sdk/blob/nanos-1314/include/os.h)
 */

#ifndef __SIMULATOR_OS_EXCEPTIONS_H
#define __SIMULATOR_OS_EXCEPTIONS_H

#include <setjmp.h>
#include <stdbool.h>

/* ----------------------------------------------------------------------- */
/* -                            TYPES                                    - */
/* ----------------------------------------------------------------------- */

// error type definition
typedef unsigned short exception_t;

// convenience declaration
typedef struct try_context_s try_context_t;

// structure to reduce the code size generated for the close try (on stm7)
struct try_context_s {
    // current exception context
    jmp_buf jmp_buf;

    // previous exception contexts (if null, then will fail the same way as
    // before, segv, therefore don't mind chaining)
    try_context_t* previous;

    // current exception if any
    exception_t ex;
};

extern try_context_t* G_try_last_open_context;

/* ----------------------------------------------------------------------- */
/* -                            EXCEPTIONS                               - */
/* ----------------------------------------------------------------------- */

// workaround to make sure defines are replaced by their value for example
#define CPP_CONCAT(x, y) CPP_CONCAT_x(x, y)
#define CPP_CONCAT_x(x, y) x##y

// -----------------------------------------------------------------------
// - BEGIN TRY
// -----------------------------------------------------------------------

#define BEGIN_TRY_L(L) \
    {                  \
        try_context_t __try##L;

// -----------------------------------------------------------------------
// - TRY
// -----------------------------------------------------------------------
#define TRY_L(L)                                \
    __try                                       \
        ##L.previous = G_try_last_open_context; \
    __try                                       \
        ##L.ex = setjmp(__try##L.jmp_buf);      \
    G_try_last_open_context = &__try##L;        \
    if (__try##L.ex == 0) {
// -----------------------------------------------------------------------
// - EXCEPTION CATCH
// -----------------------------------------------------------------------
#define CATCH_L(L, x)              \
    goto CPP_CONCAT(__FINALLY, L); \
    }                              \
    else if (__try##L.ex == x) {   \
        G_try_last_open_context = __try##L.previous;

// -----------------------------------------------------------------------
// - EXCEPTION CATCH OTHER
// -----------------------------------------------------------------------
#define CATCH_OTHER_L(L, e)        \
    goto CPP_CONCAT(__FINALLY, L); \
    }                              \
    else {                         \
        exception_t e;             \
        e = __try##L.ex;           \
        __try                      \
            ##L.ex = 0;            \
        G_try_last_open_context = __try##L.previous;

// -----------------------------------------------------------------------
// - EXCEPTION CATCH ALL
// -----------------------------------------------------------------------
#define CATCH_ALL_L(L)             \
    goto CPP_CONCAT(__FINALLY, L); \
    }                              \
    else {                         \
        __try                      \
            ##L.ex = 0;            \
        G_try_last_open_context = __try##L.previous;

// -----------------------------------------------------------------------
// - FINALLY
// -----------------------------------------------------------------------
#define FINALLY_L(L)               \
    goto CPP_CONCAT(__FINALLY, L); \
    }                              \
    CPP_CONCAT(__FINALLY, L) : G_try_last_open_context = __try##L.previous;

// -----------------------------------------------------------------------
// - END TRY
// -----------------------------------------------------------------------
#define END_TRY_L(L)             \
    if (__try##L.ex != 0) {      \
        THROW_L(L, __try##L.ex); \
    }                            \
    }

// -----------------------------------------------------------------------
// - CLOSE TRY
// -----------------------------------------------------------------------
#define CLOSE_TRY_L(L) \
    G_try_last_open_context = G_try_last_open_context->previous

// -----------------------------------------------------------------------
// - EXCEPTION THROW
// -----------------------------------------------------------------------
/*
#ifndef BOLOS_RELEASE

void os_longjmp(jmp_buf b, unsigned int exception);
#define THROW_L(L, x)                                                   \
  os_longjmp(G_try_last_open_context->jmp_buf, x)

#else
*/
#define THROW_L(L, x) longjmp(G_try_last_open_context->jmp_buf, x)
/*
#endif // BOLOS_RELEASE
*/

// Default macros when nesting is not used.
#define THROW_OS(x) THROW_L(EX, x)
#define BEGIN_TRY BEGIN_TRY_L(EX)
#define TRY TRY_L(EX)
#define CATCH(x) CATCH_L(EX, x)
#define CATCH_OTHER(e) CATCH_OTHER_L(EX, e)
#define CATCH_ALL CATCH_ALL_L(EX)
#define FINALLY FINALLY_L(EX)
#define CLOSE_TRY CLOSE_TRY_L(EX)
#define END_TRY END_TRY_L(EX)

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

#include <bc_err.h>

#define IGNORE_WHEN_FUZZING(e)                                  \
    (e == MERKLE_PROOF_MISMATCH || e == CB_TXN_HASH_MISMATCH || \
     e == MM_HASH_MISMATCH || e == CHAIN_MISMATCH ||            \
     e == ANCESTOR_TIP_MISMATCH ||                              \
     e == 0x6A94) // Validations in Merkle Proof. Not assigned a name.

#define THROW(e)                       \
    {                                  \
        if (!IGNORE_WHEN_FUZZING(e)) { \
            THROW_OS(e);               \
        }                              \
    }

#else

#define THROW(e) THROW_OS(e)

#endif

#endif // __SIMULATOR_OS_EXCEPTIONS_H

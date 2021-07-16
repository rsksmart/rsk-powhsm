/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 *   Try...catch exception implementation (taken from nanos-secure-sdk)
 *   (https://github.com/LedgerHQ/nanos-secure-sdk/blob/nanos-1314/include/os.h)
 ********************************************************************************/

#ifndef __SIMULATOR_OS_EXCEPTIONS
#define __SIMULATOR_OS_EXCEPTIONS

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
    try_context_t *previous;

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

#define BEGIN_TRY_L(L)                                                         \
    {                                                                          \
        try_context_t __try##L;

// -----------------------------------------------------------------------
// - TRY
// -----------------------------------------------------------------------
#define TRY_L(L)                                                               \
    __try                                                                      \
        ##L.previous = G_try_last_open_context;                                \
    __try                                                                      \
        ##L.ex = setjmp(__try##L.jmp_buf);                                     \
    G_try_last_open_context = &__try##L;                                       \
    if (__try##L.ex == 0) {
// -----------------------------------------------------------------------
// - EXCEPTION CATCH
// -----------------------------------------------------------------------
#define CATCH_L(L, x)                                                          \
    goto CPP_CONCAT(__FINALLY, L);                                             \
    }                                                                          \
    else if (__try##L.ex == x) {                                               \
        G_try_last_open_context = __try##L.previous;

// -----------------------------------------------------------------------
// - EXCEPTION CATCH OTHER
// -----------------------------------------------------------------------
#define CATCH_OTHER_L(L, e)                                                    \
    goto CPP_CONCAT(__FINALLY, L);                                             \
    }                                                                          \
    else {                                                                     \
        exception_t e;                                                         \
        e = __try##L.ex;                                                       \
        __try                                                                  \
            ##L.ex = 0;                                                        \
        G_try_last_open_context = __try##L.previous;

// -----------------------------------------------------------------------
// - EXCEPTION CATCH ALL
// -----------------------------------------------------------------------
#define CATCH_ALL_L(L)                                                         \
    goto CPP_CONCAT(__FINALLY, L);                                             \
    }                                                                          \
    else {                                                                     \
        __try                                                                  \
            ##L.ex = 0;                                                        \
        G_try_last_open_context = __try##L.previous;

// -----------------------------------------------------------------------
// - FINALLY
// -----------------------------------------------------------------------
#define FINALLY_L(L)                                                           \
    goto CPP_CONCAT(__FINALLY, L);                                             \
    }                                                                          \
    CPP_CONCAT(__FINALLY, L) : G_try_last_open_context = __try##L.previous;

// -----------------------------------------------------------------------
// - END TRY
// -----------------------------------------------------------------------
#define END_TRY_L(L)                                                           \
    if (__try##L.ex != 0) {                                                    \
        THROW_L(L, __try##L.ex);                                               \
    }                                                                          \
    }

// -----------------------------------------------------------------------
// - CLOSE TRY
// -----------------------------------------------------------------------
#define CLOSE_TRY_L(L)                                                         \
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
#define THROW(x) THROW_L(EX, x)
#define BEGIN_TRY BEGIN_TRY_L(EX)
#define TRY TRY_L(EX)
#define CATCH(x) CATCH_L(EX, x)
#define CATCH_OTHER(e) CATCH_OTHER_L(EX, e)
#define CATCH_ALL CATCH_ALL_L(EX)
#define FINALLY FINALLY_L(EX)
#define CLOSE_TRY CLOSE_TRY_L(EX)
#define END_TRY END_TRY_L(EX)

#endif // __SIMULATOR_OS_EXCEPTIONS
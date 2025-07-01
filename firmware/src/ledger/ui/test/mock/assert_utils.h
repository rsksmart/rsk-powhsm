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

#ifndef __ASSERT_UTILS_H
#define __ASSERT_UTILS_H

#include <assert.h>
#include <string.h>

#define ASSERT_FAIL() assert(false)

#define ASSERT_STR_EQUALS(a, b) \
    assert(0 == strcmp((const char *)a, (const char *)b))

#define ASSERT_MEMCMP(a, b, n) assert(0 == memcmp(a, b, n))

#define ASSERT_ARRAY_VALUE(arr, value)         \
    for (size_t i = 0; i < sizeof(arr); i++) { \
        assert((arr)[i] == (value));           \
    }

#define ASSERT_ARRAY_CLEARED(arr) \
    assert(memcmp(arr, (char[sizeof(arr)]){0}, sizeof(arr)) == 0)

#define ASSERT_STRUCT_CLEARED(struct_name, struct_instance) \
    assert(memcmp(&(struct_instance),                       \
                  &(struct_name){0},                        \
                  sizeof(struct_name)) == 0)

// Testing helpers
#define ASSERT_DOESNT_THROW(st)             \
    {                                       \
        BEGIN_TRY {                         \
            TRY{st} CATCH_OTHER(e) {        \
                printf("Expected no "       \
                       "exception but got " \
                       "0x%x\n",            \
                       e);                  \
                assert(false);              \
            }                               \
            FINALLY {                       \
            }                               \
        }                                   \
        END_TRY;                            \
    }

#define ASSERT_THROWS(st, ex)               \
    {                                       \
        BEGIN_TRY {                         \
            TRY {                           \
                { st; }                     \
                printf("Expected a 0x%x "   \
                       "exception but "     \
                       "none was thrown\n", \
                       ex);                 \
                assert(false);              \
            }                               \
            CATCH_OTHER(e) {                \
                if (e != ex) {              \
                    printf("Expected a "    \
                           "0x%x exception" \
                           " but got 0x%x " \
                           "instead\n",     \
                           ex,              \
                           e);              \
                    assert(false);          \
                }                           \
            }                               \
            FINALLY {                       \
            }                               \
        }                                   \
        END_TRY;                            \
    }

#endif // __ASSERT_UTILS_H

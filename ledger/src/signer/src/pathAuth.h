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

#ifndef __PATHAUTH_H
#define __PATHAUTH_H

#include <stdbool.h>

#define TOTAL_AUTHORIZED_PATHS 6
#define SINGLE_PATH_SIZE_BYTES 21

// Paths
//
extern const char authPaths[][21];
extern const char noAuthPaths[][21];
extern const int ordered_paths[TOTAL_AUTHORIZED_PATHS];

bool pathRequireAuth(unsigned char *path);
bool pathDontRequireAuth(unsigned char *path);

const char *get_ordered_path(unsigned int index);

#define KEY_PATH_COUNT() (sizeof(ordered_paths) / sizeof(ordered_paths[0]))

#endif // __PATHAUTH_H

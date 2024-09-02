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
#include <stdarg.h>

#include "log.h"

static char* log_prefix = (char*)NULL;

void LOG(const char *format, ...) {
    va_list args;
    va_start(args, format);

    if (log_prefix) {
        printf("%s", log_prefix);
    }
    vprintf(format, args);

    va_end(args);
}

void LOG_HEX(const char *prefix, const void *buffer, const size_t size) {
    if (log_prefix) {
        printf("%s", log_prefix);
    }
    printf("%s ", prefix);
    if (size > 0) {
        printf("0x");
        for (unsigned int i = 0; i < size; i++) {
            printf("%02x", ((unsigned char *)buffer)[i]);
        }
    } else {
        printf("EMPTY");
    }
    printf("\n");
}

void log_set_prefix(const char* prefix) {
    log_prefix = (char*)prefix;
}

void log_clear_prefix() {
    log_prefix = (char*)NULL;
}
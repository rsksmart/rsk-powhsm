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

#include <sys/stat.h>
#include "hsm_u.h"
#include "log.h"

#define KVSTORE_PREFIX "./kvstore-"
#define KVSTORE_SUFFIX ".dat"

static char* filename_for(char* key) {
    size_t filename_size = strlen(KVSTORE_PREFIX) + 
                           strlen(KVSTORE_SUFFIX) + 
                           strlen(key);
    char* filename = malloc(filename_size+1);
    strcpy(filename, "");
    strcat(filename, KVSTORE_PREFIX);
    strcat(filename, key);
    strcat(filename, KVSTORE_SUFFIX);
    return filename;
}

static FILE* open_file_for(char* key, char* mode, size_t* file_size) {
    char* filename = filename_for(key);
    struct stat fst;
    stat(filename, &fst);
    if (file_size) *file_size = fst.st_size;
    FILE* file = fopen(filename, mode);
    free(filename);
    return file;
}

bool kvstore_save(char* key, uint8_t* data, size_t data_size) {
    LOG("Attempting to write data for %s...\n", key);
    if (!data_size) {
        LOG("Invalid zero-length data given for key <%s>\n", key);
        return false;
    }

    FILE* file = open_file_for(key, "wb", NULL);
    if (!file) {
        LOG("Could not open file for key <%s>\n", key);
        return false;
    }

    if (fwrite(data,
              sizeof(data[0]),
              data_size,
              file) != data_size) {
        LOG("Error writing secret payload for key <%s>\n", key);
        fclose(file);
        return false;
    };

    fclose(file);
    return true;
}

bool kvstore_exists(char* key) {
    LOG("Attempting to determine existence for key <%s>...\n", key);
    size_t file_size = 0;
    FILE* file = open_file_for(key, "rb", &file_size);
    if (file) {
        fclose(file);
        return true;
    }
    return false;
}

size_t kvstore_get(char* key, uint8_t* data_buf, size_t buffer_size) {
    LOG("Attempting to read data for key <%s>...\n", key);
    size_t file_size = 0;
    FILE* file = open_file_for(key, "rb", &file_size);
    if (!file) {
        LOG("Could not open file for key <%s>\n", key);
        return 0;
    }

    if (file_size > buffer_size) {
        LOG("Payload too big for destination for key <%s>\n", key);
        fclose(file);
        return 0;
    }

    if (!file_size) {
        LOG("Invalid zero-length secret stored for key <%s>\n", key);
        fclose(file);
        return 0;
    }

    if (fread(data_buf,
              sizeof(data_buf[0]),
              file_size,
              file) != file_size) {
        LOG("Could not read payload for key <%s>\n", key);
        fclose(file);
        return 0;
    };

    fclose(file);
    return file_size;
}

bool kvstore_remove(char* key) {
    char* filename = filename_for(key);
    int result = remove(filename);
    if (result) LOG("Error removing file for key <%s>\n", key);
    free(filename);
    return !result;
}

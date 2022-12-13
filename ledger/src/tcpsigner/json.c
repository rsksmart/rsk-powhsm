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

#include "json.h"
#include "cJSON.h"

#include <stdio.h>

// Read a JSON file into memory
cJSON* read_json_file(char* file_path) {
    FILE* key_file;
    char* buffer;
    long file_size;

    key_file = fopen(file_path, "r");

    // File does not exist?
    if (key_file == NULL)
        return NULL;

    // Find file size
    fseek(key_file, 0L, SEEK_END);
    file_size = ftell(key_file);
    fseek(key_file, 0L, SEEK_SET);

    // Allocate buffer
    buffer = (char*)malloc(file_size * sizeof(char));
    if (buffer == NULL)
        return NULL;

    // Read into buffer and close the file
    fread(buffer, sizeof(char), file_size, key_file);
    fclose(key_file);

    // Parse JSON
    cJSON* json = cJSON_ParseWithLength(buffer, file_size * sizeof(char));

    // Free buffer
    free(buffer);

    return json;
}

// Write JSON from memory to disk
bool write_json_file(char* file_path, cJSON* json) {
    FILE* key_file = fopen(file_path, "w");
    if (key_file == NULL)
        return false;

    char* json_s = cJSON_Print(json);
    fputs(json_s, key_file);
    fputs("\n", key_file);

    cJSON_free(json_s);
    cJSON_Delete(json);
    fclose(key_file);

    return true;
}
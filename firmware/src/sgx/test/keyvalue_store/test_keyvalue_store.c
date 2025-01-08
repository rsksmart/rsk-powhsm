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

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "keyvalue_store.h"

// Test helpers
void setup() {
    system("rm -f ./kvstore-*.dat");
}

void assert_key_exists(char* key, bool exists) {
    assert(kvstore_exists(key) == exists);
}

void assert_key_value(char* key, uint8_t* data, size_t data_size) {
    uint8_t retrieved_data[BUFSIZ];
    size_t retrieved_size = kvstore_get(key, retrieved_data, sizeof(retrieved_data));
    assert(retrieved_size == data_size);
    assert(memcmp(retrieved_data, data, retrieved_size) == 0);
}

void save_and_assert_success(char* key, uint8_t* data, size_t data_size) {
    assert(kvstore_save(key, data, data_size));
    assert_key_exists(key, true);
}

void remove_and_assert_success(char* key) {
    assert(kvstore_remove(key));
    assert_key_exists(key, false);
}

void assert_file_exists(char* filename, bool exists) {
    FILE* file = fopen(filename, "rb");
    if (exists) {
        assert(file != NULL);
    } else {
        assert(file == NULL);
    }
    if (file) {
        fclose(file);
    }
}

// Test cases
void test_save_retrieve() {
    printf("Test save and retrieve...\n");
    setup();

    struct {
        char* key;
        uint8_t* data;
    } input_data[] = {
        {"a-key", (uint8_t*)"some piece of data"},
        {"another-key", (uint8_t*)"another piece of data"},
        {"yet-another-key", (uint8_t*)"yet another piece of data"},
        {"the-last-key", (uint8_t*)"the last piece of data"}
    };
    size_t num_inputs = sizeof(input_data) / sizeof(input_data[0]);

    for (size_t i = 0; i < num_inputs; i++) {
        save_and_assert_success(input_data[i].key, input_data[i].data, strlen((char*)input_data[i].data));
    }

    for (size_t i = 0; i < num_inputs; i++) {
        assert_key_value(input_data[i].key, input_data[i].data, strlen((char*)input_data[i].data));
    }
}

void test_kvstore_exists() {
    printf("Test kvstore_exists...\n");
    setup();

    struct {
        char* key;
        uint8_t* data;
    } existing_keys[] = {
        {"first-key", (uint8_t*)"some piece of data"},
        {"second-key", (uint8_t*)"another piece of data"},
        {"third-key", (uint8_t*)"yet another piece of data"},
    };
    size_t num_existing_keys = sizeof(existing_keys) / sizeof(existing_keys[0]);

    char* non_existing_keys[] = {
        "non-existing-key-1",
        "non-existing-key-2",
        "non-existing-key-3",
    };
    size_t num_non_existing_keys = sizeof(non_existing_keys) / sizeof(non_existing_keys[0]);

    for (size_t i = 0; i < num_existing_keys; i++) {
        save_and_assert_success(existing_keys[i].key, existing_keys[i].data, strlen((char*)existing_keys[i].data));
    }

    for (size_t i = 0; i < num_existing_keys; i++) {
        assert_key_exists(existing_keys[i].key, true);
    }

    for (size_t i = 0; i < num_non_existing_keys; i++) {
        assert_key_exists(non_existing_keys[i], false);
    }
}

void test_save_remove() {
    printf("Test save and remove...\n");
    setup();

    struct {
        char* key;
        uint8_t* data;
        bool remove;
    } input_data[] = {
        {"first-key", (uint8_t*)"some piece of data", false},
        {"second-key", (uint8_t*)"another piece of data", true},
        {"third-key", (uint8_t*)"yet another piece of data", true},
        {"fourth-key", (uint8_t*)"the last piece of data", false},
    };
    size_t num_inputs = sizeof(input_data) / sizeof(input_data[0]);

    for (size_t i = 0; i < num_inputs; i++) {
        save_and_assert_success(input_data[i].key, input_data[i].data, strlen((char*)input_data[i].data));
        assert_key_value(input_data[i].key, input_data[i].data, strlen((char*)input_data[i].data));
    }

    // Remove selected keys
    for (size_t i = 0; i < num_inputs; i++) {
        if (input_data[i].remove) {
            remove_and_assert_success(input_data[i].key);
        }
    }

    // Assert that the selected keys were removed and the others still exist
    for (size_t i = 0; i < num_inputs; i++) {
        if (input_data[i].remove) {
            assert_key_exists(input_data[i].key, false);
        } else {
            assert_key_value(input_data[i].key, input_data[i].data, strlen((char*)input_data[i].data));
        }
    }
}

void test_filename() {
    printf("Test filename for key...\n");
    setup();

    struct {
        char* key;
        uint8_t* data;
        char* filename;
    } input_data[] = {
        {"first-key", "data for the first key", "kvstore-first-key.dat"},
        {"second-key", "data for the second key", "kvstore-second-key.dat"},
        {"third-key", "data for the third key", "kvstore-third-key.dat"},
        {"fourth-key", "data for the fourth key", "kvstore-fourth-key.dat"},
    };
    size_t num_inputs = sizeof(input_data) / sizeof(input_data[0]);

    // Make sure none of the files exist
    for (size_t i = 0; i < num_inputs; i++) {
        assert_file_exists(input_data[i].filename, false);
    }

    // Save data to each key and assert that the file name is correct
    for (size_t i = 0; i < num_inputs; i++) {
        save_and_assert_success(input_data[i].key, (uint8_t*)input_data[i].data, strlen(input_data[i].data));
        assert_file_exists(input_data[i].filename, true);
    }
}

void test_sanitize_key() {
    printf("Test sanitize key...\n");
    setup();

    struct {
        char* key;
        char* filename;
        uint8_t* data;
    } input_data[] = {
        {"onlyletters", "kvstore-onlyletters.dat", "data1"},
        {"123456", "kvstore-123456.dat", "data2"},
        {"lettersandnumbers123", "kvstore-lettersandnumbers123.dat", "data3"},
        {"letters-and-numbers-with-hyphen-123", "kvstore-letters-and-numbers-with-hyphen-123.dat", "data4"},
        {"key containing spaces", "kvstore-key-containing-spaces.dat", "data5"},
        {"key containing special characters!@#$%^&*()", "kvstore-key-containing-special-characters----------.dat", "data6"},
        {"../../../../../etc/passwd", "kvstore----------------etc-passwd.dat", "data7"},
    };
    size_t num_inputs = sizeof(input_data) / sizeof(input_data[0]);

    // Make sure none of the files exist
    for (size_t i = 0; i < num_inputs; i++) {
        assert_file_exists(input_data[i].filename, false);
    }

    // Save data to each key and assert that the file name is correct
    for (size_t i = 0; i < num_inputs; i++) {
        save_and_assert_success(input_data[i].key, (uint8_t*)"some data", strlen("some data"));
        assert_file_exists(input_data[i].filename, true);
    }

    // Ensure data can be retrieved with the original key
    for (size_t i = 0; i < num_inputs; i++) {
        assert_key_value(input_data[i].key, (uint8_t*)"some data", strlen("some data"));
    }
}


int main() {
    test_save_retrieve();
    test_kvstore_exists();
    test_save_remove();
    test_filename();
    test_sanitize_key();
    return 0;
}
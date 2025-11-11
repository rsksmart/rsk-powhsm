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
#include <sys/stat.h>
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
    size_t retrieved_size =
        kvstore_get(key, retrieved_data, sizeof(retrieved_data));
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

void assert_file_contents(char* filename, uint8_t* data, size_t data_size) {
    FILE* file = fopen(filename, "rb");
    assert(file != NULL);

    uint8_t file_data[BUFSIZ];
    size_t file_size =
        fread(file_data, sizeof(file_data[0]), sizeof(file_data), file);
    assert(file_size == data_size);
    assert(memcmp(file_data, data, data_size) == 0);

    fclose(file);
}

// Test cases
void test_save_retrieve() {
    printf("Test save and retrieve...\n");
    setup();

    struct {
        char* key;
        char* data;
    } input_data[] = {{"a-key", "some piece of data"},
                      {"another-key", "another piece of data"},
                      {"yet-another-key", "yet another piece of data"},
                      {"the-last-key", "the last piece of data"}};
    size_t num_inputs = sizeof(input_data) / sizeof(input_data[0]);

    for (size_t i = 0; i < num_inputs; i++) {
        save_and_assert_success(input_data[i].key,
                                (uint8_t*)input_data[i].data,
                                strlen(input_data[i].data));
    }

    for (size_t i = 0; i < num_inputs; i++) {
        assert_key_value(input_data[i].key,
                         (uint8_t*)input_data[i].data,
                         strlen(input_data[i].data));
    }
}

void test_kvstore_exists() {
    printf("Test kvstore_exists...\n");
    setup();

    struct {
        char* key;
        char* data;
    } existing_keys[] = {
        {"first-key", "some piece of data"},
        {"second-key", "another piece of data"},
        {"third-key", "yet another piece of data"},
    };
    size_t num_existing_keys = sizeof(existing_keys) / sizeof(existing_keys[0]);

    char* non_existing_keys[] = {
        "non-existing-key-1",
        "non-existing-key-2",
        "non-existing-key-3",
    };
    size_t num_non_existing_keys =
        sizeof(non_existing_keys) / sizeof(non_existing_keys[0]);

    for (size_t i = 0; i < num_existing_keys; i++) {
        save_and_assert_success(existing_keys[i].key,
                                (uint8_t*)existing_keys[i].data,
                                strlen(existing_keys[i].data));
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
        char* data;
        bool remove;
    } input_data[] = {
        {"first-key", "some piece of data", false},
        {"second-key", "another piece of data", true},
        {"third-key", "yet another piece of data", true},
        {"fourth-key", "the last piece of data", false},
    };
    size_t num_inputs = sizeof(input_data) / sizeof(input_data[0]);

    for (size_t i = 0; i < num_inputs; i++) {
        save_and_assert_success(input_data[i].key,
                                (uint8_t*)input_data[i].data,
                                strlen(input_data[i].data));
        assert_key_value(input_data[i].key,
                         (uint8_t*)input_data[i].data,
                         strlen(input_data[i].data));
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
            assert_key_value(input_data[i].key,
                             (uint8_t*)input_data[i].data,
                             strlen(input_data[i].data));
        }
    }
}

void test_filename() {
    printf("Test filename for key...\n");
    setup();

    struct {
        char* key;
        char* data;
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

    // Save data to each key and assert that the file name and contents are
    // correct
    for (size_t i = 0; i < num_inputs; i++) {
        save_and_assert_success(input_data[i].key,
                                (uint8_t*)input_data[i].data,
                                strlen(input_data[i].data));
        assert_file_exists(input_data[i].filename, true);
        assert_file_contents(input_data[i].filename,
                             (uint8_t*)input_data[i].data,
                             strlen(input_data[i].data));
    }
}

void test_sanitize_key() {
    printf("Test sanitize key...\n");
    setup();

    struct {
        char* key;
        char* filename;
        char* data;
    } input_data[] = {
        {"onlyletters", "kvstore-onlyletters.dat", "data1"},
        {"123456", "kvstore-123456.dat", "data2"},
        {"lettersandnumbers123", "kvstore-lettersandnumbers123.dat", "data3"},
        {"letters-and-numbers-with-hyphen-123",
         "kvstore-letters-and-numbers-with-hyphen-123.dat",
         "data4"},
        {"key containing spaces", "kvstore-key-containing-spaces.dat", "data5"},
        {"key containing special characters!@#$%^&*()",
         "kvstore-key-containing-special-characters-.dat",
         "data6"},
        {"../../../../../etc/passwd", "kvstore-etc-passwd.dat", "data7"},
        {"some@#£_&-(_./file#£+-:;name", "kvstore-some-file-name.dat", "data8"},
    };
    size_t num_inputs = sizeof(input_data) / sizeof(input_data[0]);

    // Make sure none of the files exist
    for (size_t i = 0; i < num_inputs; i++) {
        assert_file_exists(input_data[i].filename, false);
    }

    // Save data to each key and assert that the file name and contents are
    // correct
    for (size_t i = 0; i < num_inputs; i++) {
        save_and_assert_success(input_data[i].key,
                                (uint8_t*)input_data[i].data,
                                strlen(input_data[i].data));
        assert_file_exists(input_data[i].filename, true);
        assert_file_contents(input_data[i].filename,
                             (uint8_t*)input_data[i].data,
                             strlen(input_data[i].data));
    }

    // Ensure data can be retrieved with the original key
    for (size_t i = 0; i < num_inputs; i++) {
        assert_key_value(input_data[i].key,
                         (uint8_t*)input_data[i].data,
                         strlen(input_data[i].data));
    }
}

void test_exists_null_key() {
    printf("Test exists with null key...\n");
    setup();

    // Attempting to check existence with a null key should fail gracefully
    assert(!kvstore_exists(NULL));
}

void test_save_null_key() {
    printf("Test save with null key...\n");
    setup();

    uint8_t data[] = "test";

    // Attempting to save with a null key should fail
    assert(!kvstore_save(NULL, data, sizeof(data)));
}

void test_save_null_data() {
    printf("Test save with null data...\n");
    setup();

    // Attempting to save with a null data buffer should fail
    assert(!kvstore_save("null-data-key", NULL, 10));
}

void test_save_zero_length_data() {
    printf("Test save with zero-length data...\n");
    setup();

    uint8_t data[] = "test";

    // Attempting to save zero-length data should fail
    assert(!kvstore_save("zero-length-key", data, 0));
    assert(!kvstore_exists("zero-length-key"));
}

void test_truncate_key() {
    printf("Test truncate key...\n");
    setup();

    // Create a key longer than KVSTORE_MAX_KEY_LEN (150)
    char long_key[200];
    memset(long_key, 'a', sizeof(long_key) - 1);
    long_key[sizeof(long_key) - 1] = '\0';

    uint8_t data[] = "data for oversized key";

    // Should successfully save and retrieve despite oversized key
    save_and_assert_success(long_key, data, sizeof(data));
    assert_key_value(long_key, data, sizeof(data));
}

void test_get_null_key() {
    printf("Test get with null key...\n");
    setup();

    uint8_t data[] = "test";
    uint8_t buf[BUFSIZ];

    save_and_assert_success("null-key-data", data, sizeof(data));

    // Attempting to get with a null key should fail gracefully
    assert(kvstore_get(NULL, buf, sizeof(buf)) == 0);
}

void test_get_null_data_buf() {
    printf("Test get with null data buffer...\n");
    setup();

    uint8_t data[] = "test";
    uint8_t buf[BUFSIZ];
    save_and_assert_success("null-data-buf-key", data, sizeof(data));

    // Attempting to get with a null data buffer should fail gracefully
    assert(kvstore_get("null-data-buf-key", NULL, sizeof(buf)) == 0);
}

void test_get_buffer_too_small() {
    printf("Test buffer too small for get...\n");
    setup();

    uint8_t data[] = "this is a long piece of data";
    uint8_t small_buf[5];

    // Save the data successfully
    save_and_assert_success("large-data-key", data, sizeof(data));

    // Attempting to read into too-small buffer should fail
    assert(kvstore_get("large-data-key", small_buf, sizeof(small_buf)) == 0);

    // Attempting to read into a buffer with enough space should succeed
    assert_key_value("large-data-key", data, sizeof(data));
}

void test_get_nonexistent_key() {
    printf("Test get nonexistent key...\n");
    setup();

    uint8_t buf[BUFSIZ];

    // Attempting to get a key that doesn't exist should return 0
    assert(kvstore_get("nonexistent-key", buf, sizeof(buf)) == 0);
}

void test_remove_nonexistent() {
    printf("Test remove nonexistent key...\n");
    setup();

    // Attempting to remove a key that doesn't exist should return false
    assert(!kvstore_remove("key-that-does-not-exist"));
}

void test_remove_null_key() {
    printf("Test remove with null key...\n");
    setup();

    // Attempting to remove with a null key should fail gracefully
    assert(!kvstore_remove(NULL));
}

void test_zero_length_file() {
    printf("Test zero-length file handling...\n");
    setup();

    // Manually create an empty kvstore file
    FILE* empty_file = fopen("./kvstore-emptyfile.dat", "wb");
    assert(empty_file != NULL);
    fclose(empty_file);

    uint8_t buf[BUFSIZ];

    // File exists but has zero length - should fail to read
    assert(kvstore_exists("emptyfile"));
    assert(kvstore_get("emptyfile", buf, sizeof(buf)) == 0);

    // Clean up
    remove("./kvstore-emptyfile.dat");
}

int main() {
    test_save_retrieve();
    test_kvstore_exists();
    test_save_remove();
    test_filename();
    test_sanitize_key();
    test_exists_null_key();
    test_save_null_key();
    test_save_null_data();
    test_save_zero_length_data();
    test_truncate_key();
    test_get_null_key();
    test_get_null_data_buf();
    test_get_buffer_too_small();
    test_get_nonexistent_key();
    test_remove_nonexistent();
    test_remove_null_key();
    test_zero_length_file();
    return 0;
}
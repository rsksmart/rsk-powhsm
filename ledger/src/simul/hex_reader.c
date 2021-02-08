#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "hex_reader.h"

/* Decode a single hex digit */
static uint8_t decode_hex_digit(char digit) {
    if (digit >= '0' && digit <= '9') {
        return (uint8_t)(digit - '0');
    }
    if (digit >= 'a' && digit <= 'f') {
        return (uint8_t)(digit - 'a' + 10);
    }
    if (digit >= 'A' && digit <= 'F') {
        return (uint8_t)(digit - 'A' + 10);
    }
    printf("Invalid hex character: %c\n", digit);
    return 0;
}

/* Decode a single hex char */
static uint8_t decode_hex(char* chars) {
    return 16*decode_hex_digit(chars[0]) + decode_hex_digit(chars[1]);
}

/*
 * Read bytes hex bytes from the text-based stream
 * Return the number of bytes actually read
 */
size_t read_hex(FILE* stream, void* dest, size_t bytes) {
    size_t bytes_read;
    for (bytes_read = 0; bytes_read < bytes; bytes_read++) {
        char hexbuf[2];
        size_t actual_read = fread(hexbuf, 1, 2, stream);
        if (actual_read == 0) {
            // No more left, return what could be read
            break;
        }
        if (actual_read != 2) {
            printf("Error reading from hex-encoded blockfile, read %lu bytes, expected 2\n", actual_read);
            return 0;
        }
        ((uint8_t*)dest)[bytes_read] = decode_hex(hexbuf);
    }
    return bytes_read;
}
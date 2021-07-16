#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

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
    // Invalid hex char
    return 16;
}

/* Decode a single hex char */
static uint8_t decode_hex(char* chars) {
    return 16*decode_hex_digit(chars[0]) + decode_hex_digit(chars[1]);
}

/* Tell whether a char is a hex char */
static inline bool is_hex_char(char c) {
    return (
        (c >= '0' && c <= '9') || 
        (c >= 'a' && c <= 'f') || 
        (c >= 'A' && c <= 'F')
    );
}

/*
 * Read src_length hex bytes from the src string
 * Return the number of bytes actually read or
 * -1 in case of error
 */
int read_hex(char* src, size_t src_length, void* dest) {
    if ((src_length % 2) != 0)
        return -1;

    size_t bytes_read = 0;
    for (int i = 0; i < src_length; i+=2) {
        if (!is_hex_char(src[i]) || !is_hex_char(src[i+1]))
            return -1;
        ((uint8_t*)dest)[bytes_read++] = decode_hex(src+i);
    }
    return bytes_read;
}
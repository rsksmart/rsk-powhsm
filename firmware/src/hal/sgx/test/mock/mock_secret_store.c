#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "mock_secret_store.h"

typedef struct mock_sest_register {
    char *key;
    uint8_t *secret;
    size_t secret_length;
} mock_sest_register_t;

#define MOCK_SEST_MAX_REGISTERS 10
typedef struct mock_secret_store {
    mock_sest_register_t registers[MOCK_SEST_MAX_REGISTERS];
    size_t num_registers;
    bool fail_next_read;
    bool fail_next_write;
} mock_secret_store_t;

static mock_secret_store_t g_mock_secret_store;

bool mock_sest_exists(char *key) {
    for (size_t i = 0; i < g_mock_secret_store.num_registers; i++) {
        if (strcmp(g_mock_secret_store.registers[i].key, key) == 0) {
            return true;
        }
    }
    return false;
}

bool mock_sest_write(char *key, uint8_t *secret, size_t secret_length) {
    if (g_mock_secret_store.fail_next_write) {
        g_mock_secret_store.fail_next_write = false;
        return false;
    }
    int register_index = -1;
    for (size_t i = 0; i < g_mock_secret_store.num_registers; i++) {
        if (strcmp(g_mock_secret_store.registers[i].key, key) == 0) {
            register_index = i;
            break;
        }
    }
    if (register_index == -1) {
        assert(g_mock_secret_store.num_registers < MOCK_SEST_MAX_REGISTERS);
        register_index = g_mock_secret_store.num_registers;
    }

    mock_sest_register_t *new_register =
        &g_mock_secret_store.registers[register_index];
    new_register->key = malloc(strlen(key) + 1);
    strcpy(new_register->key, key);
    new_register->secret = malloc(secret_length);
    memcpy(new_register->secret, secret, secret_length);
    new_register->secret_length = secret_length;
    g_mock_secret_store.num_registers++;

    return true;
}

uint8_t mock_sest_read(char *key, uint8_t *dest, size_t dest_length) {
    if (g_mock_secret_store.fail_next_read) {
        g_mock_secret_store.fail_next_read = false;
        return 0;
    }
    for (size_t i = 0; i < g_mock_secret_store.num_registers; i++) {
        if (strcmp(g_mock_secret_store.registers[i].key, key) == 0) {
            assert(dest_length >=
                   g_mock_secret_store.registers[i].secret_length);
            memcpy(dest,
                   g_mock_secret_store.registers[i].secret,
                   g_mock_secret_store.registers[i].secret_length);
            return g_mock_secret_store.registers[i].secret_length;
        }
    }
    return 0;
}

void mock_sest_init() {
    memset(&g_mock_secret_store, 0, sizeof(g_mock_secret_store));
}

void mock_sest_reset() {
    for (size_t i = 0; i < g_mock_secret_store.num_registers; i++) {
        free(g_mock_secret_store.registers[i].key);
        free(g_mock_secret_store.registers[i].secret);
    }
    memset(&g_mock_secret_store, 0, sizeof(g_mock_secret_store));
}

void mock_sest_fail_next_read(bool fail) {
    g_mock_secret_store.fail_next_read = fail;
}

void mock_sest_fail_next_write(bool fail) {
    g_mock_secret_store.fail_next_write = fail;
}

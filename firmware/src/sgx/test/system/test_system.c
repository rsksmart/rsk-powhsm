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
#include <stdio.h>
#include "assert_utils.h"
#include "apdu_utils.h"
#include "bc_state.h"
#include "hal/access.h"
#include "hal/communication.h"
#include "hal/exceptions.h"
#include "hal/log.h"
#include "apdu.h"
#include "hsm.h"
#include "instructions.h"
#include "system.h"

// Constants
#define MAX_CALLS 10
#define ACCESS_MAX_PASSWORD_LENGTH 10
#define MOCK_PASSWORD "123456"
#define MOCK_SEED                                                              \
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x01" \
    "\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"

// Mock implementations
typedef struct mock_calls_counter {
    int hsm_init_count;
    int hsm_set_external_processor_count;
    int hsm_reset_if_starting_count;
    int nvmem_load_count;
    int access_init_count;
    int access_wipe_count;
    int access_set_password_count;
    int communication_init_count;
    int access_get_retries_count;
    int access_is_locked_count;
    int access_is_wiped_count;
    int access_unlock_count;
    int seed_init_count;
    int seed_wipe_count;
    int seed_generate_count;
    int seed_available_count;
    int seed_derive_pubkey_count;
    int endorsement_init_count;
    int nvmem_init_count;
    int nvmem_register_block_count;
    int sest_init_count;
    int oe_is_outside_enclave_count;
    int upgrade_init_count;
    int upgrade_process_apdu_count;
    int evidence_init_count;
    int upgrade_reset_count;
    int do_meta_advupd_count;
} mock_calls_counter_t;

typedef struct nvmem_register_block_args {
    const char* key;
    void* addr;
    size_t size;
} nvmem_register_block_args_t;

typedef struct seed_generate_args {
    uint8_t client_seed[SEED_LENGTH];
    size_t size;
} seed_generate_args_t;

typedef struct access_set_password_args {
    char password[ACCESS_MAX_PASSWORD_LENGTH];
    uint8_t password_length;
} access_set_password_args_t;

typedef struct access_unlock_args {
    char password[ACCESS_MAX_PASSWORD_LENGTH];
    uint8_t password_length;
} access_unlock_args_t;

typedef struct hsm_reset_if_starting_args {
    unsigned char cmd;
} hsm_reset_if_starting_args_t;

typedef struct mock_call_args {
    nvmem_register_block_args_t nvmem_register_block_args;
    seed_generate_args_t seed_generate_args;
    access_set_password_args_t access_set_password_args;
    access_unlock_args_t access_unlock_args;
    hsm_reset_if_starting_args_t hsm_reset_if_starting_args;
} mock_call_args_t;

typedef struct mock_force_fail {
    bool nvmem_load;
    bool seed_init;
    bool seed_wipe;
    bool seed_generate;
    bool access_init;
    bool access_wipe;
    bool access_set_password;
    bool communication_init;
    bool endorsement_init;
    bool nvmem_register_block;
    bool sest_init;
    bool oe_is_outside_enclave;
    bool evidence_init;
} mock_force_fail_t;

typedef struct mock_data {
    mock_calls_counter_t calls_counter;
    mock_call_args_t mock_call_args[MAX_CALLS];
    mock_force_fail_t force_fail;
    external_processor_t external_processor;
    external_processor_result_t last_result;
    access_wiped_callback_t access_wiped_callback;
    bool access_locked;
    bool access_wiped;
    uint8_t access_retries;
    bool seed_available;
    const char* force_nvmem_register_block_fail_key;
} mock_data_t;

static mock_data_t G_mock_data;

// Mock helpers
#define NUM_CALLS(function_name) G_mock_data.calls_counter.function_name##_count
#define MOCK_ARGS(function_name, index) \
    G_mock_data.mock_call_args[index].function_name##_args
#define ASSERT_CALLED_WITH(function_name, call_index, ...) \
    assert_##function_name##_called_with(call_index, __VA_ARGS__)
#define ASSERT_NOT_CALLED(function_name) assert(NUM_CALLS(function_name) == 0)
#define ASSERT_HANDLED() assert(G_mock_data.last_result.handled == true)
#define ASSERT_NOT_HANDLED() assert(G_mock_data.last_result.handled == false)

#define ACCESS_LOCK() (G_mock_data.access_locked = true)
#define ACCESS_UNLOCK() (G_mock_data.access_locked = false)
#define ACCESS_SET_RETRIES(retries) (G_mock_data.access_retries = retries)
#define ACCESS_RETRIES() (G_mock_data.access_retries)
#define ACCESS_SET_WIPED(is_wiped) (G_mock_data.access_wiped = (is_wiped))
#define ACCESS_WIPED() (G_mock_data.access_wiped)

#define SEED_SET_AVAILABLE(is_available) \
    (G_mock_data.seed_available = (is_available))
#define SEED_AVAILABLE() (G_mock_data.seed_available)

#define FORCE_FAIL(function_name, fail_next) \
    (G_mock_data.force_fail.function_name = fail_next)
#define SHOULD_FAIL(function_name) (G_mock_data.force_fail.function_name)
#define FORCE_NVMEM_FAIL_ON_KEY(key) \
    (G_mock_data.force_nvmem_register_block_fail_key = key)

#define MOCK_CALL(function_name)          \
    NUM_CALLS(function_name)++;           \
    if (SHOULD_FAIL(function_name)) {     \
        FORCE_FAIL(function_name, false); \
        return false;                     \
    }

// Globals
bc_state_t N_bc_state_var;
bc_state_updating_backup_t N_bc_state_updating_backup_var;
static try_context_t G_try_last_open_context_var;
try_context_t* G_try_last_open_context = &G_try_last_open_context_var;
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];
unsigned char* G_communication_msg_buffer;

// Mock implementation of dependencies
bool oe_is_outside_enclave(const void* ptr, size_t size) {
    MOCK_CALL(oe_is_outside_enclave);
    return true;
}

void hsm_init() {
    NUM_CALLS(hsm_init)++;
}

void hsm_set_external_processor(external_processor_t external_processor) {
    NUM_CALLS(hsm_set_external_processor)++;
    G_mock_data.external_processor = external_processor;
}

void hsm_reset_if_starting(unsigned char cmd) {
    NUM_CALLS(hsm_reset_if_starting)++;
    G_mock_data.mock_call_args->hsm_reset_if_starting_args.cmd = cmd;
}

bool nvmem_load() {
    MOCK_CALL(nvmem_load);
    return true;
}

bool access_init(access_wiped_callback_t wiped_callback) {
    MOCK_CALL(access_init);
    G_mock_data.access_wiped_callback = wiped_callback;
    return true;
}

bool access_wipe() {
    MOCK_CALL(access_wipe);
    ACCESS_SET_WIPED(true);
    return true;
}

bool access_set_password(char* password, uint8_t password_length) {
    int next_index = NUM_CALLS(access_set_password);
    access_set_password_args_t* args =
        &MOCK_ARGS(access_set_password, next_index);
    memcpy(args->password, password, password_length);
    args->password_length = password_length;
    MOCK_CALL(access_set_password);
    ACCESS_SET_WIPED(false);
    return true;
}

bool communication_init(unsigned char* msg_buffer, size_t msg_buffer_size) {
    G_communication_msg_buffer = msg_buffer;
    assert(msg_buffer_size == sizeof(G_io_apdu_buffer));
    MOCK_CALL(communication_init);
    return true;
}

unsigned char* communication_get_msg_buffer() {
    return G_communication_msg_buffer;
}

uint8_t access_get_retries() {
    return ACCESS_RETRIES();
}

bool access_is_locked() {
    NUM_CALLS(access_is_locked)++;
    return G_mock_data.access_locked;
}

bool access_is_wiped() {
    NUM_CALLS(access_is_wiped)++;
    return ACCESS_WIPED();
}

bool access_unlock(char* password, uint8_t password_length) {
    int next_index = NUM_CALLS(access_unlock)++;
    access_unlock_args_t* args = &MOCK_ARGS(access_unlock, next_index);
    memcpy(args->password, password, password_length);
    args->password_length = password_length;
    return true;
}

bool seed_init() {
    MOCK_CALL(seed_init);
    return true;
}

bool seed_wipe() {
    MOCK_CALL(seed_wipe);
    SEED_SET_AVAILABLE(false);
    return true;
}

bool seed_generate(uint8_t* client_seed, uint8_t client_seed_size) {
    int next_index = NUM_CALLS(seed_generate)++;
    seed_generate_args_t* args = &MOCK_ARGS(seed_generate, next_index);
    memcpy(args->client_seed, client_seed, SEED_LENGTH);
    args->size = client_seed_size;
    if (SHOULD_FAIL(seed_generate)) {
        FORCE_FAIL(seed_generate, false);
        return false;
    }
    SEED_SET_AVAILABLE(true);
    return true;
}

bool seed_available() {
    return G_mock_data.seed_available;
}

bool sest_init() {
    MOCK_CALL(sest_init);
    return true;
}

size_t communication_get_msg_buffer_size() {
    return sizeof(G_io_apdu_buffer);
}

bool endorsement_init() {
    MOCK_CALL(endorsement_init);
    return true;
}

void endorsement_finalise() {
    // Nothing to do here
}

void nvmem_init() {
    NUM_CALLS(nvmem_init)++;
}

bool nvmem_register_block(char* key, void* addr, size_t size) {
    int next_index = NUM_CALLS(nvmem_register_block)++;
    nvmem_register_block_args_t* args =
        &MOCK_ARGS(nvmem_register_block, next_index);
    args->key = key;
    args->addr = addr;
    args->size = size;
    if ((G_mock_data.force_nvmem_register_block_fail_key) &&
        (0 == strcmp(key, G_mock_data.force_nvmem_register_block_fail_key))) {
        FORCE_NVMEM_FAIL_ON_KEY(NULL);
        return false;
    }
    return true;
}

unsigned int hsm_process_apdu(unsigned int rx) {
    assert(G_mock_data.external_processor != NULL);
    G_mock_data.last_result = G_mock_data.external_processor(rx);
    return G_mock_data.last_result.tx;
}

void upgrade_init() {
    NUM_CALLS(upgrade_init)++;
}

bool evidence_init() {
    MOCK_CALL(evidence_init);
    return true;
}

void evidence_finalise() {
    // Nothing to do here
}

unsigned int upgrade_process_apdu(volatile unsigned int rx) {
    NUM_CALLS(upgrade_process_apdu)++;
    SET_APDU_OP(APDU_OP() * 3);
    return 3;
}

void upgrade_reset() {
    NUM_CALLS(upgrade_reset)++;
}

unsigned int do_meta_advupd(unsigned int rx) {
    NUM_CALLS(do_meta_advupd)++;
    SET_APDU_OP(APDU_OP() * 5);
    return 3;
}

// Helper functions
static void setup() {
    memset(&G_mock_data, 0, sizeof(G_mock_data));
}

static void teardown() {
}

static void assert_nvmem_register_block_called_with(int call_index,
                                                    const char* key,
                                                    void* addr,
                                                    size_t size) {
    nvmem_register_block_args_t args =
        MOCK_ARGS(nvmem_register_block, call_index);
    ASSERT_STR_EQUALS(args.key, key);
    assert(args.addr == addr);
    assert(args.size == size);
}

static void assert_seed_generate_called_with(int call_index,
                                             const uint8_t* client_seed,
                                             size_t size) {
    seed_generate_args_t args = MOCK_ARGS(seed_generate, call_index);
    ASSERT_STR_EQUALS(args.client_seed, client_seed);
    assert(args.size == size);
}

static void assert_access_set_password_called_with(int call_index,
                                                   const char* password,
                                                   size_t size) {
    access_set_password_args_t args =
        MOCK_ARGS(access_set_password, call_index);
    ASSERT_STR_EQUALS(args.password, password);
    assert(args.password_length == size);
}

static void assert_access_unlock_called_with(int call_index,
                                             const char* password,
                                             size_t size) {
    access_unlock_args_t args = MOCK_ARGS(access_unlock, call_index);
    ASSERT_STR_EQUALS(args.password, password);
    assert(args.password_length == size);
}

// Test cases
void test_init_success() {
    setup();
    printf("Test system_init success...\n");

    assert(system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer)));
    assert(NUM_CALLS(oe_is_outside_enclave) == 1);
    assert(NUM_CALLS(sest_init) == 1);
    assert(NUM_CALLS(access_init) == 1);
    assert(NUM_CALLS(seed_init) == 1);
    assert(NUM_CALLS(access_is_wiped) == 1);
    assert(NUM_CALLS(communication_init) == 1);
    assert(NUM_CALLS(evidence_init) == 1);
    assert(NUM_CALLS(endorsement_init) == 1);
    assert(NUM_CALLS(nvmem_init) == 1);
    assert(NUM_CALLS(nvmem_register_block) == 2);
    ASSERT_CALLED_WITH(nvmem_register_block,
                       0,
                       "bcstate",
                       &N_bc_state_var,
                       sizeof(N_bc_state_var));
    ASSERT_CALLED_WITH(nvmem_register_block,
                       1,
                       "bcstate_updating",
                       &N_bc_state_updating_backup_var,
                       sizeof(N_bc_state_updating_backup_var));
    assert(NUM_CALLS(nvmem_load) == 1);
    assert(NUM_CALLS(hsm_init) == 1);
    assert(NUM_CALLS(hsm_set_external_processor) == 1);
    assert(NUM_CALLS(upgrade_init) == 1);

    teardown();
}

void test_init_fails_invalid_buf_size() {
    setup();
    printf("Test system_init fails with invalid buffer size...\n");

    assert(!system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer) - 1));
    ASSERT_NOT_CALLED(oe_is_outside_enclave);
    ASSERT_NOT_CALLED(sest_init);
    ASSERT_NOT_CALLED(access_init);
    ASSERT_NOT_CALLED(seed_init);
    ASSERT_NOT_CALLED(communication_init);
    ASSERT_NOT_CALLED(evidence_init);
    ASSERT_NOT_CALLED(endorsement_init);
    ASSERT_NOT_CALLED(nvmem_init);
    ASSERT_NOT_CALLED(upgrade_init);
    teardown();
}

void test_init_fails_invalid_buf_memarea() {
    setup();
    printf("Test system_init fails with invalid buffer memory area...\n");

    FORCE_FAIL(oe_is_outside_enclave, true);
    assert(!system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer)));
    assert(NUM_CALLS(oe_is_outside_enclave) == 1);
    ASSERT_NOT_CALLED(sest_init);
    ASSERT_NOT_CALLED(access_init);
    ASSERT_NOT_CALLED(seed_init);
    ASSERT_NOT_CALLED(communication_init);
    ASSERT_NOT_CALLED(evidence_init);
    ASSERT_NOT_CALLED(endorsement_init);
    ASSERT_NOT_CALLED(nvmem_init);
    ASSERT_NOT_CALLED(upgrade_init);
    teardown();
}

void test_init_fails_when_sest_init_fails() {
    setup();
    printf("Test system_init fails when sest_init fails...\n");

    FORCE_FAIL(sest_init, true);
    assert(!system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer)));
    assert(NUM_CALLS(oe_is_outside_enclave) == 1);
    assert(NUM_CALLS(sest_init) == 1);
    ASSERT_NOT_CALLED(access_init);
    ASSERT_NOT_CALLED(seed_init);
    ASSERT_NOT_CALLED(communication_init);
    ASSERT_NOT_CALLED(evidence_init);
    ASSERT_NOT_CALLED(endorsement_init);
    ASSERT_NOT_CALLED(nvmem_init);
    ASSERT_NOT_CALLED(upgrade_init);
    teardown();
}

void test_init_fails_when_access_init_fails() {
    setup();
    printf("Test system_init fails when access_init fails...\n");

    FORCE_FAIL(access_init, true);
    assert(!system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer)));
    assert(NUM_CALLS(oe_is_outside_enclave) == 1);
    assert(NUM_CALLS(sest_init) == 1);
    assert(NUM_CALLS(access_init) == 1);
    ASSERT_NOT_CALLED(seed_init);
    ASSERT_NOT_CALLED(communication_init);
    ASSERT_NOT_CALLED(evidence_init);
    ASSERT_NOT_CALLED(endorsement_init);
    ASSERT_NOT_CALLED(nvmem_init);
    ASSERT_NOT_CALLED(upgrade_init);
    teardown();
}

void test_init_fails_when_seed_init_fails() {
    setup();
    printf("Test system_init fails when seed_init fails...\n");

    FORCE_FAIL(seed_init, true);
    assert(!system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer)));
    assert(NUM_CALLS(oe_is_outside_enclave) == 1);
    assert(NUM_CALLS(sest_init) == 1);
    assert(NUM_CALLS(access_init) == 1);
    assert(NUM_CALLS(seed_init) == 1);
    ASSERT_NOT_CALLED(communication_init);
    ASSERT_NOT_CALLED(evidence_init);
    ASSERT_NOT_CALLED(endorsement_init);
    ASSERT_NOT_CALLED(nvmem_init);
    ASSERT_NOT_CALLED(upgrade_init);
    teardown();
}

void test_init_fails_when_communication_init_fails() {
    setup();
    printf("Test system_init fails when communication_init fails...\n");

    FORCE_FAIL(communication_init, true);
    assert(!system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer)));
    assert(NUM_CALLS(oe_is_outside_enclave) == 1);
    assert(NUM_CALLS(sest_init) == 1);
    assert(NUM_CALLS(access_init) == 1);
    assert(NUM_CALLS(seed_init) == 1);
    assert(NUM_CALLS(communication_init) == 1);
    ASSERT_NOT_CALLED(evidence_init);
    ASSERT_NOT_CALLED(endorsement_init);
    ASSERT_NOT_CALLED(nvmem_init);
    ASSERT_NOT_CALLED(upgrade_init);
    teardown();
}

void test_init_fails_when_evidence_init_fails() {
    setup();
    printf("Test system_init fails when communication_init fails...\n");

    FORCE_FAIL(evidence_init, true);
    assert(!system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer)));
    assert(NUM_CALLS(oe_is_outside_enclave) == 1);
    assert(NUM_CALLS(sest_init) == 1);
    assert(NUM_CALLS(access_init) == 1);
    assert(NUM_CALLS(seed_init) == 1);
    assert(NUM_CALLS(communication_init) == 1);
    assert(NUM_CALLS(evidence_init) == 1);
    ASSERT_NOT_CALLED(endorsement_init);
    ASSERT_NOT_CALLED(nvmem_init);
    ASSERT_NOT_CALLED(upgrade_init);
    teardown();
}

void test_init_fails_when_endorsement_init_fails() {
    setup();
    printf("Test system_init fails when endorsement_init fails...\n");

    FORCE_FAIL(endorsement_init, true);
    assert(!system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer)));
    assert(NUM_CALLS(oe_is_outside_enclave) == 1);
    assert(NUM_CALLS(sest_init) == 1);
    assert(NUM_CALLS(access_init) == 1);
    assert(NUM_CALLS(seed_init) == 1);
    assert(NUM_CALLS(communication_init) == 1);
    assert(NUM_CALLS(evidence_init) == 1);
    assert(NUM_CALLS(endorsement_init) == 1);
    ASSERT_NOT_CALLED(nvmem_init);
    ASSERT_NOT_CALLED(upgrade_init);
    teardown();
}

void test_init_fails_when_nvmem_register_block_fails() {
    setup();
    printf("Test system_init fails when nvmem_register_block fails...\n");

    FORCE_NVMEM_FAIL_ON_KEY("bcstate");
    assert(!system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer)));
    assert(NUM_CALLS(oe_is_outside_enclave) == 1);
    assert(NUM_CALLS(sest_init) == 1);
    assert(NUM_CALLS(access_init) == 1);
    assert(NUM_CALLS(seed_init) == 1);
    assert(NUM_CALLS(communication_init) == 1);
    assert(NUM_CALLS(evidence_init) == 1);
    assert(NUM_CALLS(endorsement_init) == 1);
    assert(NUM_CALLS(nvmem_init) == 1);
    assert(NUM_CALLS(nvmem_register_block) == 1);
    ASSERT_CALLED_WITH(nvmem_register_block,
                       0,
                       "bcstate",
                       &N_bc_state_var,
                       sizeof(N_bc_state_var));
    ASSERT_NOT_CALLED(upgrade_init);

    FORCE_NVMEM_FAIL_ON_KEY("bcstate_updating");
    assert(!system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer)));
    assert(NUM_CALLS(oe_is_outside_enclave) == 2);
    assert(NUM_CALLS(sest_init) == 2);
    assert(NUM_CALLS(access_init) == 2);
    assert(NUM_CALLS(seed_init) == 2);
    assert(NUM_CALLS(communication_init) == 2);
    assert(NUM_CALLS(evidence_init) == 2);
    assert(NUM_CALLS(endorsement_init) == 2);
    assert(NUM_CALLS(nvmem_init) == 2);
    assert(NUM_CALLS(nvmem_register_block) == 3);
    ASSERT_CALLED_WITH(nvmem_register_block,
                       1,
                       "bcstate",
                       &N_bc_state_var,
                       sizeof(N_bc_state_var));
    ASSERT_CALLED_WITH(nvmem_register_block,
                       2,
                       "bcstate_updating",
                       &N_bc_state_updating_backup_var,
                       sizeof(N_bc_state_updating_backup_var));
    ASSERT_NOT_CALLED(upgrade_init);

    teardown();
}

void test_init_fails_when_nvmem_load_fails() {
    setup();
    printf("Test system_init fails when nvmem_load fails...\n");

    FORCE_FAIL(nvmem_load, true);
    assert(!system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer)));
    assert(NUM_CALLS(oe_is_outside_enclave) == 1);
    assert(NUM_CALLS(sest_init) == 1);
    assert(NUM_CALLS(access_init) == 1);
    assert(NUM_CALLS(seed_init) == 1);
    assert(NUM_CALLS(communication_init) == 1);
    assert(NUM_CALLS(evidence_init) == 1);
    assert(NUM_CALLS(endorsement_init) == 1);
    assert(NUM_CALLS(nvmem_init) == 1);
    assert(NUM_CALLS(nvmem_load) == 1);
    assert(NUM_CALLS(nvmem_register_block) == 2);
    ASSERT_CALLED_WITH(nvmem_register_block,
                       0,
                       "bcstate",
                       &N_bc_state_var,
                       sizeof(N_bc_state_var));
    ASSERT_CALLED_WITH(nvmem_register_block,
                       1,
                       "bcstate_updating",
                       &N_bc_state_updating_backup_var,
                       sizeof(N_bc_state_updating_backup_var));
    ASSERT_NOT_CALLED(upgrade_init);

    teardown();
}

void test_system_is_wiped_when_inconsistent_state() {
    setup();
    printf("Test system is wiped when an inconsistent state is found...\n");

    // Seed available but access wiped
    SEED_SET_AVAILABLE(true);
    ACCESS_SET_WIPED(true);
    assert(system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer)));
    assert(!SEED_AVAILABLE());
    assert(ACCESS_WIPED());

    // Seed not available but access not wiped
    SEED_SET_AVAILABLE(false);
    ACCESS_SET_WIPED(false);
    assert(system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer)));
    assert(!SEED_AVAILABLE());
    assert(ACCESS_WIPED());

    // Init will fail if either access or seed wipe fails
    SEED_SET_AVAILABLE(false);
    ACCESS_SET_WIPED(false);
    FORCE_FAIL(access_wipe, true);
    assert(!system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer)));
    assert(!SEED_AVAILABLE());
    assert(!ACCESS_WIPED());

    SEED_SET_AVAILABLE(true);
    ACCESS_SET_WIPED(true);
    FORCE_FAIL(seed_wipe, true);
    assert(!system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer)));
    assert(SEED_AVAILABLE());
    assert(ACCESS_WIPED());

    teardown();
}

void test_get_mode_succeeds_when_locked() {
    setup();
    printf("Test system_process_apdu handles RSK_MODE_CMD when locked...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    ACCESS_LOCK();
    SET_APDU("\x80\x43", rx); // RSK_MODE_CMD
    assert(2 == system_process_apdu(rx));
    ASSERT_HANDLED();
    ASSERT_APDU("\x80\x02"); // APP_MODE_BOOTLOADER

    teardown();
}

void test_get_mode_ignored_when_unlocked() {
    setup();
    printf("Test system_process_apdu ignores RSK_MODE_CMD when unlocked...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    ACCESS_UNLOCK();
    SET_APDU("\x80\x43", rx); // RSK_MODE_CMD
    assert(0 == system_process_apdu(rx));
    ASSERT_NOT_HANDLED();

    teardown();
}

void test_onboard_cmd_handled() {
    setup();
    printf("Test onboard command success...\n");

    SEED_SET_AVAILABLE(false);
    ACCESS_SET_WIPED(true);
    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    SET_APDU("\x80\xA0\x00" MOCK_SEED MOCK_PASSWORD, rx); // SGX_ONBOARD
    assert(3 == system_process_apdu(rx));
    ASSERT_HANDLED();
    ASSERT_APDU("\x80\xA0\x01");
    assert(NUM_CALLS(seed_generate) == 1);
    assert(NUM_CALLS(access_set_password) == 1);
    ASSERT_CALLED_WITH(
        seed_generate, 0, (const uint8_t*)MOCK_SEED, SEED_LENGTH);
    ASSERT_CALLED_WITH(
        access_set_password, 0, MOCK_PASSWORD, strlen(MOCK_PASSWORD));
    assert(SEED_AVAILABLE());
    assert(!ACCESS_WIPED());
    teardown();
}

void test_onboard_cmd_fails_when_seed_already_available() {
    setup();
    printf("Test onboard command fails when seed already available...\n");

    SEED_SET_AVAILABLE(false);
    ACCESS_SET_WIPED(true);
    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    SEED_SET_AVAILABLE(true);
    unsigned int rx = 0;
    SET_APDU("\x80\xA0\x00" MOCK_SEED MOCK_PASSWORD, rx); // SGX_ONBOARD
    BEGIN_TRY {
        TRY {
            system_process_apdu(rx);
            // system_process_apdu should throw ERR_DEVICE_ONBOARDED
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(e == ERR_DEVICE_ONBOARDED);
        }
        FINALLY {
            ASSERT_NOT_HANDLED();
            assert(NUM_CALLS(seed_generate) == 0);
            assert(NUM_CALLS(access_set_password) == 0);
            teardown();
            return;
        }
    }
    END_TRY;
}

void test_onboard_cmd_fails_when_no_password_is_provided() {
    setup();
    printf("Test onboard command fails when no password is provided...\n");

    SEED_SET_AVAILABLE(false);
    ACCESS_SET_WIPED(true);
    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    SET_APDU("\x80\xA0\x00" MOCK_SEED, rx); // SGX_ONBOARD
    BEGIN_TRY {
        TRY {
            system_process_apdu(rx);
            // system_process_apdu should throw ERR_DEVICE_ONBOARDED
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(e == ERR_INVALID_DATA_SIZE);
        }
        FINALLY {
            ASSERT_NOT_HANDLED();
            assert(NUM_CALLS(seed_generate) == 0);
            assert(NUM_CALLS(access_set_password) == 0);
            teardown();
            return;
        }
    }
    END_TRY;
}

void test_onboard_cmd_fails_when_seed_generate_fails() {
    setup();
    printf("Test onboard command fails when seed_generate fails...\n");

    SEED_SET_AVAILABLE(false);
    ACCESS_SET_WIPED(true);
    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    FORCE_FAIL(seed_generate, true);
    unsigned int rx = 0;
    SET_APDU("\x80\xA0\x00" MOCK_SEED MOCK_PASSWORD, rx); // SGX_ONBOARD
    BEGIN_TRY {
        TRY {
            system_process_apdu(rx);
            // system_process_apdu should throw ERR_DEVICE_ONBOARDED
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(e == ERR_ONBOARDING);
        }
        FINALLY {
            ASSERT_NOT_HANDLED();
            assert(NUM_CALLS(seed_generate) == 1);
            assert(NUM_CALLS(seed_wipe) == 1);
            assert(NUM_CALLS(access_wipe) == 1);
            teardown();
            return;
        }
    }
    END_TRY;
}

void test_onboard_cmd_fails_when_set_password_fails() {
    setup();
    printf("Test onboard command fails when access_set_password fails...\n");

    SEED_SET_AVAILABLE(false);
    ACCESS_SET_WIPED(true);
    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    FORCE_FAIL(access_set_password, true);
    unsigned int rx = 0;
    SET_APDU("\x80\xA0\x00" MOCK_SEED MOCK_PASSWORD, rx); // SGX_ONBOARD
    BEGIN_TRY {
        TRY {
            system_process_apdu(rx);
            // system_process_apdu should throw ERR_DEVICE_ONBOARDED
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(e == ERR_ONBOARDING);
        }
        FINALLY {
            ASSERT_NOT_HANDLED();
            assert(NUM_CALLS(seed_generate) == 1);
            assert(NUM_CALLS(seed_wipe) == 1);
            assert(NUM_CALLS(access_wipe) == 1);
            assert(NUM_CALLS(access_set_password) == 1);
            teardown();
            return;
        }
    }
    END_TRY;
}

void test_change_password_cmd_handled() {
    setup();
    printf("Test change_password command success...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    SEED_SET_AVAILABLE(true);
    ACCESS_UNLOCK();
    SET_APDU("\x80\xA5\x00" MOCK_PASSWORD, rx); // SGX_CHANGE_PASSWORD
    assert(3 == system_process_apdu(rx));
    ASSERT_APDU("\x80\xA5\x01");
    assert(NUM_CALLS(access_set_password) == 1);
    ASSERT_CALLED_WITH(
        access_set_password, 0, MOCK_PASSWORD, strlen(MOCK_PASSWORD));
    teardown();
}

void test_change_password_cmd_fails_when_no_password_is_provided() {
    setup();
    printf(
        "Test change_password command fails when no password is provided...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    SEED_SET_AVAILABLE(true);
    ACCESS_UNLOCK();
    SET_APDU("\x80\xA5\x00", rx); // SGX_CHANGE_PASSWORD
    BEGIN_TRY {
        TRY {
            system_process_apdu(rx);
            // system_process_apdu should throw ERR_INVALID_DATA_SIZE
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(e == ERR_INVALID_DATA_SIZE);
        }
        FINALLY {
            ASSERT_NOT_HANDLED();
            ASSERT_NOT_CALLED(access_set_password);
            teardown();
            return;
        }
    }
    END_TRY;
}

void test_change_password_cmd_fails_when_access_set_password_fails() {
    setup();
    printf(
        "Test change_password command fails when no password is provided...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    SEED_SET_AVAILABLE(true);
    ACCESS_UNLOCK();
    FORCE_FAIL(access_set_password, true);
    SET_APDU("\x80\xA5\x00" MOCK_PASSWORD, rx); // SGX_CHANGE_PASSWORD
    BEGIN_TRY {
        TRY {
            system_process_apdu(rx);
            // system_process_apdu should throw ERR_PASSWORD_CHANGE
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(e == ERR_PASSWORD_CHANGE);
        }
        FINALLY {
            ASSERT_NOT_HANDLED();
            assert(NUM_CALLS(access_set_password) == 1);
            ASSERT_CALLED_WITH(
                access_set_password, 0, MOCK_PASSWORD, strlen(MOCK_PASSWORD));
            teardown();
            return;
        }
    }
    END_TRY;
}

void test_unlock_cmd_handled() {
    setup();
    printf("Test unlock command success...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    SEED_SET_AVAILABLE(true);
    ACCESS_LOCK();
    SET_APDU("\x80\xA3\x00" MOCK_PASSWORD, rx); // SGX_UNLOCK
    assert(3 == system_process_apdu(rx));
    ASSERT_HANDLED();
    ASSERT_APDU("\x80\xA3\x01");
    assert(NUM_CALLS(access_is_locked) == 1);
    assert(NUM_CALLS(access_unlock) == 1);
    ASSERT_CALLED_WITH(access_unlock, 0, MOCK_PASSWORD, strlen(MOCK_PASSWORD));

    teardown();
}

void test_unlock_cmd_handled_when_already_unlocked() {
    setup();
    printf("Test unlock command is handled when already unlocked...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    SEED_SET_AVAILABLE(true);
    ACCESS_UNLOCK();
    SET_APDU("\x80\xA3\x00" MOCK_PASSWORD, rx); // SGX_UNLOCK
    assert(3 == system_process_apdu(rx));
    ASSERT_HANDLED();
    ASSERT_APDU("\x80\xA3\x01");
    assert(NUM_CALLS(access_is_locked) == 1);
    assert(NUM_CALLS(access_unlock) == 0);
    ASSERT_APDU("\x80\xA3\x01");

    teardown();
}

void test_unlock_cmd_fails_when_no_password_is_provided() {
    setup();
    printf("Test unlock command fails when no password is provided...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    SEED_SET_AVAILABLE(true);
    ACCESS_LOCK();
    SET_APDU("\x80\xA3\x00", rx); // SGX_UNLOCK
    BEGIN_TRY {
        TRY {
            system_process_apdu(rx);
            // system_process_apdu should throw ERR_INVALID_DATA_SIZE
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(e == ERR_INVALID_DATA_SIZE);
        }
        FINALLY {
            ASSERT_NOT_HANDLED();
            ASSERT_NOT_CALLED(access_unlock);
            teardown();
            return;
        }
    }
    END_TRY;
}

void test_echo_cmd_handled() {
    setup();
    printf("Test echo command success...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    const char data[] = "\x80\xA4\x01\x02\x03\x04\x05\x06"; // SGX_ECHO
    SET_APDU(data, rx);
    assert((sizeof(data) - 1) == system_process_apdu(rx));
    ASSERT_HANDLED();
    ASSERT_APDU(data);

    teardown();
}

void test_is_locked_cmd_handled() {
    setup();
    printf("Test is_locked command...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    SEED_SET_AVAILABLE(true);
    ACCESS_LOCK();
    SET_APDU("\x80\xA1", rx); // SGX_IS_LOCKED
    assert(3 == system_process_apdu(rx));
    ASSERT_HANDLED();
    ASSERT_APDU("\x80\xA1\x01");

    ACCESS_UNLOCK();
    SET_APDU("\x80\xA1", rx); // SGX_IS_LOCKED
    assert(3 == system_process_apdu(rx));
    ASSERT_HANDLED();
    ASSERT_APDU("\x80\xA1\x00");

    teardown();
}

void test_retries_cmd_handled() {
    setup();
    printf("Test retries command success...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    SEED_SET_AVAILABLE(true);
    ACCESS_LOCK();
    ACCESS_SET_RETRIES(3);
    SET_APDU("\x80\xA2", rx); // SGX_RETRIES
    assert(3 == system_process_apdu(rx));
    ASSERT_HANDLED();
    ASSERT_APDU("\x80\xA2\x03");
}

void test_upgrade_cmd_handled() {
    setup();
    printf("Test upgrade command success...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    SET_APDU("\x80\xA6\x05", rx); // SGX_UPGRADE
    assert(3 == system_process_apdu(rx));
    ASSERT_HANDLED();
    ASSERT_APDU("\x80\xA6\x0F");
    assert(NUM_CALLS(upgrade_process_apdu) == 1);
}

void test_upgrade_resets_when_other_cmds_in_between() {
    setup();
    printf("Test upgrade command resets when other commands in between...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    SET_APDU("\x80\xA6\x05", rx); // SGX_UPGRADE
    assert(3 == system_process_apdu(rx));
    SET_APDU("\x80\xA6\x05", rx); // SGX_UPGRADE
    assert(3 == system_process_apdu(rx));
    assert(NUM_CALLS(upgrade_reset) == 1);
    assert(NUM_CALLS(upgrade_process_apdu) == 2);
    SET_APDU("\x80\x06\x00", rx); // RSK_IS_ONBOARD
    system_process_apdu(rx);
    assert(NUM_CALLS(upgrade_reset) == 2);
    SET_APDU("\x80\xA6\x05", rx); // SGX_UPGRADE
    assert(3 == system_process_apdu(rx));
    assert(NUM_CALLS(upgrade_reset) == 3);
    assert(NUM_CALLS(upgrade_process_apdu) == 3);
    SET_APDU("\x80\xA6\x05", rx); // SGX_UPGRADE
    assert(3 == system_process_apdu(rx));
    assert(NUM_CALLS(upgrade_reset) == 3);
    assert(NUM_CALLS(upgrade_process_apdu) == 4);
}

void test_heartbeat_cmd_throws_unsupported() {
    setup();
    printf("Test heartbeat command throws unsupported instruction...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    SEED_SET_AVAILABLE(true);
    ACCESS_UNLOCK();
    SET_APDU("\x80\x60\x00", rx); // SGX_ONBOARD
    BEGIN_TRY {
        TRY {
            system_process_apdu(rx);
            // system_process_apdu should throw ERR_INS_NOT_SUPPORTED
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(e == ERR_INS_NOT_SUPPORTED);
        }
        FINALLY {
            ASSERT_NOT_HANDLED();
            teardown();
            return;
        }
    }
    END_TRY;
}

void test_advance_bc_cmd_handled() {
    setup();
    printf("Test advance blockchain command success...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    SEED_SET_AVAILABLE(true);
    ACCESS_UNLOCK();
    unsigned int rx = 0;
    SET_APDU("\x80\x10\x11\x22\x33\x44", rx); // INS_ADVANCE
    assert(3 == system_process_apdu(rx));
    ASSERT_HANDLED();
    ASSERT_APDU("\x80\x10\x55");
    assert(NUM_CALLS(do_meta_advupd) == 1);
}

void test_advance_bc_cmd_fails_when_not_onboarded() {
    setup();
    printf("Test advance blockchain command fails when not onboarded...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    SEED_SET_AVAILABLE(false);
    unsigned int rx = 0;
    SET_APDU("\x80\x10\x11\x22\x33\x44", rx); // INS_ADVANCE
    BEGIN_TRY {
        TRY {
            system_process_apdu(rx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(e == ERR_DEVICE_NOT_ONBOARDED);
        }
        FINALLY {
            ASSERT_NOT_HANDLED();
            ASSERT_NOT_CALLED(do_meta_advupd);
            teardown();
            return;
        }
    }
    END_TRY;
}

void test_advance_bc_cmd_fails_when_locked() {
    setup();
    printf("Test advance blockchain command fails when locked...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    SEED_SET_AVAILABLE(true);
    ACCESS_LOCK();
    unsigned int rx = 0;
    SET_APDU("\x80\x10\x11\x22\x33\x44", rx); // INS_ADVANCE
    BEGIN_TRY {
        TRY {
            system_process_apdu(rx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(e == ERR_DEVICE_LOCKED);
        }
        FINALLY {
            ASSERT_NOT_HANDLED();
            ASSERT_NOT_CALLED(do_meta_advupd);
            teardown();
            return;
        }
    }
    END_TRY;
}

void test_advance_bc_resets_when_other_cmds_in_between() {
    setup();
    printf("Test advance blockchain command resets when other commands in "
           "between...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    SEED_SET_AVAILABLE(true);
    ACCESS_UNLOCK();

    SET_APDU("\x80\x10\x01", rx); // INS_ADVANCE
    assert(3 == system_process_apdu(rx));
    SET_APDU("\x80\x10\x02", rx); // INS_ADVANCE
    assert(3 == system_process_apdu(rx));
    assert(NUM_CALLS(hsm_reset_if_starting) == 1);
    assert(G_mock_data.mock_call_args->hsm_reset_if_starting_args.cmd ==
           INS_ADVANCE);
    assert(NUM_CALLS(do_meta_advupd) == 2);
    SET_APDU("\x80\xA1\x00", rx); // SGX_IS_LOCKED
    system_process_apdu(rx);
    assert(NUM_CALLS(hsm_reset_if_starting) == 2);
    printf("%u\n", G_mock_data.mock_call_args->hsm_reset_if_starting_args.cmd);
    assert(G_mock_data.mock_call_args->hsm_reset_if_starting_args.cmd ==
           SGX_IS_LOCKED);
    assert(NUM_CALLS(do_meta_advupd) == 2);
    SET_APDU("\x80\x10\x01", rx); // INS_ADVANCE
    assert(3 == system_process_apdu(rx));
    assert(NUM_CALLS(hsm_reset_if_starting) == 3);
    assert(G_mock_data.mock_call_args->hsm_reset_if_starting_args.cmd ==
           INS_ADVANCE);
    assert(NUM_CALLS(do_meta_advupd) == 3);
    SET_APDU("\x80\x10\x01", rx); // INS_ADVANCE
    assert(3 == system_process_apdu(rx));
    assert(NUM_CALLS(hsm_reset_if_starting) == 3);
    assert(NUM_CALLS(do_meta_advupd) == 4);
}

void test_upd_ancestor_cmd_handled() {
    setup();
    printf("Test update ancestor command success...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    SEED_SET_AVAILABLE(true);
    ACCESS_UNLOCK();
    unsigned int rx = 0;
    SET_APDU("\x80\x30\x11\x22\x33\x44", rx); // INS_UPD_ANCESTOR
    assert(3 == system_process_apdu(rx));
    ASSERT_HANDLED();
    ASSERT_APDU("\x80\x30\x55");
    assert(NUM_CALLS(do_meta_advupd) == 1);
}

void test_upd_ancestor_cmd_fails_when_not_onboarded() {
    setup();
    printf("Test update ancestor command fails when not onboarded...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    SEED_SET_AVAILABLE(false);
    unsigned int rx = 0;
    SET_APDU("\x80\x30\x11\x22\x33\x44", rx); // INS_UPD_ANCESTOR
    BEGIN_TRY {
        TRY {
            system_process_apdu(rx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(e == ERR_DEVICE_NOT_ONBOARDED);
        }
        FINALLY {
            ASSERT_NOT_HANDLED();
            ASSERT_NOT_CALLED(do_meta_advupd);
            teardown();
            return;
        }
    }
    END_TRY;
}

void test_upd_ancestor_cmd_fails_when_locked() {
    setup();
    printf("Test update ancestor command fails when locked...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    SEED_SET_AVAILABLE(true);
    ACCESS_LOCK();
    unsigned int rx = 0;
    SET_APDU("\x80\x30\x11\x22\x33\x44", rx); // INS_UPD_ANCESTOR
    BEGIN_TRY {
        TRY {
            system_process_apdu(rx);
            ASSERT_FAIL();
        }
        CATCH_OTHER(e) {
            assert(e == ERR_DEVICE_LOCKED);
        }
        FINALLY {
            ASSERT_NOT_HANDLED();
            ASSERT_NOT_CALLED(do_meta_advupd);
            teardown();
            return;
        }
    }
    END_TRY;
}

void test_upd_ancestor_resets_when_other_cmds_in_between() {
    setup();
    printf("Test update ancestor command resets when other commands in "
           "between...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    SEED_SET_AVAILABLE(true);
    ACCESS_UNLOCK();

    SET_APDU("\x80\x30\x01", rx); // INS_UPD_ANCESTOR
    assert(3 == system_process_apdu(rx));
    SET_APDU("\x80\x30\x02", rx); // INS_UPD_ANCESTOR
    assert(3 == system_process_apdu(rx));
    assert(NUM_CALLS(hsm_reset_if_starting) == 1);
    assert(G_mock_data.mock_call_args->hsm_reset_if_starting_args.cmd ==
           INS_UPD_ANCESTOR);
    assert(NUM_CALLS(do_meta_advupd) == 2);
    SET_APDU("\x80\xA1\x00", rx); // SGX_IS_LOCKED
    system_process_apdu(rx);
    assert(NUM_CALLS(hsm_reset_if_starting) == 2);
    printf("%u\n", G_mock_data.mock_call_args->hsm_reset_if_starting_args.cmd);
    assert(G_mock_data.mock_call_args->hsm_reset_if_starting_args.cmd ==
           SGX_IS_LOCKED);
    assert(NUM_CALLS(do_meta_advupd) == 2);
    SET_APDU("\x80\x30\x01", rx); // INS_UPD_ANCESTOR
    assert(3 == system_process_apdu(rx));
    assert(NUM_CALLS(hsm_reset_if_starting) == 3);
    assert(G_mock_data.mock_call_args->hsm_reset_if_starting_args.cmd ==
           INS_UPD_ANCESTOR);
    assert(NUM_CALLS(do_meta_advupd) == 3);
    SET_APDU("\x80\x30\x01", rx); // INS_UPD_ANCESTOR
    assert(3 == system_process_apdu(rx));
    assert(NUM_CALLS(hsm_reset_if_starting) == 3);
    assert(NUM_CALLS(do_meta_advupd) == 4);
}

void test_invalid_cmd_not_handled() {
    setup();
    printf("Test invalid command is ignored...\n");

    system_init(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    unsigned int rx = 0;
    SEED_SET_AVAILABLE(true);
    ACCESS_UNLOCK();
    SET_APDU("\x80\xFF", rx); // Invalid command
    assert(0 == system_process_apdu(rx));
    ASSERT_NOT_HANDLED();

    teardown();
}

int main() {
    test_init_success();
    test_init_fails_invalid_buf_size();
    test_init_fails_invalid_buf_memarea();
    test_init_fails_when_sest_init_fails();
    test_init_fails_when_access_init_fails();
    test_init_fails_when_seed_init_fails();
    test_init_fails_when_communication_init_fails();
    test_init_fails_when_evidence_init_fails();
    test_init_fails_when_endorsement_init_fails();
    test_init_fails_when_nvmem_register_block_fails();
    test_init_fails_when_nvmem_load_fails();
    test_system_is_wiped_when_inconsistent_state();
    test_get_mode_succeeds_when_locked();
    test_get_mode_ignored_when_unlocked();
    test_onboard_cmd_handled();
    test_onboard_cmd_fails_when_seed_already_available();
    test_onboard_cmd_fails_when_no_password_is_provided();
    test_onboard_cmd_fails_when_seed_generate_fails();
    test_onboard_cmd_fails_when_set_password_fails();
    test_change_password_cmd_handled();
    test_change_password_cmd_fails_when_no_password_is_provided();
    test_change_password_cmd_fails_when_access_set_password_fails();
    test_unlock_cmd_handled();
    test_unlock_cmd_handled_when_already_unlocked();
    test_unlock_cmd_fails_when_no_password_is_provided();
    test_echo_cmd_handled();
    test_is_locked_cmd_handled();
    test_retries_cmd_handled();
    test_heartbeat_cmd_throws_unsupported();
    test_upgrade_cmd_handled();
    test_upgrade_resets_when_other_cmds_in_between();
    test_advance_bc_cmd_handled();
    test_advance_bc_cmd_fails_when_not_onboarded();
    test_advance_bc_cmd_fails_when_locked();
    test_advance_bc_resets_when_other_cmds_in_between();
    test_upd_ancestor_cmd_handled();
    test_upd_ancestor_cmd_fails_when_not_onboarded();
    test_upd_ancestor_cmd_fails_when_locked();
    test_upd_ancestor_resets_when_other_cmds_in_between();
    test_invalid_cmd_not_handled();

    return 0;
}

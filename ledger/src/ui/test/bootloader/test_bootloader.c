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
#include <string.h>
#include <assert.h>
#include <pthread.h>

#include "bolos_ux.h"
#include "bootloader.h"

// Current active screen
typedef enum active_screen_e {
    SCREEN_DASHBOARD,
    SCREEN_NOT_PERSONALIZED,
    SCREEN_PROCESSING,
    SCREEN_NONE
} active_screen_t;

// Mock variables needed for bootloader module
#define IO_APDU_BUFFER_SIZE (5 + 255)
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];
bolos_ux_context_t G_bolos_ux_context;
static try_context_t G_try_last_open_context_var;
try_context_t *G_try_last_open_context = &G_try_last_open_context_var;
bolos_ux_context_t G_bolos_ux_context;
static active_screen_t G_active_screen = SCREEN_NONE;

// Mock variables used for the unit test
static unsigned int G_is_onboarded = 0;
static bool G_is_pin_set = false;
static bool G_is_authorized_signer = false;
static bool G_is_unlocked = false;
static const int IS_ONBOARDED_RETURN = 0x1234;
static unsigned char G_mock_apdu_buffer[IO_APDU_BUFFER_SIZE];
static size_t G_mock_apdu_buffer_offset = 0;
static size_t G_mock_apdu_buffer_size = 0;
static pthread_mutex_t mutex;
static pthread_cond_t io_exchange_called;
static pthread_cond_t io_exchange_free_to_run;

// Mock OS calls
unsigned int os_perso_isonboarded(void) {
    return G_is_onboarded;
}

unsigned int os_registry_count(void) {
    return 1;
}

void os_registry_get(unsigned int index, application_t *out_application_entry) {
    out_application_entry->flags = 0;
}

void os_memmove(void *dst, const void *src, unsigned int length) {
    return;
}

unsigned int os_sched_exec(unsigned int application_index) {
    return 0;
}

// Other mocks
unsigned int update_pin_buffer(volatile unsigned int rx) {
    return 0;
}

void init_signer_authorization() {
    return;
}

unsigned int do_authorize_signer(volatile unsigned int rx,
                                 sigaut_t *sigaut_ctx) {
    return 0;
}

void reset_signer_authorization(sigaut_t *sigaut_ctx) {
    return;
}

unsigned int echo(unsigned int rx) {
    return 0;
}

unsigned int get_retries() {
    return 0;
}

void reset_onboard_ctx(onboard_t *onboard_ctx) {
    return;
}

unsigned int set_host_seed(volatile unsigned int rx, onboard_t *onboard_ctx) {
    return 0;
}

unsigned int get_attestation(volatile unsigned int rx, att_t *att_ctx) {
    return 0;
}

void reset_attestation(att_t *att_ctx) {
    return;
}

unsigned int unlock() {
    return 0;
}

unsigned int onboard_device(onboard_t *onboard_ctx) {
    ASSERT_FALSE(G_is_onboarded);
    G_is_onboarded = 1;
    return 0;
}

unsigned int is_onboarded() {
    SET_APDU_AT(0, (IS_ONBOARDED_RETURN >> 8));
    SET_APDU_AT(1, (IS_ONBOARDED_RETURN & 0xff));
    return 2;
}

void clear_pin() {
    G_is_pin_set = false;
}

unsigned int set_pin() {
    G_is_pin_set = true;
    return 0;
}

unsigned int get_mode() {
    SET_APDU_AT(0, CLA);
    SET_APDU_AT(1, RSK_MODE_BOOTLOADER);
    return 2;
}

unsigned int unlock_with_pin(bool prepended_length) {
    G_is_unlocked = true;
    return 0;
}

bool is_authorized_signer(unsigned char *signer_hash) {
    return G_is_authorized_signer;
}

static void init_bolos_ux_context() {
    memset(&G_bolos_ux_context, 0, sizeof(G_bolos_ux_context));
}

void screen_dashboard_init(void) {
    G_active_screen = SCREEN_DASHBOARD;
}

void screen_not_personalized_init(void) {
    G_active_screen = SCREEN_NOT_PERSONALIZED;
}

void screen_processing_init(void) {
    G_active_screen = SCREEN_PROCESSING;
}

unsigned int screen_stack_pop(void) {
    return 0;
}

void screen_settings_apply(void) {
    return;
}

void screen_dashboard_prepare(void) {
    return;
}

// OS io operation mocks
void io_seproxyhal_init(void) {
    return;
}

void io_seproxyhal_disable_io(void) {
    return;
}

void io_seproxyhal_setup_ticker(unsigned int interval_ms) {
    return;
}

void USB_power(unsigned char enabled) {
    return;
}

static void reset_mock_apdu_buffer() {
    memset(G_mock_apdu_buffer, 0, sizeof(G_mock_apdu_buffer));
    G_mock_apdu_buffer_offset = 0;
    G_mock_apdu_buffer_size = 0;
}

static void add_mock_apdu_buffer(unsigned char data) {
    G_mock_apdu_buffer[G_mock_apdu_buffer_size++] = data;
}

unsigned short io_exchange(unsigned char channel_and_flags,
                           unsigned short tx_len) {
    pthread_mutex_lock(&mutex);
    pthread_cond_signal(&io_exchange_called);

    assert(G_mock_apdu_buffer_offset < IO_APDU_BUFFER_SIZE);
    // Reached end of buffer
    if (0 == G_mock_apdu_buffer[G_mock_apdu_buffer_offset]) {
        // All commands consumed, exit thread
        pthread_mutex_unlock(&mutex);
        pthread_exit(NULL);
    }

    // Wait until we are free to send the next command
    pthread_cond_wait(&io_exchange_free_to_run, &mutex);

    // Send next command
    SET_APDU_CLA();
    int pos = 1;
    SET_APDU_AT(pos++, G_mock_apdu_buffer[G_mock_apdu_buffer_offset++]);

    pthread_mutex_unlock(&mutex);
    return pos;
}

void *handle_bolos_ux_boot_onboarding_wrapper(void *arg) {
    handle_bolos_ux_boot_onboarding();
    // handle_bolos_ux_boot_onboarding is expected to never return when we are
    // in onboarding mode
    assert(false);
}

void *bootloader_main_wrapper(void *arg) {
    // This is the public interface for bootloader_main
    uintptr_t ret = handle_bolos_ux_boot_validate_pin();
    return (void *)ret;
}

void setup() {
    init_bolos_ux_context();
    pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&io_exchange_called, NULL);
    pthread_cond_init(&io_exchange_free_to_run, NULL);
}

void shutdown() {
    pthread_mutex_destroy(&mutex);
    pthread_cond_destroy(&io_exchange_called);
    pthread_cond_destroy(&io_exchange_free_to_run);
}

void test_onboarding() {
    printf("Test onboarding...\n");

    setup();
    G_is_onboarded = 0;
    G_active_screen = SCREEN_NONE;
    G_is_pin_set = true;

    pthread_mutex_lock(&mutex);
    reset_mock_apdu_buffer();
    add_mock_apdu_buffer(RSK_WIPE);
    add_mock_apdu_buffer(RSK_END_CMD);

    pthread_t onboarding_thread;
    pthread_create(&onboarding_thread,
                   NULL,
                   handle_bolos_ux_boot_onboarding_wrapper,
                   NULL);

    // First call to io_exchange, we have nothing to read
    pthread_cond_wait(&io_exchange_called, &mutex);
    pthread_cond_signal(&io_exchange_free_to_run);

    // Wait for next call to io_exchange
    pthread_cond_wait(&io_exchange_called, &mutex);

    // Return of RSK_WIPE
    ASSERT_EQUALS(APDU_OK, APDU_RETURN(0));
    pthread_cond_signal(&io_exchange_free_to_run);

    // Wait for next call to io_exchange
    pthread_cond_wait(&io_exchange_called, &mutex);
    // After onboarding, all commands return ERR_INS_NOT_SUPPORTED
    ASSERT_EQUALS(ERR_INS_NOT_SUPPORTED, APDU_RETURN(0));
    pthread_cond_signal(&io_exchange_free_to_run);

    pthread_mutex_unlock(&mutex);

    pthread_cancel(onboarding_thread);
    pthread_join(onboarding_thread, NULL);

    ASSERT_TRUE(G_is_onboarded);
    ASSERT_FALSE(G_is_pin_set);
    ASSERT_TRUE(G_bolos_ux_context.dashboard_redisplayed);
    ASSERT_EQUALS(G_active_screen, SCREEN_NOT_PERSONALIZED);

    shutdown();
}

void test_onboarding_while_onboarded() {
    printf("Test onboarding while device already onboarded...\n");

    setup();

    init_bolos_ux_context();
    G_is_onboarded = 1;
    G_is_pin_set = true;
    G_active_screen = SCREEN_NONE;
    ASSERT_EQUALS(BOLOS_UX_OK, handle_bolos_ux_boot_onboarding());
    ASSERT_TRUE(G_is_pin_set);
    ASSERT_TRUE(G_bolos_ux_context.dashboard_redisplayed);
    ASSERT_EQUALS(G_active_screen, SCREEN_NONE);

    shutdown();
}

void test_dashboard() {
    printf("Test dashboard without autoexec...\n");

    setup();
    G_active_screen = SCREEN_NONE;

    // Run bootloader_main and send RSK_END_CMD_NOSIG to set autoexec = 0
    pthread_mutex_lock(&mutex);
    reset_mock_apdu_buffer();
    add_mock_apdu_buffer(RSK_END_CMD_NOSIG);

    pthread_t onboarding_thread;
    pthread_create(&onboarding_thread, NULL, bootloader_main_wrapper, NULL);

    // RSK_END_CMD_NOSIG returns nothing, we just need to release io_exchange()
    pthread_cond_wait(&io_exchange_called, &mutex);
    pthread_cond_signal(&io_exchange_free_to_run);

    pthread_mutex_unlock(&mutex);

    pthread_cancel(onboarding_thread);
    pthread_join(onboarding_thread, NULL);

    handle_bolos_ux_boot_dashboard();
    ASSERT_EQUALS(G_active_screen, SCREEN_DASHBOARD);

    shutdown();
}

void test_dashboard_autoexec() {
    printf("Test dashboard with autoexec (authorized)...\n");

    setup();
    G_active_screen = SCREEN_NONE;
    G_is_authorized_signer = true;

    // Run bootloader_main and send RSK_END_CMD to set autoexec = 1
    pthread_mutex_lock(&mutex);
    reset_mock_apdu_buffer();
    add_mock_apdu_buffer(RSK_END_CMD);

    pthread_t onboarding_thread;
    pthread_create(&onboarding_thread, NULL, bootloader_main_wrapper, NULL);

    // RSK_END_CMD_NOSIG returns nothing, we just need to release io_exchange()
    pthread_cond_wait(&io_exchange_called, &mutex);
    pthread_cond_signal(&io_exchange_free_to_run);

    pthread_mutex_unlock(&mutex);

    pthread_join(onboarding_thread, NULL);

    handle_bolos_ux_boot_dashboard();

    ASSERT_TRUE(G_bolos_ux_context.app_auto_started);
    ASSERT_EQUALS(G_active_screen, SCREEN_DASHBOARD);

    shutdown();
}

void test_dashboard_autoexec_not_authorized() {
    printf("Test dashboard with autoexec (not authorized)...\n");

    setup();
    G_active_screen = SCREEN_NONE;
    G_is_authorized_signer = false;

    // Run bootloader_main and send RSK_END_CMD to set autoexec = 1
    pthread_mutex_lock(&mutex);
    reset_mock_apdu_buffer();
    add_mock_apdu_buffer(RSK_END_CMD);

    pthread_t onboarding_thread;
    pthread_create(&onboarding_thread, NULL, bootloader_main_wrapper, NULL);

    // RSK_END_CMD_NOSIG returns nothing, we just need to release io_exchange()
    pthread_cond_wait(&io_exchange_called, &mutex);
    pthread_cond_signal(&io_exchange_free_to_run);

    pthread_mutex_unlock(&mutex);

    pthread_join(onboarding_thread, NULL);

    handle_bolos_ux_boot_dashboard();

    ASSERT_FALSE(G_bolos_ux_context.app_auto_started);
    ASSERT_EQUALS(G_active_screen, SCREEN_DASHBOARD);

    shutdown();
}

void test_validate_pin() {
    printf("Test validate pin (bootloader_main)...\n");

    setup();

    G_is_onboarded = 1;

    // Run bootloader_main and send RSK_END_CMD to set autoexec = 1
    pthread_mutex_lock(&mutex);
    reset_mock_apdu_buffer();
    add_mock_apdu_buffer(RSK_IS_ONBOARD);
    add_mock_apdu_buffer(RSK_MODE_CMD);
    add_mock_apdu_buffer(RSK_END_CMD);

    pthread_t onboarding_thread;
    pthread_create(&onboarding_thread, NULL, bootloader_main_wrapper, NULL);

    // First call to io_exchange, we have nothing to read
    pthread_cond_wait(&io_exchange_called, &mutex);
    pthread_cond_signal(&io_exchange_free_to_run);

    // Wait for next call to io_exchange
    pthread_cond_wait(&io_exchange_called, &mutex);

    // Return of RSK_IS_ONBOARD
    ASSERT_EQUALS(IS_ONBOARDED_RETURN, APDU_RETURN(0));
    ASSERT_EQUALS(APDU_OK, APDU_RETURN(2));
    pthread_cond_signal(&io_exchange_free_to_run);

    // Wait for next call to io_exchange
    pthread_cond_wait(&io_exchange_called, &mutex);
    // Return of RSK_MODE_CMD
    ASSERT_EQUALS(0x8002, APDU_RETURN(0));
    ASSERT_EQUALS(APDU_OK, APDU_RETURN(2));

    pthread_cond_signal(&io_exchange_free_to_run);
    pthread_mutex_unlock(&mutex);
    unsigned int validate_pin_return;
    pthread_join(onboarding_thread, (void **)&validate_pin_return);

    ASSERT_EQUALS(G_active_screen, SCREEN_DASHBOARD);
    ASSERT_EQUALS(BOLOS_UX_OK, validate_pin_return);

    shutdown();
}

void test_consent_app_add_authorized() {
    printf("Test consent app add (app authorized)...\n");
    setup();
    G_is_authorized_signer = true;
    G_is_unlocked = false;
    G_is_pin_set = true;
    ASSERT_EQUALS(BOLOS_UX_OK, handle_bolos_ux_boot_consent_app_add(NULL));
    ASSERT_TRUE(G_is_unlocked);
    ASSERT_FALSE(G_is_pin_set);
    shutdown();
}

void test_consent_app_add_not_authorized() {
    printf("Test consent app add (app not authorized)...\n");
    setup();
    G_is_authorized_signer = false;
    G_is_unlocked = false;
    G_is_pin_set = true;
    ASSERT_EQUALS(BOLOS_UX_CANCEL, handle_bolos_ux_boot_consent_app_add(NULL));
    ASSERT_FALSE(G_is_unlocked);
    ASSERT_TRUE(G_is_pin_set);
    shutdown();
}

void test_consent_foreing_key() {
    printf("Test consent foreing key...\n");
    setup();
    ASSERT_EQUALS(BOLOS_UX_OK, handle_bolos_ux_boot_consent_foreing_key());
    shutdown();
}

void test_consent_app_del() {
    printf("Test consent app del...\n");
    setup();
    ASSERT_EQUALS(BOLOS_UX_OK, handle_bolos_ux_boot_consent_app_del());
    shutdown();
}

void test_processing() {
    printf("Test processing...\n");
    setup();
    G_active_screen = SCREEN_NONE;
    handle_bolos_ux_boot_processing();
    ASSERT_EQUALS(SCREEN_PROCESSING, G_active_screen);
    shutdown();
}

int main() {
    test_onboarding();
    test_onboarding_while_onboarded();
    test_dashboard();
    test_dashboard_autoexec();
    test_dashboard_autoexec_not_authorized();
    test_validate_pin();
    test_consent_app_add_authorized();
    test_consent_app_add_not_authorized();
    test_consent_foreing_key();
    test_consent_app_del();
    test_processing();

    return 0;
}

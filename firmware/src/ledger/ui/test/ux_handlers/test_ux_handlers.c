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

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "assert_utils.h"
#include "ux_handlers.h"
#include "defs.h"
#include "bolos_ux_common.h"
#include "bootloader.h"

typedef enum current_screen_t {
    SCREEN_NONE,
    SCREEN_NOT_PERSONALIZED,
    SCREEN_DASHBOARD,
    SCREEN_PROCESSING
} current_screen_t;

// Mock variables needed for ux_handlers module
bolos_ux_context_t G_bolos_ux_context;
static current_screen_t G_current_screen;
static bootloader_mode_t G_bootloader_mode;
static unsigned int G_interval_ms;
static unsigned char G_app_hash[] = "app-hash";

// Mock variables
static bool G_screen_settings_apply_called;
static bool G_os_perso_isonboarded_called;
static bool G_io_seproxyhal_init_called;
static int G_usb_power_called;
static bool G_bootloader_main_called;
static bool G_io_seproxyhal_setup_ticker_called;
static bool G_is_authorized_signer_called;
static bool G_screen_stack_pop_called;
static bool G_io_seproxyhal_disable_io_called;
static bool G_os_sched_exec_called;
static bool G_is_authorized_signer_called;
static bool G_unlock_with_pin_called;
static bool G_clear_pin_called;
static bool G_heartbeat_main_called;

static bool G_is_onboarded;
static bool G_is_authorized;

static void setup() {
    G_bolos_ux_context.dashboard_redisplayed = 0;
    G_bolos_ux_context.app_auto_started = 0;
    G_screen_settings_apply_called = false;
    G_os_perso_isonboarded_called = false;
    G_io_seproxyhal_init_called = false;
    G_usb_power_called = 1;
    G_bootloader_main_called = false;
    G_io_seproxyhal_setup_ticker_called = false;
    G_is_authorized_signer_called = false;
    G_screen_stack_pop_called = false;
    G_io_seproxyhal_disable_io_called = false;
    G_os_sched_exec_called = false;
    G_is_authorized_signer_called = false;
    G_unlock_with_pin_called = false;
    G_is_onboarded = false;
    G_is_authorized = false;
    G_clear_pin_called = false;
    G_current_screen = SCREEN_NONE;
    G_interval_ms = 0;
    G_heartbeat_main_called = false;
}

// Mock os function definitions
void USB_power(unsigned char enabled) {
    G_usb_power_called <<= 1;
    G_usb_power_called += enabled ? 1 : 0;
}

void io_seproxyhal_setup_ticker(unsigned int interval_ms) {
    assert(G_interval_ms == interval_ms);
    G_io_seproxyhal_setup_ticker_called = true;
}

void io_seproxyhal_disable_io(void) {
    G_io_seproxyhal_disable_io_called = true;
}

void io_seproxyhal_init(void) {
    G_io_seproxyhal_init_called = true;
}

unsigned int os_perso_isonboarded(void) {
    G_os_perso_isonboarded_called = true;
    return G_is_onboarded;
}

unsigned int os_registry_count(void) {
    return 1;
}

void os_registry_get(unsigned int index, application_t* out_application_entry) {
    assert(0 == index);
    assert(NULL != out_application_entry);
    out_application_entry->flags = 0;
    out_application_entry->hash = G_app_hash;
}

unsigned int os_sched_exec(unsigned int application_index) {
    assert(0 == application_index);
    G_os_sched_exec_called = true;
    return 0;
}

// Mock functions from other modules
void bootloader_main(bootloader_mode_t mode) {
    assert(G_bootloader_mode == mode);
    G_bootloader_main_called = true;
}

void clear_pin() {
    G_clear_pin_called = true;
}

unsigned int unlock_with_pin(bool prepended_length) {
    assert(false == prepended_length);
    G_unlock_with_pin_called = true;
    return 0;
}

bool is_authorized_signer(unsigned char* signer_hash) {
    assert(signer_hash == G_app_hash);
    G_is_authorized_signer_called = true;
    return G_is_authorized;
}

void screen_dashboard_init(void) {
    G_current_screen = SCREEN_DASHBOARD;
}

void screen_not_personalized_init(void) {
    G_current_screen = SCREEN_NOT_PERSONALIZED;
}

void screen_processing_init(void) {
    G_current_screen = SCREEN_PROCESSING;
}

void screen_settings_apply(void) {
    G_screen_settings_apply_called = true;
}

unsigned int screen_stack_pop(void) {
    G_screen_stack_pop_called = true;
    return 0;
}

void ui_heartbeat_main(ui_heartbeat_t* ui_heartbeat_ctx) {
    assert(&G_bolos_ux_context.ui_heartbeat == ui_heartbeat_ctx);
    G_heartbeat_main_called = true;
}

// Test cases
void test_handle_boot_onboarding() {
    printf("Test BOLOS_UX_BOOT_ONBOARDING...\n");
    setup();
    G_is_onboarded = false;
    G_bootloader_mode = BOOTLOADER_MODE_ONBOARD;

    assert(BOLOS_UX_CANCEL == handle_bolos_ux_boot_onboarding());
    assert(G_screen_settings_apply_called);
    assert(1 == G_bolos_ux_context.dashboard_redisplayed);
    assert(G_os_perso_isonboarded_called);
    assert(G_io_seproxyhal_init_called);
    assert(G_usb_power_called == 3);
    assert(G_bootloader_main_called);
    assert(SCREEN_NOT_PERSONALIZED == G_current_screen);
}

void test_handle_boot_onboarding_already_onboarded() {
    printf("Test BOLOS_UX_BOOT_ONBOARDING (device already onboarded)...\n");
    setup();
    G_is_onboarded = true;

    assert(BOLOS_UX_OK == handle_bolos_ux_boot_onboarding());
    assert(G_screen_settings_apply_called);
    assert(1 == G_bolos_ux_context.dashboard_redisplayed);
    assert(G_os_perso_isonboarded_called);
    assert(!G_io_seproxyhal_init_called);
    assert(G_usb_power_called == 1);
    assert(!G_bootloader_main_called);
    assert(SCREEN_NONE == G_current_screen);
}

void test_handle_dashboard_action_dashboard() {
    printf("Test BOLOS_UX_DASHBOARD when action is set to dashboard...\n");
    setup();
    set_dashboard_action(DASHBOARD_ACTION_DASHBOARD);
    G_interval_ms = 100;

    handle_bolos_ux_boot_dashboard();
    assert(G_screen_settings_apply_called);
    assert(G_io_seproxyhal_setup_ticker_called);
    assert(SCREEN_DASHBOARD == G_current_screen);
    assert(0 == G_bolos_ux_context.app_auto_started);
    assert(!G_is_authorized_signer_called);
    assert(!G_screen_stack_pop_called);
    assert(!G_io_seproxyhal_disable_io_called);
    assert(!G_os_sched_exec_called);
}

void test_handle_dashboard_action_app_authorized() {
    printf("Test BOLOS_UX_DASHBOARD when action is set to app and signer is "
           "authorized...\n");
    setup();
    set_dashboard_action(DASHBOARD_ACTION_APP);
    G_interval_ms = 100;
    G_is_authorized = true;

    handle_bolos_ux_boot_dashboard();
    assert(G_screen_settings_apply_called);
    assert(G_io_seproxyhal_setup_ticker_called);
    assert(SCREEN_NONE == G_current_screen);
    assert(1 == G_bolos_ux_context.app_auto_started);
    assert(G_is_authorized_signer_called);
    assert(G_screen_stack_pop_called);
    assert(G_io_seproxyhal_disable_io_called);
    assert(G_os_sched_exec_called);
}

void test_handle_dashboard_action_app_not_authorized() {
    printf("Test BOLOS_UX_DASHBOARD when action is set to app and signer is "
           "not authorized...\n");
    setup();
    set_dashboard_action(DASHBOARD_ACTION_APP);
    G_interval_ms = 100;
    G_is_authorized = false;

    handle_bolos_ux_boot_dashboard();
    assert(G_screen_settings_apply_called);
    assert(G_io_seproxyhal_setup_ticker_called);
    assert(SCREEN_DASHBOARD == G_current_screen);
    assert(0 == G_bolos_ux_context.app_auto_started);
    assert(G_is_authorized_signer_called);
    assert(!G_screen_stack_pop_called);
    assert(!G_io_seproxyhal_disable_io_called);
    assert(!G_os_sched_exec_called);
}

void test_handle_dashboard_action_heartbeat_app_authorized() {
    printf("Test BOLOS_UX_DASHBOARD when action is set to heartbeat and app is "
           "authorized...\n");
    setup();
    set_dashboard_action(DASHBOARD_ACTION_UI_HEARTBEAT);
    G_interval_ms = 100;
    G_is_authorized = true;

    handle_bolos_ux_boot_dashboard();
    assert(G_io_seproxyhal_disable_io_called);
    assert(G_io_seproxyhal_init_called);
    assert(G_usb_power_called == 5);
    assert(G_heartbeat_main_called);
    assert(G_is_authorized_signer_called);
    assert(1 == G_bolos_ux_context.app_auto_started);
    assert(G_os_sched_exec_called);
    assert(!G_screen_settings_apply_called);
    assert(!G_io_seproxyhal_setup_ticker_called);
    assert(SCREEN_NONE == G_current_screen);
}

void test_handle_dashboard_action_heartbeat_app_not_authorized() {
    printf("Test BOLOS_UX_DASHBOARD when action is set to heartbeat and app is "
           "not authorized...\n");
    setup();
    set_dashboard_action(DASHBOARD_ACTION_UI_HEARTBEAT);
    G_interval_ms = 100;
    G_is_authorized = false;

    handle_bolos_ux_boot_dashboard();
    assert(G_io_seproxyhal_disable_io_called);
    assert(G_io_seproxyhal_init_called);
    assert(G_usb_power_called == 5);
    assert(G_heartbeat_main_called);
    assert(G_is_authorized_signer_called);
    assert(0 == G_bolos_ux_context.app_auto_started);
    assert(!G_os_sched_exec_called);
    assert(G_screen_settings_apply_called);
    assert(G_io_seproxyhal_setup_ticker_called);
    assert(SCREEN_DASHBOARD == G_current_screen);
}

void test_handle_validate_pin() {
    printf("Test BOLOS_UX_VALIDATE_PIN...\n");
    setup();
    G_bootloader_mode = BOOTLOADER_MODE_DEFAULT;

    assert(BOLOS_UX_OK == handle_bolos_ux_boot_validate_pin());
    assert(G_io_seproxyhal_init_called);
    assert(G_usb_power_called == 3);
    assert(G_bootloader_main_called);
}

void test_handle_consent_app_add_authorized() {
    printf("Test BOLOS_UX_CONSENT_APP_ADD (authorized)...\n");
    setup();
    G_is_authorized = true;

    assert(BOLOS_UX_OK == handle_bolos_ux_boot_consent_app_add(G_app_hash));
    assert(G_is_authorized_signer_called);
    assert(G_unlock_with_pin_called);
    assert(G_clear_pin_called);
}

void test_handle_consent_app_add_not_authorized() {
    printf("Test BOLOS_UX_CONSENT_APP_ADD (not authorized)...\n");
    setup();
    G_is_authorized = false;

    assert(BOLOS_UX_CANCEL == handle_bolos_ux_boot_consent_app_add(G_app_hash));
    assert(G_is_authorized_signer_called);
    assert(!G_unlock_with_pin_called);
    assert(!G_clear_pin_called);
}

void test_handle_consent_foreing_key() {
    printf("Test BOLOS_UX_CONSENT_FOREIGN_KEY...\n");
    assert(BOLOS_UX_OK == handle_bolos_ux_boot_consent_foreing_key());
}

void test_handle_consent_app_del() {
    printf("Test BOLOS_UX_CONSENT_APP_DEL...\n");
    assert(BOLOS_UX_OK == handle_bolos_ux_boot_consent_app_del());
}

void test_handle_processing() {
    printf("Test BOLOS_UX_PROCESSING...\n");
    handle_bolos_ux_boot_processing();
    assert(SCREEN_PROCESSING == G_current_screen);
}

int main() {
    test_handle_boot_onboarding();
    test_handle_boot_onboarding_already_onboarded();
    test_handle_dashboard_action_dashboard();
    test_handle_dashboard_action_app_authorized();
    test_handle_dashboard_action_app_not_authorized();
    test_handle_dashboard_action_heartbeat_app_authorized();
    test_handle_validate_pin();
    test_handle_consent_app_add_authorized();
    test_handle_consent_app_add_not_authorized();
    test_handle_consent_foreing_key();
    test_handle_consent_app_del();
    test_handle_processing();
}
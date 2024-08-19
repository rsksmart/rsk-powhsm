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
#include "signer_ux.h"

static unsigned int G_mock_idle_time_ms;
static unsigned int G_mock_screensaver_timeout_ms;
enum mock_ui_state { MOCK_UI_INFO, MOCK_UI_SCREENSAVER, MOCK_UI_INVALID };
enum mock_ui_state G_mock_ui_state;

// Helper functions
static unsigned int max(unsigned int a, unsigned int b) {
    return a > b ? a : b;
}

// Mock function calls
void signer_ux_info(void) {
    G_mock_ui_state = MOCK_UI_INFO;
}

void signer_ux_screensaver(void) {
    G_mock_ui_state = MOCK_UI_SCREENSAVER;
}

// Test cases
void setup() {
    G_mock_idle_time_ms = 0;
    G_mock_screensaver_timeout_ms = 30000;
    G_mock_ui_state = MOCK_UI_INVALID;
    signer_ux_init(G_mock_screensaver_timeout_ms);
}

void test_init() {
    printf("Test init...\n");
    setup();
    assert(MOCK_UI_INFO == G_mock_ui_state);
}

void test_ui_info_ui_screensaver_transition() {
    printf("Test transition from UI_INFO to UI_SCREENSAVER...\n");
    setup();
    signer_ux_handle_ticker_event(G_mock_screensaver_timeout_ms - 1);
    assert(MOCK_UI_INFO == G_mock_ui_state);
    signer_ux_handle_ticker_event(1);
    assert(MOCK_UI_SCREENSAVER == G_mock_ui_state);
}

void test_ui_screensaver_ui_info_transition() {
    printf("Test transition from UI_SCREENSAVER to UI_INFO...\n");
    setup();
    signer_ux_handle_ticker_event(G_mock_screensaver_timeout_ms);
    assert(MOCK_UI_SCREENSAVER == G_mock_ui_state);
    signer_ux_handle_button_press();
    assert(MOCK_UI_INFO == G_mock_ui_state);
}

void test_multiple_button_presses() {
    printf("Test multiple button presses...\n");
    setup();
    for (int i = 0; i < 100; ++i) {
        signer_ux_handle_ticker_event(G_mock_screensaver_timeout_ms - 1);
        assert(MOCK_UI_INFO == G_mock_ui_state);
        signer_ux_handle_button_press();
        assert(MOCK_UI_INFO == G_mock_ui_state);
    }
}

void test_timer_overflow() {
    printf("Test timer overflow protection...\n");
    setup();
    unsigned int mock_tick_ms = 100;
    signer_ux_handle_ticker_event(__UINT32_MAX__ - 100);
    assert(MOCK_UI_SCREENSAVER == G_mock_ui_state);
    for (int i = 0; i < 1000; i += mock_tick_ms) {
        signer_ux_handle_ticker_event(mock_tick_ms);
        assert(MOCK_UI_SCREENSAVER == G_mock_ui_state);
    }
    signer_ux_handle_button_press();
    assert(MOCK_UI_INFO == G_mock_ui_state);
}

int main() {
    test_init();
    test_ui_info_ui_screensaver_transition();
    test_ui_screensaver_ui_info_transition();
    test_multiple_button_presses();
    test_timer_overflow();

    return 0;
}

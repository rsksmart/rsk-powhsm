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
#include <string.h>
#include "mock.h"
#include "signer_ux.h"

static unsigned int G_mock_screensaver_timeout_ms;

// The arguments passed to the last call to UX_DISPLAY
static mock_signer_ux_element_t *G_elements_array_arg;
static void *G_callback_arg;
// Mock implementation of UX_DISPLAY
void UX_DISPLAY(const mock_signer_ux_element_t *elements_array,
                void *callback) {
    G_elements_array_arg = (mock_signer_ux_element_t *)elements_array;
    G_callback_arg = callback;
}

// Helper functions
// These functions simply assert that the last call to UX_DISPLAY was made
// with the expected arguments
static void assert_ui_info() {
    assert(G_elements_array_arg != NULL);
    assert(G_callback_arg == NULL);
    assert(G_elements_array_arg[0].component.type == BAGL_RECTANGLE);
    assert(G_elements_array_arg[0].component.width == 128);
    assert(G_elements_array_arg[0].component.height == 32);
    assert(G_elements_array_arg[0].component.fgcolor == 0x000000);
    assert(G_elements_array_arg[0].component.bgcolor == 0xFFFFFF);

    assert(G_elements_array_arg[1].component.type == BAGL_LABELINE);
    assert(G_elements_array_arg[1].component.width == 128);
    assert(G_elements_array_arg[1].component.height == 11);
    assert(G_elements_array_arg[1].component.fgcolor == 0xFFFFFF);
    assert(G_elements_array_arg[1].component.bgcolor == 0x000000);
    assert(0 == strcmp(G_elements_array_arg[1].text, "Signer running..."));

    assert(G_callback_arg == NULL);
}

static void assert_ui_screensaver() {
    assert(G_elements_array_arg != NULL);
    assert(G_callback_arg == NULL);
    assert(G_elements_array_arg[0].component.type == BAGL_RECTANGLE);
    assert(G_elements_array_arg[0].component.width == 128);
    assert(G_elements_array_arg[0].component.height == 32);
    assert(G_elements_array_arg[0].component.stroke == 0x000000);
    assert(G_elements_array_arg[0].component.fgcolor == 0x000000);
    assert(G_elements_array_arg[0].component.bgcolor == 0x000000);
    assert(G_elements_array_arg[0].text == NULL);

    assert(G_callback_arg == NULL);
}

// Test cases
void setup() {
    G_mock_screensaver_timeout_ms = 30000;
    G_elements_array_arg = NULL;
    G_callback_arg = NULL;
    signer_ux_init(G_mock_screensaver_timeout_ms);
}

void test_init() {
    printf("Test init...\n");
    setup();
    assert_ui_info();
}

void test_ui_info_ui_screensaver_transition() {
    printf("Test transition from UI_INFO to UI_SCREENSAVER...\n");
    setup();
    signer_ux_handle_ticker_event(G_mock_screensaver_timeout_ms - 1);
    assert_ui_info();
    signer_ux_handle_ticker_event(1);
    assert_ui_screensaver();
}

void test_ui_screensaver_ui_info_transition() {
    printf("Test transition from UI_SCREENSAVER to UI_INFO...\n");
    setup();
    signer_ux_handle_ticker_event(G_mock_screensaver_timeout_ms);
    assert_ui_screensaver();
    signer_ux_handle_button_press();
    assert_ui_info();
}

void test_multiple_button_presses() {
    printf("Test multiple button presses...\n");
    setup();
    for (int i = 0; i < 100; ++i) {
        signer_ux_handle_ticker_event(G_mock_screensaver_timeout_ms - 1);
        assert_ui_info();
        signer_ux_handle_button_press();
        assert_ui_info();
    }
}

void test_timer_overflow() {
    printf("Test timer overflow protection...\n");
    setup();
    unsigned int mock_tick_ms = 100;
    signer_ux_handle_ticker_event(__UINT32_MAX__ - 100);
    assert_ui_screensaver();
    for (int i = 0; i < 1000; i += mock_tick_ms) {
        signer_ux_handle_ticker_event(mock_tick_ms);
        assert_ui_screensaver();
    }
    signer_ux_handle_button_press();
    assert_ui_info();
}

int main() {
    test_init();
    test_ui_info_ui_screensaver_transition();
    test_ui_screensaver_ui_info_transition();
    test_multiple_button_presses();
    test_timer_overflow();

    return 0;
}

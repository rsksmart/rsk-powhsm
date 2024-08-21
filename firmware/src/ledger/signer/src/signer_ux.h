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

#ifndef __SIGNER_UX_H
#define __SIGNER_UX_H

/*
 * Initialize the UX state.
 *
 * @arg[in] screensaver_timeout_ms The time after which the screen saver is
 *                                 displayed if no button is pressed
 */
void signer_ux_init(unsigned int screensaver_timeout_ms);

/*
 * Handle a button press event.
 *
 * This function should be called whenever a button is pressed.
 */
void signer_ux_handle_button_press(void);
/*
 * Handles a ticker event.
 *
 * Increments the internal timer and updates the UI state if necessary.
 *
 * @arg[in] interval_ms Time spent since last ticker event
 */
void signer_ux_handle_ticker_event(unsigned int interval_ms);

// all screens
void signer_ux_info(void);
void signer_ux_screensaver(void);

#endif // __SIGNER_UX_H

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

#include "os.h"
#include "apdu.h"
#include "communication.h"
#include "modes.h"

/**
 * Implement the RSK ECHO command.
 *
 * @arg[in]  rx          number of received bytes from the Host
 * @returns              number of transmited bytes to the host
 */
unsigned int echo(unsigned int rx) {
    return rx;
}

/**
 * Implement the RSK MODE command.
 *
 * This returns either bootloader or heartbeat mode, depending
 * on the argument (which signals where it is called from)
 *
 * @arg[in] ui_heartbeat_main whether called from the ui heartbeat main
 * @returns number of transmited bytes to the host
 */
unsigned int get_mode(bool ui_heartbeat_main) {
    unsigned char output_index = CMDPOS;
    SET_APDU_AT(output_index++,
                ui_heartbeat_main ? APP_MODE_UI_HEARTBEAT
                                  : APP_MODE_BOOTLOADER);
    return output_index;
}

/**
 * Implement the RSK RETRIES command.
 *
 * Returns the current number of pin retries for the device
 *
 * @returns number of transmited bytes to the host
 */
unsigned int get_retries() {
    unsigned char output_index = OP;
    SET_APDU_AT(output_index++, (unsigned char)os_global_pin_retries());
    return output_index;
}

/**
 * Process an exception generated by running a command.
 * This could be used either from the bootloader
 * or from the UI heartbeat main.
 *
 * @arg[in] ex              the exception to process
 * @arg[in] tx              the current APDU buffer size
 * @arg[in] comm_reset_cb   callback to reset the state
 * @returns                 the resulting APDU buffer size
 */
unsigned int comm_process_exception(unsigned short ex,
                                    unsigned int tx,
                                    comm_reset_cb_t comm_reset_cb) {
    unsigned short sw = 0;

    // Reset the state in case of an error
    if (ex != APDU_OK || tx + 2 > sizeof(G_io_apdu_buffer)) {
        comm_reset_cb();
    }

    switch (ex & 0xF000) {
    case 0x6000:
    case 0x9000:
        sw = ex;
        break;
    default:
        sw = 0x6800 | (ex & 0x7FF);
        break;
    }

    // Unexpected exception => report
    // (check for a potential overflow first)
    if (tx + 2 > sizeof(G_io_apdu_buffer)) {
        tx = 0;
        sw = 0x6983;
    }
    SET_APDU_AT(tx++, sw >> 8);
    SET_APDU_AT(tx++, sw);

    return tx;
}
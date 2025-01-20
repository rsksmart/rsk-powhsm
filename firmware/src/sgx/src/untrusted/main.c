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

/*******************************************************************************
 *   powHSM
 *
 *   Main SGX source file
 ********************************************************************************/

#include <stdio.h>
#include <argp.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>

#include "io.h"
#include "enclave_proxy.h"
#include "enclave_provider.h"
#include "log.h"

// Argp option spec
static struct argp_option options[] = {
    {"bind", 'b', "ADDRESS", 0, "Address to bind to", 0},
    {"port", 'p', "PORT", 0, "Port to listen on", 0},
    {0}};

// Argument definitions for argp
struct arguments {
    char *bind;
    int port;
    char *enclave_path;
};

// Argp individual option parsing function
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    switch (key) {
    case 'b':
        arguments->bind = arg;
        break;
    case 'p':
        if (!(arguments->port = atoi(arg))) {
            argp_failure(state, 1, 0, "Invalid numeric port given: %s", arg);
        }
        break;
    case ARGP_KEY_ARG:
        if (arguments->enclave_path) {
            argp_failure(state, 1, 0, "Too many arguments given");
        }
        arguments->enclave_path = arg;
        break;
    case ARGP_KEY_END:
        if (!arguments->enclave_path) {
            argp_failure(state, 1, 0, "No enclave path given");
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

// The argp parser
static struct argp argp = {
    options,
    parse_opt,
    "ENCLAVE_PATH",
    "SGX powHSM",
    NULL,
    NULL,
    NULL,
};

static void finalise_with(int exit_code) {
    printf("Terminating...\n");
    io_finalise();
    // TODO: finalize enclave, i/o
    printf("Done. Bye.\n");
    exit(exit_code);
}

static void finalise(int signum) {
    (void)signum; // Suppress unused parameter warning

    finalise_with(0);
}

static void set_signal_handlers() {
    signal(SIGINT, finalise);
    signal(SIGTERM, finalise);
    signal(SIGHUP, finalise);
    signal(SIGABRT, finalise);
}

int main(int argc, char **argv) {
    set_signal_handlers();

    // Arguments (with default values)
    struct arguments arguments = {
        "127.0.0.1", // Bind address
        7777,        // Port
        NULL,        // Enclave path
    };

    // Parse arguments
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    LOG("SGX powHSM starting...\n");

    LOG("Initialising enclave provider...\n");
    if (!epro_init(arguments.enclave_path)) {
        LOG("Error initialising enclave provider\n");
        goto main_error;
    }

    LOG("Initialising system...\n");
    if (!eprx_system_init(io_apdu_buffer, sizeof(io_apdu_buffer))) {
        LOG("Error initialising system\n");
        goto main_error;
    }
    LOG("System initialised\n");

    LOG("Initialising server...\n");
    if (!io_init(arguments.port, arguments.bind)) {
        LOG("Error initialising server\n");
        goto main_error;
    }
    LOG("Server initialised\n");

    LOG("HSM running...\n");

    unsigned int rx = 0;
    unsigned int tx = 0;

    while (true) {
        rx = io_exchange(tx);

        if (rx) {
            tx = eprx_system_process_apdu(rx);
        }
    }

    LOG("Exited main loop unexpectedly\n");

main_error:
    finalise_with(1);
    return 1;
}

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
 *   Main TCPSigner source file
 ********************************************************************************/

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <setjmp.h>
#include <argp.h>

#include "os.h"
#include "tcp.h"
#include "hsmsim_exceptions.h"
#include "hsmsim_nu.h"
#include "hsmsim_ecdsa.h"

#include "hsm.h"
#include "hsm-ledger.h"
#include "bc_advance.h"
#include "bc_state.h"

#include "hex_reader.h"

#include "log.h"

// Argp option spec
static struct argp_option options[] = {
    {"bind", 'b', "ADDRESS", 0, "Address to bind to"},
    {"port", 'p', "PORT", 0, "Port to listen on"},
    {"checkpoint", 'c', "HASH", 0, "Checkpoint block hash"},
    {"difficulty", 'd', "DIFFICULTY", 0, "Minimum required difficulty"},
    {"network", 'n', "NETWORK", 0, "Network to use"},
    {"key", 'k', "KEYFILE", 0, "Private key file to load"},
    {"verbose", 'v', 0, 0, "Produce verbose output"},
    {"inputfile", 'i', "INPUTFILE", 0, "Read input from file"},
    {"replicafile", 'r', "REPLICAFILE", 0, "Copy inputs to this file"},
    {0}};

// Argument definitions for argp
struct arguments {
    char *bind;
    int port;
    char *checkpoint_s;
    char *difficulty_s;
    char *network;
    char *key_file_path;
    bool verbose;

    uint8_t checkpoint[HASH_SIZE];
    uint8_t difficulty_b[sizeof(DIGIT_T) * BIGINT_LEN];
    DIGIT_T difficulty[BIGINT_LEN];
    uint8_t network_identifier;
    char inputfile[PATH_MAX];
    char replicafile[PATH_MAX];
    bool filemode;
};

// Argp individual option parsing function
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    uint8_t offset;
    struct arguments *arguments = state->input;

    switch (key) {
    case 'v':
        arguments->verbose = true;
        break;
    case 'b':
        arguments->bind = arg;
        break;
    case 'p':
        if (!(arguments->port = atoi(arg))) {
            argp_failure(state, 1, 0, "Invalid numeric port given: %s", arg);
        }
        break;
    case 'c':
        arguments->checkpoint_s = arg;
        if (strlen(arg) != sizeof(arguments->checkpoint) * 2 &&
            strlen(arg) != sizeof(arguments->checkpoint) * 2 + 2) {
            argp_failure(state,
                         1,
                         0,
                         "Checkpoint must be a 32-byte hex encoded string "
                         "(optionally prefixed with 0x)");
        }
        offset = (arg[0] == '0' && arg[1] == 'x') ? 2 : 0;
        if (read_hex(arg + offset,
                     strlen(arg + offset),
                     arguments->checkpoint) != sizeof(arguments->checkpoint)) {
            argp_failure(state, 1, 0, "Invalid checkpoint given: %s", arg);
        }
        break;
    case 'd':
        arguments->difficulty_s = arg;
        if (strlen(arg) > sizeof(arguments->difficulty_b) * 2 + 2) {
            argp_failure(state,
                         1,
                         0,
                         "Difficulty must be a hex encoded string (optionally "
                         "prefixed with 0x) of at most %u bytes",
                         sizeof(arguments->difficulty_b));
        }
        offset = (arg[0] == '0' && arg[1] == 'x') ? 2 : 0;
        uint8_t dif_offset =
            sizeof(arguments->difficulty_b) - strlen(arg + offset) / 2;
        if (strlen(arg + offset) < 2 ||
            read_hex(arg + offset,
                     strlen(arg + offset),
                     arguments->difficulty_b + dif_offset) == -1) {
            argp_failure(state, 1, 0, "Invalid difficulty given: %s", arg);
        }
        bigint(arguments->difficulty_b,
               sizeof(arguments->difficulty_b),
               arguments->difficulty,
               sizeof(arguments->difficulty) /
                   sizeof(arguments->difficulty[0]));
        break;
    case 'n':
        arguments->network = arg;
        if (!(arguments->network_identifier =
                  get_network_identifier_by_name(arg))) {
            argp_failure(state, 1, 0, "Invalid network given: %s", arg);
        }
        break;
    case 'k':
        arguments->key_file_path = arg;
        break;
    case 'r':
        strncpy(
            arguments->replicafile, arg, sizeof(arguments->replicafile) - 1);
        break;
    case 'i':
        strncpy(arguments->inputfile, arg, sizeof(arguments->inputfile) - 1);
        arguments->filemode = true;
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
    "",
    "TCPSigner -- an x86 implementation of the HSM signer"};

// Main function
void main(int argc, char **argv) {
    // Arguments with default values
    struct arguments arguments = {
        "127.0.0.1", // Bind address
        8888,        // Port
        "bdcb3c17c7aee714cec8ad900341bfd987b452280220dcbd6e7191f67ea420"
        "9b",          // Checkpoint
        "0x32",        // Difficulty
        "regtest",     // Network
        "key.secp256", // Key file
        false,         // verbose
    };

    // Convert default checkpoint
    read_hex(arguments.checkpoint_s,
             strlen(arguments.checkpoint_s),
             arguments.checkpoint);
    // Convert default difficulty
    read_hex(arguments.difficulty_s + 2 /* Skip 0x */,
             strlen(arguments.difficulty_s),
             arguments.difficulty_b +
                 (sizeof(arguments.difficulty_b) -
                  strlen(arguments.difficulty_s + 2 /* Skip 0x */) / 2));
    bigint(arguments.difficulty_b,
           sizeof(arguments.difficulty_b),
           arguments.difficulty,
           sizeof(arguments.difficulty) / sizeof(arguments.difficulty[0]));
    // Convert default network
    arguments.network_identifier =
        get_network_identifier_by_name(arguments.network);

// If compiling with AFL, tell AFL to not close and open
// the process every time but to clone it from here.
// __AFL_LOOP is another optimization for AFL.
// https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    // Parse arguments
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    // Output welcome message & parameters
    info("TCPSigner starting.\n");

    info("Signer parameters:\n");
    info_hex("Checkpoint", arguments.checkpoint, sizeof(arguments.checkpoint));
    info_hex(
        "Difficulty", arguments.difficulty_b, sizeof(arguments.difficulty_b));
    info("Network: %s\n", arguments.network);

    // Set checkpoint
    memmove(
        INITIAL_BLOCK_HASH, arguments.checkpoint, sizeof(arguments.checkpoint));
    // Set difficulty
    memmove(MIN_REQUIRED_DIFFICULTY,
            arguments.difficulty,
            sizeof(arguments.difficulty));
    // Set network
    hsmsim_set_network(arguments.network_identifier);

    // Initialize ECDSA
    if (!hsmsim_ecdsa_initialize(arguments.key_file_path)) {
        info("Error during ECDSA initialization\n");
        exit(1);
    }
    info("ECDSA initialized.\n");

    // Initialize hsm
    hsm_init();

#ifdef __AFL_HAVE_MANUAL_CONTROL
    while (__AFL_LOOP(10000)) {
#endif
        FILE *inputfd;
        if (arguments.filemode) {
            info("Using file %s as input\n", arguments.inputfile);
            if ((inputfd = fopen(arguments.inputfile, "rb")) == NULL) {
                info("Error opening file %s as input\n", arguments.inputfile);
                exit(1);
            }

            os_io_set_input_file(inputfd);
        } else {
            info("Starting TCP server on %s:%i\n",
                 arguments.bind,
                 arguments.port);
            int server = start_server(arguments.port, arguments.bind);
            os_io_set_server(server);
        }

        FILE *replicafd;
        if (strlen(arguments.replicafile) > 0) {
            info("Using file %s as replica\n", arguments.replicafile);
            if ((replicafd = fopen(arguments.replicafile, "ab")) == NULL) {
                info("Error opening file %s as replica\n",
                     arguments.replicafile);
                exit(1);
            };
            os_io_set_replica_file(replicafd);
        };

        hsm_ledger_main_loop();

        if (replicafd != NULL) {
            fclose(replicafd);
        }
        if (inputfd != NULL) {
            fclose(inputfd);
        }

#ifdef __AFL_HAVE_MANUAL_CONTROL
    }
#endif
}

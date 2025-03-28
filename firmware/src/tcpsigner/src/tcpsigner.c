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
#include <signal.h>

#include "hal/communication.h"
#include "hal/seed.h"
#include "hal/endorsement.h"
#include "hal/log.h"

#include "hsmsim_io.h"
#include "hsmsim_nu.h"
#include "hsmsim_admin.h"

#include "hsm.h"
#include "ui_heartbeat.h"
#include "bc_advance.h"
#include "bc_state.h"
#include "bc_diff.h"
#include "defs.h"
#include "hex_reader.h"

typedef enum {
    ARG_NU_WASABI = 0xaa00,
    ARG_NU_PAPYRUS,
    ARG_NU_IRIS,
} arg_non_printable_t;

// Hardcoded BIP32 paths for the JSON keyfile
const char *BIP32_PATHS[] = {
    "m/44'/0'/0'/0/0",   // BTC
    "m/44'/1'/0'/0/0",   // tBTC
    "m/44'/1'/1'/0/0",   // tRSK
    "m/44'/1'/2'/0/0",   // tMST
    "m/44'/137'/0'/0/0", // RSK
    "m/44'/137'/1'/0/0", // MST
};
const size_t BIP32_PATHS_COUNT = sizeof(BIP32_PATHS) / sizeof(BIP32_PATHS[0]);

/**
 * UI heartbeat memory area
 * There's probably a better
 * place for this. Leave here
 * for now.
 */
ui_heartbeat_t ui_heartbeat_ctx;

// Argp option spec
static struct argp_option options[] = {
    {"att", 'a', "ATTFILE", 0, "Attestation key file to load"},
    {"bind", 'b', "ADDRESS", 0, "Address to bind to"},
    {"port", 'p', "PORT", 0, "Port to listen on"},
    {"checkpoint", 'c', "HASH", 0, "Checkpoint block hash"},
    {"difficulty", 'd', "DIFFICULTY", 0, "Minimum required difficulty"},
    {"diffcap", 'y', "DIFFICULTYCAP", 0, "Individual block difficulty cap"},
    {"network", 'n', "NETWORK", 0, "Network to use"},
    {"key", 'k', "KEYFILE", 0, "Private key file to load"},
    {"verbose", 'v', 0, 0, "Produce verbose output"},
    {"inputfile", 'i', "INPUTFILE", 0, "Read input from file"},
    {"replicafile", 'r', "REPLICAFILE", 0, "Copy inputs to this file"},
    {"nuwasabi",
     ARG_NU_WASABI,
     "BLOCKNUMBER",
     0,
     "Custom Wasabi activation block number"},
    {"nupapyrus",
     ARG_NU_PAPYRUS,
     "BLOCKNUMBER",
     0,
     "Custom Papyrus activation block number"},
    {"nuiris",
     ARG_NU_IRIS,
     "BLOCKNUMBER",
     0,
     "Custom Iris activation block number"},
    {0}};

// Argument definitions for argp
struct arguments {
    char *bind;
    int port;
    char *checkpoint_s;
    char *difficulty_s;
    char *network;
    char *key_file_path;
    char *att_file_path;
    bool verbose;

    uint8_t checkpoint[HASH_SIZE];
    uint8_t difficulty_b[sizeof(DIGIT_T) * BIGINT_LEN];
    DIGIT_T difficulty[BIGINT_LEN];
    bool have_difficulty_cap;
    DIGIT_T difficulty_cap[BIGINT_LEN];
    uint8_t network_identifier;
    char inputfile[PATH_MAX];
    char replicafile[PATH_MAX];
    bool filemode;
    int activation_bn;
    int network_upgrade_overrides_count;
    network_upgrade_activation_t
        network_upgrade_overrides[MAX_NETWORK_UPGRADE_ACTIVATIONS];
};

// Argp individual option parsing function
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    uint8_t offset;
    struct arguments *arguments = state->input;

    switch (key) {
    case 'a':
        arguments->att_file_path = arg;
        break;
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
    case 'y':
        arguments->difficulty_s = arg;
        offset = (arg[0] == '0' && arg[1] == 'x') ? 2 : 0;
        if (strlen(arg) > sizeof(arguments->difficulty_b) * 2 + offset) {
            argp_failure(state,
                         1,
                         0,
                         "Difficulty must be a hex encoded string (optionally "
                         "prefixed with 0x) of at most %lu bytes",
                         sizeof(arguments->difficulty_b));
        }
        uint8_t dif_offset =
            sizeof(arguments->difficulty_b) - strlen(arg + offset) / 2;
        if (strlen(arg + offset) < 2 ||
            read_hex(arg + offset,
                     strlen(arg + offset),
                     arguments->difficulty_b + dif_offset) == -1) {
            argp_failure(state, 1, 0, "Invalid difficulty given: %s", arg);
        }
        DIGIT_T *dest;
        uint16_t dest_size;
        if (key == 'y') {
            arguments->have_difficulty_cap = true;
            dest = arguments->difficulty_cap;
            dest_size = sizeof(arguments->difficulty_cap) /
                        sizeof(arguments->difficulty_cap[0]);
        } else {
            dest = arguments->difficulty;
            dest_size = sizeof(arguments->difficulty) /
                        sizeof(arguments->difficulty[0]);
        }
        parse_bigint_be(arguments->difficulty_b,
                        sizeof(arguments->difficulty_b),
                        dest,
                        dest_size);
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
    case ARG_NU_WASABI:
    case ARG_NU_PAPYRUS:
    case ARG_NU_IRIS:
        if ((arguments->activation_bn = atoi(arg)) < 0 ||
            (arguments->activation_bn == 0 && strcmp("0", arg))) {
            argp_failure(
                state, 1, 0, "Invalid activation block number given: %s", arg);
        }
        arguments
            ->network_upgrade_overrides[arguments
                                            ->network_upgrade_overrides_count]
            .network_upgrade = key - ARG_NU_WASABI + NU_WASABI;
        arguments
            ->network_upgrade_overrides[arguments
                                            ->network_upgrade_overrides_count]
            .activation_bn = arguments->activation_bn;
        arguments->network_upgrade_overrides_count++;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static unsigned short admin_process(unsigned short rx) {
    if (hsmsim_admin_need_process(rx)) {
        return hsmsim_admin_process_apdu(rx);
    }

    // Signal nothing needed to process
    return 0;
}

// The argp parser
static struct argp argp = {
    options,
    parse_opt,
    "",
    "TCPSigner -- an x86 implementation of the HSM signer"};

static void finalise() {
    LOG("Caught termination signal. Bye.\n");
    exit(0);
}

static void set_signal_handlers() {
    signal(SIGINT, finalise);
    signal(SIGTERM, finalise);
    signal(SIGHUP, finalise);
    signal(SIGABRT, finalise);
}

static void signer_main_loop() {
    unsigned int rtx = 0;

    while (!hsm_exit_requested()) {
        rtx = hsmsim_io_exchange(rtx);
        rtx = hsm_process_apdu(rtx);
    }
}

// Main function
void main(int argc, char **argv) {
    set_signal_handlers();

    // Arguments with default values
    struct arguments arguments = {
        "127.0.0.1", // Bind address
        8888,        // Port
        "bdcb3c17c7aee714cec8ad900341bfd987b452280220dcbd6e7191f67ea420"
        "9b",          // Checkpoint
        "0x32",        // Difficulty
        "regtest",     // Network
        "key.secp256", // Key file
        "attid.json",  // Attestation key file
        false,         // verbose
    };

    // No custom difficulty cap by default
    arguments.have_difficulty_cap = false;

    // No network upgrade activations overrides by default
    arguments.network_upgrade_overrides_count = 0;

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
    parse_bigint_be(arguments.difficulty_b,
                    sizeof(arguments.difficulty_b),
                    arguments.difficulty,
                    sizeof(arguments.difficulty) /
                        sizeof(arguments.difficulty[0]));
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
    LOG("TCPSigner starting.\n");

    // Output signer version
    LOG("Signer version: %u.%u.%u\n",
        VERSION_MAJOR,
        VERSION_MINOR,
        VERSION_PATCH);

    LOG("Signer parameters:\n");
    LOG_HEX("Checkpoint:", arguments.checkpoint, sizeof(arguments.checkpoint));
    LOG_BIGD_HEX("Difficulty: ",
                 arguments.difficulty,
                 sizeof(arguments.difficulty) / sizeof(arguments.difficulty[0]),
                 "\n");
    LOG("Network: %s\n", arguments.network);

    // Set checkpoint
    memmove(
        INITIAL_BLOCK_HASH, arguments.checkpoint, sizeof(arguments.checkpoint));
    // Set difficulty
    memmove(MIN_REQUIRED_DIFFICULTY,
            arguments.difficulty,
            sizeof(arguments.difficulty));
    // Set network
    hsmsim_set_network(arguments.network_identifier);

    // Set custom block difficulty cap (if any)
    if (arguments.have_difficulty_cap) {
        memmove(MAX_BLOCK_DIFFICULTY,
                arguments.difficulty_cap,
                sizeof(arguments.difficulty_cap));
    }
    LOG_BIGD_HEX("Block difficulty cap: ",
                 MAX_BLOCK_DIFFICULTY,
                 sizeof(MAX_BLOCK_DIFFICULTY) / sizeof(MAX_BLOCK_DIFFICULTY[0]),
                 "\n");

    // Set network upgrade activation overrides
    for (int i = 0; i < arguments.network_upgrade_overrides_count; i++)
        hsmsim_set_network_upgrade_block_number(
            arguments.network_upgrade_overrides[i]);
    // Display network upgrade activation configuration
    LOG("Network upgrade activation block numbers (latest takes "
        "precedence):\n");
    network_upgrade_activation_t *activations =
        hsmsim_get_network_upgrade_activations();
    for (int i = 0; i < hsmsim_get_network_upgrade_activations_count(); i++) {
        LOG("\t%s: %u\n",
            hsmsim_get_network_upgrade_name(activations[i].network_upgrade),
            activations[i].activation_bn);
    }

    // Initialize the seed module
    if (!seed_init(arguments.key_file_path, BIP32_PATHS, BIP32_PATHS_COUNT)) {
        LOG("Error during seed module initialization\n");
        exit(1);
    }

    LOG("Seed module initialized.\n");

    // Initialize Attestation
    if (!endorsement_init(arguments.att_file_path)) {
        LOG("Error during endorsement module initialization\n");
        exit(1);
    }

    // Initialize admin
    hsmsim_admin_init();

    // Initialize I/O
    hsmsim_io_init();

    // Initialize hsm
    hsm_init();

#ifdef __AFL_HAVE_MANUAL_CONTROL
    while (__AFL_LOOP(10000)) {
#endif
        FILE *inputfd;
        if (arguments.filemode) {
            LOG("Using file %s as input\n", arguments.inputfile);
            if ((inputfd = fopen(arguments.inputfile, "rb")) == NULL) {
                LOG("Error opening file %s as input\n", arguments.inputfile);
                exit(1);
            }

            hsmsim_io_set_input_file(inputfd);
        } else {
            LOG("Starting TCP server on %s:%i\n",
                arguments.bind,
                arguments.port);
            hsmsim_io_set_and_start_server(arguments.port, arguments.bind);
        }

        FILE *replicafd;
        if (strlen(arguments.replicafile) > 0) {
            LOG("Using file %s as replica\n", arguments.replicafile);
            if ((replicafd = fopen(arguments.replicafile, "ab")) == NULL) {
                LOG("Error opening file %s as replica\n",
                    arguments.replicafile);
                exit(1);
            };
            hsmsim_io_set_replica_file(replicafd);
        };

        // Set the admin module callback for the communication module
        hsmsim_io_set_external_module_process(&admin_process);

        // Run the Signer main loop and the
        // UI heartbeat main loop in an alternate
        // fashion.
        while (true) {
            LOG("Running signer main loop...\n");
            hsm_init();
            signer_main_loop();
            // Send an empty reply so that the client
            // doesn't hang waiting
            hsmsim_io_reply();

            LOG("Running UI heartbeat main loop...\n");
            ui_heartbeat_init(&ui_heartbeat_ctx);
            ui_heartbeat_main(&ui_heartbeat_ctx);
            // Ditto
            hsmsim_io_reply();
        }

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

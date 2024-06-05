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

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "hsmsim_nu.h"
#include "bc_diff.h"

#define NETWORK_NAME_MAINNET "mainnet"
#define NETWORK_NAME_TESTNET "testnet"
#define NETWORK_NAME_REGTEST "regtest"

static DIGIT_T MAX_BLOCK_DIFFICULTY_MAINNET[BIGINT_LEN] = BCDIFF_MBD_MAINNET;
static DIGIT_T MAX_BLOCK_DIFFICULTY_TESTNET[BIGINT_LEN] = BCDIFF_MBD_TESTNET;
static DIGIT_T MAX_BLOCK_DIFFICULTY_REGTEST[BIGINT_LEN] = BCDIFF_MBD_REGTEST;

static const network_upgrade_activation_t NETCONFIG_REGTEST[] = {
    {NU_WASABI, 0}, {NU_PAPYRUS, 0}, {NU_IRIS, 0}};

static const network_upgrade_activation_t NETCONFIG_TESTNET[] = {
    {NU_WASABI, TESTNET_WASABI_ABN},
    {NU_PAPYRUS, TESTNET_PAPYRUS_ABN},
    {NU_IRIS, TESTNET_IRIS_ABN}};

static const network_upgrade_activation_t NETCONFIG_MAINNET[] = {
    {NU_ANCIENT, MAINNET_ANCIENT_ABN},
    {NU_WASABI, MAINNET_WASABI_ABN},
    {NU_PAPYRUS, MAINNET_PAPYRUS_ABN},
    {NU_IRIS, MAINNET_IRIS_ABN}};

static network_upgrade_activation_t
    network_upgrade_activations[MAX_NETWORK_UPGRADE_ACTIVATIONS];
static unsigned int network_upgrade_activations_count;

static uint8_t network_identifier;

void hsmsim_set_network_upgrade(uint32_t block_number,
                                uint8_t* dst_network_upgrade) {
    network_upgrade_activation_t current = {NU_UNKNOWN, 0};
    // Find the latest network upgrade that applies for the given block number
    for (int i = 0; i < network_upgrade_activations_count; i++) {
        if (block_number >= network_upgrade_activations[i].activation_bn &&
            network_upgrade_activations[i].activation_bn >=
                current.activation_bn) {
            current.activation_bn =
                network_upgrade_activations[i].activation_bn;
            current.network_upgrade =
                network_upgrade_activations[i].network_upgrade;
        }
    }
    *dst_network_upgrade = current.network_upgrade;
}

uint8_t hsmsim_get_network_identifier() {
    return network_identifier;
}

const char* get_network_name(uint8_t netid) {
    switch (netid) {
    case NETID_MAINNET:
        return "mainnet";
    case NETID_TESTNET:
        return "testnet";
    case NETID_REGTEST:
        return "regtest";
    default:
        return "";
    }
}

uint8_t get_network_identifier_by_name(char* name) {
    if (!strcmp(name, NETWORK_NAME_MAINNET))
        return NETID_MAINNET;
    if (!strcmp(name, NETWORK_NAME_TESTNET))
        return NETID_TESTNET;
    if (!strcmp(name, NETWORK_NAME_REGTEST))
        return NETID_REGTEST;
    return 0;
}

bool hsmsim_set_network(uint8_t netid) {
    network_identifier = netid;
    const network_upgrade_activation_t* activations;
    switch (netid) {
    case NETID_MAINNET:
        activations = NETCONFIG_MAINNET;
        network_upgrade_activations_count =
            sizeof(NETCONFIG_MAINNET) / sizeof(NETCONFIG_MAINNET[0]);
        memmove(MAX_BLOCK_DIFFICULTY,
                MAX_BLOCK_DIFFICULTY_MAINNET,
                sizeof(MAX_BLOCK_DIFFICULTY_MAINNET));
        break;
    case NETID_TESTNET:
        activations = NETCONFIG_TESTNET;
        network_upgrade_activations_count =
            sizeof(NETCONFIG_TESTNET) / sizeof(NETCONFIG_TESTNET[0]);
        memmove(MAX_BLOCK_DIFFICULTY,
                MAX_BLOCK_DIFFICULTY_TESTNET,
                sizeof(MAX_BLOCK_DIFFICULTY_TESTNET));
        break;
    case NETID_REGTEST:
        activations = NETCONFIG_REGTEST;
        network_upgrade_activations_count =
            sizeof(NETCONFIG_REGTEST) / sizeof(NETCONFIG_REGTEST[0]);
        memmove(MAX_BLOCK_DIFFICULTY,
                MAX_BLOCK_DIFFICULTY_REGTEST,
                sizeof(MAX_BLOCK_DIFFICULTY_REGTEST));
        break;
    default:
        return false;
    }

    // Copy activations
    memset(network_upgrade_activations, 0, sizeof(network_upgrade_activations));
    for (int i = 0; i < network_upgrade_activations_count; i++) {
        network_upgrade_activations[i].activation_bn =
            activations[i].activation_bn;
        network_upgrade_activations[i].network_upgrade =
            activations[i].network_upgrade;
    }

    return true;
}

bool hsmsim_set_network_upgrade_block_number(
    network_upgrade_activation_t network_upgrade_activation) {
    for (int i = 0; i < network_upgrade_activations_count; i++) {
        if (network_upgrade_activations[i].network_upgrade ==
            network_upgrade_activation.network_upgrade) {
            network_upgrade_activations[i].activation_bn =
                network_upgrade_activation.activation_bn;
            return true;
        }
    }
    return false;
}

int hsmsim_get_network_upgrade_activations_count() {
    return network_upgrade_activations_count;
}

network_upgrade_activation_t* hsmsim_get_network_upgrade_activations() {
    return network_upgrade_activations;
}

char* hsmsim_get_network_upgrade_name(network_upgrade_t nu) {
    switch (nu) {
    case NU_ANCIENT:
        return "Ancient";
    case NU_WASABI:
        return "Wasabi";
    case NU_PAPYRUS:
        return "Papyrus";
    case NU_IRIS:
        return "Iris";
    case NU_UNKNOWN:
    default:
        return "Unknown";
    }
}

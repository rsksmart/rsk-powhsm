/*******************************************************************************
 *   HSM 2.1
 *   (c) 2021 RSK
 *   Ledger Nano S BOLOS simulator layer
 *
 *   Network-upgrade related functions
 ********************************************************************************/

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "hsmsim_nu.h"

#define NETWORK_NAME_MAINNET "mainnet"
#define NETWORK_NAME_TESTNET "testnet"
#define NETWORK_NAME_REGTEST "regtest"

typedef struct network_upgrade_activation_s {
    network_upgrade_t network_upgrade;
    uint32_t activation_bn;
} network_upgrade_activation_t;

static const network_upgrade_activation_t NETCONFIG_REGTEST[] = {{NU_IRIS, 0}};

static const network_upgrade_activation_t NETCONFIG_TESTNET[] = {
    {NU_WASABI, TESTNET_WASABI_ABN},
    {NU_PAPYRUS, TESTNET_PAPYRUS_ABN},
    {NU_IRIS, TESTNET_IRIS_ABN}};

static const network_upgrade_activation_t NETCONFIG_MAINNET[] = {
    {NU_ANCIENT, MAINNET_ANCIENT_ABN},
    {NU_WASABI, MAINNET_WASABI_ABN},
    {NU_PAPYRUS, MAINNET_PAPYRUS_ABN},
    {NU_IRIS, MAINNET_IRIS_ABN}};

static const network_upgrade_activation_t* network_upgrade_activations;

static uint8_t network_identifier;

void hsmsim_set_network_upgrade(uint32_t block_number,
                                uint8_t* dst_network_upgrade) {
    network_upgrade_activation_t current = {NU_UNKNOWN, 0};
    // Find the latest network upgrade that applies for the given block number
    for (int i = 0; i < sizeof(network_upgrade_activations) /
                            sizeof(network_upgrade_activations[0]);
         i++) {
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
    switch (netid) {
    case NETID_MAINNET:
        network_upgrade_activations = NETCONFIG_MAINNET;
        break;
    case NETID_TESTNET:
        network_upgrade_activations = NETCONFIG_TESTNET;
        break;
    case NETID_REGTEST:
        network_upgrade_activations = NETCONFIG_REGTEST;
        break;
    default:
        return false;
    }
    return true;
}
#ifndef __BC_NU
#define __BC_NU

// -----------------------------------------------------------------------
// Determine network upgrade given a block number.
// -----------------------------------------------------------------------

// Network upgrades constants (ancient means pre-orchid).
//
// NOTE: In order to save memory, pow.c assumes that network upgrades fit an
// uint8_t. Therefore values must not be above 0xff.
typedef enum {
    NU_UNKNOWN = 0x00,
    NU_ANCIENT = 0xa0,
    NU_WASABI,
    NU_PAPYRUS,
    NU_IRIS
} network_upgrade_t;

// Network identifier constants
#define NETID_MAINNET 0x01
#define NETID_TESTNET 0x02
#define NETID_REGTEST 0x03

// Activation block numbers
#define MAINNET_ANCIENT_ABN     0
#define MAINNET_WASABI_ABN      1591000UL
#define MAINNET_PAPYRUS_ABN     2392700UL
#define MAINNET_IRIS_ABN        3589500UL

#define TESTNET_WASABI_ABN      0
#define TESTNET_PAPYRUS_ABN     863000UL
#define TESTNET_IRIS_ABN        2027200UL

#ifdef TESTNET
#define SET_NETWORK_UPGRADE(bn, x)          \
    {                                       \
        if (bn >= TESTNET_IRIS_ABN)         \
            *(x) = NU_IRIS;                 \
        else if (bn >= TESTNET_PAPYRUS_ABN) \
            *(x) = NU_PAPYRUS;              \
        else                                \
            *(x) = NU_WASABI;               \
    }
#define GET_NETWORK_IDENTIFIER() NETID_TESTNET
#elif defined(REGTEST)
#define SET_NETWORK_UPGRADE(bn, x) \
    { *(x) = NU_IRIS; }
#define GET_NETWORK_IDENTIFIER() NETID_REGTEST
#elif defined(HSM_SIMULATOR)
#include "hsmsim_nu.h"
#define SET_NETWORK_UPGRADE(bn, x) hsmsim_set_network_upgrade(bn, x)
#define GET_NETWORK_IDENTIFIER() hsmsim_get_network_identifier()
#else
#define SET_NETWORK_UPGRADE(bn, x) \
    {                              \
        if (bn >= MAINNET_IRIS_ABN)       \
            *(x) = NU_IRIS;           \
        else if (bn >= MAINNET_PAPYRUS_ABN)  \
            *(x) = NU_PAPYRUS;        \
        else if (bn >= MAINNET_WASABI_ABN)  \
            *(x) = NU_WASABI;         \
        else                       \
            *(x) = NU_ANCIENT;        \
    }
#define GET_NETWORK_IDENTIFIER() NETID_MAINNET
#endif

#endif // POWNU

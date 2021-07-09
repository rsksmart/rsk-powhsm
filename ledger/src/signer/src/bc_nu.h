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

#ifdef TESTNET
#define SET_NETWORK_UPGRADE(bn, x) \
    {                              \
        if (bn >= 2027200UL)       \
            x = NU_IRIS;           \
        else if (bn >= 863000UL)   \
            x = NU_PAPYRUS;        \
        else                       \
            x = NU_WASABI;         \
    }
#define NETWORK_IDENTIFIER 0x02
#elif defined(REGTEST)
#define SET_NETWORK_UPGRADE(bn, x) \
    { x = NU_IRIS; }
#define NETWORK_IDENTIFIER 0x03
#else
#define SET_NETWORK_UPGRADE(bn, x) \
    {                              \
        if (bn >= 3589500UL)       \
            x = NU_IRIS;           \
        else if (bn >= 2392700UL)  \
            x = NU_PAPYRUS;        \
        else if (bn >= 1591000UL)  \
            x = NU_WASABI;         \
        else                       \
            x = NU_ANCIENT;        \
    }
#define NETWORK_IDENTIFIER 0x01
#endif

#endif // POWNU

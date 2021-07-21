/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   BTC TX parser state machine
 ********************************************************************************/

#ifndef TXPARSER_H
#define TXPARSER_H

#include <stdbool.h>

#include "sha256.h"
#include "keccak256.h"
#include "defs.h"

// TX state machine parsing context
typedef struct {
    unsigned int tx_version;             // Transaction version
    unsigned int tx_total_len;           // BTC transaction total length
    unsigned int tx_total_read;          // BTC transaction total read
    unsigned int script_length;          // TX Script length
    unsigned int tx_input_index_to_sign; // Index to sign
    unsigned int btc_input_counter;      // Amount of inputs in the TX
    unsigned int currentTxInput;         // Current input being parsed
    unsigned int *out_index;             // TX out index
    // Sha256 hashes CTXs
    SHA256_CTX TX_hash;
    SHA256_CTX signatureHash;
    unsigned int script_read; // Script offset inside TX
    // Signature hash of the selected input, and hash of the whole BTC TX
    unsigned char signatureHashBuf[32];
    unsigned char TXHashBuf[32];
    bool validHashes; // Indicates valid hashes have been calculated
    bool validContract, validSignature; // Individual checks indicators
    // Input validation
    unsigned char expectedRXBytes;
} TX_CTX;

#ifndef FEDHM_EMULATOR
// Privatekey from PATH
#include "os.h"
extern cx_ecfp_private_key_t privateKey;
#endif

// Signature type
#define SIGHASH_ALL 1
#define TXDEBUG 0
void SM_TX_START(TX_CTX *ctx,
                 PARSE_STM *state,
                 unsigned int rx,
                 unsigned int *tx); // INIT parser
void SM_TX_HDR(TX_CTX *ctx,
               PARSE_STM *state,
               unsigned int rx,
               unsigned int *tx); // parsing field header
void SM_TX_VARINT(TX_CTX *ctx,
                  PARSE_STM *state,
                  unsigned int rx,
                  unsigned int *tx); // Load multi-byte varint
// Input parser
void SM_TX_INPUT_START(TX_CTX *ctx,
                       PARSE_STM *state,
                       unsigned int rx,
                       unsigned int *tx);
void SM_TX_INPUT_READ(TX_CTX *ctx,
                      PARSE_STM *state,
                      unsigned int rx,
                      unsigned int *tx);
// Read script
void SM_TX_SCRIPT_READ(TX_CTX *ctx,
                       PARSE_STM *state,
                       unsigned int rx,
                       unsigned int *tx);
// Read remaining of TX
void SM_TX_INPUT_REMAINING(TX_CTX *ctx,
                           PARSE_STM *state,
                           unsigned int rx,
                           unsigned int *tx);
// Check and do signature
void SM_TX_END(TX_CTX *ctx,
               PARSE_STM *state,
               unsigned int rx,
               unsigned int *tx);

#endif // TXPARSER_H

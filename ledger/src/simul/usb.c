/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   USB simulator layer
 ********************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "usb.h"
#include "usbdata.h"
#include "defs.h"
#include "const.h"

#include "bc_state.h"
#include "bc_state_host.h"
#include "bc_advance.h"
#include "bc_ancestor.h"
#include "bc_adv_upd_host.h"
#include "bc_single_block.h"

// the global apdu buffer
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

// Which advance host to use
extern int advance_host;

// Print a buffer to stderr
void printBuf(unsigned char *buf, int len) {
    int i;
    fprintf(stderr, "io_exchange(%d): ", len);
    for (i = 0; i < len; i++)
        fprintf(stderr, "\\x%02x", buf[i]);
    fprintf(stderr, "\n");
}

// Copy segment of buffer into simulated USB I/O
unsigned char copySegment(unsigned char *buf,
                          unsigned int buflen,
                          int *offset) {
    char requestBytes;
    G_io_apdu_buffer[0] = CLA;
    G_io_apdu_buffer[1] = INS_SIGN;
    requestBytes = G_io_apdu_buffer[TXLEN];
    // fprintf(stderr,"TX: Sending %d bytes\n",requestBytes);
    if ((*offset) + requestBytes > buflen) {
        requestBytes = buflen - (*offset);
        G_io_apdu_buffer[OP] |= P1_LAST;
    }
    memcpy(&G_io_apdu_buffer[DATA], buf + (*offset), requestBytes);
    (*offset) += requestBytes;
    return (requestBytes + 3);
}

int receiptOffset = 0, btcOffset = 0, MPOffset = 0;
// Reset data pointers to start a new transfter
void resetTransfer() {
    receiptOffset = btcOffset = MPOffset = 0;
}
// This function emulates the HOST device
unsigned short io_exchange(unsigned char channel_and_flags,
                           unsigned char tx_len) {
    char requestBytes;
    static int receiptOffset = 0, btcOffset = 0;
    printf("HID <= ");
    for (int i = 0; i < tx_len; i++)
        printf("%02x", G_io_apdu_buffer[i]);
    printf("\n");

    // **** Blockchain state simulator **** //

    uint16_t transmit_len;
    if (APDU_CMD() == INS_GET_STATE) {
        // Delegate to blockchain state host simulator if necessary
        transmit_len = bc_get_state_host(tx_len);
    } else if (APDU_CMD() == INS_RESET_STATE) {
        // Delegate to blockchain reset state host simulator if necessary
        transmit_len = bc_reset_state_host(tx_len);
    } else if (APDU_CMD() == INS_ADVANCE) {
        // Delegate to blockchain advance host simulator if necessary
        switch (advance_host) {
            case SINGLE_BLOCK_HOST:
                transmit_len = bc_single_block();
                break;
            case ADV_UPD_HOST:
            default:
                transmit_len = bc_advance_host();
                break;
        }
    } else if (APDU_CMD() == INS_UPD_ANCESTOR) {
        // Delegate to update ancestor host simulator if necessary
        transmit_len = bc_upd_ancestor_host();
    }

    // Debug what we are transmitting to the dongle
    printf("HID => ");
    for (int i = 0; i < transmit_len; i++)
        printf("%02x", G_io_apdu_buffer[i]);
    printf("\n");
    return transmit_len;

    // **** Signer simulator **** //

    SET_APDU_CLA(CLA);
    SET_APDU_CMD(INS_SIGN);
    switch (APDU_OP()) {
    case P1_PATH:
        SET_APDU_OP(P1_PATH);
        memcpy(APDU_DATA_PTR, G_path, PATH_LEN);
        tx_len = PATH_LEN + DATA;
        break;
    case P1_RECEIPT:
        SET_APDU_OP(P1_RECEIPT);
        tx_len = copySegment(receipt, RECEIPT_LEN, &receiptOffset);
        break;
    case P1_BTC:
        SET_APDU_OP(P1_BTC);
        tx_len = copySegment(BTCTran, BTCTran_LEN, &btcOffset);
        break;
    case P1_MERKLEPROOF:
        SET_APDU_OP(P1_MERKLEPROOF);
        G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
        tx_len = copySegment(MerkleProof, MerkleProof_LEN, &MPOffset);
        break;
    }
    printf("HID => ");
    for (int i = 0; i < tx_len; i++)
        printf("%02x", G_io_apdu_buffer[i]);
    printf("\n");

    return tx_len;
}

// Mocking assorted OS functions, constants and types
unsigned int os_endorsement_key2_derive_sign_data(
    unsigned char src, unsigned int srcLength, unsigned char *signature) {return 0;}

unsigned int os_endorsement_get_code_hash(unsigned char *buffer) {return 0;}

void moxie_swi_crypto_cleanup(void){};

void os_perso_derive_node_bip32(cx_curve_t curve, unsigned int *path,
    unsigned int pathLength, unsigned char *privateKey,
    unsigned char *chain) {};

int cx_ecdsa_init_private_key(cx_curve_t curve, unsigned char *rawkey,
    unsigned int key_len, cx_ecfp_private_key_t *key) {return 0;}

void os_memmove(void *dst, const void *src, unsigned int length) {};

int cx_ecfp_generate_pair(
    cx_curve_t curve, cx_ecfp_public_key_t *pubkey,
    cx_ecfp_private_key_t *privkey, int keepprivate) {return 0;}
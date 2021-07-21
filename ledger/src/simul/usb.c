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

#include "bc_state.h"
#include "bc_state_host.h"
#include "bc_advance.h"
#include "bc_ancestor.h"
#include "bc_adv_upd_host.h"

// the global apdu buffer
unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

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

    // Delegate to blockchain state host simulator if necessary
    if (APDU_CMD() == INS_GET_STATE) {
        return bc_get_state_host(tx_len);
    }
    if (APDU_CMD() == INS_RESET_STATE) {
        return bc_reset_state_host(tx_len);
    }

    // Delegate to blockchain advance host simulator if necessary
    if (APDU_CMD() == INS_ADVANCE) {
        return bc_advance_host();
    }

    // Delegate to update ancestor host simulator if necessary
    if (APDU_CMD() == INS_UPD_ANCESTOR) {
        return bc_upd_ancestor_host();
    }

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

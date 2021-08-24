// TODO: check input lenghts and correct structure on every state

case INS_SIGN:
// If not running in emulator mode, reset all other operations first
#ifndef FEDHM_EMULATOR
reset_if_starting(INS_SIGN);
#endif
//---------------------- PATH Parser --------------------------
// Generate key with path
if ((G_io_apdu_buffer[OP] & 0xF) == P1_PATH) {
    unsigned char privateKeyData[HASHLEN];
    if ((rx != DATA + PATHLEN + INPUTINDEXLEN) &&
        (rx != DATA + PATHLEN + HASHLEN))
        THROW(
            0x6A87); // Wrong buffer size, has to be either 28
                     // (DATA+PATHLEN+INPUTINDEXLEN) or 56 (DATA+PATHLEN+HASHEN)
    unsigned int path[5];
    // Read_path
    int pathlen = 5; // G_io_apdu_buffer[3]; // path len always 5
    memmove(path, &G_io_apdu_buffer[DATA + 1], pathlen * sizeof(int));
#ifndef FEDHM_EMULATOR
    os_perso_derive_node_bip32(
        CX_CURVE_256K1, path, pathlen, privateKeyData, NULL);
    cx_ecdsa_init_private_key(
        CX_CURVE_256K1, privateKeyData, HASHLEN, &privateKey);
    cx_ecfp_generate_pair(CX_CURVE_256K1, &publicKey, &privateKey, 1);
#else
    printf("P1_PATH: Input Index:%d\n", tx_ctx.tx_input_index_to_sign);
#endif
    // If path requires authorization, continue with authorization and
    // validation state machine
    if (pathRequireAuth(&G_io_apdu_buffer[DATA])) {
        if (rx != DATA + PATHLEN + INPUTINDEXLEN)
            THROW(0x6A90); // Wrong buffer size for authorized sign
        memmove(&tx_ctx.tx_input_index_to_sign,
                &G_io_apdu_buffer[DATA + PATHLEN],
                INPUTINDEXLEN);
        G_io_apdu_buffer[OP] = P1_BTC;
        tx_ctx.expectedRXBytes = G_io_apdu_buffer[TXLEN] = 0;
        state = S_CMD_START;
        tx_ctx.validContract = false;
        tx_ctx.validSignature = false;
        tx = 4;
        break;
    }
    // If path doesn't require authorization, go directly do the signing state
    else if (pathDontRequireAuth(&G_io_apdu_buffer[DATA])) {
        if (rx != DATA + PATHLEN + HASHLEN)
            THROW(0x6A91); // Wrong buffer size for unauthorized sign
        G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
        mp_ctx.expectedRXBytes = G_io_apdu_buffer[TXLEN] = 0;
        state = S_SIGN_MESSAGE;
        // Skip validations
        memmove(mp_ctx.signatureHash,
                &G_io_apdu_buffer[DATA + PATHLEN],
                sizeof(mp_ctx.signatureHash));
        tx = 4;
        break;
    }
    // If no path match, then bail out
    THROW(0x6a8f); // Invalid Key Path
    break;
}
// For testing, we use a hardcoded receipt root TODO: CHANGE THIS ON FINAL
// RELEASE
#ifdef HARDCODED_RECEIPTROOT
memmove(ReceiptsRootBuf, ReceiptsRootConst, sizeof(ReceiptsRootBuf));
#else
memmove(ReceiptsRootBuf,
        N_bc_state.ancestor_receipt_root,
        sizeof(ReceiptsRootBuf));
#endif
//---------------------- BTC TX Parser --------------------------
if (G_io_apdu_buffer[OP] & P1_BTC) {
    // Input len check
    if (state != S_TX_REMAINING)
        if (rx - DATA != tx_ctx.expectedRXBytes)
            THROW(0x6A87);
    switch (state) {
    case S_CMD_START:                          // Start the state machine
                                               // Check for valid parameters
        SM_TX_START(&tx_ctx, &state, rx, &tx); // INIT parser
        break;
    case S_TX_HDR: // parsing field header
        SM_TX_HDR(&tx_ctx, &state, rx, &tx);
        break;
    case S_TX_INPUT_START:
        SM_TX_INPUT_START(&tx_ctx, &state, rx, &tx);
        break;
    case S_TX_VARINT:
        SM_TX_VARINT(&tx_ctx, &state, rx, &tx);
        break;
    case S_TX_INPUT_READ:
        SM_TX_INPUT_READ(&tx_ctx, &state, rx, &tx);
        break;
    case S_TX_REMAINING:
        SM_TX_INPUT_REMAINING(&tx_ctx, &state, rx, &tx);
        break;
    case S_TX_END:
        SM_TX_END(&tx_ctx, &state, rx, &tx);
        rlp_ctx.expectedRXBytes = G_io_apdu_buffer[TXLEN];
        break;
    default: // Invalid state
        THROW(0x6A89);
    }
    // Save the amount of bytes we request, to check at RX
    tx_ctx.expectedRXBytes = G_io_apdu_buffer[TXLEN];
}
//---------------------- Receipt RLP Parser --------------------------
if (G_io_apdu_buffer[OP] & P1_RECEIPT) {
    static unsigned int oldListLevel = 0;
    // Input len check
    if (state != S_RLP_FINISH)
        if (rx - DATA != rlp_ctx.expectedRXBytes)
            THROW(0x6A87);
    switch (state) {
    // Start the state machine
    case S_CMD_START:
        keccak_init(&ReceiptHash);
        SM_RLP_START(&rlp_ctx, &state, rx, &tx);
        tx_ctx.validContract = false;
        tx_ctx.validSignature = false;
        break;
    // parsing field body
    case S_RLP_FIELD:
        keccak_update(&ReceiptHash,
                      &G_io_apdu_buffer[DATA],
                      rx - DATA); // Update Receipt hash
        // If parsing another event, automatically invalidate the contract.
        if (rlp_ctx.listLevel < 3) {
            tx_ctx.validContract = false;
            tx_ctx.validSignature = false;
        }
        // If exiting any leaf node, also invalidate contract
        if (oldListLevel > rlp_ctx.listLevel) {
            tx_ctx.validContract = false;
            tx_ctx.validSignature = false;
        }
        oldListLevel = rlp_ctx.listLevel;
        // Check for Contract Address
        if ((rlp_ctx.listLevel == 3) && (rlp_ctx.fieldCount == 1)) {
            char cmpbuf[CONTRACTADDRESS_LEN];
            // Check input size
            if (rx != CONTRACTADDRESS_LEN + DATA)
                THROW(0x6A87);
            // Dont memcmp flash to RAM
            memmove(cmpbuf, ContractAddress, CONTRACTADDRESS_LEN);
            if (!memcmp(&G_io_apdu_buffer[DATA],
                        ContractAddress,
                        CONTRACTADDRESS_LEN))
                tx_ctx.validContract = true;
        }
        // Check for correct Signature
        if ((rlp_ctx.listLevel == 4) &&
            (rlp_ctx.fieldCount == EXPECTED_TOPIC_SIGNATURE_INDEX)) {
            char cmpbuf[CONTRACTSIGNATURE_LEN];
            // Check input size
            if (rx != CONTRACTSIGNATURE_LEN + DATA)
                THROW(0x6A87);
            // Dont memcmp flash to RAM
            memmove(cmpbuf, ContractSignature, CONTRACTSIGNATURE_LEN);
            if (!memcmp(&G_io_apdu_buffer[DATA],
                        ContractSignature,
                        CONTRACTSIGNATURE_LEN))
                if (tx_ctx.validContract == true)
                    tx_ctx.validSignature = true;
        }
        // Check BTC TX hash
        if ((rlp_ctx.listLevel == 4) &&
            (rlp_ctx.fieldCount == EXPECTED_TOPIC_BTC_TX_INDEX + 1) &&
            tx_ctx.validContract && tx_ctx.validSignature &&
            tx_ctx.validHashes) {
            // Check input size
            if (rx != sizeof(tx_ctx.TXHashBuf) + DATA)
                THROW(0x6A87);
            // TX hash == receipt TX hash check
            if (!memcmp(
                    tx_ctx.TXHashBuf,
                    &G_io_apdu_buffer[DATA],
                    sizeof(
                        tx_ctx.TXHashBuf))) { // Matching TX found, Contract is
                                              // valid and Receipt Signature is
                                              // valid. Sign the signatureHash
#ifdef FEDHM_EMULATOR
                tx = 0;
                fprintf(stderr,
                        "[I] RLP parsing done. Valid TX found. "
                        "ValidContract=%s ValidSignature=%s ValidHashes=%s\n",
                        tx_ctx.validContract ? "true" : "false",
                        tx_ctx.validSignature ? "true" : "false",
                        tx_ctx.validHashes ? "true" : "false");
#endif
                G_io_apdu_buffer[CLAPOS] = CLA;
                G_io_apdu_buffer[CMDPOS] = INS_SIGN;
                G_io_apdu_buffer[OP] = P1_RECEIPT;
                G_io_apdu_buffer[TXLEN] = RLP_MAX_TRANSFER;
                tx = 4;
                state = S_RLP_FINISH;
            } else
                SM_RLP_FIELD(&rlp_ctx, &state, rx, &tx);
        } else
            SM_RLP_FIELD(&rlp_ctx, &state, rx, &tx);
        break;
    // parsing field header
    case S_RLP_HDR:
        keccak_update(&ReceiptHash,
                      &G_io_apdu_buffer[DATA],
                      rx - DATA); // Update Receipt hash
        SM_RLP_HDR(&rlp_ctx, &state, rx, &tx);
        break;
    // Finish RLP transmission
    case S_RLP_FINISH:
        keccak_update(&ReceiptHash,
                      &G_io_apdu_buffer[DATA],
                      rx - DATA);            // Update Receipt hash
        if (rx - DATA == RLP_MAX_TRANSFER) { // Data still remains
            G_io_apdu_buffer[CLAPOS] = CLA;
            G_io_apdu_buffer[CMDPOS] = INS_SIGN;
            G_io_apdu_buffer[OP] = P1_RECEIPT;
            G_io_apdu_buffer[TXLEN] = RLP_MAX_TRANSFER;
            tx = 4;
            state = S_RLP_FINISH;
        } else { // Last chunk transmitted
            keccak_final(&ReceiptHash, ReceiptHashBuf);
#ifdef FEDHM_EMULATOR
            printf("LAST CHUNK, RLP Keccak256: ");
            for (int i = 0; i < sizeof(ReceiptHashBuf); i++)
                printf("%02x", ReceiptHashBuf[i]);
            printf("\n");
#endif
            G_io_apdu_buffer[CLAPOS] = CLA;
            G_io_apdu_buffer[CMDPOS] = INS_SIGN;
            G_io_apdu_buffer[OP] = P1_MERKLEPROOF;
            G_io_apdu_buffer[TXLEN] = 1; // Return trie merkle tree NodeCount
            state = S_MP_START;
            tx = 4;
        }
        break;
    default: // Invalid state
        THROW(0x6A89);
    }
    // Save the amount of bytes we request, to check at RX
    rlp_ctx.expectedRXBytes = G_io_apdu_buffer[TXLEN];
} else
    //---------------------- Merkle Proof Parser --------------------------
    if (G_io_apdu_buffer[OP] & P1_MERKLEPROOF) {
    unsigned char signatureHashCopy[HASHLEN];
    // Input len check
    if (state != S_MP_START)
        if (rx - DATA != mp_ctx.expectedRXBytes)
            THROW(0x6A87);
    switch (state) {
    case S_MP_START:
        memmove(signatureHashCopy,
                tx_ctx.signatureHashBuf,
                sizeof(signatureHashCopy));
        MP_START(&mp_ctx,
                 &state,
                 rx,
                 &tx,
                 ReceiptHashBuf,
                 ReceiptsRootBuf,
                 signatureHashCopy); // INIT parser
        break;
    case S_MP_NODE_SHARED_PREFIX_HDR:
        MP_NODE_SHARED_PREFIX_HDR(&mp_ctx, &state, rx, &tx);
        break;
    case S_MP_NODE_SHARED_PREFIX_BODY:
        MP_NODE_SHARED_PREFIX_BODY(&mp_ctx, &state, rx, &tx);
        break;
    case S_MP_NODE_SHARED_PREFIX_VARINT_HDR:
        MP_NODE_SHARED_PREFIX_VARINT_HDR(&mp_ctx, &state, rx, &tx);
        break;
    case S_MP_NODE_SHARED_PREFIX_VARINT_BODY:
        MP_NODE_SHARED_PREFIX_VARINT_BODY(&mp_ctx, &state, rx, &tx);
        break;
    case S_MP_NODE_HDR:
        MP_NODE_HDR(&mp_ctx, &state, rx, &tx);
        break;
    case S_MP_NODE_HDR2:
        MP_NODE_HDR2(&mp_ctx, &state, rx, &tx);
        break;
    case S_MP_NODE_LEFT:
        MP_NODE_LEFT(&mp_ctx, &state, rx, &tx);
        break;
    case S_MP_NODE_LEFT_BYTES:
        MP_NODE_LEFT_BYTES(&mp_ctx, &state, rx, &tx);
        break;
    case S_MP_NODE_RIGHT:
        MP_NODE_RIGHT(&mp_ctx, &state, rx, &tx);
        break;
    case S_MP_NODE_RIGHT_BYTES:
        MP_NODE_RIGHT_BYTES(&mp_ctx, &state, rx, &tx);
        break;
    case S_MP_NODE_CHILDRENSIZE:
        MP_NODE_CHILDRENSIZE(&mp_ctx, &state, rx, &tx);
        break;
    case S_MP_NODE_VARINT_HDR:
        MP_NODE_VARINT_HDR(&mp_ctx, &state, rx, &tx);
        break;
    case S_MP_NODE_VARINT_BODY:
        MP_NODE_VARINT_BODY(&mp_ctx, &state, rx, &tx);
        break;
    case S_MP_NODE_VALUE:
        MP_NODE_VALUE(&mp_ctx, &state, rx, &tx);
        break;
    case S_MP_NODE_VALUE_LEN:
        MP_NODE_VALUE_LEN(&mp_ctx, &state, rx, &tx);
        break;
    case S_MP_NODE_REMAINING:
        MP_NODE_REMAINING(&mp_ctx, &state, rx, &tx);
        break;
    case S_SIGN_MESSAGE:
#ifdef FEDHM_EMULATOR
        printf("[I] MP parsing done. Valid TX found. ValidContract=%s "
               "ValidSignature=%s \n",
               tx_ctx.validContract ? "true" : "false",
               tx_ctx.validSignature ? "true" : "false");
        tx = 0;
#else
// Matching TX found, Contract is valid, Receipt Signature is valid and Merkle
// Tree passes al verifications. Sign the signatureHash
#if TARGET_ID == 0x31100003
        tx = cx_ecdsa_sign((void *)&privateKey,
                           CX_RND_RFC6979 | CX_LAST,
                           CX_SHA256,
                           mp_ctx.signatureHash,
                           sizeof(mp_ctx.signatureHash),
                           &G_io_apdu_buffer[DATA],
                           NULL);
#else
        tx = cx_ecdsa_sign((void *)&privateKey,
                           CX_RND_RFC6979 | CX_LAST,
                           CX_SHA256,
                           mp_ctx.signatureHash,
                           sizeof(mp_ctx.signatureHash),
                           &G_io_apdu_buffer[DATA]);
#endif
#endif
        tx += DATA;
        G_io_apdu_buffer[CLAPOS] = CLA;
        G_io_apdu_buffer[CMDPOS] = INS_SIGN;
        G_io_apdu_buffer[OP] = P1_SUCCESS; // Command finished
        state = S_CMD_FINISHED;
        break;
    default: // Invalid state
        THROW(0x6A89);
    }
    // Save the amount of bytes we request, to check at RX
    mp_ctx.expectedRXBytes = G_io_apdu_buffer[TXLEN];
    // Check if we request more than our buffer size
    if (mp_ctx.expectedRXBytes > IO_APDU_BUFFER_SIZE)
        THROW(0x6A89);
#ifdef FEDHM_EMULATOR
    //
    static int TX = 0;
    static int TXCNT = 0;
    if (mp_ctx.expectedRXBytes != 0) {
        TX += mp_ctx.expectedRXBytes;
        TXCNT++;
    };
    if (state == S_CMD_FINISHED)
        printf("-----Total tranfers: %d ---Total bytes: %d\n", TXCNT, TX);
#endif
}
break;

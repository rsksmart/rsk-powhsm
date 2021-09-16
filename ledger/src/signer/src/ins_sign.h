// *** Important: ***
// All this code is included in the context
// of a:
// case INS_SIGN:
// statement within hsm.c.
// ******************

#define SET_APDU_FOR_SIGN() \
    SET_APDU_CLA(); \
    SET_APDU_CMD(INS_SIGN);

while (true) {

// Reset all other operations first
reset_if_starting(INS_SIGN);

// Check for a valid OP, otherwise throw an error
if ((APDU_OP() & 0xF) != P1_PATH &&
    (APDU_OP() & 0xF) != P1_BTC &&
    (APDU_OP() & 0xF) != P1_RECEIPT &&
    (APDU_OP() & 0xF) != P1_MERKLEPROOF) {
    THROW(0x6A87);
}

//---------------------- PATH Parser --------------------------
// Generate key with path
if ((APDU_OP() & 0xF) == P1_PATH) {
    if ((rx != DATA + PATHLEN + INPUTINDEXLEN) &&
        (rx != DATA + PATHLEN + HASHLEN))
        THROW(0x6A87); // Wrong buffer size, has to be either 28
                     // (DATA+PATHLEN+INPUTINDEXLEN) or 56 (DATA+PATHLEN+HASHEN)
    SAFE_MEMMOVE(
        path, sizeof(path),
        APDU_DATA_PTR + 1, APDU_TOTAL_DATA_SIZE - 1,
        RSK_PATH_LEN * sizeof(int),
        THROW(0x6A87));
    // If path requires authorization, continue with authorization and
    // validation state machine
    if (pathRequireAuth(APDU_DATA_PTR)) {
        if (rx != DATA + PATHLEN + INPUTINDEXLEN)
            THROW(0x6A90); // Wrong buffer size for authorized sign
        SAFE_MEMMOVE(
            &tx_ctx.tx_input_index_to_sign, sizeof(tx_ctx.tx_input_index_to_sign),
            APDU_DATA_PTR + PATHLEN, APDU_TOTAL_DATA_SIZE - PATHLEN,
            INPUTINDEXLEN,
            THROW(0x6A87));
        SET_APDU_OP(P1_BTC);
        SET_APDU_TXLEN(0);
        tx_ctx.expectedRXBytes = APDU_TXLEN();
        state = S_CMD_START;
        tx_ctx.validContract = false;
        tx_ctx.validSignature = false;
        tx = TX_FOR_TXLEN();
        goto continue_sign_loop;
    }
    // If path doesn't require authorization, go directly do the signing state
    else if (pathDontRequireAuth(APDU_DATA_PTR)) {
        if (rx != DATA + PATHLEN + HASHLEN)
            THROW(0x6A91); // Wrong buffer size for unauthorized sign
        SET_APDU_OP(P1_MERKLEPROOF);
        SET_APDU_TXLEN(0);
        mp_ctx.expectedRXBytes = APDU_TXLEN();
        state = S_SIGN_MESSAGE;
        // Skip validations
        SAFE_MEMMOVE(
            mp_ctx.signatureHash, sizeof(mp_ctx.signatureHash),
            APDU_DATA_PTR + PATHLEN, APDU_TOTAL_DATA_SIZE - PATHLEN,
            sizeof(mp_ctx.signatureHash),
            THROW(0x6A87));
        tx = TX_FOR_TXLEN();
        goto continue_sign_loop;
    }
    // If no path match, then bail out
    THROW(0x6a8f); // Invalid Key Path
}

// Copy the ancestor receipts root from the current
// blockchain state
SAFE_MEMMOVE(
    ReceiptsRootBuf, sizeof(ReceiptsRootBuf),
    N_bc_state.ancestor_receipt_root, sizeof(N_bc_state.ancestor_receipt_root),
    sizeof(ReceiptsRootBuf),
    THROW(0x6A87));

//---------------------- BTC TX Parser --------------------------
if (APDU_OP() & P1_BTC) {
    // Input len check
    if ((state != S_TX_REMAINING && (rx - DATA) != tx_ctx.expectedRXBytes) ||
        (state == S_TX_REMAINING && rx < DATA)) {
        THROW(0x6A87);
    }
    
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
        rlp_ctx.expectedRXBytes = APDU_TXLEN();
        // Check if we request more than our buffer size
        if (rlp_ctx.expectedRXBytes > IO_APDU_BUFFER_SIZE)
            THROW(0x6A89);
        break;
    default: // Invalid state
        THROW(0x6A89);
    }
    // Save the amount of bytes we request, to check at RX
    tx_ctx.expectedRXBytes = APDU_TXLEN();
    // Check if we request more than our buffer size
	if (tx_ctx.expectedRXBytes > IO_APDU_BUFFER_SIZE)
		THROW(0x6A89);
}

//---------------------- Receipt RLP Parser --------------------------
if (APDU_OP() & P1_RECEIPT) {
    static unsigned int oldListLevel = 0;
    // Input len check
    if ((state != S_RLP_FINISH && (rx - DATA) != rlp_ctx.expectedRXBytes) ||
        (state == S_RLP_FINISH && rx < DATA)) {
        THROW(0x6A87);
    }

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
                      APDU_DATA_PTR,
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
            // Check input size
            if (rx != CONTRACTADDRESS_LEN + DATA)
                THROW(0x6A87);
            if (!memcmp(APDU_DATA_PTR,
                        ContractAddress,
                        CONTRACTADDRESS_LEN))
                tx_ctx.validContract = true;
        }
        // Check for correct Signature
        if ((rlp_ctx.listLevel == 4) &&
            (rlp_ctx.fieldCount == EXPECTED_TOPIC_SIGNATURE_INDEX)) {
            // Check input size
            if (rx != CONTRACTSIGNATURE_LEN + DATA)
                THROW(0x6A87);
            if (!memcmp(APDU_DATA_PTR,
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
                    APDU_DATA_PTR,
                    sizeof(
                        tx_ctx.TXHashBuf))) { // Matching TX found, Contract is
                                              // valid and Receipt Signature is
                                              // valid. Sign the signatureHash

                LOG("[I] RLP parsing done. Valid TX found."
                    "ValidContract=%s ValidSignature=%s ValidHashes=%s\n",
                    tx_ctx.validContract ? "true" : "false",
                    tx_ctx.validSignature ? "true" : "false",
                    tx_ctx.validHashes ? "true" : "false");

                SET_APDU_FOR_SIGN();
                SET_APDU_OP(P1_RECEIPT);
                SET_APDU_TXLEN(RLP_MAX_TRANSFER);
                tx = TX_FOR_TXLEN();
                state = S_RLP_FINISH;
            } else
                SM_RLP_FIELD(&rlp_ctx, &state, rx, &tx);
        } else
            SM_RLP_FIELD(&rlp_ctx, &state, rx, &tx);
        break;
    // parsing field header
    case S_RLP_HDR:
        keccak_update(&ReceiptHash,
                      APDU_DATA_PTR,
                      rx - DATA); // Update Receipt hash
        SM_RLP_HDR(&rlp_ctx, &state, rx, &tx);
        break;
    // Finish RLP transmission
    case S_RLP_FINISH:
        if (rx > DATA) {
            keccak_update(&ReceiptHash,
                        APDU_DATA_PTR,
                        rx - DATA); // Update Receipt hash
        }
        if (rx - DATA == RLP_MAX_TRANSFER) { // Data still remains
            SET_APDU_FOR_SIGN();
            SET_APDU_OP(P1_RECEIPT);
            SET_APDU_TXLEN(RLP_MAX_TRANSFER);
            tx = TX_FOR_TXLEN();
            state = S_RLP_FINISH;
        } else { // Last chunk transmitted
            keccak_final(&ReceiptHash, ReceiptHashBuf);
            LOG_HEX("LAST CHUNK, RLP Keccak256: ", ReceiptHashBuf, sizeof(ReceiptHashBuf));
            SET_APDU_FOR_SIGN();
            SET_APDU_OP(P1_MERKLEPROOF);
            SET_APDU_TXLEN(1); // Return trie merkle tree NodeCount
            state = S_MP_START;
            tx = TX_FOR_TXLEN();
        }
        break;
        
    default: // Invalid state
        THROW(0x6A89);
    }
    // Save the amount of bytes we request, to check at RX
    rlp_ctx.expectedRXBytes = APDU_TXLEN();
    // Check if we request more than our buffer size
	if (rlp_ctx.expectedRXBytes > IO_APDU_BUFFER_SIZE)
		THROW(0x6A89);
    goto continue_sign_loop;
}
//---------------------- Merkle Proof Parser --------------------------
else if (APDU_OP() & P1_MERKLEPROOF) {
    unsigned char signatureHashCopy[HASHLEN];
    unsigned char privateKeyData[KEYLEN];
    // Input len check
    if (state != S_MP_START)
        if (rx - DATA != mp_ctx.expectedRXBytes)
            THROW(0x6A87);
    switch (state) {
    case S_MP_START:
        SAFE_MEMMOVE(
            signatureHashCopy, sizeof(signatureHashCopy),
            tx_ctx.signatureHashBuf, sizeof(tx_ctx.signatureHashBuf),
            sizeof(signatureHashCopy),
            THROW(0x6A87));
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
    case S_SIGN_MESSAGE: {
        // Matching TX found, Contract is valid, Receipt Signature is valid and Merkle
        // Tree passes al verifications. Sign the signatureHash

        LOG("[I] MP parsing done. Valid TX found. ValidContract=%s "
            "ValidSignature=%s \n",
            tx_ctx.validContract ? "true" : "false",
            tx_ctx.validSignature ? "true" : "false");

        tx = do_sign(
            path, RSK_PATH_LEN, 
            mp_ctx.signatureHash, sizeof(mp_ctx.signatureHash), 
            APDU_DATA_PTR, APDU_TOTAL_DATA_SIZE);

        // Error signing?
        if (tx == DO_SIGN_ERROR) {
            THROW(0x6A99);
        }

        tx += DATA;
        SET_APDU_FOR_SIGN();
        SET_APDU_OP(P1_SUCCESS); // Command finished
        state = S_CMD_FINISHED;
        break;
    }
    default: // Invalid state
        THROW(0x6A89);
    }
    // CMD_FINISHED state uses the whole buffer, no expectedRXbytes are needed.
    if (state!=S_CMD_FINISHED)
	{
	// Save the amount of bytes we request, to check at RX
	mp_ctx.expectedRXBytes = APDU_TXLEN();
	// Check if we request more than our buffer size
	if (mp_ctx.expectedRXBytes > IO_APDU_BUFFER_SIZE)
		THROW(0x6A89);
	}
}

// Re-run the logic if we are requesting zero bytes and still
// haven't finished with the signing instruction.
//
// Important: this is not only an optimization to avoid 
// unnecessary APDU exchange cycles,
// but also some operations (e.g. unauthorized signing)
// depend upon this logic to function correctly.
continue_sign_loop:

if (APDU_CMD() == INS_SIGN &&
    APDU_TXLEN() == 0 &&
    state != S_CMD_FINISHED) {
    rx = 3;
} else {
    break;
}

} // while (true)
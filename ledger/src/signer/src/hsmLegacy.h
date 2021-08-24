/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   HSM 1.1 Legacy commands
 ********************************************************************************/

case RSK_MODE_CMD: // print mode
G_io_apdu_buffer[1] = RSK_MODE_APP;
tx = 2;
THROW(0x9000);
break;

case RSK_IS_ONBOARD: // Wheter it's onboarded or not
G_io_apdu_buffer[1] = os_perso_isonboarded();
G_io_apdu_buffer[2] = VERSION_MAJOR;
G_io_apdu_buffer[3] = VERSION_MINOR;
G_io_apdu_buffer[4] = VERSION_PATCH;
tx = 5;
THROW(0x9000);
break;

case RSK_GET_LOG:
if (rx != 4)
    THROW(0x6A87); /// Wrong buffer size
index = G_io_apdu_buffer[3];
log_entry le;
read_log(index, &le);
switch (G_io_apdu_buffer[2]) {
case 0:
    os_memmove(&G_io_apdu_buffer[1], le.hash, sizeof(le.hash));
    tx = 1 + sizeof(le.hash);
    break;
case 1:
    os_memmove(&G_io_apdu_buffer[1], le.signature, sizeof(le.signature));
    tx = 1 + sizeof(le.signature);
    break;
case 2:
    os_memmove(&G_io_apdu_buffer[1], le.time, sizeof(le.time));
    tx = 1 + sizeof(le.time);
    break;
}
THROW(0x9000);
break;

case RSK_GET_APP_HASH:
os_endorsement_get_code_hash(G_io_apdu_buffer);
tx = 32;
THROW(0x9000);
break;

case RSK_GET_ENDORSEMENT_PUBKEY:
os_endorsement_get_public_key(2, G_io_apdu_buffer);
tx = 65;
THROW(0x9000);
break;

case RSK_GET_ATTESTATION:
tx = attestation_len;
// Check if attestation exists
if (tx < 1)
    THROW(0x6A87);
// Sanity Check
if (tx > sizeof(G_io_apdu_buffer))
    THROW(0x6A87);
os_memmove(G_io_apdu_buffer, attestation, tx);
THROW(0x9000);
break;

case INS_GET_PUBLIC_KEY: {
    cx_ecfp_public_key_t publicKey;
    cx_ecfp_private_key_t privateKey;
    unsigned char privateKeyData[32];
    if (rx != 3 + 20)
        THROW(0x6A87); // Wrong buffer size (has to be 32)
    moxie_swi_crypto_cleanup();
    unsigned int path[5];
    int pathlen = 5; // G_io_apdu_buffer[2];
    os_memmove(path, &G_io_apdu_buffer[3], pathlen * 4);
    os_perso_derive_node_bip32(
        CX_CURVE_256K1, path, pathlen, privateKeyData, NULL);
    cx_ecdsa_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &privateKey);
    cx_ecfp_generate_pair(CX_CURVE_256K1, &publicKey, &privateKey, 1);
    os_memmove(G_io_apdu_buffer, publicKey.W, 65);
    tx = 65;
    THROW(0x9000);
} break;

case RSK_END_CMD: // return to dashboard
os_sched_exit(0);
return;
// goto return_to_dashboard;

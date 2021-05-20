/*******************************************************************************
 *   HSM 2.0
 *   (c) 2020 RSK
 *   HSM 1.1 Legacy commands
 ********************************************************************************/

case RSK_MODE_CMD: // print mode
    reset_if_starting(RSK_MODE_CMD);
    G_io_apdu_buffer[1] = RSK_MODE_APP;
    tx = 2;
    THROW(0x9000);
    break;

case RSK_IS_ONBOARD: // Wheter it's onboarded or not
    reset_if_starting(RSK_IS_ONBOARD);
    G_io_apdu_buffer[1] = os_perso_isonboarded();
    G_io_apdu_buffer[2] = VERSION_MAJOR;
    G_io_apdu_buffer[3] = VERSION_MINOR;
    G_io_apdu_buffer[4] = VERSION_PATCH;
    tx = 5;
    THROW(0x9000);
    break;

case INS_GET_PUBLIC_KEY:
    reset_if_starting(INS_GET_PUBLIC_KEY);

    // Check the received data size
    if (rx != DATA + sizeof(uint32_t)*RSK_PATH_LEN)
        THROW(0x6A87); // Wrong buffer size

    // Check for path validity before returning the public key
    if (!(pathRequireAuth(G_io_apdu_buffer+2) ||
        pathDontRequireAuth(G_io_apdu_buffer+2))) {
        // If no path match, then bail out
        THROW(0x6A8F); // Invalid Key Path
    }

    // Derive the public key
    os_memmove(path, G_io_apdu_buffer+3, RSK_PATH_LEN * sizeof(uint32_t));
    tx = do_pubkey(
        path, RSK_PATH_LEN,
        G_io_apdu_buffer, sizeof(G_io_apdu_buffer));

    // Error deriving?
    if (tx == DO_PUBKEY_ERROR) {
        THROW(0x6A99);
    }

    THROW(0x9000);
    break;

#include <string.h>

#include "hal/constants.h"
#include "hal/communication.h"
#include "hal/seed.h"
#include "hal/access.h"
#include "hal/endorsement.h"
#include "hal/nvmem.h"
#include "hal/exceptions.h"
#include "hal/log.h"

#include "secret_store.h"
#include "hsm.h"
#include "apdu.h"
#include "instructions.h"
#include "modes.h"
#include "bc_state.h"
#include "err.h"
#include "bc_err.h"

/**
 * APDU buffer
 */
#define EXPECTED_APDU_BUFFER_SIZE 85
static unsigned char* apdu_buffer;
static size_t apdu_buffer_size;

static void wipe_system() {
    seed_wipe();
    access_wipe();
}

static void on_access_wiped() {
    if (!seed_wipe()) {
        LOG("Error wiping seed module\n");
    }
    LOG("Seed wiped\n");
}

static unsigned int do_onboard(unsigned int rx) {
    // Validations
    if (seed_available()) {
        THROW(ERR_DEVICE_ONBOARDED);
    }

    // Require seed plus a nonblank password
    if (APDU_DATA_SIZE(rx) < SEED_LENGTH + 1) {
        THROW(ERR_INVALID_DATA_SIZE);
    }

    // Onboarding
    uint8_t tmp_buffer[apdu_buffer_size];
    memcpy(tmp_buffer, APDU_DATA_PTR, SEED_LENGTH);
    if (!seed_generate(tmp_buffer, SEED_LENGTH)) {
        wipe_system();
        THROW(ERR_ONBOARDING);
    }

    size_t password_length = APDU_DATA_SIZE(rx) - SEED_LENGTH;
    memcpy(tmp_buffer, APDU_DATA_PTR + SEED_LENGTH, password_length);
    if (!access_set_password((char*)tmp_buffer, password_length)) {
        wipe_system();
        THROW(ERR_ONBOARDING);
    }

    SET_APDU_OP(1);
    return TX_NO_DATA();
}

static unsigned int do_change_password(unsigned int rx) {
    // Require a nonblank password
    if (APDU_DATA_SIZE(rx) < 1) {
        THROW(ERR_INVALID_DATA_SIZE);
    }

    // Password change
    uint8_t tmp_buffer[apdu_buffer_size];
    size_t password_length = APDU_DATA_SIZE(rx);
    memcpy(tmp_buffer, APDU_DATA_PTR, password_length);
    if (!access_set_password((char*)tmp_buffer, password_length)) {
        THROW(ERR_PASSWORD_CHANGE);
    }

    SET_APDU_OP(1);
    return TX_NO_DATA();
}

static unsigned int do_unlock(unsigned int rx) {
    if (!access_is_locked()) {
        SET_APDU_OP(1);
        return TX_NO_DATA();
    }

    if (APDU_DATA_SIZE(rx) == 0) {
        THROW(ERR_INVALID_DATA_SIZE);
    }

    SET_APDU_OP(access_unlock((char*)APDU_DATA_PTR, APDU_DATA_SIZE(rx)) ? 1
                                                                        : 0);
    return TX_NO_DATA();
}

static unsigned int do_echo(unsigned int rx) {
    return rx;
}

static external_processor_result_t system_do_process_apdu(unsigned int rx) {
    external_processor_result_t result = {
        .handled = true,
        .tx = 0,
    };

    switch (APDU_CMD()) {
    // Reports the bootloader mode only if the device is locked
    // Otherwise command is ignored and the powHSM handler will
    // take over instead.
    case RSK_MODE_CMD:
        if (access_is_locked()) {
            SET_APDU_CMD(APP_MODE_BOOTLOADER);
            result.tx = 2;
            break;
        }
        result.handled = false;
        break;
    case SGX_ONBOARD:
        result.tx = do_onboard(rx);
        break;
    case SGX_IS_LOCKED:
        REQUIRE_ONBOARDED();
        SET_APDU_OP(access_is_locked() ? 1 : 0);
        result.tx = TX_NO_DATA();
        break;
    case SGX_RETRIES:
        REQUIRE_ONBOARDED();
        SET_APDU_OP(access_get_retries());
        result.tx = TX_NO_DATA();
        break;
    case SGX_UNLOCK:
        REQUIRE_ONBOARDED();
        result.tx = do_unlock(rx);
        break;
    case SGX_ECHO:
        result.tx = do_echo(rx);
        break;
    case SGX_CHANGE_PASSWORD:
        REQUIRE_ONBOARDED();
        REQUIRE_UNLOCKED();
        result.tx = do_change_password(rx);
        break;
    default:
        result.handled = false;
    }

    return result;
}

unsigned int system_process_apdu(unsigned int rx) {
    return hsm_process_apdu(rx);
}

bool system_init(unsigned char* msg_buffer, size_t msg_buffer_size) {
    // Setup the shared APDU buffer
    if (msg_buffer_size != EXPECTED_APDU_BUFFER_SIZE) {
        LOG("Expected APDU buffer size to be %u but got %lu\n",
            EXPECTED_APDU_BUFFER_SIZE,
            msg_buffer_size);
        return false;
    }
    apdu_buffer = msg_buffer;
    apdu_buffer_size = msg_buffer_size;

    // Initialize modules
    LOG("Initializing modules...\n");
    if (!sest_init()) {
        LOG("Error initializing secret store module\n");
        return false;
    }

    if (!access_init(on_access_wiped)) {
        LOG("Error initializing access module\n");
        return false;
    }

    if (!seed_init()) {
        LOG("Error initializing seed module\n");
        return false;
    }

    // Make sure both access and seed are in the same state
    if (!seed_available() ^ access_is_wiped()) {
        LOG("Inconsistent system state detected\n");
        if (!access_wipe() || !seed_wipe()) {
            LOG("System wipe failed\n");
            return false;
        }
        LOG("System wiped\n");
    }

    if (!communication_init(apdu_buffer, apdu_buffer_size)) {
        LOG("Error initializing communication module\n");
        return false;
    }

    if (!endorsement_init()) {
        LOG("Error initializing endorsement module\n");
        return false;
    }

    nvmem_init();
    if (!nvmem_register_block(
            "bcstate", &N_bc_state_var, sizeof(N_bc_state_var))) {
        LOG("Error registering bcstate block\n");
        return false;
    }
    if (!nvmem_register_block("bcstate_updating",
                              &N_bc_state_updating_backup_var,
                              sizeof(N_bc_state_updating_backup_var))) {
        LOG("Error registering bcstate_updating block\n");
        return false;
    }

    if (!nvmem_load()) {
        LOG("Error loading nvmem\n");
        return false;
    }

    LOG("Modules initialized\n");

    LOG("Initializing powHSM...\n");
    hsm_init();
    hsm_set_external_processor(system_do_process_apdu);
    LOG("powHSM initialized\n");

    return true;
}

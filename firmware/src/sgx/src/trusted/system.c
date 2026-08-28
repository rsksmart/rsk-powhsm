#include <string.h>
#include <openenclave/enclave.h>

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
#include "upgrade.h"
#include "evidence.h"
#include "meta_bc.h"

/**
 * APDU buffer (host pointer and local enclave copy)
 */
#define APDU_BUFFER_SIZE (2048 + 5)

static unsigned char* host_apdu_buffer;
static unsigned char apdu_buffer[APDU_BUFFER_SIZE];

static void wipe_system() {
    seed_wipe();
    access_wipe();
}

static void on_access_wiped() {
    if (!seed_wipe()) {
        DEBUG("Error wiping seed module\n");
    }
    INFO("Seed wiped\n");
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
    uint8_t tmp_buffer[sizeof(apdu_buffer)];
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
    uint8_t tmp_buffer[sizeof(apdu_buffer)];
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

static unsigned char curr_cmd;

static void reset_unless_cmd_is(unsigned char cmd) {
    if (cmd != curr_cmd) {
        // Reset all modules' contexts
        hsm_reset_if_starting(cmd);
        upgrade_reset();
        curr_cmd = cmd;
    }
}

#define INFO_CMD(cmd)           \
    if (APDU_CMD() != curr_cmd) \
    INFO("> " cmd "\n")

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
        INFO_CMD("Mode");
        if (access_is_locked()) {
            reset_unless_cmd_is(RSK_MODE_CMD);
            SET_APDU_CMD(APP_MODE_BOOTLOADER);
            result.tx = 2;
            break;
        }
        result.handled = false;
        break;
    case SGX_ONBOARD:
        INFO_CMD("Onboard")
        reset_unless_cmd_is(SGX_ONBOARD);
        result.tx = do_onboard(rx);
        break;
    case SGX_IS_LOCKED:
        INFO_CMD("Is locked?")
        REQUIRE_ONBOARDED();
        reset_unless_cmd_is(SGX_IS_LOCKED);
        SET_APDU_OP(access_is_locked() ? 1 : 0);
        result.tx = TX_NO_DATA();
        break;
    case SGX_RETRIES:
        INFO_CMD("Get pin retries")
        REQUIRE_ONBOARDED();
        reset_unless_cmd_is(SGX_RETRIES);
        SET_APDU_OP(access_get_retries());
        result.tx = TX_NO_DATA();
        break;
    case SGX_UNLOCK:
        INFO_CMD("Unlock")
        REQUIRE_ONBOARDED();
        reset_unless_cmd_is(SGX_UNLOCK);
        result.tx = do_unlock(rx);
        break;
    case SGX_ECHO:
        INFO_CMD("Echo")
        reset_unless_cmd_is(SGX_ECHO);
        result.tx = do_echo(rx);
        break;
    case SGX_CHANGE_PASSWORD:
        INFO_CMD("Change pin")
        REQUIRE_ONBOARDED();
        REQUIRE_UNLOCKED();
        reset_unless_cmd_is(SGX_CHANGE_PASSWORD);
        result.tx = do_change_password(rx);
        break;
    case SGX_UPGRADE:
        INFO_CMD("Upgrade")
        reset_unless_cmd_is(SGX_UPGRADE);
        result.tx = upgrade_process_apdu(rx);
        break;
    case INS_HEARTBEAT:
        INFO_CMD("Heartbeat")
        // For now, we don't support heartbeat in SGX
        THROW(ERR_INS_NOT_SUPPORTED);
        break;
    // Override the default hsm module handlers for these
    // commands
    case INS_ADVANCE:
    case INS_UPD_ANCESTOR:
        if (APDU_CMD() == INS_ADVANCE) {
            INFO_CMD("Advance blockchain state");
        } else {
            INFO_CMD("Update ancestor block");
        }
        REQUIRE_UNLOCKED();
        REQUIRE_ONBOARDED();
        reset_unless_cmd_is(APDU_CMD());
        result.tx = do_meta_advupd(rx);
        break;
    default:
        reset_unless_cmd_is(0);
        result.handled = false;
    }

    return result;
}

unsigned int system_process_apdu(unsigned int rx) {
    // Copy host APDU => enclave APDU
    memcpy(apdu_buffer, host_apdu_buffer, sizeof(apdu_buffer));
    unsigned int tx = hsm_process_apdu(rx);
    // Copy enclave APDU => host APDU
    memcpy(host_apdu_buffer, apdu_buffer, sizeof(apdu_buffer));
    return tx;
}

bool system_init(unsigned char* msg_buffer, size_t msg_buffer_size) {
    // Validate that host and enclave APDU buffers have the same size
    if (msg_buffer_size != sizeof(apdu_buffer)) {
        DEBUG("Expected APDU buffer size to be %lu but got %lu\n",
              sizeof(apdu_buffer),
              msg_buffer_size);
        return false;
    }

    // Validate that the host APDU buffer is entirely outside the enclave
    // memory space
    if (!oe_is_outside_enclave(msg_buffer, msg_buffer_size)) {
        DEBUG("APDU buffer memory area not outside the enclave\n");
        return false;
    }

    // Set the pointer to the host APDU buffer
    host_apdu_buffer = msg_buffer;

    // Initialize modules
    INFO("Initializing modules...\n");
    if (!sest_init()) {
        INFO("Error initializing secret store module\n");
        return false;
    }

    if (!access_init(on_access_wiped)) {
        INFO("Error initializing access module\n");
        return false;
    }

    if (!seed_init()) {
        INFO("Error initializing seed module\n");
        return false;
    }

    // Make sure both access and seed are in the same state
    if (!seed_available() ^ access_is_wiped()) {
        INFO("Inconsistent system state detected, will attempt to wipe\n");
        if (!access_wipe() || !seed_wipe()) {
            DEBUG("System wipe failed\n");
            return false;
        }
        INFO("System wiped\n");
    }

    if (!communication_init(apdu_buffer, sizeof(apdu_buffer))) {
        INFO("Error initializing communication module\n");
        return false;
    }

#ifndef SIM_BUILD
    if (!evidence_init()) {
        INFO("Error initializing evidence module\n");
        return false;
    }

    if (!endorsement_init()) {
        INFO("Error initializing endorsement module\n");
        return false;
    }
#else
    INFO("Simulation build. Evidence and Endorsement modules not available.\n");
#endif

    nvmem_init();
    if (!nvmem_register_block(
            "bcstate", &N_bc_state_var, sizeof(N_bc_state_var))) {
        INFO("Error registering bcstate block\n");
        return false;
    }
    if (!nvmem_register_block("bcstate_backup",
                              &N_bc_state_backup_var,
                              sizeof(N_bc_state_backup_var))) {
        INFO("Error registering bcstate_backup block\n");
        return false;
    }

    if (!nvmem_load()) {
        INFO("Error loading nvmem\n");
        return false;
    }

    upgrade_init();

    INFO("Modules initialized\n");

    INFO("Initializing powHSM...\n");
    hsm_init();
    hsm_set_external_processor(system_do_process_apdu);
    curr_cmd = 0;
    INFO("powHSM initialized\n");

    return true;
}

void system_finalise() {
    // Finalise modules
    endorsement_finalise();
    evidence_finalise();
}

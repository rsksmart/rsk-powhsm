import struct
import time
from comm.protocol import HSM2Protocol, HSM2ProtocolError, HSM2ProtocolInterrupt
from ledger.hsm2dongle import HSM2Dongle, HSM2DongleError, \
                              HSM2DongleErrorResult, HSM2DongleTimeout, HSM2FirmwareVersion
from comm.bitcoin import get_unsigned_tx, get_tx_hash

class HSM2ProtocolLedger(HSM2Protocol):
    # Current manager supports HSM UI <= 2.1.0 and HSM APP <= 2.1.0
    UI_VERSION = HSM2FirmwareVersion(2,1,0)
    APP_VERSION = HSM2FirmwareVersion(2,1,0)

    # Amount of time to wait to make sure the app is opened
    OPEN_APP_WAIT = 1 #second

    def __init__(self, pin, dongle):
        super().__init__()
        self.hsm2dongle = dongle
        self.pin = pin

    def initialize_device(self):
        # Connection
        try:
            self.logger.info("Connecting to dongle")
            self.hsm2dongle.connect()
            self.logger.info("Connected to dongle")
        except HSM2DongleError as e:
            self.logger.error(e)
            raise HSM2ProtocolError(e)

        # Onboard check
        try:
            is_onboarded = self.hsm2dongle.is_onboarded()
            self.logger.info("Dongle onboarded: %s", "yes" if is_onboarded else "no")
            if not is_onboarded:
                self.logger.error("Dongle not onboarded, exiting")
                raise HSM2ProtocolError("Dongle not onboarded")
        except HSM2DongleError as e:
            self.logger.info("Could not determine onboarded status. If unlocked, "+\
                             "please enter the signing app and rerun the manager. Otherwise,"+\
                             "disconnect and reconnect the ledger nano and try again")
            raise HSM2ProtocolInterrupt()

        # Mode check
        self.logger.info("Finding mode")
        current_mode = self.hsm2dongle.get_current_mode()
        self.logger.debug("Mode #%s", current_mode)

        if current_mode == HSM2Dongle.MODE.BOOTLOADER:
            self._handle_bootloader()

            # After handling the bootloader, we need to reload the mode since
            # it should change
            self.logger.info("Finding mode")
            current_mode = self.hsm2dongle.get_current_mode()
            self.logger.debug("Mode #%s", current_mode)

        # In this point, the mode should be app.
        # Otherwise, we tell the user to manually enter the app and run
        # the manager again
        if current_mode != HSM2Dongle.MODE.APP:
            self.logger.info("Dongle mode unknown. Please manually enter the signing app and re-run the manager")
            raise HSM2ProtocolInterrupt()

        self.logger.info("Mode: Signing App")

        # Verify that the app's version is correct
        self._dongle_app_version = self.hsm2dongle.get_version()
        self._check_version(self._dongle_app_version, self.APP_VERSION, "App")

        # Get and report signer parameters
        signer_parameters = self.hsm2dongle.get_signer_parameters()
        self.logger.info("Gathered signer parameters")
        self.logger.info("Checkpoint 0x%s", signer_parameters.checkpoint)
        self.logger.info("Minimum required difficulty %s", hex(signer_parameters.min_required_difficulty))
        self.logger.info("Network %s", signer_parameters.network.name)

    # Do what needs to be done to get past the "bootloader" mode
    # That includes checking the bootloader (UI) version, testing echo,
    # unlocking the device and (potentially) changing the device PIN
    # Finally, exiting the bootloader which should take the user to the
    # signer app.
    def _handle_bootloader(self):
        self.logger.info("Mode: Bootloader")

        # Version check
        self._dongle_ui_version = self.hsm2dongle.get_version()
        self._check_version(self._dongle_ui_version, self.UI_VERSION, "UI")

        # Echo check
        self.logger.info("Sending echo")
        if not self.hsm2dongle.echo():
            self._error("Echo error")
        self.logger.info("Echo OK")

        # Unlock device with PIN
        self.logger.info("Unlocking with PIN")
        if not self.hsm2dongle.unlock(self.pin.get_pin()):
            self._error("Unable to unlock: PIN mismatch")
        self.logger.info("PIN accepted")

        # First PIN use check
        if self.pin.needs_change():
            try:
                self.logger.info("PIN change need detected. Generating and changing PIN")
                self.pin.start_change()
                self.logger.info("Sending new PIN")
                if not self.hsm2dongle.new_pin(self.pin.get_new_pin()):
                    raise Exception("Dongle reported fail to change pin. Pin invalid?")
                self.pin.commit_change()
                self.logger.info("PIN changed. Please disconnect and reconnect the ledger nano")
            except Exception as e:
                self.pin.abort_change()
                self.logger.error("Error changing PIN: %s. Please disconnect and reconnect the ledger nano and try again", format(e))
            finally:
                raise HSM2ProtocolInterrupt()

        # This loads the app if in bootloader mode
        # This usually fails with a timeout, but its fine cause
        # what happens is that when opening the app,
        # the ledger disconnects from usb and reconnects
        self.logger.info("Loading Signing app")
        try: self.hsm2dongle.exit_menu()
        except: pass

        # Wait a little bit to make sure the app is loaded
        # and then reconnect to the dongle
        time.sleep(self.OPEN_APP_WAIT)
        self.hsm2dongle.disconnect()
        self.hsm2dongle.connect()


    def _check_version(self, fware_version, mware_version, name):
        self.logger.info("%s version: %s (supported <= %s)", name, fware_version, mware_version)
        if not mware_version.supports(fware_version):
            self._error("Unsupported %s version: Dongle reports %s, Node needs <= %s" % (name, fware_version, mware_version))

    def _error(self, msg):
        self.logger.error(msg)
        raise HSM2ProtocolError(msg)

    def _get_pubkey(self, request):
        try:
            return (self.ERROR_CODE_OK, {
                "pubKey":  self.hsm2dongle.get_public_key(request["keyId"])
                })
        except HSM2DongleErrorResult as e:
            return (self.ERROR_CODE_INVALID_KEYID, )
        except HSM2DongleTimeout as e:
            self.logger.error("Dongle timeout getting public key")
            return (self.ERROR_CODE_DEVICE, )
        except HSM2DongleError as e:
            self._error("Dongle error in get_pubkey: %s" % str(e))

    def _sign(self, request):
        # First validate the required fields are OK
        if "message" in request and "hash" in request["message"]:
            #### Unauthorized signing ####
            message_validation = self._validate_message(request, what="hash")
            if message_validation < self.ERROR_CODE_OK:
                return (message_validation,)

            try:
                sign_result = self.hsm2dongle.sign_unauthorized(key_id=request["keyId"],
                    hash=request["message"]["hash"])
            except HSM2DongleTimeout as e:
                self.logger.error("Dongle timeout signing")
                return (self.ERROR_CODE_DEVICE, )
            except HSM2DongleError as e:
                self._error("Dongle error in sign: %s" % str(e))
        else:
            #### Authorized signing ####
            auth_validation = self._validate_auth(request, mandatory=True)
            if auth_validation < self.ERROR_CODE_OK:
                return (auth_validation,)

            message_validation = self._validate_message(request, what="tx")
            if message_validation < self.ERROR_CODE_OK:
                return (message_validation,)

            # Make sure the transaction
            # is fully unsigned before sending.
            try:
                unsigned_btc_tx = get_unsigned_tx(request["message"]["tx"])
                self.logger.debug("Unsigned BTC tx: %s", get_tx_hash(unsigned_btc_tx))
            except Exception as e:
                self.logger.error("Error unsigning BTC tx: %s", str(e))
                return (self.ERROR_CODE_INVALID_MESSAGE, )

            try:
                sign_result = self.hsm2dongle.sign_authorized(key_id=request["keyId"],
                    rsk_tx_receipt=request["auth"]["receipt"],
                    receipt_merkle_proof=request["auth"]["receipt_merkle_proof"],
                    btc_tx=unsigned_btc_tx,
                    input_index=request["message"]["input"])
            except HSM2DongleTimeout as e:
                self.logger.error("Dongle timeout signing")
                return (self.ERROR_CODE_DEVICE, )
            except HSM2DongleError as e:
                self._error("Dongle error in sign: %s" % str(e))

        # Signing result is the same for both authorized and non authorized signing
        if not sign_result[0]:
            return (self._translate_sign_error(sign_result[1]),)
        signature = sign_result[1]

        return (self.ERROR_CODE_OK, {
            "signature": {
                "r": signature.r,
                "s": signature.s
            }
        })

    def _translate_sign_error(self, error_code):
        return ({
            HSM2Dongle.RESPONSE.SIGN.ERROR_PATH: self.ERROR_CODE_INVALID_KEYID,
            HSM2Dongle.RESPONSE.SIGN.ERROR_BTC_TX: self.ERROR_CODE_INVALID_MESSAGE,
            HSM2Dongle.RESPONSE.SIGN.ERROR_TX_RECEIPT: self.ERROR_CODE_INVALID_AUTH,
            HSM2Dongle.RESPONSE.SIGN.ERROR_MERKLE_PROOF: self.ERROR_CODE_INVALID_AUTH,
            HSM2Dongle.RESPONSE.SIGN.ERROR_HASH: self.ERROR_CODE_INVALID_MESSAGE,
            HSM2Dongle.RESPONSE.SIGN.ERROR_UNEXPECTED: self.ERROR_CODE_DEVICE
        }).get(error_code, self.ERROR_CODE_UNKNOWN)

    def _blockchain_state(self, request):
        try:
            state = self.hsm2dongle.get_blockchain_state()
        except (HSM2DongleError, HSM2DongleTimeout) as e:
            self.logger.error("Dongle error getting blockchain state: %s", str(e))
            return (self.ERROR_CODE_DEVICE,)

        state_result = {
            "best_block": state["best_block"],
            "newest_valid_block": state["newest_valid_block"],
            "ancestor_block": state["ancestor_block"],
            "ancestor_receipts_root": state["ancestor_receipts_root"],
            "updating": {
                "best_block": state["updating.best_block"],
                "newest_valid_block": state["updating.newest_valid_block"],
                "next_expected_block": state["updating.next_expected_block"],
                "total_difficulty": state["updating.total_difficulty"],
                "in_progress": state["updating.in_progress"],
                "already_validated": state["updating.already_validated"],
                "found_best_block": state["updating.found_best_block"],
            }
        }

        return (self.ERROR_CODE_OK, { "state": state_result })

    def _reset_advance_blockchain(self, request):
        try:
            self.hsm2dongle.reset_advance_blockchain()
        except (HSM2DongleError, HSM2DongleTimeout) as e:
            self.logger.error("Dongle error resetting advance blockchain: %s", str(e))
            return (self.ERROR_CODE_DEVICE,)

        return (self.ERROR_CODE_OK, {})

    def _advance_blockchain(self, request):
        try:
            advance_result = self.hsm2dongle.advance_blockchain(request["blocks"], self._dongle_app_version)

            return (self._translate_advance_result(advance_result[1]), {})
        except (HSM2DongleError, HSM2DongleTimeout) as e:
            self.logger.error("Dongle error in advance blockchain: %s", str(e))
            return (self.ERROR_CODE_DEVICE,)

    def _translate_advance_result(self, result):
        return ({
            HSM2Dongle.RESPONSE.ADVANCE.OK_TOTAL: self.ERROR_CODE_OK,
            HSM2Dongle.RESPONSE.ADVANCE.OK_PARTIAL: self.ERROR_CODE_OK_PARTIAL,
            HSM2Dongle.RESPONSE.ADVANCE.ERROR_INIT: self.ERROR_CODE_DEVICE,
            HSM2Dongle.RESPONSE.ADVANCE.ERROR_COMPUTE_METADATA: self.ERROR_CODE_INVALID_INPUT_BLOCKS,
            HSM2Dongle.RESPONSE.ADVANCE.ERROR_METADATA: self.ERROR_CODE_DEVICE,
            HSM2Dongle.RESPONSE.ADVANCE.ERROR_BLOCK_DATA: self.ERROR_CODE_DEVICE,
            HSM2Dongle.RESPONSE.ADVANCE.ERROR_INVALID_BLOCK: self.ERROR_CODE_INVALID_INPUT_BLOCKS,
            HSM2Dongle.RESPONSE.ADVANCE.ERROR_POW_INVALID: self.ERROR_CODE_POW_INVALID,
            HSM2Dongle.RESPONSE.ADVANCE.ERROR_CHAINING_MISMATCH: self.ERROR_CODE_CHAINING_MISMATCH,
            HSM2Dongle.RESPONSE.ADVANCE.ERROR_UNSUPPORTED_CHAIN: self.ERROR_CODE_INVALID_INPUT_BLOCKS,
            HSM2Dongle.RESPONSE.ADVANCE.ERROR_UNEXPECTED: self.ERROR_CODE_UNKNOWN,
        }).get(result, self.ERROR_CODE_UNKNOWN)

    def _update_ancestor_block(self, request):
        try:
            update_result = self.hsm2dongle.update_ancestor(request["blocks"], self._dongle_app_version)

            return (self._translate_update_ancestor_result(update_result[1]), {})
        except (HSM2DongleError, HSM2DongleTimeout) as e:
            self.logger.error("Dongle error in update ancestor: %s", str(e))
            return (self.ERROR_CODE_DEVICE,)

    def _translate_update_ancestor_result(self, result):
        return ({
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.OK_TOTAL: self.ERROR_CODE_OK,
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_INIT: self.ERROR_CODE_DEVICE,
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_COMPUTE_METADATA: self.ERROR_CODE_INVALID_INPUT_BLOCKS,
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_METADATA: self.ERROR_CODE_DEVICE,
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_BLOCK_DATA: self.ERROR_CODE_DEVICE,
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_INVALID_BLOCK: self.ERROR_CODE_INVALID_INPUT_BLOCKS,
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_CHAINING_MISMATCH: self.ERROR_CODE_CHAINING_MISMATCH,
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_TIP_MISMATCH: self.ERROR_CODE_TIP_MISMATCH,
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_REMOVE_MM_FIELDS: self.ERROR_CODE_INVALID_INPUT_BLOCKS,
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_UNEXPECTED: self.ERROR_CODE_UNKNOWN,
        }).get(result, self.ERROR_CODE_UNKNOWN)

# The MIT License (MIT)
#
# Copyright (c) 2021 RSK Labs Ltd
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import time
from comm.protocol import HSM2Protocol, HSM2ProtocolError, HSM2ProtocolInterrupt
from ledger.hsm2dongle import (
    HSM2Dongle,
    HSM2DongleBaseError,
    HSM2DongleError,
    HSM2DongleErrorResult,
    HSM2DongleTimeoutError,
    HSM2DongleCommError,
    HSM2FirmwareVersion,
)
from comm.bitcoin import get_unsigned_tx, get_tx_hash


class HSM2ProtocolLedger(HSM2Protocol):
    # Current manager supported versions for HSM UI and HSM SIGNER (<=)
    UI_VERSION = HSM2FirmwareVersion(4, 0, 0)
    APP_VERSION = HSM2FirmwareVersion(4, 0, 0)

    # Amount of time to wait to make sure the app is opened
    OPEN_APP_WAIT = 1  # second

    # Required minimum number of pin retries available to proceed with unlocking
    MIN_AVAILABLE_RETRIES = 2

    def __init__(self, pin, dongle):
        super().__init__()
        self.hsm2dongle = dongle
        self._comm_issue = False
        self.pin = pin

    def initialize_device(self):
        # Connection
        try:
            self.logger.info("Connecting to dongle")
            self.hsm2dongle.connect()
            self.logger.info("Connected to dongle")
        except HSM2DongleBaseError as e:
            self.logger.error(e)
            raise HSM2ProtocolError(e)

        # Onboard check
        try:
            is_onboarded = self.hsm2dongle.is_onboarded()
            self.logger.info("Dongle onboarded: %s", "yes" if is_onboarded else "no")
            if not is_onboarded:
                self.logger.error("Dongle not onboarded, exiting")
                raise HSM2ProtocolError("Dongle not onboarded")
        except HSM2DongleBaseError:
            self.logger.info(
                "Could not determine onboarded status. If unlocked, "
                + "please enter the signing app and rerun the manager. Otherwise,"
                + "disconnect and reconnect the ledger nano and try again"
            )
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

        # In this point, the mode should be signer.
        # Otherwise, we tell the user to manually enter the signer and run
        # the manager again
        if current_mode != HSM2Dongle.MODE.SIGNER:
            self.logger.info(
                "Dongle mode unknown. Please manually enter the signer "
                "and re-run the manager"
            )
            raise HSM2ProtocolInterrupt()

        self.logger.info("Mode: Signing App")

        # Verify that the app's version is correct
        self._dongle_app_version = self.hsm2dongle.get_version()
        self._check_version(self._dongle_app_version, self.APP_VERSION, "App")

        # Get and report signer parameters
        signer_parameters = self.hsm2dongle.get_signer_parameters()
        self.logger.info("Gathered signer parameters")
        self.logger.info("Checkpoint 0x%s", signer_parameters.checkpoint)
        self.logger.info(
            "Minimum required difficulty %s",
            hex(signer_parameters.min_required_difficulty),
        )
        self.logger.info("Network %s", signer_parameters.network.name)

    def report_comm_issue(self):
        self._comm_issue = True

    def ensure_connection(self):
        if not self._comm_issue:
            return

        # Attempt to reconnect
        self.logger.info("Attempting dongle reconnection")
        self.hsm2dongle.disconnect()
        try:
            self.initialize_device()
            self._comm_issue = False
            self.logger.info("Reconnection successful")
        except HSM2ProtocolError as e:
            # Capture any initialization issues
            # (which would include communication problems,
            # such as failure to connect) and bubble them
            # as a dongle communication error, so that
            # the reply to the client will be appropiate and
            # a subsequent reconnection will be attempted
            # upon the next command
            # (don't log anything here, initialize_device will have done so)
            raise HSM2DongleCommError("While attempting to reconnect: %s", str(e))

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

        # Get the number of retries available to unlock the device
        # Then, only proceed if there is more than the minimum available
        # retries required (otherwise we risk wiping the device)
        try:
            self.logger.info("Retrieving available pin retries")
            retries = self.hsm2dongle.get_retries()
            self.logger.info("Available pin retries: %d", retries)
            if retries < self.MIN_AVAILABLE_RETRIES:
                self.logger.error(
                    "Available number of pin retries (%d) not enough "
                    "to attempt a device unlock. Aborting.",
                    retries,
                )
                raise HSM2ProtocolInterrupt()
        except HSM2DongleBaseError as e:
            self.logger.error(
                "While trying to get number of pin retries: %s. Aborting.", str(e)
            )
            raise HSM2ProtocolInterrupt()

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
                self.logger.info(
                    "PIN changed. Please disconnect and reconnect the ledger nano"
                )
            except Exception as e:
                self.pin.abort_change()
                self.logger.error(
                    "Error changing PIN: %s. Please disconnect and "
                    "reconnect the ledger nano and try again",
                    format(e),
                )
            finally:
                raise HSM2ProtocolInterrupt()

        # This loads the app if in bootloader mode
        # This usually fails with a timeout, but its fine cause
        # what happens is that when opening the app,
        # the ledger disconnects from usb and reconnects
        self.logger.info("Loading Signing app")
        try:
            self.hsm2dongle.exit_menu()
        except Exception:
            # exit_menu() always throws due to USB disconnection. we don't care
            pass

        self._wait_and_reconnect()

    def _wait_and_reconnect(self):
        # Wait a little bit to make sure the app is loaded
        # and then reconnect to the dongle
        time.sleep(self.OPEN_APP_WAIT)
        self.hsm2dongle.disconnect()
        self.hsm2dongle.connect()

    def _check_version(self, fware_version, mware_version, name):
        self.logger.info(
            "%s version: %s (supported <= %s)", name, fware_version, mware_version
        )
        if not mware_version.supports(fware_version):
            self._error(
                "Unsupported %s version: Dongle reports %s, Node needs <= %s"
                % (name, fware_version, mware_version)
            )

    def _error(self, msg):
        self.logger.error(msg)
        raise HSM2ProtocolError(msg)

    def _get_pubkey(self, request):
        try:
            self.ensure_connection()
            return (
                self.ERROR_CODE_OK,
                {"pubKey": self.hsm2dongle.get_public_key(request["keyId"])},
            )
        except HSM2DongleErrorResult:
            return (self.ERROR_CODE_INVALID_KEYID,)
        except HSM2DongleTimeoutError:
            self.logger.error("Dongle timeout getting public key")
            return (self.ERROR_CODE_DEVICE,)
        except HSM2DongleCommError:
            # Signal a communication problem and return a device error
            self._comm_issue = True
            self.logger.error("Dongle communication error getting public key")
            return (self.ERROR_CODE_DEVICE,)
        except HSM2DongleError as e:
            return self._error("Dongle error in get_pubkey: %s" % str(e))

    def _sign(self, request):
        # First validate the required fields are OK
        if "message" in request and "hash" in request["message"]:
            # Unauthorized signing
            message_validation = self._validate_message(request, what="hash")
            if message_validation < self.ERROR_CODE_OK:
                return (message_validation,)

            try:
                self.ensure_connection()
                sign_result = self.hsm2dongle.sign_unauthorized(
                    key_id=request["keyId"], hash=request["message"]["hash"]
                )
            except HSM2DongleTimeoutError:
                self.logger.error("Dongle timeout signing")
                return (self.ERROR_CODE_DEVICE,)
            except HSM2DongleCommError:
                # Signal a communication problem and return a device error
                self._comm_issue = True
                self.logger.error("Dongle communication error signing")
                return (self.ERROR_CODE_DEVICE,)
            except HSM2DongleError as e:
                self._error("Dongle error in sign: %s" % str(e))
        else:
            # Authorized signing
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
                return (self.ERROR_CODE_INVALID_MESSAGE,)

            try:
                self.ensure_connection()
                sign_result = self.hsm2dongle.sign_authorized(
                    key_id=request["keyId"],
                    rsk_tx_receipt=request["auth"]["receipt"],
                    receipt_merkle_proof=request["auth"]["receipt_merkle_proof"],
                    btc_tx=unsigned_btc_tx,
                    input_index=request["message"]["input"],
                )
            except HSM2DongleTimeoutError:
                self.logger.error("Dongle timeout signing")
                return (self.ERROR_CODE_DEVICE,)
            except HSM2DongleCommError:
                # Signal a communication problem and return a device error
                self._comm_issue = True
                self.logger.error("Dongle communication error signing")
                return (self.ERROR_CODE_DEVICE,)
            except HSM2DongleError as e:
                self._error("Dongle error in sign: %s" % str(e))

        # Signing result is the same for both authorized and non authorized signing
        if not sign_result[0]:
            return (self._translate_sign_error(sign_result[1]),)
        signature = sign_result[1]

        return (self.ERROR_CODE_OK, {"signature": {"r": signature.r, "s": signature.s}})

    def _translate_sign_error(self, error_code):
        return (
            {
                HSM2Dongle.RESPONSE.SIGN.ERROR_PATH: self.ERROR_CODE_INVALID_KEYID,
                HSM2Dongle.RESPONSE.SIGN.ERROR_BTC_TX: self.ERROR_CODE_INVALID_MESSAGE,
                HSM2Dongle.RESPONSE.SIGN.ERROR_TX_RECEIPT: self.ERROR_CODE_INVALID_AUTH,
                HSM2Dongle.RESPONSE.SIGN.ERROR_MERKLE_PROOF: self.ERROR_CODE_INVALID_AUTH,
                HSM2Dongle.RESPONSE.SIGN.ERROR_HASH: self.ERROR_CODE_INVALID_MESSAGE,
                HSM2Dongle.RESPONSE.SIGN.ERROR_UNEXPECTED: self.ERROR_CODE_DEVICE,
            }
        ).get(error_code, self.ERROR_CODE_UNKNOWN)

    def _blockchain_state(self, request):
        try:
            self.ensure_connection()
            state = self.hsm2dongle.get_blockchain_state()
        except (HSM2DongleError, HSM2DongleTimeoutError) as e:
            self.logger.error("Dongle error getting blockchain state: %s", str(e))
            return (self.ERROR_CODE_DEVICE,)
        except HSM2DongleCommError:
            # Signal a communication problem and return a device error
            self._comm_issue = True
            self.logger.error("Dongle communication error getting blockchain state")
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
            },
        }

        return (self.ERROR_CODE_OK, {"state": state_result})

    def _reset_advance_blockchain(self, request):
        try:
            self.ensure_connection()
            self.hsm2dongle.reset_advance_blockchain()
        except (HSM2DongleError, HSM2DongleTimeoutError) as e:
            self.logger.error("Dongle error resetting advance blockchain: %s", str(e))
            return (self.ERROR_CODE_DEVICE,)
        except HSM2DongleCommError:
            # Signal a communication problem and return a device error
            self._comm_issue = True
            self.logger.error("Dongle communication error resetting advance blockchain")
            return (self.ERROR_CODE_DEVICE,)

        return (self.ERROR_CODE_OK, {})

    def _advance_blockchain(self, request):
        try:
            self.ensure_connection()
            advance_result = self.hsm2dongle.advance_blockchain(
                request["blocks"], request["brothers"]
            )
            return (self._translate_advance_result(advance_result[1]), {})
        except (HSM2DongleError, HSM2DongleTimeoutError) as e:
            self.logger.error("Dongle error in advance blockchain: %s", str(e))
            return (self.ERROR_CODE_DEVICE,)
        except HSM2DongleCommError:
            # Signal a communication problem and return a device error
            self._comm_issue = True
            self.logger.error("Dongle communication error in advance blockchain")
            return (self.ERROR_CODE_DEVICE,)

    def _translate_advance_result(self, result):
        DERR = HSM2Dongle.RESPONSE.ADVANCE
        return ({
            DERR.OK_TOTAL: self.ERROR_CODE_OK,
            DERR.OK_PARTIAL: self.ERROR_CODE_OK_PARTIAL,
            DERR.ERROR_INIT: self.ERROR_CODE_DEVICE,
            DERR.ERROR_COMPUTE_METADATA: self.ERROR_CODE_INVALID_INPUT_BLOCKS,  # noqa E501
            DERR.ERROR_METADATA: self.ERROR_CODE_DEVICE,
            DERR.ERROR_BLOCK_DATA: self.ERROR_CODE_DEVICE,
            DERR.ERROR_INVALID_BLOCK: self.ERROR_CODE_INVALID_INPUT_BLOCKS, # noqa E501
            DERR.ERROR_POW_INVALID: self.ERROR_CODE_POW_INVALID,
            DERR.ERROR_CHAINING_MISMATCH: self.ERROR_CODE_CHAINING_MISMATCH,  # noqa E501
            DERR.ERROR_UNSUPPORTED_CHAIN: self.ERROR_CODE_INVALID_INPUT_BLOCKS,  # noqa E501
            DERR.ERROR_INVALID_BROTHERS: self.ERROR_CODE_INVALID_BROTHERS,  # noqa E501
            DERR.ERROR_UNEXPECTED: self.ERROR_CODE_UNKNOWN,
        }).get(result, self.ERROR_CODE_UNKNOWN)

    def _update_ancestor_block(self, request):
        try:
            self.ensure_connection()
            update_result = self.hsm2dongle.update_ancestor(request["blocks"])
            return (self._translate_update_ancestor_result(update_result[1]), {})
        except (HSM2DongleError, HSM2DongleTimeoutError) as e:
            self.logger.error("Dongle error in update ancestor: %s", str(e))
            return (self.ERROR_CODE_DEVICE,)
        except HSM2DongleCommError:
            # Signal a communication problem and return a device error
            self._comm_issue = True
            self.logger.error("Dongle communication error in update ancestor")
            return (self.ERROR_CODE_DEVICE,)

    def _translate_update_ancestor_result(self, result):
        return ({
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.OK_TOTAL: self.ERROR_CODE_OK,
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_INIT: self.ERROR_CODE_DEVICE,
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_COMPUTE_METADATA: self.ERROR_CODE_INVALID_INPUT_BLOCKS,  # noqa E501
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_METADATA: self.ERROR_CODE_DEVICE,
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_BLOCK_DATA: self.ERROR_CODE_DEVICE,
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_INVALID_BLOCK: self.ERROR_CODE_INVALID_INPUT_BLOCKS,  # noqa E501
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_CHAINING_MISMATCH: self.ERROR_CODE_CHAINING_MISMATCH,  # noqa E501
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_TIP_MISMATCH: self.ERROR_CODE_TIP_MISMATCH,  # noqa E501
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_REMOVE_MM_FIELDS: self.ERROR_CODE_INVALID_INPUT_BLOCKS,  # noqa E501
            HSM2Dongle.RESPONSE.UPD_ANCESTOR.ERROR_UNEXPECTED: self.ERROR_CODE_UNKNOWN,
        }).get(result, self.ERROR_CODE_UNKNOWN)

    def _get_blockchain_parameters(self, request):
        try:
            self.ensure_connection()
            params = self.hsm2dongle.get_signer_parameters()
            return (self.ERROR_CODE_OK, {"parameters": {
                "checkpoint": params.checkpoint,
                "minimum_difficulty": params.min_required_difficulty,
                "network": params.network.name.lower()}
            })
        except (HSM2DongleError, HSM2DongleTimeoutError) as e:
            self.logger.error("Dongle error in get parameters: %s", str(e))
            return (self.ERROR_CODE_DEVICE,)
        except HSM2DongleCommError:
            # Signal a communication problem and return a device error
            self._comm_issue = True
            self.logger.error("Dongle communication error in get parameters")
            return (self.ERROR_CODE_DEVICE,)

    def _signer_heartbeat(self, request):
        try:
            self.ensure_connection()

            heartbeat = self.hsm2dongle.get_signer_heartbeat(request["udValue"])
            # Treat any user-errors as a device (unexpected) error
            if not(heartbeat[0]):
                return (self.ERROR_CODE_DEVICE,)
            heartbeat = heartbeat[1]

            return (self.ERROR_CODE_OK, {
                "pubKey": heartbeat["pubKey"],
                "message": heartbeat["message"],
                "tweak": heartbeat["tweak"],
                "signature": {
                    "r": heartbeat["signature"].r,
                    "s": heartbeat["signature"].s
                }
            })
        except (HSM2DongleError, HSM2DongleTimeoutError) as e:
            self.logger.error("Dongle error in signer heartbeat: %s", str(e))
            return (self.ERROR_CODE_DEVICE,)
        except HSM2DongleCommError:
            # Signal a communication problem and return a device error
            self._comm_issue = True
            self.logger.error("Dongle communication error in signer heartbeat")
            return (self.ERROR_CODE_DEVICE,)

    def _ui_heartbeat(self, request):
        try:
            self.ensure_connection()

            # Check the current mode
            initial_mode = self.hsm2dongle.get_current_mode()

            # Can only gather the UI heartbeat from either the Signer or
            # the UI heartbeat mode itself
            if not(initial_mode in [self.hsm2dongle.MODE.SIGNER,
                                    self.hsm2dongle.MODE.UI_HEARTBEAT]):
                self.logger.error("Dongle not in Signer or UI heartbeat mode when"
                                  " trying to gather UI heartbeat")
                return (self.ERROR_CODE_DEVICE,)

            # Exit the signer
            if initial_mode == self.hsm2dongle.MODE.SIGNER:
                # This should raise a communication error due to USB
                # disconnection. Treat as successful
                try:
                    self.hsm2dongle.exit_app()
                except HSM2DongleCommError:
                    pass
                self._wait_and_reconnect()
                # Check we are now in UI heartbeat mode
                new_mode = self.hsm2dongle.get_current_mode()
                if new_mode != self.hsm2dongle.MODE.UI_HEARTBEAT:
                    self.logger.error("Expected dongle to be in UI heartbeat"
                                      f" mode but got {new_mode}")
                    return (self.ERROR_CODE_DEVICE,)

            # Gather the heartbeat and immediately try to go back
            # to the signer. Deal with the heartbeat result later.
            heartbeat = self.hsm2dongle.get_ui_heartbeat(request["udValue"])

            # Exit the UI heartbeat to return to the signer
            if initial_mode == self.hsm2dongle.MODE.SIGNER:
                # This should raise a communication error due to USB
                # disconnection. Treat as successful
                try:
                    self.hsm2dongle.exit_app()
                except HSM2DongleCommError:
                    pass
                self._wait_and_reconnect()
                # Check we are now back in the Signer
                new_mode = self.hsm2dongle.get_current_mode()
                if new_mode != self.hsm2dongle.MODE.SIGNER:
                    self.logger.error("Expected dongle to be in Signer"
                                      f" mode but got {new_mode}")
                    return (self.ERROR_CODE_DEVICE,)

            # Treat any user-errors as a device (unexpected) error
            if not(heartbeat[0]):
                return (self.ERROR_CODE_DEVICE,)
            heartbeat = heartbeat[1]

            return (self.ERROR_CODE_OK, {
                "pubKey": heartbeat["pubKey"],
                "message": heartbeat["message"],
                "tweak": heartbeat["tweak"],
                "signature": {
                    "r": heartbeat["signature"].r,
                    "s": heartbeat["signature"].s
                }
            })
        except (HSM2DongleError, HSM2DongleTimeoutError) as e:
            self.logger.error("Dongle error in UI heartbeat: %s", str(e))
            return (self.ERROR_CODE_DEVICE,)
        except HSM2DongleCommError:
            # Signal a communication problem and return a device error
            self._comm_issue = True
            self.logger.error("Dongle communication error in UI heartbeat")
            return (self.ERROR_CODE_DEVICE,)

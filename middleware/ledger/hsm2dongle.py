import struct
from enum import IntEnum, auto
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
from .signature import HSM2DongleSignature
from .version import HSM2FirmwareVersion
from .parameters import HSM2FirmwareParameters
from .block_utils import rlp_mm_payload_size, remove_mm_fields_if_present, get_coinbase_txn
from comm.pow import coinbase_tx_get_hash
import logging

#### Enumerations ####

# Dongle commands
class _Command(IntEnum):
    IS_ONBOARD = 0x06
    ECHO = 0x02 # UI command
    SIGN = 0x02 # Signer command
    GET_PUBLIC_KEY = 0x04
    SEND_PIN = 0x41
    UNLOCK = 0xfe
    CHANGE_PIN = 0x08
    GET_MODE = 0x43
    EXIT_MENU = 0xff
    GET_STATE = 0x20
    RESET_AB = 0x21
    ADVANCE = 0x10
    UPD_ANCESTOR = 0x30
    GET_PARAMETERS = 0x11
    SEED = 0x44
    WIPE = 0x07
    UI_ATT = 0x50
    SIGNER_ATT = 0x50
    RETRIES = 0x45

# Sign command OPs
class _SignOps(IntEnum):
    PATH = 0x01
    BTC_TX = 0x02
    TX_RECEIPT = 0x04
    MERKLE_PROOF = 0x08
    SUCCESS = 0x81

# Get blockchain state command OPs
class _GetStateOps(IntEnum):
    HASH = 0x01
    DIFF = 0x02
    FLAGS = 0x03

# Reset advance blockchain command OPs
class _ResetAdvanceOps(IntEnum):
    INIT = 0x01
    DONE = 0x02

# Advance blockchain command OPs
class _AdvanceOps(IntEnum):
    INIT = 0x02
    HEADER_META = 0x03
    HEADER_CHUNK = 0x04
    PARTIAL = 0x05
    SUCCESS = 0x06

# Update ancestor command OPs
class _UpdateAncestorOps(IntEnum):
    INIT = 0x02
    HEADER_META = 0x03
    HEADER_CHUNK = 0x04
    SUCCESS = 0x05

# UI attestation OPs
class _UIAttestationOps(IntEnum):
    OP_PUBKEY = 0x01
    OP_HASH = 0x02
    OP_SIGNATURE = 0x03
    OP_GET = 0x04
    OP_APP_HASH = 0x05

# Signer attestation OPs
class _SignerAttestationOps(IntEnum):
    OP_GET = 0x01
    OP_GET_MESSAGE = 0x02
    OP_APP_HASH = 0x03

# Command Ops
class _Ops:
    SIGN = _SignOps
    GST = _GetStateOps
    RAV = _ResetAdvanceOps
    ADVANCE = _AdvanceOps
    UPD_ANCESTOR = _UpdateAncestorOps
    UI_ATT = _UIAttestationOps
    SIGNER_ATT = _SignerAttestationOps

# Protocol offsets
class _Offset(IntEnum):
    CLA = 0
    CMD = 1
    OP = 2
    DATA = 3

# Device modes
class _Mode(IntEnum):
    BOOTLOADER = 0x02
    APP = 0x03
    UNKNOWN = 0xff

# Get blockchain state flag indexes
class _GetStateFlagOffset(IntEnum):
    IN_PROGRESS = 0
    ALREADY_VALIDATED = 1
    FOUND_BEST_BLOCK = 2

# Get blockchain state constants
class _GetState:
    FLAG_OFFSET = _GetStateFlagOffset
    HASH_VALUES = {
        "best_block": 0x01,
        "newest_valid_block": 0x02,
        "ancestor_block": 0x03,
        "ancestor_receipts_root": 0x05,
        "updating.best_block": 0x81,
        "updating.newest_valid_block": 0x82,
        "updating.next_expected_block": 0x84,
    }

# Sign command errors
class _SignError(IntEnum):
    DATA_SIZE = 0x6a87
    INPUT = auto()
    STATE = auto()
    RLP = auto()
    RLP_INT = auto()
    RLP_DEPTH = auto()
    TX_HASH_MISMATCH = auto()
    TX_VERSION = auto()
    INVALID_PATH = auto()
    DATA_SIZE_AUTH = auto()
    DATA_SIZE_NOAUTH = auto()
    NODE_VERSION = auto()
    SHARED_PREFIX_TOO_BIG = auto()
    RECEIPT_HASH_MISMATCH = auto()
    NODE_CHAINING_MISMATCH = auto()
    RECEIPT_ROOT_MISMATCH = auto()

# Get public key command errors
class _GetPubKeyError(IntEnum):
    DATA_SIZE = 0x6A87

# Advance blockchain and update ancestor command errors
class _AdvanceUpdateError(IntEnum):
    UNKNOWN = 0
    PROT_INVALID = 0x6b87
    RLP_INVALID = auto()
    BLOCK_TOO_OLD = auto()
    BLOCK_TOO_SHORT = auto()
    PARENT_HASH_INVALID = auto()
    RECEIPT_ROOT_INVALID = auto()
    BLOCK_NUM_INVALID = auto()
    BLOCK_DIFF_INVALID = auto()
    UMM_ROOT_INVALID = auto()
    BTC_HEADER_INVALID = auto()
    MERKLE_PROOF_INVALID = auto()
    BTC_CB_TXN_INVALID = auto()
    MM_RLP_LEN_MISMATCH = auto()
    BTC_DIFF_MISMATCH = auto()
    MERKLE_PROOF_MISMATCH = auto()
    MM_HASH_MISMATCH = auto()
    MERKLE_PROOF_OVERFLOW = auto()
    CB_TXN_OVERFLOW = auto()
    BUFFER_OVERFLOW = auto()
    CHAIN_MISMATCH = auto()
    TOTAL_DIFF_OVERFLOW = auto()
    ANCESTOR_TIP_MISMATCH = auto()
    CB_TXN_HASH_MISMATCH = auto()

class _UIError(IntEnum):
    INVALID_PIN = 0x69a0

class _UIAttestationError(IntEnum):
    PROT_INVALID = 0x6a01
    CA_MISMATCH = 0x6a02
    NO_ONBOARD   = 0x6a03
    INTERNAL = 0x6b04

class _SignerAttestationError(IntEnum):
    PROT_INVALID = 0x6b00
    INTERNAL = 0x6b01

# Error codes
class _Error:
    SIGN = _SignError
    GETPUBKEY = _GetPubKeyError
    ADVANCE = _AdvanceUpdateError
    UPD_ANCESTOR = _AdvanceUpdateError
    UI = _UIError
    UI_ATT = _UIAttestationError
    SIGNER_ATT = _SignerAttestationError

    # Whether a given code is in the
    # user-defined (RSK firmware) specific error code range
    @staticmethod
    def is_user_defined_error(code):
        return code >= 0x69a0 and code <= 0x6bff

# Sign command responses to the user
class _SignResponse(IntEnum):
    ERROR_PATH = -1
    ERROR_BTC_TX = -2
    ERROR_TX_RECEIPT = -3
    ERROR_MERKLE_PROOF = -4
    ERROR_HASH = -5
    ERROR_UNEXPECTED = -10

# Advance blockchain responses to the user
class _AdvanceResponse(IntEnum):
    OK_TOTAL = 1
    OK_PARTIAL = 2

    ERROR_INIT = -1
    ERROR_COMPUTE_METADATA = -2
    ERROR_METADATA = -3
    ERROR_BLOCK_DATA = -4
    ERROR_INVALID_BLOCK = -5
    ERROR_POW_INVALID = -6
    ERROR_CHAINING_MISMATCH = -7
    ERROR_UNSUPPORTED_CHAIN = -8
    ERROR_UNEXPECTED = -10

# Update ancestor responses to the user
class _UpdateAncestorResponse(IntEnum):
    OK_TOTAL = 1

    ERROR_INIT = -1
    ERROR_COMPUTE_METADATA = -2
    ERROR_METADATA = -3
    ERROR_BLOCK_DATA = -4
    ERROR_INVALID_BLOCK = -5
    ERROR_CHAINING_MISMATCH = -6
    ERROR_TIP_MISMATCH = -7
    ERROR_REMOVE_MM_FIELDS = -8
    ERROR_UNEXPECTED = -10

# Responses
class _Response:
    SIGN = _SignResponse
    ADVANCE = _AdvanceResponse
    UPD_ANCESTOR = _UpdateAncestorResponse

# Onboarding constants
class _Onboarding(IntEnum):
    SEED_LENGTH = 32
    TIMEOUT = 10

class HSM2DongleBaseError(RuntimeError):
    pass

class HSM2DongleError(HSM2DongleBaseError):
    pass

class HSM2DongleTimeout(HSM2DongleBaseError):
    @staticmethod
    def is_timeout(exc):
        if type(exc) == CommException and \
            exc.sw == 0x6f00 and \
            exc.message == "Timeout":
            return True
        return False

class HSM2DongleErrorResult(HSM2DongleBaseError):
    @property
    def error_code(self):
        return self.args[0]

# Handles low-level communication with an HSM2 dongle
class HSM2Dongle:
    #### Ledger constants ####
    HASH_SIZE = 32

    # APDU prefix
    CLA = 0x80

    # Enumeration shorthands
    OFF = _Offset
    CMD = _Command
    MODE = _Mode
    OP = _Ops
    ERR = _Error
    GST = _GetState
    RESPONSE = _Response
    ONBOARDING = _Onboarding

    # Dongle exchange timeout
    DONGLE_TIMEOUT = 10 # seconds

    # Protocol version dependent features
    MIN_VERSION_META_CBTXHASH = HSM2FirmwareVersion(2,1,0)
    MIN_VERSION_UI_GET_RETRIES = HSM2FirmwareVersion(2,1,0)

    def __init__(self, debug):
        self.logger = logging.getLogger("dongle")
        self.debug = debug

    # Send command to device
    def _send_command(self, command, data=b'', timeout=DONGLE_TIMEOUT):
        try:
            cmd = struct.pack('BB%ds' % len(data), self.CLA, command, data)
            self.logger.debug("Sending command: 0x%s", cmd.hex())
            result = self.dongle.exchange(cmd, timeout=timeout)
            self.logger.debug("Received: 0x%s", result.hex())
        except (CommException, BaseException) as e:
            # If this is a user-defined exception, raise an
            # error result exception
            if type(e) == CommException:
                error_code = e.sw
                if _Error.is_user_defined_error(error_code):
                    self.logger.error("Received error code: %s", hex(error_code))
                    raise HSM2DongleErrorResult(error_code)

            # If this is a dongle timeout, raise a timeout exception
            if HSM2DongleTimeout.is_timeout(e):
                raise HSM2DongleTimeout()

            # Otherwise, raise a standard error
            msg = "Error sending command: %s" % str(e)
            self.logger.error(msg)
            raise HSM2DongleError(msg)
        except Exception as e:
            msg = "Unknown error sending command: %s" % str(e)
            self.logger.critical(msg)
            raise HSM2DongleError(msg)
        return result

    # Connect to the dongle
    def connect(self):
        try:
            self.logger.info("Connecting")
            self.dongle = getDongle(self.debug)
            self.logger.info("Connected")
        except CommException as e:
            msg = "Error connecting: %s" % e.message
            self.logger.error(msg)
            raise HSM2DongleError(msg)

    # Disconnect from dongle
    def disconnect(self):
        try:
            self.logger.info("Disconnecting")
            if self.dongle and self.dongle.opened:
                self.dongle.close()
            self.logger.info("Disconnected")
        except CommException as e:
            msg = "Error disconnecting: %s" % e.message
            self.logger.error(msg)
            raise HSM2DongleError(msg)

    # Return device mode
    def get_current_mode(self):
        try:
            apdu_rcv = self._send_command(self.CMD.GET_MODE)
            return self.MODE(apdu_rcv[1])
        except HSM2DongleError:
            return self.MODE.UNKNOWN

    # Echo message
    def echo(self):
        message = bytes([0x41, 0x42, 0x43])
        result = bytes(self._send_command(self.CMD.ECHO, message))
        # Result should be the command plus the message
        expected_result = bytes([self.CLA, self.CMD.ECHO]) + message
        return result == expected_result

    # Return true if the hsm2 is onboarded
    def is_onboarded(self):
        self.logger.info("Sending isOnboarded")
        apdu_rcv = self._send_command(self.CMD.IS_ONBOARD)
        is_onboard = apdu_rcv[1]==1
        self.logger.info("isOnboarded: %s", "yes" if is_onboard else "no")
        return is_onboard

    # Attempt to onboard the device using the given seed and pin
    # Return the generated backup
    def onboard(self, seed, pin):
        if type(seed) != bytes or len(seed) != self.ONBOARDING.SEED_LENGTH:
            raise HSM2DongleError("Invalid seed given")

        self.logger.info("Sending seed")
        for i, b in enumerate(seed):
            self._send_command(self.CMD.SEED, bytes([i, b]))

        self.logger.info("Sending pin")
        self._send_pin(pin, True)

        self.logger.info("Sending wipe")
        apdu_rcv = self._send_command(self.CMD.WIPE, timeout=self.ONBOARDING.TIMEOUT)

        if apdu_rcv[1] != 2:
            raise HSM2DongleError("Error onboarding. Got '%s'" % apdu_rcv.hex())

        return True

    # send PIN to device, optionally prepending its length
    def _send_pin(self, pin, prepend_length):
        final_pin = pin
        if prepend_length:
            final_pin = bytes([len(pin)]) + final_pin

        for i in range(len(final_pin)):
            self._send_command(self.CMD.SEND_PIN,bytes([i,final_pin[i]]))

    # unlock the device with the PIN sent
    def unlock(self, pin):
        # Send the pin, then send the unlock command per se
        self._send_pin(pin, prepend_length=False)
        apdu_rcv = self._send_command(self.CMD.UNLOCK, bytes([0x00,0x00]))

        # Zero indicates wrong pin. Nonzero indicates device unlocked
        return apdu_rcv[2] != 0

    # replace PIN with a new one
    def new_pin(self, pin):
        try:
            # Send the pin, then send the replace command per se
            self._send_pin(pin, prepend_length=True)
            self._send_command(self.CMD.CHANGE_PIN)
            # All is good
            return True
        except HSM2DongleErrorResult as e:
            # Tried to set an invalid pin
            if e.error_code == self.ERR.UI.INVALID_PIN:
                return False
            # Something else happened
            raise e

    # returns an instance of HSM2FirmwareVersion representing
    # the version of the currently running firmware on the HSM2
    # that is connected (i.e., could be either the signer or ui)
    def get_version(self):
        apdu_rcv = self._send_command(self.CMD.IS_ONBOARD)
        return HSM2FirmwareVersion(apdu_rcv[2], apdu_rcv[3], apdu_rcv[4])

    # returns the number of pin retries available
    def get_retries(self):
        apdu_rcv = self._send_command(self.CMD.RETRIES)
        return apdu_rcv[2]

    # returns an instance of HSM2FirmwareParameters representing
    # the parameters of the currently running firmware on the HSM2
    # that is connected (it should be running the signer).
    def get_signer_parameters(self):
        try:
            apdu_rcv = self._send_command(self.CMD.GET_PARAMETERS)
            return HSM2FirmwareParameters.from_dongle_format(apdu_rcv[self.OFF.DATA:])
        except ValueError as e:
            msg = "While getting signer firmware parameters: %s" % str(e)
            self.logger.error(msg)
            raise HSM2DongleError(msg)

    # exit the ledger nano S menu
    def exit_menu(self):
        self._send_command(self.CMD.EXIT_MENU, bytes([0x00,0x00]))

    # get the public key for a bip32 path
    # key_id: BIP32Path
    def get_public_key(self, key_id):
        publicKey = self._send_command(self.CMD.GET_PUBLIC_KEY, key_id.to_binary())
        return publicKey.hex()

    # Ask the device to sign a specific input of a given unsigned bitcoin transaction
    # using the given RSK transaction receipt as an authorization for the signature.
    # key_id: BIP32Path
    # rsk_tx_receipt: hex string
    # btc_tx: hex string
    # receipt_merkle_proof: list
    # input_index: int
    def sign_authorized(self, key_id, rsk_tx_receipt, receipt_merkle_proof,
                        btc_tx, input_index):
        # *** Signing protocol ***
        # The order in which things are required and then sent is:
        # 1. BIP32 path & BTC tx input index (single message)
        # 2. BTC transaction (several messages, as required by ledger)
        # 3. RSK transaction receipt (several messages, as required by ledger)
        # 4. RSK Tx receipt merkle proof (several messages, as required by ledger)
        # (Note: in theory, one could depend only on the order in which
        # the ledger requires data and send it blindly. In practice,
        # we know exactly the order in which the device will require
        # the data, and use that order to validate it as we go.)
        #
        # During these exchanges, an exception can be raised at any moment, which
        # would signal failure signing. Specific error codes come with HSM2DongleErrorResult
        # exception instances and are handled accordingly. Anything else
        # is treated as an unexpected error and is let for the calling layer
        # to handle.

        # Step 1. Send path and input index
        key_id_bytes = key_id.to_binary()
        input_index_bytes = input_index.to_bytes(4, byteorder='little', signed=False)
        data = bytes([self.OP.SIGN.PATH]) + key_id_bytes + input_index_bytes
        try:
            self.logger.debug("Sign: sending path - %s", data.hex())
            response = self._send_command(self.CMD.SIGN, data)

            # We expect the device to ask for the BTC tx next.
            # If this doesn't happen, error out
            if response[self.OFF.OP] != self.OP.SIGN.BTC_TX:
                self.logger.error("Sign: unexpected response %s", response.hex())
                return (False, self.RESPONSE.SIGN.ERROR_UNEXPECTED)

            # How many bytes to send in the next message
            bytes_requested = response[self.OFF.DATA]
        except HSM2DongleErrorResult as e:
            self.logger.error("Sign returned: %s", hex(e.error_code))
            if e.error_code in [self.ERR.SIGN.DATA_SIZE, self.ERR.SIGN.DATA_SIZE_AUTH, \
                                self.ERR.SIGN.DATA_SIZE_NOAUTH]:
                return (False, self.RESPONSE.SIGN.ERROR_PATH)
            return (False, self.RESPONSE.SIGN.ERROR_UNEXPECTED)

        # Step 2. Send BTC transaction
        # Prefix the BTC transaction with the total length of the payload encoded as a
        # 4 bytes little endian unsigned integer. The total length should include
        # those 4 bytes.
        try:
            LENGTH_PREFIX_IN_BYTES = 4

            btc_tx_bytes = bytes.fromhex(btc_tx)
            length_prefix_bytes = (len(btc_tx_bytes)+LENGTH_PREFIX_IN_BYTES).\
                        to_bytes(LENGTH_PREFIX_IN_BYTES, byteorder='little', signed=False)

            data =  length_prefix_bytes + btc_tx_bytes

            response = self._send_data_in_chunks(
                command=self.CMD.SIGN,
                operation=self.OP.SIGN.BTC_TX,
                next_operations=[self.OP.SIGN.TX_RECEIPT],
                data=data,
                initial_bytes=bytes_requested,
                operation_name="sign",
                data_description="BTC tx"
            )

            if not response[0]:
                return (False, self.RESPONSE.SIGN.ERROR_UNEXPECTED)

            bytes_requested = response[1][self.OFF.DATA]
        except HSM2DongleErrorResult as e:
            self.logger.error("Sign returned: %s", hex(e.error_code))
            if e.error_code in [self.ERR.SIGN.INPUT, \
                self.ERR.SIGN.DATA_SIZE, \
                self.ERR.SIGN.TX_HASH_MISMATCH, \
                self.ERR.SIGN.TX_VERSION]:
                return (False, self.RESPONSE.SIGN.ERROR_BTC_TX)
            return (False, self.RESPONSE.SIGN.ERROR_UNEXPECTED)

        # Step 3. Send transaction receipt
        try:
            response = self._send_data_in_chunks(
                command=self.CMD.SIGN,
                operation=self.OP.SIGN.TX_RECEIPT,
                next_operations=[self.OP.SIGN.MERKLE_PROOF],
                data=bytes.fromhex(rsk_tx_receipt),
                initial_bytes=bytes_requested,
                operation_name="sign",
                data_description="tx receipt"
            )

            if not response[0]:
                return (False, self.RESPONSE.SIGN.ERROR_UNEXPECTED)

            bytes_requested = response[1][self.OFF.DATA]
        except HSM2DongleErrorResult as e:
            self.logger.error("Sign returned: %s", hex(e.error_code))
            if e.error_code in [self.ERR.SIGN.STATE, self.ERR.SIGN.RLP, \
                                self.ERR.SIGN.RLP_INT, self.ERR.SIGN.RLP_DEPTH, \
                                self.ERR.SIGN.DATA_SIZE]:
                return (False, self.RESPONSE.SIGN.ERROR_TX_RECEIPT)
            return (False, self.RESPONSE.SIGN.ERROR_UNEXPECTED)

        # Step 4. Send tx receipt merkle proof
        # The format for the receipts merkle proof is as follows:
        # 1 byte for the number of nodes
        # For each node: 1 byte for the node length + the node bytes.
        try:
            if len(receipt_merkle_proof) > 255:
                raise ValueError("Too many nodes")

            merkle_proof_bytes = bytes([len(receipt_merkle_proof)])
            for node in receipt_merkle_proof:
                node_bytes = bytes.fromhex(node)
                if len(node_bytes) > 255:
                    raise ValueError("Node too big: %s" % node)
                merkle_proof_bytes = merkle_proof_bytes + bytes([len(node_bytes)]) + node_bytes
        except ValueError as e:
            self.logger.error("Sign: invalid receipts merkle proof: %s", str(e))
            return (False, self.RESPONSE.SIGN.ERROR_MERKLE_PROOF)

        try:
            response = self._send_data_in_chunks(
                command=self.CMD.SIGN,
                operation=self.OP.SIGN.MERKLE_PROOF,
                next_operations=[self.OP.SIGN.SUCCESS],
                data=merkle_proof_bytes,
                initial_bytes=bytes_requested,
                operation_name="sign",
                data_description="receipts merkle proof"
            )

            if not response[0]:
                return (False, self.RESPONSE.SIGN.ERROR_UNEXPECTED)
        except HSM2DongleErrorResult as e:
            self.logger.error("Sign returned: %s", hex(e.error_code))
            if e.error_code in [self.ERR.SIGN.DATA_SIZE, \
                                self.ERR.SIGN.STATE, \
                                self.ERR.SIGN.NODE_VERSION, \
                                self.ERR.SIGN.SHARED_PREFIX_TOO_BIG, \
                                self.ERR.SIGN.RECEIPT_HASH_MISMATCH, \
                                self.ERR.SIGN.NODE_CHAINING_MISMATCH,
                                self.ERR.SIGN.RECEIPT_ROOT_MISMATCH]:
                return (False, self.RESPONSE.SIGN.ERROR_MERKLE_PROOF)
            return (False, self.RESPONSE.SIGN.ERROR_UNEXPECTED)

        # If we get here, we should have a signature in the data part.
        # Return success along with it.
        try:
            return (True, HSM2DongleSignature(response[1][self.OFF.DATA:]))
        except Exception as e:
            self.logger.error("Error parsing signature: %s", str(e))
            return (False, self.RESPONSE.SIGN.ERROR_UNEXPECTED)

    # Ask the device to sign a specific hash without any authorization.
    # key_id: BIP32Path
    # hash: hex string
    def sign_unauthorized(self, key_id, hash):
        # *** Signing protocol ***
        # This signing method requires a single message that contains the
        # BIP32 path & hash to sign.
        #
        # An exception can be raised, which
        # would signal failure signing. Specific error codes come with HSM2DongleErrorResult
        # exception instances and are handled accordingly. Anything else
        # is treated as an unexpected error and is let for the calling layer
        # to handle.

        try:
            hash_bytes = bytes.fromhex(hash)
        except ValueError as e:
            self.logger.error("Sign: invalid hash - %s", hash)
            return (False, self.RESPONSE.SIGN.ERROR_HASH)

        # Send path and hash to sign
        try:
            key_id_bytes = key_id.to_binary()
            data = bytes([self.OP.SIGN.PATH]) + key_id_bytes + hash_bytes
            self.logger.debug("Sign: sending path and hash - %s", data.hex())
            response = self._send_command(self.CMD.SIGN, data)

            # Special case: if the device asks for a BTC transaction, then
            # there's a case of both invalid path and invalid hash. Report invalid hash
            if response[self.OFF.OP] == self.OP.SIGN.BTC_TX:
                return (False, self.RESPONSE.SIGN.ERROR_HASH)

            # We expect the device to report success signing
            # If this doesn't happen, error out
            if response[self.OFF.OP] != self.OP.SIGN.SUCCESS:
                self.logger.error("Sign: unexpected response %s", response.hex())
                return (False, self.RESPONSE.SIGN.ERROR_UNEXPECTED)
        except HSM2DongleErrorResult as e:
            self.logger.error("Sign returned: %s", hex(e.error_code))
            if e.error_code in [self.ERR.SIGN.DATA_SIZE, self.ERR.SIGN.DATA_SIZE_NOAUTH]:
                return (False, self.RESPONSE.SIGN.ERROR_HASH)
            elif e.error_code in [self.ERR.SIGN.INVALID_PATH, self.ERR.SIGN.DATA_SIZE_AUTH]:
                return (False, self.RESPONSE.SIGN.ERROR_PATH)
            return (False, self.RESPONSE.SIGN.ERROR_UNEXPECTED)

        # If we get here, we should have a signature in the data part.
        # Return success along with it.
        try:
            return (True, HSM2DongleSignature(response[self.OFF.DATA:]))
        except Exception as e:
            self.logger.error("Error parsing signature: %s", str(e))
            return (False, self.RESPONSE.SIGN.ERROR_UNEXPECTED)

    def get_blockchain_state(self):
        state = {}

        # Get hashes
        for (key, hash_cmd) in self.GST.HASH_VALUES.items():
            self.logger.info("Getting hash value for '%s'", key)
            result = self._send_command(self.CMD.GET_STATE, bytes([self.OP.GST.HASH, hash_cmd]))

            # Validate result
            if result[self.OFF.OP] != self.OP.GST.HASH or \
                result[self.OFF.DATA] != hash_cmd or \
                len(result[self.OFF.DATA+1:]) != self.HASH_SIZE:
                msg = "Invalid response for hash: %s" % result.hex()
                self.logger.error(msg)
                raise HSM2DongleError(msg)

            state[key] = result[self.OFF.DATA+1:].hex()

        # Get difficulty
        self.logger.info("Getting difficulty")
        result = self._send_command(self.CMD.GET_STATE, bytes([self.OP.GST.DIFF]))
        if result[self.OFF.OP] != self.OP.GST.DIFF:
            msg = "Invalid response for difficulty: %s" % result.hex()
            self.logger.error(msg)
            raise HSM2DongleError(msg)

        state["updating.total_difficulty"] = int.from_bytes(\
                    result[self.OFF.DATA:], byteorder="big", signed=False)

        # Get flags
        self.logger.info("Getting flags")
        result = self._send_command(self.CMD.GET_STATE, bytes([self.OP.GST.FLAGS]))
        if result[self.OFF.OP] != self.OP.GST.FLAGS or \
            len(result[self.OFF.DATA:]) != 3:
            msg = "Invalid response for flags: %s" % result.hex()
            self.logger.error(msg)
            raise HSM2DongleError(msg)

        state["updating.in_progress"] = bool(result[self.OFF.DATA + self.GST.FLAG_OFFSET.IN_PROGRESS])
        state["updating.already_validated"] = bool(result[self.OFF.DATA + self.GST.FLAG_OFFSET.ALREADY_VALIDATED])
        state["updating.found_best_block"] = bool(result[self.OFF.DATA + self.GST.FLAG_OFFSET.FOUND_BEST_BLOCK])

        return state

    def reset_advance_blockchain(self):
        self.logger.info("Resetting advance blockchain")
        result = self._send_command(self.CMD.RESET_AB, bytes([self.OP.RAV.INIT]))
        if result[self.OFF.OP] != self.OP.RAV.DONE:
            msg = "Invalid response for reset advance blockchain: %s" % result.hex()
            self.logger.error(msg)
            raise HSM2DongleError(msg)

        return True

    # Ask the device to update its blockchain references by processing
    # a given set of blocks.
    # blocks: list of hex strings
    # (each hex string is a raw block header,
    # which should *always* include merge mining fields)
    def advance_blockchain(self, blocks, version):
        # Convenient shorthands
        err = self.ERR.ADVANCE
        response = self.RESPONSE.ADVANCE
        return self._do_block_operation("advance", blocks, self.CMD.ADVANCE,
            self.OP.ADVANCE, err, response, {
                err.BUFFER_OVERFLOW: response.ERROR_INVALID_BLOCK,
                err.MERKLE_PROOF_OVERFLOW: response.ERROR_INVALID_BLOCK,
                err.CB_TXN_OVERFLOW: response.ERROR_INVALID_BLOCK,
                err.RLP_INVALID: response.ERROR_INVALID_BLOCK,
                err.BLOCK_TOO_SHORT: response.ERROR_INVALID_BLOCK,
                err.PARENT_HASH_INVALID: response.ERROR_INVALID_BLOCK,
                err.UMM_ROOT_INVALID: response.ERROR_INVALID_BLOCK,
                err.BTC_HEADER_INVALID: response.ERROR_INVALID_BLOCK,
                err.MERKLE_PROOF_INVALID: response.ERROR_INVALID_BLOCK,
                err.BLOCK_DIFF_INVALID: response.ERROR_INVALID_BLOCK,
                err.BLOCK_NUM_INVALID: response.ERROR_INVALID_BLOCK,
                err.BLOCK_TOO_OLD: response.ERROR_INVALID_BLOCK,
                err.MM_RLP_LEN_MISMATCH: response.ERROR_INVALID_BLOCK,
                err.MERKLE_PROOF_MISMATCH: response.ERROR_POW_INVALID,
                err.BTC_CB_TXN_INVALID: response.ERROR_POW_INVALID,
                err.MM_HASH_MISMATCH: response.ERROR_POW_INVALID,
                err.BTC_DIFF_MISMATCH: response.ERROR_POW_INVALID,
                err.CB_TXN_HASH_MISMATCH: response.ERROR_POW_INVALID,
                err.CHAIN_MISMATCH: response.ERROR_CHAINING_MISMATCH,
                err.TOTAL_DIFF_OVERFLOW: response.ERROR_UNSUPPORTED_CHAIN,
                err.PROT_INVALID: response.ERROR_BLOCK_DATA,
            }, version)

    # Ask the device to update its ancestor block and ancestor receipts root
    # references by processing a given set of blocks.
    # blocks: list of hex strings
    # (each hex string is a raw block header,
    # which doesn't need to include merge mining fields -
    # those will be stripped for efficiency before being sent
    # to the device anyway)
    def update_ancestor(self, blocks, version):
        # Convenient shorthands
        err = self.ERR.UPD_ANCESTOR
        response = self.RESPONSE.UPD_ANCESTOR

        # Optimization: remove merge mining fields (if present) from blocks
        try:
            self.logger.info("Removing merge mining fields from %d blocks", len(blocks))
            optimized_blocks = list(map(remove_mm_fields_if_present, blocks))
        except ValueError as e:
            self.logger.error("While removing merge mining fields: %s", str(e))
            return (False, response.ERROR_REMOVE_MM_FIELDS)

        return self._do_block_operation("updancestor",
            optimized_blocks, self.CMD.UPD_ANCESTOR,
            self.OP.UPD_ANCESTOR, err, response, {
                err.BUFFER_OVERFLOW: response.ERROR_INVALID_BLOCK,
                err.RLP_INVALID: response.ERROR_INVALID_BLOCK,
                err.BLOCK_TOO_SHORT: response.ERROR_INVALID_BLOCK,
                err.PARENT_HASH_INVALID: response.ERROR_INVALID_BLOCK,
                err.RECEIPT_ROOT_INVALID: response.ERROR_INVALID_BLOCK,
                err.BTC_HEADER_INVALID: response.ERROR_INVALID_BLOCK,
                err.BLOCK_NUM_INVALID: response.ERROR_INVALID_BLOCK,
                err.BLOCK_TOO_OLD: response.ERROR_INVALID_BLOCK,
                err.MM_RLP_LEN_MISMATCH: response.ERROR_INVALID_BLOCK,
                err.ANCESTOR_TIP_MISMATCH: response.ERROR_TIP_MISMATCH,
                err.CHAIN_MISMATCH: response.ERROR_CHAINING_MISMATCH,
                err.PROT_INVALID: response.ERROR_BLOCK_DATA,
            }, version)

    def get_ui_attestation(self, ca_pubkey_hex, ca_hash_hex, ca_signature_hex):
        # Parse hexadecimal values
        ca_pubkey = bytes.fromhex(ca_pubkey_hex)
        ca_hash = bytes.fromhex(ca_hash_hex)
        ca_signature = bytes.fromhex(ca_signature_hex)

        # Get UI hash
        ui_hash = self._send_command(self.CMD.UI_ATT, bytes([self.OP.UI_ATT.OP_APP_HASH]))[self.OFF.DATA:]

        # Send pubkey and retrieve message
        data = bytes([self.OP.UI_ATT.OP_PUBKEY]) + ca_pubkey
        message = self._send_command(self.CMD.UI_ATT, data)[3:]

        # Send hash
        data = bytes([self.OP.UI_ATT.OP_HASH]) + ca_hash
        self._send_command(self.CMD.UI_ATT, data)

        # Send signature
        data = bytes([self.OP.UI_ATT.OP_SIGNATURE, len(ca_signature)]) + ca_signature
        self._send_command(self.CMD.UI_ATT, data)

        # Retrieve attestation
        attestation = self._send_command(self.CMD.UI_ATT, bytes([self.OP.UI_ATT.OP_GET]))[self.OFF.DATA:]

        return {
            "app_hash": ui_hash.hex(),
            "message": message.hex(),
            "signature": attestation.hex(),
        }

    def get_signer_attestation(self):
        # Get signer hash
        signer_hash = self._send_command(self.CMD.SIGNER_ATT, bytes([self.OP.SIGNER_ATT.OP_APP_HASH]))[self.OFF.DATA:]

        # Retrieve attestation
        attestation = self._send_command(self.CMD.SIGNER_ATT, bytes([self.OP.SIGNER_ATT.OP_GET]))[self.OFF.DATA:]

        # Retrieve message
        message = self._send_command(self.CMD.SIGNER_ATT, bytes([self.OP.SIGNER_ATT.OP_GET_MESSAGE]))[self.OFF.DATA:]

        return {
            "app_hash": signer_hash.hex(),
            "message": message.hex(),
            "signature": attestation.hex(),
        }

    # Used both for advance blockchain and update ancestor given the protocol
    # is the same
    def _do_block_operation(self, operation_name, blocks, command, ops,
                            errors, responses, chunk_error_mapping, version):
        # *** Block operation protocol ***
        # The order in which things are required and then sent is:
        # 1. Initialization, where the total number of blocks to send is sent.
        # 2. For each block header:
        # 2.1. Block metadata (single message):
        #   - MM payload size in bytes
        #   (see the block_utils.rlp_mm_payload_size method for details on this)
        #   - (only for >=2.1.0) In case of an advance blockchain operation, coinbase transaction hash
        #   (see the block_utils.coinbase_tx_get_hash for details on this)
        # 2.2. Block chunks: block header pieces as requested by the ledger.
        #
        # During these exchanges, an exception can be raised at any moment, which
        # would signal failure. Specific error codes come with HSM2DongleErrorResult
        # exception instances and are handled accordingly. Anything else
        # is treated as an unexpected error and is let for the calling layer
        # to handle.

        # Step 1. Send initialization
        num_blocks_bytes = len(blocks).to_bytes(4, byteorder='big', signed=False)
        data = bytes([ops.INIT]) + num_blocks_bytes
        try:
            self.logger.info("%s: sending initialization - %s", operation_name.capitalize(), data.hex())
            response = self._send_command(command, data)

            # We expect the device to ask for block metadata next.
            # If this doesn't happen, error out
            if response[self.OFF.OP] != ops.HEADER_META:
                self.logger.error("%s: unexpected response %s", operation_name.capitalize(), response.hex())
                return (False, responses.ERROR_UNEXPECTED)
        except HSM2DongleErrorResult as e:
            self.logger.error("%s returned: %s", operation_name.capitalize(), hex(e.error_code))
            if e.error_code in [errors.PROT_INVALID]:
                return (False, responses.ERROR_INIT)
            return (False, responses.ERROR_UNEXPECTED)

        # Step 2. Send blocks
        total_blocks = len(blocks)
        for block_number, block in enumerate(blocks, 1):
            self.logger.info("%s: sending block #%d/%d", operation_name.capitalize(), block_number, total_blocks)

            # Step 2.1. Compute and send block metadata
            # (this will also validate that the block is a valid RLP-encoded list
            # of the proper size)
            try:
                mm_payload_size = rlp_mm_payload_size(block)
                self.logger.debug("Metadata: MM payload length %d", mm_payload_size)
                mm_payload_size_bytes = mm_payload_size.to_bytes(2, byteorder='big', signed=False)
                cb_txn_hash = bytes([])
                if command == self.CMD.ADVANCE and version >= self.MIN_VERSION_META_CBTXHASH:
                    cb_txn_hash = bytes.fromhex(coinbase_tx_get_hash(get_coinbase_txn(block)))
                    self.logger.debug("Metadata: CB txn hash: %s", cb_txn_hash.hex())
                data = bytes([ops.HEADER_META]) + mm_payload_size_bytes + cb_txn_hash
                self.logger.info("%s: sending metadata - %s", operation_name.capitalize(), data.hex())
                response = self._send_command(command, data)

                # We expect the device to ask for a block chunk next.
                # If this doesn't happen, error out
                if response[self.OFF.OP] != ops.HEADER_CHUNK:
                    self.logger.error("%s: unexpected response %s", operation_name.capitalize(), response.hex())
                    return (False, responses.ERROR_UNEXPECTED)

                # How many bytes to send as the first block chunk
                bytes_requested = response[self.OFF.DATA]
            except ValueError as e:
                self.logger.error("Computing block metadata: %s", str(e))
                return (False, responses.ERROR_COMPUTE_METADATA)
            except HSM2DongleErrorResult as e:
                self.logger.error("%s returned: %s", operation_name.capitalize(), hex(e.error_code))
                if e.error_code in [errors.PROT_INVALID]:
                    return (False, responses.ERROR_METADATA)
                return (False, responses.ERROR_UNEXPECTED)

            # Step 2.2. Send block data in chunks
            try:
                # Next possible operations depending on the specific command
                # (the advance blockchain operation has also got a "partial" success)
                next_operations = [ops.HEADER_CHUNK, ops.HEADER_META, ops.SUCCESS]
                if command == self.CMD.ADVANCE:
                    next_operations.append(ops.PARTIAL)

                response = self._send_data_in_chunks(
                    command=command,
                    operation=ops.HEADER_CHUNK,
                    next_operations=next_operations,
                    data=bytes.fromhex(block),
                    initial_bytes=bytes_requested,
                    operation_name=operation_name,
                    data_description="block"
                )

                if not response[0]:
                    return (False, responses.ERROR_UNEXPECTED)
            except HSM2DongleErrorResult as e:
                self.logger.error("%s returned: %s", operation_name.capitalize(), hex(e.error_code))
                return (False, chunk_error_mapping.get(e.error_code, responses.ERROR_UNEXPECTED))

            # Partial success?
            if command == self.CMD.ADVANCE and response[1][self.OFF.OP] == ops.PARTIAL:
                self.logger.info("%s: partial success", operation_name.capitalize())
                return (True, responses.OK_PARTIAL)

            # Success?
            if response[1][self.OFF.OP] == ops.SUCCESS:
                self.logger.info("%s: total success", operation_name.capitalize())
                return (True, responses.OK_TOTAL)

        # We shouldn't be able to ever reach this point
        msg = "%s: unexpected state" % operation_name.capitalize()
        self.logger.fatal(msg)
        raise HSM2DongleError(msg)

    # Send a specific piece of data in chunks to the device
    # as the device requests bytes from it.
    # Validate responses wrt current operation and next possible expected operations
    # Exceptions are to be handled by the caller
    def _send_data_in_chunks(self, command, operation, next_operations,
                             data, initial_bytes, operation_name, data_description):
        offset = 0
        bytes_requested = initial_bytes
        total_bytes_sent = 0
        finished = False
        while not finished:
            to_send = data[offset:offset+bytes_requested]
            to_send_length = len(to_send)
            self.logger.debug("%s: sending %s chunk [%d:%d] - %s",
                              operation_name.capitalize(), data_description,
                              offset, offset+to_send_length, to_send.hex())
            response = self._send_command(command, bytes([operation]) + to_send)

            # Increase count and buffer pointer
            total_bytes_sent += to_send_length
            offset += to_send_length

            # We expect the device to either ask for the current or for the
            # next operation.
            # If none of this happens, error out
            if  response[self.OFF.OP] not in ([operation] + next_operations):
                self.logger.debug("Current operation %s, next operations %s, ledger requesting %s", \
                                  hex(operation),
                                  str(list(map(lambda op: hex(op), next_operations))),
                                  hex(response[2]))
                self.logger.error("%s: unexpected response %s",
                                  operation_name.capitalize(), response.hex())
                return (False, response)

            # We finish when the device requests the next piece of data
            finished = response[self.OFF.OP] != operation

            # How many bytes to send in the next message
            if not finished:
                bytes_requested = response[self.OFF.DATA]
                self.logger.debug("Dongle requested %d bytes", bytes_requested)

        # All is good
        return (True, response)

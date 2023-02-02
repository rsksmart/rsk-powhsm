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

import logging
from .bip32 import BIP32Path
from .utils import is_nonempty_hex_string, is_hex_string_of_length

LOGGER_NAME = "protocol"


class HSM2ProtocolError(RuntimeError):
    pass


class HSM2ProtocolInterrupt(Exception):
    pass


class HSM2Protocol:
    # Request/Response keys
    COMMAND_KEY = "command"
    ERROR_CODE_KEY = "errorcode"
    VERSION_KEY = "version"

    # Success error codes
    ERROR_CODE_OK = 0
    ERROR_CODE_OK_PARTIAL = 1

    # Auth-related error codes
    ERROR_CODE_INVALID_AUTH = -101
    ERROR_CODE_INVALID_MESSAGE = -102
    ERROR_CODE_INVALID_KEYID = -103

    # Blockchain bookkeeping error codes
    ERROR_CODE_CHAINING_MISMATCH = -201
    ERROR_CODE_POW_INVALID = -202
    ERROR_CODE_TIP_MISMATCH = -203
    ERROR_CODE_INVALID_INPUT_BLOCKS = -204
    ERROR_CODE_INVALID_BROTHERS = -205

    # Heartbeat error codes
    ERROR_CODE_INVALID_HEARTBEAT_UD_VALUE = -301

    # Generic error codes
    ERROR_CODE_FORMAT_ERROR = -901
    ERROR_CODE_INVALID_REQUEST = -902
    ERROR_CODE_COMMAND_UNKNOWN = -903
    ERROR_CODE_WRONG_VERSION = -904
    ERROR_CODE_DEVICE = -905
    ERROR_CODE_UNKNOWN = -906

    # Protocol version
    VERSION = 4

    # Commands
    VERSION_COMMAND = "version"
    SIGN_COMMAND = "sign"
    GETPUBKEY_COMMAND = "getPubKey"
    ADVANCE_BLOCKCHAIN_COMMAND = "advanceBlockchain"
    RESET_ADVANCE_BLOCKCHAIN_COMMAND = "resetAdvanceBlockchain"
    BLOCKCHAIN_STATE_COMMAND = "blockchainState"
    UPDATE_ANCESTOR_BLOCK_COMMAND = "updateAncestorBlock"
    GET_BLOCKCHAIN_PARAMETERS = "blockchainParameters"
    SIGNER_HEARTBEAT = "signerHeartbeat"
    UI_HEARTBEAT = "uiHeartbeat"

    # Minimum number of blocks to update the ancestor block
    MINIMUM_UPDATE_ANCESTOR_BLOCKS = 1

    # Signer and UI heartbeat user-defined value sizes
    SIGNER_HBT_UD_VALUE_SIZE = 16  # bytes
    UI_HBT_UD_VALUE_SIZE = 32  # bytes

    def __init__(self):
        self.logger = logging.getLogger(LOGGER_NAME)
        self._init_mappings()

    def handle_request(self, request):
        self.logger.info("In %s", request)
        response = self.__internal_handle_request(request)
        self.logger.info("Out %s", response)
        return response

    def __internal_handle_request(self, request):
        if type(request) != dict:
            return self.format_error()

        if self.COMMAND_KEY not in request:
            return self._invalid_request()

        if (
            request[self.COMMAND_KEY] != self.VERSION_COMMAND
            and self.VERSION_KEY not in request
        ):
            return self._invalid_request()

        if self.VERSION_KEY in request and request[self.VERSION_KEY] != self.VERSION:
            return self._wrong_version()

        command = request[self.COMMAND_KEY]
        self.logger.debug("Cmd: %s", command)
        if command not in self._known_commands:
            return self._command_unknown()

        # Perform generic input validation
        validation_result = self._validation_mappings[command](request)
        if validation_result < 0:
            return {self.ERROR_CODE_KEY: validation_result}

        # Operations MUST return a tuple with TWO elements.
        # First element MUST be an integer representing the outcome of the operation.
        # Second element MUST be a dictionary with the result (if the operation is
        # successful)
        # or None if the operation failed.
        # In the first element, a nonnegative integer indicates success, and then
        # the result is the second
        # element of the tuple with added protocol overhead.
        # A negative integer indicates failure.

        operation_result = self._mappings[command](request)
        result = operation_result[0]
        if result < 0:
            return {self.ERROR_CODE_KEY: result}

        output = operation_result[1]
        output[self.ERROR_CODE_KEY] = result
        return output

    def initialize_device(self):
        self._not_implemented("initialize_device")

    def device_error(self):
        self.logger.debug("Generic error")
        return {self.ERROR_CODE_KEY: self.ERROR_CODE_DEVICE}

    def unknown_error(self):
        self.logger.debug("Generic error")
        return {self.ERROR_CODE_KEY: self.ERROR_CODE_UNKNOWN}

    def format_error(self):
        self.logger.debug("Format error")
        return {self.ERROR_CODE_KEY: self.ERROR_CODE_FORMAT_ERROR}

    def _invalid_request(self):
        self.logger.debug("Invalid request")
        return {self.ERROR_CODE_KEY: self.ERROR_CODE_INVALID_REQUEST}

    def _wrong_version(self):
        self.logger.debug("Invalid version")
        return {self.ERROR_CODE_KEY: self.ERROR_CODE_WRONG_VERSION}

    def _command_unknown(self):
        self.logger.debug("Command unknown")
        return {self.ERROR_CODE_KEY: self.ERROR_CODE_COMMAND_UNKNOWN}

    def _version(self, request):
        return (0, {self.VERSION_KEY: self.VERSION})

    def _validate_advance_blockchain(self, request):
        # Validate blocks presence, type and minimum length
        if (
            "blocks" not in request
            or type(request["blocks"]) != list
            or len(request["blocks"]) == 0
        ):
            self.logger.info("Blocks field not present, not an array or empty")
            return self.ERROR_CODE_INVALID_INPUT_BLOCKS

        # Validate blocks elements are strings
        if not all(type(item) == str for item in request["blocks"]):
            self.logger.info("Some of the blocks elements are not strings")
            return self.ERROR_CODE_INVALID_INPUT_BLOCKS

        # Validate brothers presence, type and length
        if (
            "brothers" not in request
            or type(request["brothers"]) != list
            or len(request["brothers"]) != len(request["blocks"])
        ):
            self.logger.info("Brothers field not present, not an array or "
                             "different in length to Blocks field")
            return self.ERROR_CODE_INVALID_BROTHERS

        # Validate brother elements are lists of strings
        if not all(type(item) == list for item in request["brothers"]) or \
           not all(type(item) == str for brother_list in request["brothers"]
                   for item in brother_list):
            self.logger.info("Some of the brother list elements are not strings")
            return self.ERROR_CODE_INVALID_BROTHERS

        return self.ERROR_CODE_OK

    def _advance_blockchain(self, request):
        self._not_implemented(self.ADVANCE_BLOCKCHAIN_COMMAND)

    def _reset_advance_blockchain(self, request):
        self._not_implemented(self.RESET_ADVANCE_BLOCKCHAIN_COMMAND)

    def _blockchain_state(self, request):
        self._not_implemented(self.BLOCKCHAIN_STATE_COMMAND)

    def _validate_update_ancestor_block(self, request):
        # Validate blocks presence, type and minimum length
        if (
            "blocks" not in request
            or type(request["blocks"]) != list
            or len(request["blocks"]) < self.MINIMUM_UPDATE_ANCESTOR_BLOCKS
        ):
            self.logger.info(
                "Blocks field not present, not an array or shorter than the minimum "
                "(%d blocks)" % self.MINIMUM_UPDATE_ANCESTOR_BLOCKS
            )
            return self.ERROR_CODE_INVALID_INPUT_BLOCKS

        # Validate blocks elements are strings
        if not all(type(item) == str for item in request["blocks"]):
            self.logger.info("Some of the blocks elements are not strings")
            return self.ERROR_CODE_INVALID_INPUT_BLOCKS

        return self.ERROR_CODE_OK

    def _update_ancestor_block(self, request):
        self._not_implemented(self.UPDATE_ANCESTOR_BLOCK_COMMAND)

    def _validate_key_id(self, request):
        # The keyId field must be present
        if "keyId" not in request or type(request["keyId"]) != str:
            self.logger.info("Key ID field not present")
            return self.ERROR_CODE_INVALID_KEYID

        try:
            # This overrides the "keyId" within the request itself, which
            # might not be the best idea. Nevertheless, the only possible
            # thing to do with this key id (which should be a BIP32 path every time)
            # is validate it and then use it as a BIP32Path. The original string
            # won't be needed and can always be retrieved using the BIP32Path
            # instance.
            request["keyId"] = BIP32Path(request["keyId"])
        except ValueError as e:
            self.logger.info("Invalid Key ID: %s", str(e))
            return self.ERROR_CODE_INVALID_KEYID

        return self.ERROR_CODE_OK

    def _validate_auth(self, request, mandatory):
        # The authorization field must either:
        # - Not be present if mandatory == False
        # - Be a dictionary with all the required fields
        if "auth" not in request:
            return self.ERROR_CODE_OK if not mandatory else self.ERROR_CODE_INVALID_AUTH

        auth = request["auth"]

        # Validate auth field is present and a dictionary (object)
        if type(auth) != dict:
            self.logger.info("Authorization field not an object")
            return self.ERROR_CODE_INVALID_AUTH

        # Validate receipt presence and type
        if (
            "receipt" not in auth
            or type(auth["receipt"]) != str
            or not is_nonempty_hex_string(auth["receipt"])
        ):
            self.logger.info(
                "Transaction receipt field not present or not a nonempty hex string"
            )
            return self.ERROR_CODE_INVALID_AUTH

        # Validate receipt merkle proof inclusion presence, type and minimum length
        if (
            "receipt_merkle_proof" not in auth
            or type(auth["receipt_merkle_proof"]) != list
            or len(auth["receipt_merkle_proof"]) == 0
        ):
            self.logger.info(
                "Receipt merkle proof field not present or not a nonempty array"
            )
            return self.ERROR_CODE_INVALID_AUTH

        # Validate merkle proof elements are nonempty hex strings
        if not all(
            type(item) == str and is_nonempty_hex_string(item)
            for item in auth["receipt_merkle_proof"]
        ):
            self.logger.info(
                "Some of the receipt merkle proof elements are not nonempty hex strings"
            )
            return self.ERROR_CODE_INVALID_AUTH

        return self.ERROR_CODE_OK

    def _validate_message(self, request, what):
        # Message field must always be present and a dictionary
        # Also, it must:
        # - Contain exactly a "hash" element of type string (1) that must be a 32-byte hex
        #   (what is "any" or "hash")
        # - Contain exactly a "tx" element of type string that is a hex string and
        #   an "input" element of type int (2)
        #   (what is "any" or "tx")

        # Validate message presence and components
        if "message" not in request or type(request["message"]) != dict:
            self.logger.info("Message field not present or not an object")
            return self.ERROR_CODE_INVALID_MESSAGE

        message = request["message"]

        # (1)?
        if (
            what in ["any", "hash"]
            and len(message) == 1
            and "hash" in message
            and type(message["hash"]) == str
            and is_hex_string_of_length(message["hash"], 32)
        ):
            return self.ERROR_CODE_OK

        # (2)?
        if (
            what in ["any", "tx"]
            and len(message) == 2
            and "tx" in message
            and "input" in message
            and type(message["tx"]) == str
            and is_nonempty_hex_string(message["tx"])
            and type(message["input"]) == int
        ):
            return self.ERROR_CODE_OK

        self.logger.info("Message field for expected message of type '%s' invalid", what)
        return self.ERROR_CODE_INVALID_MESSAGE

    def _validate_get_pubkey(self, request):
        # Validate key id
        # SIDE EFFECT: request["keyId"] is turned into a comm.bip32.BIP32Path instance
        keyid_validation = self._validate_key_id(request)
        if keyid_validation < self.ERROR_CODE_OK:
            return keyid_validation

        return self.ERROR_CODE_OK

    # In concrete classes, this should implement the "getPubKey" operation
    # The parameters of the operation are within the "request" dictionary:
    # keyId: a BIP32Path instance
    def _get_pubkey(self, request):
        self._not_implemented(self.GETPUBKEY_COMMAND)

    def _validate_sign(self, request):
        # Validate key id
        # SIDE EFFECT: request["keyId"] is turned into a comm.bip32.BIP32Path instance
        keyid_validation = self._validate_key_id(request)
        if keyid_validation < self.ERROR_CODE_OK:
            return keyid_validation

        # Validate auth fields
        auth_validation = self._validate_auth(request, mandatory=False)
        if auth_validation < self.ERROR_CODE_OK:
            return auth_validation

        # Validate message fields
        message_validation = self._validate_message(request, what="any")
        if message_validation < self.ERROR_CODE_OK:
            return message_validation

        return self.ERROR_CODE_OK

    # In concrete classes, this should implement the "sign" operation
    # The parameters of the operation are within the "request" dictionary:
    # keyId: a BIP32Path instance
    # message: an object that can contain "tx" (str), "input" (int) or "hash" (str)
    #          objects within.
    # auth: an object that can contain "receipt" and "receipt_merkle_proof"
    #          (all str) objects within.
    def _sign(self, request):
        self._not_implemented(self.SIGN_COMMAND)

    def _get_blockchain_parameters(self, request):
        self._not_implemented(self.GET_BLOCKCHAIN_PARAMETERS)

    def _validate_signer_heartbeat(self, request):
        # Validate UD value presence, type and length
        if (
            "udValue" not in request
            or type(request["udValue"]) != str
            or not(is_hex_string_of_length(request["udValue"],
                                           self.SIGNER_HBT_UD_VALUE_SIZE))
        ):
            self.logger.info(
                "User defined value field not present or not a "
                f"{self.SIGNER_HBT_UD_VALUE_SIZE}-byte hex string"
            )
            return self.ERROR_CODE_INVALID_HEARTBEAT_UD_VALUE

        return self.ERROR_CODE_OK

    def _signer_heartbeat(self, request):
        self._not_implemented(self.SIGNER_HEARTBEAT)

    def _validate_ui_heartbeat(self, request):
        # Validate UD value presence, type and length
        if (
            "udValue" not in request
            or type(request["udValue"]) != str
            or not(is_hex_string_of_length(request["udValue"], self.UI_HBT_UD_VALUE_SIZE))
        ):
            self.logger.info(
                "User defined value field not present or not a "
                f"{self.UI_HBT_UD_VALUE_SIZE}-byte hex string"
            )
            return self.ERROR_CODE_INVALID_HEARTBEAT_UD_VALUE

        return self.ERROR_CODE_OK

    def _ui_heartbeat(self, request):
        self._not_implemented(self.UI_HEARTBEAT)

    def _not_implemented(self, funcname):
        self.logger.warning("%s not implemented", funcname)
        raise NotImplementedError(funcname)

    def _init_mappings(self):
        self.logger.debug("Initializing mappings")
        self._mappings = {
            self.VERSION_COMMAND: self._version,
            self.SIGN_COMMAND: self._sign,
            self.GETPUBKEY_COMMAND: self._get_pubkey,
            self.ADVANCE_BLOCKCHAIN_COMMAND: self._advance_blockchain,
            self.RESET_ADVANCE_BLOCKCHAIN_COMMAND: self._reset_advance_blockchain,
            self.BLOCKCHAIN_STATE_COMMAND: self._blockchain_state,
            self.UPDATE_ANCESTOR_BLOCK_COMMAND: self._update_ancestor_block,
            self.GET_BLOCKCHAIN_PARAMETERS: self._get_blockchain_parameters,
            self.SIGNER_HEARTBEAT: self._signer_heartbeat,
            self.UI_HEARTBEAT: self._ui_heartbeat,
        }

        # Command input validations
        self._validation_mappings = {
            self.VERSION_COMMAND: lambda r: 0,
            self.SIGN_COMMAND: self._validate_sign,
            self.GETPUBKEY_COMMAND: self._validate_get_pubkey,
            self.ADVANCE_BLOCKCHAIN_COMMAND: self._validate_advance_blockchain,
            self.RESET_ADVANCE_BLOCKCHAIN_COMMAND: lambda r: 0,
            self.BLOCKCHAIN_STATE_COMMAND: lambda r: 0,
            self.UPDATE_ANCESTOR_BLOCK_COMMAND: self._validate_update_ancestor_block,
            self.GET_BLOCKCHAIN_PARAMETERS: lambda r: 0,
            self.SIGNER_HEARTBEAT: self._validate_signer_heartbeat,
            self.UI_HEARTBEAT: self._validate_ui_heartbeat,
        }
        self._known_commands = self._mappings.keys()

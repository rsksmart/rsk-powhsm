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

from .protocol import HSM2Protocol
from .utils import is_hex_string_of_length


class HSM1Protocol(HSM2Protocol):
    # Auth-related error codes
    ERROR_CODE_INVALID_AUTH = -2
    ERROR_CODE_INVALID_MESSAGE = -2
    ERROR_CODE_INVALID_KEYID = -2

    # Generic error codes (taken from the original v1 server)
    ERROR_CODE_FORMAT_ERROR = -2
    ERROR_CODE_INVALID_REQUEST = -2
    ERROR_CODE_COMMAND_UNKNOWN = -2
    ERROR_CODE_WRONG_VERSION = -666
    ERROR_CODE_DEVICE = -2
    ERROR_CODE_UNKNOWN = -2

    # Protocol version
    VERSION = 1

    def __init__(self):
        super().__init__()

    def _validate_sign(self, request):
        # Validate key id
        # SIDE EFFECT: request["keyId"] is turned into a comm.bip32.BIP32Path instance
        keyid_validation = self._validate_key_id(request)
        if keyid_validation < self.ERROR_CODE_OK:
            return keyid_validation

        # Validate message field
        # It must always be present and a string that must be a 32-byte hex
        if (
            "message" not in request
            or type(request["message"]) != str
            or not is_hex_string_of_length(request["message"], 32)
        ):
            self.logger.info(
                "Message field not present, not a string or not a 32-byte hex"
            )
            return self.ERROR_CODE_INVALID_MESSAGE

        return self.ERROR_CODE_OK

    def _init_mappings(self):
        self.logger.debug("Initializing mappings")
        self._mappings = {
            self.VERSION_COMMAND: self._version,
            self.SIGN_COMMAND: self._sign,
            self.GETPUBKEY_COMMAND: self._get_pubkey,
        }

        # Command input validations
        self._validation_mappings = {
            self.VERSION_COMMAND: lambda r: 0,
            self.SIGN_COMMAND: self._validate_sign,
            self.GETPUBKEY_COMMAND: self._validate_get_pubkey,
        }
        self._known_commands = self._mappings.keys()

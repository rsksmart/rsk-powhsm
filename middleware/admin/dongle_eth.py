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

import ecdsa
import struct

from enum import IntEnum
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException


class _ErrorCode(IntEnum):
    WRONG_APP = 0x6511
    INVALID_PATH = 0x6a15
    DONGLE_LOCKED = 0x6b0c


class DongleEthError(RuntimeError):
    ERR = _ErrorCode

    ERROR_MESSAGES = {
        ERR.WRONG_APP: "Ethereum app not open",
        ERR.INVALID_PATH: "Invalid path for Ethereum app",
        ERR.DONGLE_LOCKED: "Device locked"
    }

    @staticmethod
    def from_error_code(code):
        message = DongleEthError.ERROR_MESSAGES.get(code, "Unknown error")
        return DongleEthError("Error sending command: %s" % message)


# Dongle commands
class _Command(IntEnum):
    GET_PUBLIC_ADDRESS = 0x02,
    SIGN_PERSONAL_MSG = 0x08


class _Offset(IntEnum):
    PUBKEY = 1
    SIG_R = 1
    SIG_S = 33
    SIG_S_END = 65


# Handles low-level communication with an ledger device running Ethereum App
class DongleEth:
    # APDU prefix
    CLA = 0xE0

    # Enumeration shorthands
    CMD = _Command
    OFF = _Offset

    # Maximum size of msg allowed by sign command
    MAX_MSG_LEN = 255

    def __init__(self, debug):
        self.debug = debug

    # Connect to the dongle
    def connect(self):
        try:
            self.dongle = getDongle(self.debug)
        except CommException as e:
            msg = "Error connecting: %s" % e.message
            raise DongleEthError(msg)

    # Disconnect from dongle
    def disconnect(self):
        try:
            if self.dongle and self.dongle.opened:
                self.dongle.close()
        except CommException as e:
            msg = "Error disconnecting: %s" % e.message
            raise DongleEthError(msg)

    def get_pubkey(self, path):
        # Skip length byte
        dongle_path = path.to_binary("big")[1:]
        result = self._send_command(self.CMD.GET_PUBLIC_ADDRESS,
                                    bytes([0x00, 0x00, len(dongle_path) + 1,
                                           len(path.elements)]) + dongle_path)
        pubkey = result[self.OFF.PUBKEY:self.OFF.PUBKEY + result[0]]
        return bytes(pubkey)

    def sign(self, path, msg):
        if len(msg) > self.MAX_MSG_LEN:
            raise DongleEthError("Message greater than maximum supported size of "
                                 f"{self.MAX_MSG_LEN} bytes")

        # Skip length byte
        dongle_path = path.to_binary("big")[1:]
        encoded_tx = struct.pack(">I", len(msg)) + msg
        result = self._send_command(self.CMD.SIGN_PERSONAL_MSG,
                                    bytes([0x00, 0x00,
                                           len(dongle_path) + 1 + len(encoded_tx),
                                           len(path.elements)])
                                    + dongle_path + encoded_tx)

        r = result[self.OFF.SIG_R:self.OFF.SIG_S].hex()
        s = result[self.OFF.SIG_S:self.OFF.SIG_S_END].hex()

        return ecdsa.util.sigencode_der(int(r, 16), int(s, 16), 0)

    def _send_command(self, cmd, data):
        try:
            apdu = bytes([self.CLA, cmd]) + data
            return self.dongle.exchange(apdu)
        except CommException as e:
            raise DongleEthError.from_error_code(e.sw)
        except BaseException as e:
            raise DongleEthError("Error sending command: %s" % str(e))

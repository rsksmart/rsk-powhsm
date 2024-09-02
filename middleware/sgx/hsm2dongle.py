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

from enum import IntEnum
from ledger.hsm2dongle_tcp import HSM2DongleTCP


class SgxCommand(IntEnum):
    SGX_UNLOCK = 0xA3,
    SGX_ECHO = 0xA4,


class HSM2DongleSGX(HSM2DongleTCP):
    # Echo message
    def echo(self):
        message = bytes([0x41, 0x42, 0x43])
        result = bytes(self._send_command(SgxCommand.SGX_ECHO, message))
        # Result should be the command plus the message
        expected_result = bytes([self.CLA, SgxCommand.SGX_ECHO]) + message
        return result == expected_result

    # Unlock the device with the given pin
    def unlock(self, pin):
        response = self._send_command(SgxCommand.SGX_UNLOCK, bytes([0]) + pin)

        # Nonzero indicates device unlocked
        return response[2] != 0

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

from .case import TestCase, TestCaseError
from misc.tcpsigner_admin import TcpSignerAdmin
import output


class NvmStats(TestCase):
    @classmethod
    def op_name(cls):
        return "nvmStats"

    def __init__(self, spec):
        self.subop = spec["subop"]
        if self.subop not in self._subops.keys():
            raise TestCaseError(f"Invalid NVM stats sub operation: {self.subop}")

        super().__init__(spec)

    def run(self, dongle, debug, run_args):
        try:
            self._subops[self.subop](self, dongle, debug, run_args)
        except RuntimeError as e:
            raise TestCaseError(str(e))

    def _doReset(self, dongle, debug, run_args):
        dongle.dongle.exchange(
            bytes([TcpSignerAdmin.CLA,
                   TcpSignerAdmin.CMD_RESET_NVM,
                   TcpSignerAdmin.OP_NONE]))

    def _doPrint(self, dongle, debug, run_args):
        result = dongle.dongle.exchange(
            bytes([TcpSignerAdmin.CLA,
                   TcpSignerAdmin.CMD_GET_NVM,
                   TcpSignerAdmin.OP_NONE]))

        # We're expecting a single unsigned BE value at the data position prepended
        # by its length in bytes.
        # That corresponds to the total number of NVM writes
        doff = TcpSignerAdmin.APDU_OFFSET_DATA
        if len(result) <= doff:
            raise TestCaseError(f"Invalid NVM stats returned from dongle: {result.hex()}")

        nvm_writes_length = result[doff]
        if nvm_writes_length < 1 or \
           nvm_writes_length > (len(result)-doff+1):
            raise TestCaseError(f"Invalid NVM stats returned from dongle: {result.hex()}")

        nvm_writes = int.from_bytes(
            result[doff+1:doff+1+nvm_writes_length],
            byteorder="big",
            signed=False)

        output.info("\n********************************\n")
        output.info(f"Total NVM writes: {nvm_writes}\n")
        output.info("********************************\n")

    _subops = {
        "reset": _doReset,
        "print": _doPrint,
    }

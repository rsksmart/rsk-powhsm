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
from ledgerblue.comm import CommException


class AdminIsOnboarded(TestCase):
    VALUE_FALSE = 0
    VALUE_TRUE = 1

    @classmethod
    def op_name(cls):
        return "adminIsOnboarded"

    def __init__(self, spec):
        self.value = spec["value"]
        if self.value is not None and type(self.value) != bool:
            raise TestCaseError(f"Invalid admin is onboarded value: {self.value}")

        super().__init__(spec)

    def run(self, dongle, debug, run_args):
        try:
            dongle.dongle.exchange(
                bytes([TcpSignerAdmin.CLA,
                       TcpSignerAdmin.CMD_SET_IS_ONBOARDED,
                       TcpSignerAdmin.OP_NONE,
                       self.VALUE_TRUE if self.value else self.VALUE_FALSE]))

            # Verify it has been set correctly
            result = dongle.dongle.exchange(
                bytes([TcpSignerAdmin.CLA,
                       TcpSignerAdmin.CMD_GET_IS_ONBOARDED,
                       TcpSignerAdmin.OP_NONE]))

            # We're expecting a single byte output at the data offset
            doff = TcpSignerAdmin.APDU_OFFSET_DATA
            if len(result) <= doff:
                raise TestCaseError("Invalid admin is onboarded returned "
                                    f"from dongle: {result.hex()}")

            result_value = result[doff] != self.VALUE_FALSE
            if result_value != self.value:
                raise TestCaseError("Failed to set admin is onboarded value. Expected "
                                    f"{self.value} but got {result} ({result_value})")
        except (RuntimeError, CommException) as e:
            if type(self.expected) == int:
                if type(e) == CommException:
                    error_code = e.sw
                    error_code_desc = hex(error_code)
                else:
                    error_code = None
                    error_code_desc = "no error"

                if self.expected != error_code:
                    raise TestCaseError("Expected error code "
                                        f"{self.expected_desc} but got {error_code_desc}")
            else:
                raise TestCaseError(str(e))

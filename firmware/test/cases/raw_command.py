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
from ledgerblue.comm import CommException
from comm.utils import is_nonempty_hex_string


class RawCommand(TestCase):
    VALUE_FALSE = 0
    VALUE_TRUE = 1

    @classmethod
    def op_name(cls):
        return "rawCommand"

    def __init__(self, spec):
        if not is_nonempty_hex_string(spec.get("command")) and spec.get("command") != "":
            raise TestCaseError(f"Invalid raw command: {spec.get("command")}")
        self.command = bytes.fromhex(spec.get("command"))

        # Override default constructor behavior for expectation
        self.expected = spec.get("expected")
        spec["expected"] = True

        super().__init__(spec)

        # Normal result expectation
        if not is_nonempty_hex_string(self.expected):
            self.expected = None
        else:
            self.expected = bytes.fromhex(self.expected)

        # Exception expectation
        self.exception = spec.get("exception")
        if self.exception is not None:
            self.exception_desc = self.exception
            self.exception = self._parse_int(self.exception)

    def run(self, dongle, debug, run_args):
        try:
            result = dongle.dongle.exchange(self.command)
            if self.expected is not None and self.expected != result:
                raise TestCaseError("Unexpected raw command result: "
                                    f"expected {self.expected.hex()} but got "
                                    f"{result.hex()}")
            if self.exception is not None:
                raise TestCaseError(f"Expected command to raise an {self.exception_desc} "
                                    f"exception but got 0x{result.hex()} as "
                                    "result instead")
        except TestCaseError as e:
            raise e
        except (RuntimeError, CommException) as e:
            if self.exception is not None:
                if type(e) == CommException:
                    error_code = e.sw
                    error_code_desc = hex(error_code)
                else:
                    error_code = None
                    error_code_desc = "no error"

                if self.exception != error_code:
                    raise TestCaseError("Expected error code {self.exception_desc} "
                                        f"but got {error_code_desc}")
            else:
                raise TestCaseError(str(e))

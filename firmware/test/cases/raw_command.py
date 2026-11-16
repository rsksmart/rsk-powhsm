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
        super().__init__(spec)

        self.commands = spec.get("command")
        if type(self.commands) == str:
            self.commands = [self.commands]

        if type(self.commands) == list and \
           all(map(lambda c: is_nonempty_hex_string(c) or c == "", self.commands)):
            self.commands = list(map(lambda c: bytes.fromhex(c), self.commands))
        else:
            raise TestCaseError(f"Invalid raw command: {spec.get("command")}")

    def run(self, dongle, debug, run_args):
        try:
            for command in self.commands:
                dongle.dongle.exchange(command)

            if self.expected is not True:
                raise TestCaseError(f"Expected error code {self.expected_desc} "
                                    "but got a successful response")
        except TestCaseError as e:
            raise e
        except CommException as e:
            error_code = e.sw
            error_code_desc = hex(error_code)

            if self.expected is True:
                raise TestCaseError("Expected a successful response but got "
                                    f"error code {error_code_desc}")

            if self.expected != error_code:
                raise TestCaseError(f"Expected error code {self.expected_desc} "
                                    f"but got {error_code_desc}")

            # All good, expected error code
        except RuntimeError as e:
            raise TestCaseError(str(e))

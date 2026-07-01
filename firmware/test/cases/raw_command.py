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

    def _parse_cmds(self, commands, optional=True):
        if optional and commands is None:
            return None

        if type(commands) == str:
            return [bytes.fromhex(commands)]

        if type(commands) == list and \
           all(map(lambda c: is_nonempty_hex_string(c) or c == "", commands)):
            return list(map(bytes.fromhex, commands))

        raise TestCaseError(f"Invalid raw commands: {commands}")

    def _run_cmds_ignore_errors(self, dongle, commands):
        if commands is not None:
            for command in commands:
                try:
                    dongle.dongle.exchange(command)
                except CommException:
                    pass

    def __init__(self, spec):
        super().__init__(spec)

        self.commands = self._parse_cmds(spec.get("command"), optional=False)
        self.setup = self._parse_cmds(spec.get("setup"), optional=True)
        self.teardown = self._parse_cmds(spec.get("teardown"), optional=True)

    def run(self, dongle, debug, run_args):
        try:
            self._run_cmds_ignore_errors(dongle, self.setup)

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
        finally:
            self._run_cmds_ignore_errors(dongle, self.teardown)

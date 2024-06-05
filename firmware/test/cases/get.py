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


class GetBlockchainState(TestCase):
    @classmethod
    def op_name(cls):
        return "getState"

    def __init__(self, spec):
        super().__init__(spec)

    def run(self, dongle, debug, run_args):
        try:
            state = dongle.get_blockchain_state()
            debug(f"State: {state}")
            # Expectations on the retrieved state (optional)
            if type(self.expected) == dict:
                for key in self.expected:
                    if state.get(key) != self.expected[key]:
                        raise TestCaseError(f"Expected {key} to be {self.expected[key]} "
                                            f"but got {state.get(key)}")
        except RuntimeError as e:
            if type(self.expected) == int:
                if dongle.last_comm_exception is not None:
                    error_code = dongle.last_comm_exception.sw
                    error_code_desc = hex(error_code)
                else:
                    error_code = None
                    error_code_desc = "no error"

                if self.expected != error_code:
                    raise TestCaseError("Expected error code "
                                        f"{self.expected_desc} but got {error_code_desc}")
            else:
                raise TestCaseError(str(e))

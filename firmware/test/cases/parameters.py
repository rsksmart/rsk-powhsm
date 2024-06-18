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


class GetBlockchainParameters(TestCase):
    @classmethod
    def op_name(cls):
        return "blockchainParameters"

    def __init__(self, spec):
        super().__init__(spec)

    def run(self, dongle, debug, run_args):
        try:
            params = dongle.get_signer_parameters()
            debug(f"Parameters: {params}")
            self.params = {}
            self.params["checkpoint"] = params.checkpoint
            self.params["minimum_difficulty"] = params.min_required_difficulty
            self.params["network"] = params.network.name.lower()

            # Accept "minimum_difficulty" param as int or str
            key = "minimum_difficulty"
            if type(self.expected[key]) == str:
                self.expected[key] = self._parse_int(self.expected[key])

            for key in ["checkpoint", "minimum_difficulty", "network"]:
                if self.params[key] != self.expected[key]:
                    raise TestCaseError(f"Expected {key} to be {self.expected[key]} "
                                        f"but got {self.params[key]}")

        except RuntimeError as e:
            raise TestCaseError(str(e))

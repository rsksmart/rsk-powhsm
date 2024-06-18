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


class UpdateAncestor(TestCase):
    @classmethod
    def op_name(cls):
        return "updateAncestor"

    def __init__(self, spec):
        self.blocks = spec["blocks"]
        self.chunk_size = spec.get("chunkSize", len(self.blocks))

        super().__init__(spec)

    def run(self, dongle, debug, run_args):
        try:
            debug(f"About to send {len(self.blocks)} blocks")
            offset = 0
            while offset < len(self.blocks):
                chunk = self.blocks[offset:offset + self.chunk_size]

                debug(f"Sending blocks {offset} to {offset+len(chunk)-1} "
                      f"({len(chunk)} blocks)...")
                result = dongle.update_ancestor(chunk)
                debug(f"Dongle replied with {result}")

                offset += self.chunk_size

                if dongle.last_comm_exception is not None:
                    error_code = dongle.last_comm_exception.sw
                    error_code_desc = hex(error_code)
                else:
                    error_code = result[1]
                    error_code_desc = error_code

                if self.expected is True:
                    if not result[0]:
                        raise TestCaseError("Expected success but got failure with "
                                            f"code {error_code_desc}")
                    elif error_code != dongle.RESPONSE.UPD_ANCESTOR.OK_TOTAL:
                        raise TestCaseError(
                            f"Expected {dongle.RESPONSE.UPD_ANCESTOR.OK_TOTAL} (success) "
                            f"but got {error_code_desc}")
                else:
                    if result[0]:
                        raise TestCaseError("Expected failure but got success with "
                                            f"code {error_code_desc}")
                    elif error_code != self.expected:
                        raise TestCaseError("Expected failure with code "
                                            f"{self.expected_desc} but got failure "
                                            f"with code {error_code_desc}")

        except RuntimeError as e:
            raise TestCaseError(str(e))

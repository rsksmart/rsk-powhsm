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
import ledger.hsm2dongle


class AdvanceBlockchain(TestCase):
    @classmethod
    def op_name(cls):
        return "advanceBlockchain"

    def __init__(self, spec):
        self.blocks = spec["blocks"]
        self.brothers = spec["brothers"]
        self.chunk_size = spec.get("chunkSize", len(self.blocks))
        self.partial = spec.get("partial", False)
        self.reset_before = spec.get("resetBefore", False)
        self.skip_brother_sorting = spec.get("skipBrotherSorting", False)

        # listLength applies to all blocks
        # (will usually be used to test a single block that fails to validate)
        self.list_length = spec.get("listLength", None)
        if self.list_length:
            if self.list_length.startswith("0x"):
                self.list_length = self.list_length[2:]
            self.list_length = bytes.fromhex(self.list_length)

        super().__init__(spec)

    def _change_rlp_list_length(self, block_hex):
        bs = bytes.fromhex(block_hex)
        bs = bs[:1] + self.list_length + bs[len(self.list_length) + 1:]
        return bs.hex()

    def run(self, dongle, debug, run_args):
        try:
            if self.reset_before:
                debug("Resetting advance blockchain before starting")
                dongle.reset_advance_blockchain()

            debug(f"About to send {len(self.blocks)} blocks")
            offset = 0
            while offset < len(self.blocks):
                blocks_chunk = self.blocks[offset:offset + self.chunk_size]
                brothers_chunk = self.brothers[offset:offset + self.chunk_size]

                if self.list_length:
                    # Mock RLP payload size and coinbase tx getters
                    old_rlp_mm_payload_size = ledger.hsm2dongle.rlp_mm_payload_size
                    first_block_rlp_mm_payload_size = old_rlp_mm_payload_size(
                        blocks_chunk[0])
                    ledger.hsm2dongle.rlp_mm_payload_size = (
                        lambda h: first_block_rlp_mm_payload_size)
                    old_get_coinbase_txn = ledger.hsm2dongle.get_coinbase_txn
                    first_block_coinbase_txn = old_get_coinbase_txn(blocks_chunk[0])
                    ledger.hsm2dongle.get_coinbase_txn = (
                        lambda h: first_block_coinbase_txn)
                    # Change list lengths
                    blocks_chunk = list(map(self._change_rlp_list_length, blocks_chunk))

                if self.skip_brother_sorting:
                    # Mock block hash getter so that it returns the same
                    # for any block - sorting is skipped
                    old_get_block_hash = ledger.hsm2dongle.get_block_hash
                    ledger.hsm2dongle.get_block_hash = lambda h: "00"

                debug(f"Sending blocks {offset} to {offset + len(blocks_chunk) - 1} "
                      f"({len(blocks_chunk)} blocks)...")
                result = dongle.advance_blockchain(blocks_chunk, brothers_chunk)
                debug(f"Dongle replied with {result}")

                offset += self.chunk_size

                if self.list_length:
                    # Change mocks back
                    ledger.hsm2dongle.rlp_mm_payload_size = old_rlp_mm_payload_size
                    ledger.hsm2dongle.get_coinbase_txn = old_get_coinbase_txn

                if self.skip_brother_sorting:
                    # Change mocks back
                    ledger.hsm2dongle.get_block_hash = old_get_block_hash

                if dongle.last_comm_exception is not None:
                    error_code = dongle.last_comm_exception.sw
                    error_code_desc = hex(error_code)
                else:
                    error_code = result[1]
                    error_code_desc = error_code

                if self.expected is True:
                    if not result[0]:
                        raise TestCaseError("Expected success but got "
                                            f"failure with code {error_code_desc}")
                    elif (offset < len(self.blocks)
                          and error_code != dongle.RESPONSE.ADVANCE.OK_PARTIAL):
                        raise TestCaseError(
                            f"Expected {dongle.RESPONSE.ADVANCE.OK_PARTIAL} (partial "
                            f"success) but got {error_code_desc}")
                    elif (offset >= len(self.blocks) and not self.partial
                          and error_code != dongle.RESPONSE.ADVANCE.OK_TOTAL):
                        raise TestCaseError(
                            f"Expected {dongle.RESPONSE.ADVANCE.OK_TOTAL} (total "
                            f"success) but got {error_code_desc}")
                    elif (offset >= len(self.blocks) and self.partial
                          and error_code != dongle.RESPONSE.ADVANCE.OK_PARTIAL):
                        raise TestCaseError(
                            f"Expected {dongle.RESPONSE.ADVANCE.OK_PARTIAL} (partial "
                            f"success) but got {error_code_desc}")
                else:
                    if result[0]:
                        raise TestCaseError("Expected failure but got success with "
                                            f"code {error_code_desc}")
                    elif error_code != self.expected:
                        raise TestCaseError("Expected failure with "
                                            f"code {self.expected_desc} but got failure "
                                            f"with code {error_code_desc}")

        except RuntimeError as e:
            raise TestCaseError(str(e))

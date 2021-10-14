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

from unittest import TestCase
from unittest.mock import Mock, call
from parameterized import parameterized
import rlp
import ledger.block_utils as bu


class TestBlockUtils(TestCase):
    def test_rlp_first_element_list_payload_length_ok(self):
        elements = [
            b"hello",
            b"abcd",
            b"10"*10000,
            b"",
            b"a",
            [b"another", b"", b"list", b"1"*9999],
        ]
        expected_payload_length = sum(map(lambda e: len(rlp.encode(e)), elements))
        self.assertEqual(
            expected_payload_length,
            bu.rlp_first_element_list_payload_length(rlp.encode(elements)),
        )

    def test_rlp_first_element_list_payload_length_ok_emptylist(self):
        self.assertEqual(0, bu.rlp_first_element_list_payload_length(rlp.encode([])))

    def test_rlp_first_element_list_payload_length_notalist(self):
        with self.assertRaises(ValueError):
            bu.rlp_first_element_list_payload_length(rlp.encode(b"abcd"))

    @parameterized.expand([
        ("17 elements", 17, 1),
        ("18 elements", 18, 1),
        ("19 elements", 19, 3),
        ("20 elements", 20, 3),
    ])
    def test_rlp_mm_payload_size_ok(self, _, num_fields, num_fields_to_exclude):
        bu.rlp_first_element_list_payload_length = Mock(return_value="what-i-wanted")
        block = self._makeblock(num_fields)

        self.assertEqual("what-i-wanted", bu.rlp_mm_payload_size(rlp.encode(block).hex()))
        self.assertEqual(
            [call(rlp.encode(block[:-num_fields_to_exclude]))],
            bu.rlp_first_element_list_payload_length.call_args_list,
        )

    def test_rlp_mm_payload_size_wrong_list_size(self):
        with self.assertRaises(ValueError):
            bu.rlp_mm_payload_size(rlp.encode([b"abcd"]*15).hex())

        with self.assertRaises(ValueError):
            bu.rlp_mm_payload_size(rlp.encode([b"abcd"]*21).hex())

    def test_rlp_mm_payload_size_wrong_datatype(self):
        with self.assertRaises(ValueError):
            bu.rlp_mm_payload_size("notahex")

        with self.assertRaises(ValueError):
            bu.rlp_mm_payload_size(b"abcd")

    @parameterized.expand([
        ("17 elements, remove all", 17, False, 16, False),
        ("18 elements, remove all", 18, False, 17, False),
        ("19 elements, remove all", 19, False, 16, False),
        ("20 elements, remove all", 20, False, 17, False),
        ("17 elements, remove all, hex", 17, False, 16, True),
        ("18 elements, remove all, hex", 18, False, 17, True),
        ("19 elements, remove all, hex", 19, False, 16, True),
        ("20 elements, remove all, hex", 20, False, 17, True),
        ("17 elements, leave BTC block", 17, True, 17, False),
        ("18 elements, leave BTC block", 18, True, 18, False),
        ("19 elements, leave BTC block", 19, True, 17, False),
        ("20 elements, leave BTC block", 20, True, 18, False),
        ("17 elements, leave BTC block, hex", 17, True, 17, True),
        ("18 elements, leave BTC block, hex", 18, True, 18, True),
        ("19 elements, leave BTC block, hex", 19, True, 17, True),
        ("20 elements, leave BTC block, hex", 20, True, 18, True),
    ])
    def test_remove_mm_fields_if_present_ok(self, _, num_fields, leave_btcblock,
                                            expected_fields, hex_result):
        block = self._makeblock(num_fields)

        result_bytes = bu.remove_mm_fields_if_present(rlp.encode(block).hex(),
                                                      leave_btcblock=leave_btcblock,
                                                      hex=hex_result)

        if hex_result:
            result_bytes = bytes.fromhex(result_bytes)

        self.assertEqual(self._makeblock(expected_fields), rlp.decode(result_bytes))

    def _makeblock(self, num_fields):
        return list(map(lambda e: bytes([e])*e, range(num_fields)))

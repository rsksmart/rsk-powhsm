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
from unittest.mock import patch
from simulator.rsk.receipt import RskTransactionReceipt, RskReceiptLog
import rlp
import sha3

import logging

logging.disable(logging.CRITICAL)


class TestRskTransactionReceipt(TestCase):
    def setUp(self):
        receipt_list = [0]*6
        receipt_list[3] = ["these", "are", "the", "logs"]
        self.mocked_receipt = rlp.encode(receipt_list).hex()
        self.mocked_receipt_hash = (sha3.keccak_256(bytes.fromhex(
            self.mocked_receipt)).digest().hex())

    @patch("simulator.rsk.receipt.RskReceiptLog")
    def test_decoding_ok_noprefix(self, RskReceiptLogMock):
        RskReceiptLogMock.side_effect = lambda s: "*%s*" % s.decode("utf-8")

        tx_receipt = RskTransactionReceipt(self.mocked_receipt)
        self.assertEqual(tx_receipt.logs, ["*these*", "*are*", "*the*", "*logs*"])
        self.assertEqual(tx_receipt.hash, self.mocked_receipt_hash)

    def test_decoding_nonhex(self):
        with self.assertRaises(ValueError):
            RskTransactionReceipt("this-is-not-hexadecimal")

    def test_decoding_nonrlp(self):
        with self.assertRaises(ValueError):
            RskTransactionReceipt("aabbccddeeff")

    def test_decoding_list_length_invalid(self):
        mocked_receipt = rlp.encode([1, 2, 3]).hex()
        with self.assertRaises(ValueError):
            RskTransactionReceipt(mocked_receipt)

    class TestError(Exception):
        pass

    @patch("simulator.rsk.receipt.RskReceiptLog")
    def test_decoding_list_length_invalid_logs(self, RskReceiptLogMock):
        RskReceiptLogMock.side_effect = TestRskTransactionReceipt.TestError
        mocked_receipt = rlp.encode([1, 2, 3, [1], 5, 6]).hex()
        with self.assertRaises(TestRskTransactionReceipt.TestError):
            RskTransactionReceipt(mocked_receipt)


class TestRskReceiptLog(TestCase):
    def setUp(self):
        self.log = RskReceiptLog([
            bytes.fromhex("aabbcc"),
            [bytes.fromhex("11"), bytes.fromhex("22")],
            bytes.fromhex("ddeeff"),
        ])

    def test_address(self):
        self.assertEqual(self.log.address, "aabbcc")

    def test_topics(self):
        self.assertEqual(self.log.topics, ["11", "22"])

    def test_signature(self):
        self.assertEqual(self.log.signature, "11")

    def test_data(self):
        self.assertEqual(self.log.data, "ddeeff")

    def test_invalid_list_length(self):
        with self.assertRaises(ValueError):
            RskReceiptLog([1, 2])

    def test_invalid_topics(self):
        with self.assertRaises(AttributeError):
            RskReceiptLog([bytes.fromhex("aabbcc"), [1, 2, 3], bytes.fromhex("ddeeff")])

    def test_no_signature(self):
        log = RskReceiptLog([bytes.fromhex("aabbcc"), [], bytes.fromhex("ddeeff")])
        self.assertIsNone(log.signature)

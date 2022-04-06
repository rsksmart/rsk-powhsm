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
from comm.utils import bitwise_and_bytes

import logging

logging.disable(logging.CRITICAL)


class TestBitwiseAndBytes(TestCase):
    def test_ones(self):
        self.assertEqual(
            "1234567890",
            bitwise_and_bytes(bytes.fromhex("1234567890"),
                              bytes.fromhex("ffffffffff")).hex(),
        )

    def test_zeroes(self):
        self.assertEqual(
            "0000000000",
            bitwise_and_bytes(bytes.fromhex("1234567890"),
                              bytes.fromhex("0000000000")).hex(),
        )

    def test_mixed(self):
        self.assertEqual(
            "020406080e",
            bitwise_and_bytes(bytes.fromhex("123456789e"),
                              bytes.fromhex("0f0f0f0f0f")).hex(),
        )

        self.assertEqual(
            "0004000608",
            bitwise_and_bytes(bytes.fromhex("123456779a"),
                              bytes.fromhex("0406080e0d")).hex(),
        )

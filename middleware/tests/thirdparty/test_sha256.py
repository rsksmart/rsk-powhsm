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
import hashlib
import random
import os
import thirdparty.sha256

import logging

logging.disable(logging.CRITICAL)


class TestSha256(TestCase):
    _MAX_MESSAGE_LENGTH = 256
    _NUM_CASES = 100

    def test_sha256_random(self):
        for i in range(self._NUM_CASES):
            (message, expected) = self.generate_random_testcase()
            actual = thirdparty.sha256.SHA256(message).digest()
            self.assertEqual(expected, actual)

    def test_sha256_multiple_of_64(self):
        for i in range(self._NUM_CASES):
            (message, expected) = self.generate_random_testcase(64)
            actual = thirdparty.sha256.SHA256(message).digest()
            self.assertEqual(expected, actual)

    def generate_random_testcase(self, multiple_of=1):
        len = (int(random.uniform(0, self._MAX_MESSAGE_LENGTH // multiple_of + 1)) *
               multiple_of)
        message = os.urandom(len)
        out = hashlib.sha256(message)
        return (message, out.digest())

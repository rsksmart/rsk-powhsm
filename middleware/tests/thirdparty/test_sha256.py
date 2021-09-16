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
        len = (int(random.uniform(0, self._MAX_MESSAGE_LENGTH//multiple_of + 1)) *
               multiple_of)
        message = os.urandom(len)
        out = hashlib.sha256(message)
        return (message, out.digest())

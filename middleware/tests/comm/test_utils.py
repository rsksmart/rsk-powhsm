from unittest import TestCase
from comm.utils import bitwise_and_bytes

import logging
logging.disable(logging.CRITICAL)

class TestBitwiseAndBytes(TestCase):
    def test_ones(self):
        self.assertEqual('1234567890', \
            bitwise_and_bytes(bytes.fromhex('1234567890'), bytes.fromhex('ffffffffff')).hex())

    def test_zeroes(self):
        self.assertEqual('0000000000', \
            bitwise_and_bytes(bytes.fromhex('1234567890'), bytes.fromhex('0000000000')).hex())

    def test_mixed(self):
        self.assertEqual('020406080e', \
            bitwise_and_bytes(bytes.fromhex('123456789e'), bytes.fromhex('0f0f0f0f0f')).hex())

        self.assertEqual('0004000608', \
            bitwise_and_bytes(bytes.fromhex('123456779a'), bytes.fromhex('0406080e0d')).hex())

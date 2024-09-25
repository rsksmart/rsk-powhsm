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
from unittest.mock import Mock, patch
from sgx.hsm2dongle import HSM2DongleSGX
from ledger.hsm2dongle import HSM2DongleError

import logging

logging.disable(logging.CRITICAL)


class TestHSM2DongleSGX(TestCase):
    EXPECTED_DONGLE_TIMEOUT = 10

    @patch("ledger.hsm2dongle_tcp.getDongle")
    def setUp(self, getDongleMock):
        self.dongle = Mock()
        self.getDongleMock = getDongleMock
        self.getDongleMock.return_value = self.dongle
        self.hsm2dongle = HSM2DongleSGX("a-host", 1234, "a-debug-value")

        self.getDongleMock.assert_not_called()
        self.hsm2dongle.connect()
        self.getDongleMock.assert_called_with("a-host", 1234, "a-debug-value")
        self.assertEqual(self.hsm2dongle.dongle, self.dongle)

    def assert_exchange_called(self, bs):
        self.dongle.exchange.assert_called_with(bs, timeout=self.EXPECTED_DONGLE_TIMEOUT)

    def test_echo_ok(self):
        self.dongle.exchange.return_value = bytes([0x80, 0xA4, 0x41, 0x42, 0x43])
        self.assertTrue(self.hsm2dongle.echo())
        self.assert_exchange_called(bytes([0x80, 0xA4, 0x41, 0x42, 0x43]))

    def test_echo_response_differs(self):
        self.dongle.exchange.return_value = bytes([1, 2, 3])
        self.assertFalse(self.hsm2dongle.echo())
        self.assert_exchange_called(bytes([0x80, 0xA4, 0x41, 0x42, 0x43]))

    def test_echo_error_triggered(self):
        self.dongle.exchange.side_effect = RuntimeError("SomethingWentWrong")
        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.echo()
        self.assert_exchange_called(bytes([0x80, 0xA4, 0x41, 0x42, 0x43]))

    def test_unlock_ok(self):
        self.dongle.exchange.return_value = bytes([0xAA, 0xBB, 0xCC, 0xDD])
        self.assertTrue(self.hsm2dongle.unlock(b'a-password'))
        self.assert_exchange_called(bytes([0x80, 0xA3, 0x00]) + b'a-password')

    def test_unlock_wrong_pass(self):
        self.dongle.exchange.return_value = bytes([0xAA, 0xBB, 0x00, 0xDD])
        self.assertFalse(self.hsm2dongle.unlock(b'wrong-pass'))
        self.assert_exchange_called(bytes([0x80, 0xA3, 0x00]) + b'wrong-pass')

    def test_newpin_ok(self):
        self.dongle.exchange.return_value = bytes([0xAA, 0xBB, 0x01, 0xDD])
        self.assertTrue(self.hsm2dongle.new_pin(b'new-password'))
        self.assert_exchange_called(bytes([0x80, 0xA5, 0x00]) + b'new-password')

    def test_newpin_error(self):
        self.dongle.exchange.return_value = bytes([0xAA, 0xBB, 0x55, 0xDD])
        self.assertFalse(self.hsm2dongle.new_pin(b'new-password'))
        self.assert_exchange_called(bytes([0x80, 0xA5, 0x00]) + b'new-password')

    def test_get_retries(self):
        self.dongle.exchange.return_value = bytes([0xAA, 0xBB, 0x05, 0xDD])
        self.assertEqual(5, self.hsm2dongle.get_retries())
        self.assert_exchange_called(bytes([0x80, 0xA2]))

    def test_onboard_ok(self):
        self.dongle.exchange.return_value = bytes([0xAA, 0xBB, 0x01])
        self.assertTrue(self.hsm2dongle.onboard(bytes.fromhex("aa"*32), b"12345678"))
        self.assert_exchange_called(bytes([0x80, 0xA0, 0x00]) +
                                    bytes.fromhex("aa"*32) +
                                    b"12345678")

    def test_onboard_seed_invalid_type(self):
        self.dongle.exchange.return_value = bytes([0xAA, 0xBB, 0x01])

        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.onboard(1234, b"12345678")

        self.assertFalse(self.dongle.exchange.called)

    def test_onboard_seed_invalid_length(self):
        self.dongle.exchange.return_value = bytes([0xAA, 0xBB, 0x01])

        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.onboard(b"abcd", b"12345678")

        self.assertFalse(self.dongle.exchange.called)

    def test_onboard_pin_invalid_type(self):
        self.dongle.exchange.return_value = bytes([0xAA, 0xBB, 0x01])

        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.onboard(bytes.fromhex("aa"*32), 4444)

        self.assertFalse(self.dongle.exchange.called)

    def test_onboard_error_result(self):
        self.dongle.exchange.return_value = bytes([0xAA, 0xBB, 0xCC])

        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.onboard(bytes.fromhex("aa"*32), b'12345678')

        self.assert_exchange_called(bytes([0x80, 0xA0, 0x00]) +
                                    bytes.fromhex("aa"*32) +
                                    b"12345678")

    def test_onboard_error_xchg(self):
        self.dongle.exchange.side_effect = RuntimeError("SomethingWentWrong")

        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.onboard(bytes.fromhex("aa"*32), b'12345678')

        self.assert_exchange_called(bytes([0x80, 0xA0, 0x00]) +
                                    bytes.fromhex("aa"*32) +
                                    b"12345678")

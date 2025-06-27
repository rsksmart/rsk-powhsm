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
from unittest.mock import Mock, patch, call
from sgx.hsm2dongle import HSM2DongleSGX
from ledger.hsm2dongle import HSM2DongleError
from tests.ledger.test_hsm2dongle import \
    TestHSM2DongleBase, HSM2DongleTestMode  # noqa: F401

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

    def assert_xchg_called_ith(self, i, bs):
        self.assertGreaterEqual(self.dongle.exchange.call_count, i+1)
        self.assertEqual(
            call(bs, timeout=self.EXPECTED_DONGLE_TIMEOUT),
            self.dongle.exchange.call_args_list[i], f"Call #{i} mismatch")

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

    def test_migrate_db_spec_ok(self):
        self.dongle.exchange.side_effect = [
            bytes([0xAA, 0xBB, 0xCC]),
            bytes([0xAA, 0xBB, 0x01]),
            bytes([0xAA, 0xBB, 0x01]),
            bytes([0xAA, 0xBB, 0x00]),
        ]

        self.hsm2dongle.migrate_db_spec(
            0x12, b"a"*5, b"b"*5,
            [b"c"*10, b"d"*10, b"e"*10])

        self.assertEqual(4, self.dongle.exchange.call_count)
        self.assert_xchg_called_ith(0, bytes([0x80, 0xA6, 0x01, 0x12]) + b"aaaaabbbbb")
        self.assert_xchg_called_ith(1, bytes([0x80, 0xA6, 0x02]) + b"cccccccccc")
        self.assert_xchg_called_ith(2, bytes([0x80, 0xA6, 0x02]) + b"dddddddddd")
        self.assert_xchg_called_ith(3, bytes([0x80, 0xA6, 0x02]) + b"eeeeeeeeee")

    def test_migrate_db_spec_notenough_sigs(self):
        self.dongle.exchange.side_effect = [
            bytes([0xAA, 0xBB, 0xCC]),
            bytes([0xAA, 0xBB, 0x01]),
            bytes([0xAA, 0xBB, 0x01]),
        ]

        with self.assertRaises(HSM2DongleError) as e:
            self.hsm2dongle.migrate_db_spec(
                0x12, b"a"*5, b"b"*5,
                [b"c"*10, b"d"*10])

        self.assertIn("signatures gathered", e.exception.message)

        self.assertEqual(3, self.dongle.exchange.call_count)
        self.assert_xchg_called_ith(0, bytes([0x80, 0xA6, 0x01, 0x12]) + b"aaaaabbbbb")
        self.assert_xchg_called_ith(1, bytes([0x80, 0xA6, 0x02]) + b"cccccccccc")
        self.assert_xchg_called_ith(2, bytes([0x80, 0xA6, 0x02]) + b"dddddddddd")

    def test_migrate_db_spec_err_raised(self):
        self.dongle.exchange.side_effect = [
            bytes([0xAA, 0xBB, 0xCC]),
            HSM2DongleError("something happened"),
        ]

        with self.assertRaises(HSM2DongleError) as e:
            self.hsm2dongle.migrate_db_spec(
                0x12, b"a"*5, b"b"*5,
                [b"c"*10, b"d"*10])

        self.assertIn("something happened", e.exception.message)

        self.assertEqual(2, self.dongle.exchange.call_count)
        self.assert_xchg_called_ith(0, bytes([0x80, 0xA6, 0x01, 0x12]) + b"aaaaabbbbb")
        self.assert_xchg_called_ith(1, bytes([0x80, 0xA6, 0x02]) + b"cccccccccc")

    def test_migrate_db_get_evidence_ok(self):
        self.dongle.exchange.side_effect = [
            bytes([0xAA, 0xBB, 0x01]) + b"a"*3,
            bytes([0xAA, 0xBB, 0x01]) + b"b"*5,
            bytes([0xAA, 0xBB, 0x00]) + b"c"*7,
        ]

        self.assertEqual(b"aaabbbbbccccccc", self.hsm2dongle.migrate_db_get_evidence())

        self.assertEqual(3, self.dongle.exchange.call_count)
        for i in [0, 1, 2]:
            self.assert_xchg_called_ith(i, bytes([0x80, 0xA6, 0x03]))

    def test_migrate_db_get_evidence_err_raised(self):
        self.dongle.exchange.side_effect = [
            bytes([0xAA, 0xBB, 0x01]) + b"a"*3,
            HSM2DongleError("oopsies"),
        ]

        with self.assertRaises(HSM2DongleError) as e:
            self.hsm2dongle.migrate_db_get_evidence()

        self.assertIn("oopsies", e.exception.message)

        self.assertEqual(2, self.dongle.exchange.call_count)
        for i in [0, 1]:
            self.assert_xchg_called_ith(i, bytes([0x80, 0xA6, 0x03]))

    def test_migrate_db_send_evidence_ok(self):
        self.dongle.exchange.side_effect = [
            bytes([0xAA, 0xBB, 0x01]),
            bytes([0xAA, 0xBB, 0x01]),
            bytes([0xAA, 0xBB, 0x01]),
            bytes([0xAA, 0xBB, 0x01]),
            bytes([0xAA, 0xBB, 0x01]),
            bytes([0xAA, 0xBB, 0x01]),
            bytes([0xAA, 0xBB, 0x00]),
        ]

        self.hsm2dongle.migrate_db_send_evidence(
            b"1"*80 +
            b"2"*80 +
            b"3"*80 +
            b"4"*80 +
            b"5"*80 +
            b"6"*80 +
            b"7"*56
        )

        self.assertEqual(7, self.dongle.exchange.call_count)
        self.assert_xchg_called_ith(0, bytes([0x80, 0xA6, 0x04, 0x02, 0x18]) + b"1"*80)
        self.assert_xchg_called_ith(1, bytes([0x80, 0xA6, 0x04]) + b"2"*80)
        self.assert_xchg_called_ith(2, bytes([0x80, 0xA6, 0x04]) + b"3"*80)
        self.assert_xchg_called_ith(3, bytes([0x80, 0xA6, 0x04]) + b"4"*80)
        self.assert_xchg_called_ith(4, bytes([0x80, 0xA6, 0x04]) + b"5"*80)
        self.assert_xchg_called_ith(5, bytes([0x80, 0xA6, 0x04]) + b"6"*80)
        self.assert_xchg_called_ith(6, bytes([0x80, 0xA6, 0x04]) + b"7"*56)

    def test_migrate_db_send_evidence_noack(self):
        self.dongle.exchange.side_effect = [
            bytes([0xAA, 0xBB, 0x01]),
            bytes([0xAA, 0xBB, 0x01]),
            bytes([0xAA, 0xBB, 0x01]),
        ]

        with self.assertRaises(HSM2DongleError) as e:
            self.hsm2dongle.migrate_db_send_evidence(
                b"1"*80 +
                b"2"*80 +
                b"3"*67
            )

        self.assertIn("evidence ack", e.exception.message)

        self.assertEqual(3, self.dongle.exchange.call_count)
        self.assert_xchg_called_ith(0, bytes([0x80, 0xA6, 0x04, 0x00, 0xe3]) + b"1"*80)
        self.assert_xchg_called_ith(1, bytes([0x80, 0xA6, 0x04]) + b"2"*80)
        self.assert_xchg_called_ith(2, bytes([0x80, 0xA6, 0x04]) + b"3"*67)

    def test_migrate_db_send_evidence_err_raised(self):
        self.dongle.exchange.side_effect = [
            bytes([0xAA, 0xBB, 0x01]),
            bytes([0xAA, 0xBB, 0x01]),
            HSM2DongleError("sgx made a boo boo")
        ]

        with self.assertRaises(HSM2DongleError) as e:
            self.hsm2dongle.migrate_db_send_evidence(
                b"1"*40 +
                b"2"*40 +
                b"3"*1280
            )

        self.assertIn("boo boo", e.exception.message)

        self.assertEqual(3, self.dongle.exchange.call_count)
        self.assert_xchg_called_ith(
            0, bytes([0x80, 0xA6, 0x04, 0x05, 0x50]) + b"1"*40 + b"2"*40)
        self.assert_xchg_called_ith(
            1, bytes([0x80, 0xA6, 0x04]) + b"3"*80)
        self.assert_xchg_called_ith(
            2, bytes([0x80, 0xA6, 0x04]) + b"3"*80)

    def test_migrate_db_get_data_ok(self):
        self.dongle.exchange.return_value = \
            bytes([0xAA, 0xBB, 0xCC]) + b"0123456789abcdef"

        self.assertEqual(b"0123456789abcdef", self.hsm2dongle.migrate_db_get_data())

        self.assertEqual(1, self.dongle.exchange.call_count)
        self.assert_xchg_called_ith(0, bytes([0x80, 0xA6, 0x05]))

    def test_migrate_db_get_data_nodata(self):
        self.dongle.exchange.return_value = bytes([0xAA, 0xBB, 0xCC])

        with self.assertRaises(HSM2DongleError) as e:
            self.hsm2dongle.migrate_db_get_data()

        self.assertIn("data gathering failed", e.exception.message)

        self.assertEqual(1, self.dongle.exchange.call_count)
        self.assert_xchg_called_ith(0, bytes([0x80, 0xA6, 0x05]))

    def test_migrate_db_get_data_err_raised(self):
        self.dongle.exchange.side_effect = HSM2DongleError("migration nana")

        with self.assertRaises(HSM2DongleError) as e:
            self.hsm2dongle.migrate_db_get_data()

        self.assertIn("migration nana", e.exception.message)

        self.assertEqual(1, self.dongle.exchange.call_count)
        self.assert_xchg_called_ith(0, bytes([0x80, 0xA6, 0x05]))

    def test_migrate_db_send_data_ok(self):
        self.dongle.exchange.return_value = bytes([0xAA, 0xBB, 0xCC])

        self.hsm2dongle.migrate_db_send_data(b"aabbccddeeff44556677")

        self.assertEqual(1, self.dongle.exchange.call_count)
        self.assert_xchg_called_ith(
            0, bytes([0x80, 0xA6, 0x05]) + b"aabbccddeeff44556677")

    def test_migrate_db_send_data_err_raised(self):
        self.dongle.exchange.side_effect = HSM2DongleError("data bad bad")

        with self.assertRaises(HSM2DongleError) as e:
            self.hsm2dongle.migrate_db_send_data(b"aabbccddeeff44556677")

        self.assertIn("bad bad", e.exception.message)

        self.assertEqual(1, self.dongle.exchange.call_count)
        self.assert_xchg_called_ith(
            0, bytes([0x80, 0xA6, 0x05]) + b"aabbccddeeff44556677")

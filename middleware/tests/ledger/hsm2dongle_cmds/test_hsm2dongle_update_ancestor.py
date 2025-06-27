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

from unittest.mock import Mock, patch, call
from parameterized import parameterized
from ..test_hsm2dongle import TestHSM2DongleBase
from ledger.hsm2dongle import HSM2DongleError
from ledgerblue.commException import CommException

import logging

logging.disable(logging.CRITICAL)


class TestHSM2DongleUpdateAncestor(TestHSM2DongleBase):
    @patch("ledger.hsm2dongle.remove_mm_fields_if_present")
    @patch("ledger.hsm2dongle.rlp_mm_payload_size")
    def test_update_ancestor_ok(self, mmplsize_mock, rmvflds_mock):
        rmvflds_mock.side_effect = lambda h: h[:-bytes.fromhex(h)[-1]*2]
        mmplsize_mock.side_effect = lambda h: len(h)//8
        blocks_spec = [
            # (block bytes, chunk size)
            (
                self.buf(300) +
                bytes.fromhex("aabbccddeeff0011220a"),
                80,
            ),
            (
                self.buf(250) +
                bytes.fromhex("1122334405"),
                100,
            ),
            (
                self.buf(130) +
                bytes.fromhex("334455aabbccdd2211982311aacdfe10"),
                50,
            ),
        ]

        self.dongle.exchange.side_effect = [
            bs for excs in map(lambda s: self.spec_to_exchange(s, trim=True), blocks_spec)
            for bs in excs
        ] + [bytes([0, 0, 0x05])]  # Success response

        blocks_hex = list(map(lambda bs: bs[0].hex(), blocks_spec))
        self.assertEqual((True, 1),
                         self.hsm2dongle.update_ancestor(blocks_hex))

        self.assert_exchange([
            [0x30, 0x02, 0x00, 0x00, 0x00, 0x03],  # Init, 3 blocks
            [0x30, 0x03, 0x00, 0x4B],  # Block #1 meta
            [0x30, 0x04] + list(blocks_spec[0][0][80*0:80*1]),  # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*1:80*2]),  # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*2:80*3]),  # Block #1 chunk
            [0x30, 0x04] +
            list(blocks_spec[0][0][80*3:80*4][:-blocks_spec[0][0][-1]]),  # Block #1 chunk
            [0x30, 0x03, 0x00, 0x3E],  # Block #2 meta
            [0x30, 0x04] + list(blocks_spec[1][0][100*0:100*1]),  # Block #2 chunk
            [0x30, 0x04] + list(blocks_spec[1][0][100*1:100*2]),  # Block #2 chunk
            [0x30, 0x04] +
            list(blocks_spec[1][0][100*2:100 *
                                   3][:-blocks_spec[1][0][-1]]),  # Block #2 chunk
            [0x30, 0x03, 0x00, 0x20],  # Block #3 meta
            [0x30, 0x04] + list(blocks_spec[2][0][50*0:50*1]),  # Block #2 chunk
            [0x30, 0x04] + list(blocks_spec[2][0][50*1:50*2]),  # Block #3 chunk
            [0x30, 0x04] +
            list(blocks_spec[2][0][50*2:50*3][:-blocks_spec[2][0][-1]]),  # Block #3 chunk
        ])

    @parameterized.expand([
        ("prot_invalid", 0x6B87, -4),
        ("rlp_invalid", 0x6B88, -5),
        ("block_too_old", 0x6B89, -5),
        ("block_too_short", 0x6B8A, -5),
        ("parent_hash_invalid", 0x6B8B, -5),
        ("receipt_root_invalid", 0x6B8C, -5),
        ("block_num_invalid", 0x6B8D, -5),
        ("btc_header_invalid", 0x6B90, -5),
        ("mm_rlp_len_mismatch", 0x6B93, -5),
        ("buffer_overflow", 0x6B99, -5),
        ("chain_mismatch", 0x6B9A, -6),
        ("ancestor_tip_mismatch", 0x6B9C, -7),
        ("unexpected", 0x6BFF, -10),
        ("error_response", bytes([0, 0, 0xFF]), -10),
    ])
    @patch("ledger.hsm2dongle.remove_mm_fields_if_present")
    @patch("ledger.hsm2dongle.rlp_mm_payload_size")
    def test_update_ancestor_chunk_error_result(self, _, error_code, response,
                                                mmplsize_mock, rmvflds_mock):
        rmvflds_mock.side_effect = lambda h: h
        mmplsize_mock.side_effect = lambda h: len(h)//8
        blocks_spec = [
            # (block bytes, chunk size)
            (self.buf(300), 80),
            (self.buf(250), 100),
            (self.buf(140), 50),
        ]

        side_effect = [
            bs for excs in map(self.spec_to_exchange, blocks_spec)
            for bs in excs
        ]
        # Make the second chunk of the second block fail
        exchange_index = (
            1 + (300//80 + 2) + 2
        )  # Init + first block meta & chunks + second block meta & first chunk
        if type(error_code) == bytes:
            side_effect[exchange_index] = error_code
        else:
            side_effect[exchange_index] = CommException("a-message", error_code)
        side_effect = side_effect[:exchange_index + 1]
        self.dongle.exchange.side_effect = side_effect

        blocks_hex = list(map(lambda bs: bs[0].hex(), blocks_spec))
        self.assertEqual(
            (False, response),
            self.hsm2dongle.update_ancestor(blocks_hex),
        )

        self.assert_exchange([
            [0x30, 0x02, 0x00, 0x00, 0x00, 0x03],  # Init, 3 blocks
            [0x30, 0x03, 0x00, 0x4B],  # Block #1 meta
            [0x30, 0x04] + list(blocks_spec[0][0][80*0:80*1]),  # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*1:80*2]),  # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*2:80*3]),  # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*3:80*4]),  # Block #1 chunk
            [0x30, 0x03, 0x00, 0x3E],  # Block #2 meta
            [0x30, 0x04] + list(blocks_spec[1][0][100*0:100*1]),  # Block #2 chunk
            [0x30, 0x04] + list(blocks_spec[1][0][100*1:100*2]),  # Block #2 chunk
        ])

    @parameterized.expand([
        ("prot_invalid", 0x6B87, -3),
        ("unexpected", 0x6BFF, -10),
        ("error_response", bytes([0, 0, 0xFF]), -10),
    ])
    @patch("ledger.hsm2dongle.remove_mm_fields_if_present")
    @patch("ledger.hsm2dongle.rlp_mm_payload_size")
    def test_update_ancestor_metadata_error_result(self, _, error_code, response,
                                                   mmplsize_mock, rmvflds_mock):
        rmvflds_mock.side_effect = lambda h: h
        mmplsize_mock.side_effect = lambda h: len(h)//8
        blocks_spec = [
            # (block bytes, chunk size)
            (self.buf(300), 80),
            (self.buf(250), 100),
            (self.buf(140), 50),
        ]

        side_effect = [
            bs for excs in map(self.spec_to_exchange, blocks_spec)
            for bs in excs
        ]
        # Make the metadata of the third block fail
        exchange_index = (
            1 + (300//80 + 2) + (250//100 + 2)
        )  # Init + first and second block meta & chunks + third block meta
        if type(error_code) == bytes:
            side_effect[exchange_index] = error_code
        else:
            side_effect[exchange_index] = CommException("a-message", error_code)
        side_effect = side_effect[:exchange_index + 1]
        self.dongle.exchange.side_effect = side_effect

        blocks_hex = list(map(lambda bs: bs[0].hex(), blocks_spec))
        self.assertEqual(
            (False, response),
            self.hsm2dongle.update_ancestor(blocks_hex),
        )

        self.assert_exchange([
            [0x30, 0x02, 0x00, 0x00, 0x00, 0x03],  # Init, 3 blocks
            [0x30, 0x03, 0x00, 0x4B],  # Block #1 meta
            [0x30, 0x04] + list(blocks_spec[0][0][80*0:80*1]),  # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*1:80*2]),  # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*2:80*3]),  # Block #1 chunk
            [0x30, 0x04] + list(blocks_spec[0][0][80*3:80*4]),  # Block #1 chunk
            [0x30, 0x03, 0x00, 0x3E],  # Block #2 meta
            [0x30, 0x04] + list(blocks_spec[1][0][100*0:100*1]),  # Block #2 chunk
            [0x30, 0x04] + list(blocks_spec[1][0][100*1:100*2]),  # Block #2 chunk
            [0x30, 0x04] + list(blocks_spec[1][0][100*2:100*3]),  # Block #2 chunk
            [0x30, 0x03, 0x00, 0x23],  # Block #3 meta
        ])

    @patch("ledger.hsm2dongle.remove_mm_fields_if_present")
    @patch("ledger.hsm2dongle.rlp_mm_payload_size")
    def test_update_ancestor_metadata_error_generating(self, mmplsize_mock, rmvflds_mock):
        rmvflds_mock.side_effect = lambda h: h
        mmplsize_mock.side_effect = ValueError()
        self.dongle.exchange.side_effect = [bytes([0, 0, 0x03])]

        self.assertEqual(
            (False, -2),
            self.hsm2dongle.update_ancestor(["first-block", "second-block"]),
        )

        self.assert_exchange([
            [0x30, 0x02, 0x00, 0x00, 0x00, 0x02],  # Init, 2 blocks
        ])
        self.assertEqual([call("first-block")], mmplsize_mock.call_args_list)

    @parameterized.expand([
        ("prot_invalid", CommException("a-message", 0x6B87), -1),
        ("unexpected", CommException("a-message", 0x6BFF), -10),
        ("invalid_response", bytes([0, 0, 0xFF]), -10),
    ])
    @patch("ledger.hsm2dongle.remove_mm_fields_if_present")
    def test_update_ancestor_init_error(self, _, error, response, rmvflds_mock):
        rmvflds_mock.side_effect = lambda h: h
        self.dongle.exchange.side_effect = [error]

        self.assertEqual(
            (False, response),
            self.hsm2dongle.update_ancestor(["first-block", "second-block"]),
        )

        self.assert_exchange([
            [0x30, 0x02, 0x00, 0x00, 0x00, 0x02],  # Init, 2 blocks
        ])

    @patch("ledger.hsm2dongle.remove_mm_fields_if_present")
    def test_update_ancestor_remove_mmfields_exception(self, rmvflds_mock):
        rmvflds_mock.side_effect = ValueError("an error")

        self.assertEqual(
            (False, -8),
            self.hsm2dongle.update_ancestor(["first-block", "second-block"]),
        )

        self.assert_exchange([])

    def test_authorize_signer_ok(self):
        self.dongle.exchange.side_effect = [
            bytes(),  # Response to hash, iteration - doesn't matter
            bytes.fromhex("aaaaaa01"),  # Response to first signature, MORE
            bytes.fromhex("aaaaaa02"),  # Response to second signature, OK
        ]

        self.assertTrue(self.hsm2dongle.authorize_signer(Mock(
            signer_version=Mock(hash="ee"*32, iteration=0x4321),
            signatures=["aa"*20, "bb"*25]
        )))

        self.assert_exchange([
            [0x51, 0x01] + [0xee]*32 + [0x43, 0x21],  # Sigver, hash plus iteration
            [0x51, 0x02] + [0xaa]*20,  # Signature #1
            [0x51, 0x02] + [0xbb]*25,  # Signature #2
        ])

    def test_authorize_signer_ok_first_sig(self):
        self.dongle.exchange.side_effect = [
            bytes(),  # Response to hash, iteration - doesn't matter
            bytes.fromhex("aaaaaa02"),  # Response to first signature, OK
        ]

        self.assertTrue(self.hsm2dongle.authorize_signer(Mock(
            signer_version=Mock(hash="ee"*32, iteration=0x4321),
            signatures=["aa"*20, "bb"*25]
        )))

        self.assert_exchange([
            [0x51, 0x01] + [0xee]*32 + [0x43, 0x21],  # Sigver, hash plus iteration
            [0x51, 0x02] + [0xaa]*20,  # Signature #1
        ])

    def test_authorize_signer_sigver_error(self):
        self.dongle.exchange.side_effect = [
            CommException("an-error"),  # Response to hash, iteration - error
        ]

        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.authorize_signer(Mock(
                signer_version=Mock(hash="ee"*32, iteration=0x4321),
                signatures=["aa"*20, "bb"*25]
            ))

        self.assert_exchange([
            [0x51, 0x01] + [0xee]*32 + [0x43, 0x21],  # Sigver, hash plus iteration
        ])

    def test_authorize_signer_signature_error(self):
        self.dongle.exchange.side_effect = [
            bytes(),  # Response to hash, iteration - doesn't matter
            bytes.fromhex("aaaaaa01"),  # Response to first signature, MORE
            CommException("an-error"),  # Response to second signature, ERROR
        ]

        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.authorize_signer(Mock(
                signer_version=Mock(hash="ee"*32, iteration=0x4321),
                signatures=["aa"*20, "bb"*25]
            ))

        self.assert_exchange([
            [0x51, 0x01] + [0xee]*32 + [0x43, 0x21],  # Sigver, hash plus iteration
            [0x51, 0x02] + [0xaa]*20,  # Signature #1
            [0x51, 0x02] + [0xbb]*25,  # Signature #2
        ])

    def test_authorize_not_enough_signatures(self):
        self.dongle.exchange.side_effect = [
            bytes(),  # Response to hash, iteration - doesn't matter
            bytes.fromhex("aaaaaa01"),  # Response to first signature, MORE
            bytes.fromhex("aaaaaa01"),  # Response to second signature, MORE
        ]

        with self.assertRaises(HSM2DongleError):
            self.hsm2dongle.authorize_signer(Mock(
                signer_version=Mock(hash="ee"*32, iteration=0x4321),
                signatures=["aa"*20, "bb"*25]
            ))

        self.assert_exchange([
            [0x51, 0x01] + [0xee]*32 + [0x43, 0x21],  # Sigver, hash plus iteration
            [0x51, 0x02] + [0xaa]*20,  # Signature #1
            [0x51, 0x02] + [0xbb]*25,  # Signature #2
        ])

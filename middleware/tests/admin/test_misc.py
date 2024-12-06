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
from admin.misc import get_ud_value_for_attestation, RskClientError, AdminError

import logging

logging.disable(logging.CRITICAL)


class TestGetUdValueForAttestation(TestCase):
    def test_hex_string(self):
        self.assertEqual("aa"*32, get_ud_value_for_attestation("aa"*32))
        self.assertEqual("aa"*32, get_ud_value_for_attestation("0x"+"aa"*32))

    @patch("admin.misc.RskClient")
    def test_ud_source_ok(self, RskClient):
        rsk_client = Mock()
        RskClient.return_value = rsk_client
        rsk_client.get_best_block_number.return_value = "the-best-block-number"
        rsk_client.get_block_by_number.return_value = {"hash": "0x" + "bb"*32}

        self.assertEqual("bb"*32, get_ud_value_for_attestation("a-ud-source"))

        RskClient.assert_called_with("a-ud-source")
        rsk_client.get_best_block_number.assert_called()
        rsk_client.get_block_by_number.assert_called_with("the-best-block-number")

    @patch("admin.misc.RskClient")
    def test_ud_source_client_error(self, RskClient):
        rsk_client = Mock()
        RskClient.return_value = rsk_client
        rsk_client.get_best_block_number.return_value = "the-best-block-number"
        rsk_client.get_block_by_number.side_effect = RskClientError("an-error")

        with self.assertRaises(AdminError) as e:
            get_ud_value_for_attestation("a-ud-source")
        self.assertIn("an-error", str(e.exception))

        RskClient.assert_called_with("a-ud-source")
        rsk_client.get_best_block_number.assert_called()
        rsk_client.get_block_by_number.assert_called_with("the-best-block-number")

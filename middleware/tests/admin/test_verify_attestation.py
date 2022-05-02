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
from unittest.mock import Mock, patch, mock_open
from adm import create_actions, create_parser
from admin.misc import not_implemented
from admin.verify_attestation import UI_MESSAGE_HEADER, SIGNER_MESSAGE_HEADER
import hashlib
import secp256k1 as ec

import logging

logging.disable(logging.CRITICAL)


@patch("sys.stdout.write")
class TestVerifyAttestation(TestCase):

    VALID_PUBLIC_KEY = '04ef25f25c6b142785e4912b78eb08e8a47c03722af4d3c1705631e97868a5bddb4eaa821560b6a55942466084cabfba9233bfc564e60293663a0667cd3b6807e6' # noqa E501

    def get_result(self):
        pubkey = ec.PublicKey(bytes.fromhex(self.VALID_PUBLIC_KEY), raw=True)
        pubkeys_hash = hashlib.sha256()
        pubkeys_hash.update(pubkey.serialize(compressed=False))
        key_hash = pubkeys_hash.digest()

        return {
            "ui": (True, UI_MESSAGE_HEADER.hex() + "112233", "11223344"),
            "signer": (True, SIGNER_MESSAGE_HEADER.hex() + key_hash.hex(), "11223344"),
        }

    def setUp(self):
        self.actions = create_actions()
        self.parser = create_parser(self.actions)

    @patch("admin.certificate.HSMCertificate")
    @patch("admin.verify_attestation.HSMCertificate")
    @patch("json.loads")
    def test_verify_attestation(self, loads, admin_certificate, certificate, _):
        path = "m/44'/0'/0'/0/0"
        key = self.VALID_PUBLIC_KEY
        loads.return_value = {path: key}
        admin_certificate.from_jsonfile = Mock(return_value=certificate)
        certificate.validate_and_get_values = Mock(return_value=self.get_result())

        with patch('builtins.open', mock_open(read_data='')):
            options = self.parser.parse_args([
                '-t', 'certification-path', '-r', key, '-b', 'pubkeys-path',
                'verify_attestation'
            ])
            self.actions.get(options.operation, not_implemented)(options)

    @patch("admin.certificate.HSMCertificate")
    @patch("admin.verify_attestation.HSMCertificate")
    @patch("json.loads")
    def test_verify_attestation_invalid_key(self, loads, admin_certificate, certificate,
                                            _):
        path = "m/44'/0'/0'/0/0"
        key = "1122334455"
        loads.return_value = {path: key}
        admin_certificate.from_jsonfile = Mock(return_value=certificate)
        certificate.validate_and_get_values = Mock(return_value=self.get_result())

        with patch('builtins.open', mock_open(read_data='')):
            options = self.parser.parse_args([
                '-t', 'certification-path', '-r', key, '-b', 'pubkeys-path',
                'verify_attestation'
            ])
            with self.assertRaises(Exception):
                self.actions.get(options.operation, not_implemented)(options)

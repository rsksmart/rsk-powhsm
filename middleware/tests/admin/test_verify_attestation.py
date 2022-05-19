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

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, call, patch, mock_open

from admin.misc import AdminError
from admin.pubkeys import PATHS
from admin.verify_attestation import (do_verify_attestation,
                                      UI_MESSAGE_HEADER, SIGNER_MESSAGE_HEADER,
                                      UI_DERIVATION_PATH, UD_VALUE_LENGTH,
                                      PUBKEY_COMPRESSED_LENGTH)

import ecdsa
import secp256k1 as ec
import hashlib

import logging

logging.disable(logging.CRITICAL)


@patch("sys.stdout.write")
class TestVerifyAttestation(TestCase):
    def setUp(self):
        self.certification_path = 'certification-path'
        self.pubkeys_path = 'pubkeys-path'
        options = {
            'attestation_certificate_file_path': self.certification_path,
            'pubkeys_file_path': self.pubkeys_path,
            'root_authority': None
        }
        self.default_options = SimpleNamespace(**options)

        paths = []
        for path in PATHS.values():
            paths.append(str(path))

        self.public_keys = {}
        self.expected_pubkeys_output = []
        pubkeys_hash = hashlib.sha256()
        path_name_padding = max(map(len, paths))
        for path in sorted(paths):
            pubkey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1).get_verifying_key()
            self.public_keys[path] = pubkey.to_string('compressed').hex()
            pubkey_to_hash = ec.PublicKey(bytes.fromhex(self.public_keys[path]), raw=True)
            pubkeys_hash.update(pubkey_to_hash.serialize(compressed=False))
            self.expected_pubkeys_output.append(
                f"{(path + ':').ljust(path_name_padding+1)} "
                f"{pubkey_to_hash.serialize(compressed=True).hex()}"
            )
        self.pubkeys_hash = pubkeys_hash.digest()

        self.ui_msg = bytes.fromhex(UI_MESSAGE_HEADER.hex() + 'aa' * 132)
        self.ui_hash = bytes.fromhex('bb' * 32)
        self.signer_msg = bytes.fromhex(SIGNER_MESSAGE_HEADER.hex() +
                                        self.pubkeys_hash.hex())
        self.signer_hash = bytes.fromhex('cc' * 32)
        self.result = {}
        self.result['ui'] = (True, self.ui_msg.hex(), self.ui_hash.hex())
        self.result['signer'] = (True, self.signer_msg.hex(), self.signer_hash.hex())

    @patch("admin.verify_attestation.head")
    @patch("admin.verify_attestation.HSMCertificate")
    @patch("json.loads")
    def test_verify_attestation(self,
                                loads_mock,
                                certificate_mock,
                                head_mock,
                                _):
        loads_mock.return_value = self.public_keys
        att_cert = Mock()
        att_cert.validate_and_get_values = Mock(return_value=self.result)
        certificate_mock.from_jsonfile = Mock(return_value=att_cert)

        with patch('builtins.open', mock_open(read_data='')) as file_mock:
            do_verify_attestation(self.default_options)

        self.assertEqual([call(self.pubkeys_path, 'r')], file_mock.call_args_list)
        self.assertEqual([call(self.certification_path)],
                         certificate_mock.from_jsonfile.call_args_list)

        mh_len = len(UI_MESSAGE_HEADER)
        ud_value = self.ui_msg[mh_len:mh_len + UD_VALUE_LENGTH]
        ca_pubkey = self.ui_msg[mh_len + UD_VALUE_LENGTH + PUBKEY_COMPRESSED_LENGTH:]
        ui_pubkey = self.ui_msg[mh_len + UD_VALUE_LENGTH:mh_len + UD_VALUE_LENGTH +
                                PUBKEY_COMPRESSED_LENGTH]
        expected_call_ui = call(
            [
                "UI verified with:",
                f"UD value: {ud_value.hex()}",
                f"CA: {ca_pubkey.hex()}",
                f"Derived public key ({UI_DERIVATION_PATH}): {ui_pubkey.hex()}",
                f"Installed UI hash: {self.ui_hash.hex()}",
            ],
            fill="-",
        )
        self.assertEqual(expected_call_ui, head_mock.call_args_list[1])

        mh_len = len(SIGNER_MESSAGE_HEADER)
        expected_call_signer = call(
            ["Signer verified with public keys:"] + self.expected_pubkeys_output + [
                "",
                f"Hash: {self.signer_msg[mh_len:].hex()}",
                f"Installed Signer hash: {self.signer_hash.hex()}",
            ],
            fill="-",
        )
        self.assertEqual(expected_call_signer, head_mock.call_args_list[2])

    def test_verify_attestation_no_certificate(self, _):
        options = self.default_options
        options.attestation_certificate_file_path = None
        with self.assertRaises(AdminError) as e:
            do_verify_attestation(options)
        self.assertEqual('No attestation certificate file given', str(e.exception))

    def test_verify_attestation_no_pubkey(self, _):
        options = self.default_options
        options.pubkeys_file_path = None

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(options)
        self.assertEqual('No public keys file given', str(e.exception))

    @patch("json.loads")
    def test_verify_attestation_invalid_pubkeys_map(self, loads_mock, _):
        loads_mock.return_value = 'invalid-json'
        with patch('builtins.open', mock_open(read_data='')):
            with self.assertRaises(ValueError) as e:
                do_verify_attestation(self.default_options)

        self.assertEqual(('Unable to read public keys from "pubkeys-path": Public keys '
                          'file must contain an object as a top level element'),
                         str(e.exception))

    @patch("json.loads")
    def test_verify_attestation_invalid_pubkey(self, loads_mock, _):
        loads_mock.return_value = {'invalid-path': 'invalid-key'}
        with patch('builtins.open', mock_open(read_data='')):
            with self.assertRaises(AdminError) as e:
                do_verify_attestation(self.default_options)

        self.assertEqual('Invalid public key for path invalid-path: invalid-key',
                         str(e.exception))

    @patch("json.loads")
    def test_verify_attestation_no_ui_derivation_key(self, loads_mock, _):
        incomplete_pubkeys = self.public_keys
        incomplete_pubkeys.pop(UI_DERIVATION_PATH, None)
        loads_mock.return_value = incomplete_pubkeys

        with patch('builtins.open', mock_open(read_data='')) as file_mock:
            with self.assertRaises(AdminError) as e:
                do_verify_attestation(self.default_options)

        self.assertEqual([call(self.pubkeys_path, 'r')], file_mock.call_args_list)
        self.assertEqual((f'Public key with path {UI_DERIVATION_PATH} not present '
                          'in public key file'),
                         str(e.exception))

    @patch("admin.verify_attestation.HSMCertificate")
    @patch("json.loads")
    def test_verify_attestation_invalid_certificate(self,
                                                    loads_mock,
                                                    certificate_mock,
                                                    _):
        loads_mock.return_value = self.public_keys
        certificate_mock.from_jsonfile = Mock(side_effect=Exception('error-msg'))

        with patch('builtins.open', mock_open(read_data='')) as file_mock:
            with self.assertRaises(AdminError) as e:
                do_verify_attestation(self.default_options)

        self.assertEqual([call(self.pubkeys_path, 'r')], file_mock.call_args_list)
        self.assertEqual('While loading the attestation certificate file: error-msg',
                         str(e.exception))

    @patch("admin.verify_attestation.HSMCertificate")
    @patch("json.loads")
    def test_verify_attestation_no_ui_att(self,
                                          loads_mock,
                                          certificate_mock,
                                          _):
        loads_mock.return_value = self.public_keys

        result = self.result
        result.pop('ui', None)
        att_cert = Mock()
        att_cert.validate_and_get_values = Mock(return_value=self.result)
        certificate_mock.from_jsonfile = Mock(return_value=att_cert)

        with patch('builtins.open', mock_open(read_data='')) as file_mock:
            with self.assertRaises(AdminError) as e:
                do_verify_attestation(self.default_options)

        self.assertEqual([call(self.pubkeys_path, 'r')], file_mock.call_args_list)
        self.assertEqual('Certificate does not contain a UI attestation',
                         str(e.exception))

    @patch("admin.verify_attestation.HSMCertificate")
    @patch("json.loads")
    def test_verify_attestation_invalid_ui_att(self,
                                               loads_mock,
                                               certificate_mock,
                                               _):
        loads_mock.return_value = self.public_keys
        result = self.result
        result['ui'] = (False, 'ui')
        att_cert = Mock()
        att_cert.validate_and_get_values = Mock(return_value=result)
        certificate_mock.from_jsonfile = Mock(return_value=att_cert)

        with patch('builtins.open', mock_open(read_data='')) as file_mock:
            with self.assertRaises(AdminError) as e:
                do_verify_attestation(self.default_options)

        self.assertEqual([call(self.pubkeys_path, 'r')], file_mock.call_args_list)
        self.assertEqual("Invalid UI attestation: error validating 'ui'",
                         str(e.exception))

    @patch("admin.verify_attestation.HSMCertificate")
    @patch("json.loads")
    def test_verify_attestation_no_signer_att(self,
                                              loads_mock,
                                              certificate_mock,
                                              _):
        loads_mock.return_value = self.public_keys

        result = self.result
        result.pop('signer', None)
        att_cert = Mock()
        att_cert.validate_and_get_values = Mock(return_value=self.result)
        certificate_mock.from_jsonfile = Mock(return_value=att_cert)

        with patch('builtins.open', mock_open(read_data='')) as file_mock:
            with self.assertRaises(AdminError) as e:
                do_verify_attestation(self.default_options)

        self.assertEqual([call(self.pubkeys_path, 'r')], file_mock.call_args_list)
        self.assertEqual('Certificate does not contain a Signer attestation',
                         str(e.exception))

    @patch("admin.verify_attestation.HSMCertificate")
    @patch("json.loads")
    def test_verify_attestation_invalid_signer_att(self,
                                                   loads_mock,
                                                   certificate_mock,
                                                   _):
        loads_mock.return_value = self.public_keys
        result = self.result
        result['signer'] = (False, 'signer')
        att_cert = Mock()
        att_cert.validate_and_get_values = Mock(return_value=result)
        certificate_mock.from_jsonfile = Mock(return_value=att_cert)

        with patch('builtins.open', mock_open(read_data='')) as file_mock:
            with self.assertRaises(AdminError) as e:
                do_verify_attestation(self.default_options)

        self.assertEqual([call(self.pubkeys_path, 'r')], file_mock.call_args_list)
        self.assertEqual(("Invalid Signer attestation: error validating 'signer'"),
                         str(e.exception))

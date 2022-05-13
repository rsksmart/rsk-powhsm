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
from unittest.mock import Mock, call, patch, mock_open

from adm import main
from admin.certificate import HSMCertificate
from admin.misc import AdminError
from admin.pubkeys import PATHS
from admin.verify_attestation import (UI_MESSAGE_HEADER, SIGNER_MESSAGE_HEADER,
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
        pubkeys_hash = pubkeys_hash.digest()

        # Adapted from attestation.md example
        self.certificate = {
            "version": 1,
            "targets": [
                "ui",
                "signer"
            ],
            "elements": [
                {
                    "name": "attestation",
                    "message": ("ff043bc81f42c85b1cafb66f2af7ba29c61aac0357ae0228ea479d77"
                                "5c908ee412ca857f892c38c300c7e7283298dea535723955448fe6ed"
                                "b906a4dc4738cbb61e86"),
                    "signature": ("3045022100cb411ef6771105a8eb71c85295450fac36edd8abfca7"
                                  "bfcf55dbca0fe9842a0f022056055f6f34f4f0c0bfe6620611b181"
                                  "39fc816b8c64447452ea31d2551c0dcff2"),
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": ("0210b48081be20280434a28e4185e735964a36b5cd8817cbdde534f2"
                                "839f04c5f998927a36f08343726de175327fa5272e3929b9c357f36f"
                                "2128c92e14af359ce0e00734d2c93f4c07"),
                    "signature": ("30440220181d61b12165b0dd0548cb574577d9f9419a894da56e5b"
                                  "1323375c3b9435622a0220290a29b2a06bbd481b0d0587abadddee"
                                  "39c002ed7f269ac11b23917e7c5c615e"),
                    "signed_by": "root"
                },
                {
                    "name": "ui",
                    "message": UI_MESSAGE_HEADER.hex() + ("3a045993ce2195967539196548251c"
                                                          "78d1b75b73cc39424dc2570f73c1f8"
                                                          "9fd55f8eb96538377f31ee0a68799d"
                                                          "151b56e3bc539995e61206b09a3087"
                                                          "8560702c1157"),
                    "signature": ("304402207744f1f7080766b560d83e35a33bd624a5cabf3ae0b635"
                                  "45e3b42cbbca7fe1f002207d476d3c0fb55c19aeca8e186cd40ba5"
                                  "f6c8957e297cab1dea364e6a94c180a2"),
                    "signed_by": "attestation",
                    "tweak": ("4b73dc1bdd565dd2c7af9587ae33b7db65fbb95fc174fd701d45c70df8"
                              "bb4f51")
                },
                {
                    "name": "signer",
                    "message": SIGNER_MESSAGE_HEADER.hex() + pubkeys_hash.hex(),
                    "signature": ("304402202ebb12c6a780eedb8f3f9e811cea3e920f06308a91e527"
                                  "cc2b24ed1923d1d1110220576bcaa97e0042e1c3e4da7d6f735155"
                                  "078a7c8c55b7c745f9e474fadd176dd9"),
                    "signed_by": "attestation",
                    "tweak": ("26ec706760ea301358d40fe669edc4422dc8ec3cdfe898a4332b7d33b6"
                              "ba2e96")
                }
            ]
        }

    @patch("admin.verify_attestation.head")
    @patch("admin.certificate.HSMCertificateElement.is_valid")
    @patch("admin.verify_attestation.HSMCertificate")
    @patch("json.loads")
    def test_verify_attestation(self,
                                loads_mock,
                                certificate_mock,
                                is_valid_mock,
                                head_mock,
                                _):
        loads_mock.return_value = self.public_keys
        certificate_mock.from_jsonfile = Mock(
            return_value=HSMCertificate(self.certificate))
        is_valid_mock.return_value = True

        mh_len = len(UI_MESSAGE_HEADER)
        ui_message = bytes.fromhex(self.certificate['elements'][2]['message'])
        ui_hash = bytes.fromhex(self.certificate['elements'][2]['tweak'])
        ud_value = ui_message[mh_len:mh_len + UD_VALUE_LENGTH].hex()
        ui_public_key = ui_message[mh_len + UD_VALUE_LENGTH:mh_len + UD_VALUE_LENGTH +
                                   PUBKEY_COMPRESSED_LENGTH].hex()
        ca_public_key = ui_message[mh_len +
                                   UD_VALUE_LENGTH + PUBKEY_COMPRESSED_LENGTH:].hex()
        expected_call_ui = call(
            [
                "UI verified with:",
                f"UD value: {ud_value}",
                f"CA: {ca_public_key}",
                f"Derived public key ({UI_DERIVATION_PATH}): {ui_public_key}",
                f"Installed UI hash: {ui_hash.hex()}",
            ],
            fill="-",
        )

        mh_len = len(SIGNER_MESSAGE_HEADER)
        signer_message = bytes.fromhex(self.certificate['elements'][3]['message'])
        signer_hash = bytes.fromhex(self.certificate['elements'][3]['tweak'])
        expected_call_signer = call(
            ["Signer verified with public keys:"] + self.expected_pubkeys_output + [
                "",
                f"Hash: {signer_message[mh_len:].hex()}",
                f"Installed Signer hash: {signer_hash.hex()}",
            ],
            fill="-",
        )

        with patch('builtins.open', mock_open(read_data='')) as file_mock:
            with patch('sys.argv', [
                    'adm.py',
                    '-t', 'certification-path',
                    '-b', 'pubkeys-path',
                    'verify_attestation'
            ]):
                main()
        self.assertEqual([call('pubkeys-path', 'r')], file_mock.call_args_list)
        self.assertEqual([call('certification-path')],
                         certificate_mock.from_jsonfile.call_args_list)
        self.assertTrue(is_valid_mock.called)
        self.assertEqual(expected_call_ui, head_mock.call_args_list[1])
        self.assertEqual(expected_call_signer, head_mock.call_args_list[2])

    def test_verify_attestation_no_certificate(self, _):
        with patch('sys.argv', [
                'adm.py',
                '-b', 'pubkeys-path',
                'verify_attestation'
        ]):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertEqual('No attestation certificate file given', str(e.exception))

    def test_verify_attestation_no_pubkey(self, _):
        with patch('sys.argv', [
                'adm.py',
                '-t', 'certification-path',
                'verify_attestation'
        ]):
            with self.assertRaises(AdminError) as e:
                main()
        self.assertEqual('No public keys file given', str(e.exception))

    @patch("json.loads")
    def test_verify_attestation_invalid_pubkeys_map(self, loads_mock, _):
        loads_mock.return_value = 'invalid-json'
        with patch('builtins.open', mock_open(read_data='')):
            with patch('sys.argv', [
                    'adm.py',
                    '-t', 'certification-path',
                    '-b', 'pubkeys-path',
                    'verify_attestation'
            ]):
                with self.assertRaises(ValueError) as e:
                    main()
        self.assertEqual(('Unable to read public keys from "pubkeys-path": Public keys '
                          'file must contain an object as a top level element'),
                         str(e.exception))

    @patch("json.loads")
    def test_verify_attestation_invalid_pubkey(self, loads_mock, _):
        loads_mock.return_value = {'invalid-path': 'invalid-key'}
        with patch('builtins.open', mock_open(read_data='')):
            with patch('sys.argv', [
                    'adm.py',
                    '-t', 'certification-path',
                    '-b', 'pubkeys-path',
                    'verify_attestation'
            ]):
                with self.assertRaises(AdminError) as e:
                    main()
        self.assertEqual('Invalid public key for path invalid-path: invalid-key',
                         str(e.exception))

    @patch("json.loads")
    def test_verify_attestation_no_ui_derivation_key(self, loads_mock, _):
        incomplete_pubkeys = self.public_keys
        incomplete_pubkeys.pop(UI_DERIVATION_PATH, None)
        loads_mock.return_value = incomplete_pubkeys

        with patch('builtins.open', mock_open(read_data='')) as file_mock:
            with patch('sys.argv', [
                    'adm.py',
                    '-t', 'certification-path',
                    '-b', 'pubkeys-path',
                    'verify_attestation'
            ]):
                with self.assertRaises(AdminError) as e:
                    main()
        self.assertEqual([call('pubkeys-path', 'r')], file_mock.call_args_list)
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
            with patch('sys.argv', [
                    'adm.py',
                    '-t', 'certification-path',
                    '-b', 'pubkeys-path',
                    'verify_attestation'
            ]):
                with self.assertRaises(AdminError) as e:
                    main()
        self.assertEqual([call('pubkeys-path', 'r')], file_mock.call_args_list)
        self.assertEqual('While loading the attestation certificate file: error-msg',
                         str(e.exception))

    @patch("admin.certificate.HSMCertificate.validate_and_get_values")
    @patch("admin.verify_attestation.HSMCertificate")
    @patch("json.loads")
    def test_verify_attestation_no_ui_att(self,
                                          loads_mock,
                                          certificate_mock,
                                          validate_mock,
                                          _):
        loads_mock.return_value = self.public_keys
        certificate_mock.from_jsonfile = Mock(
            return_value=HSMCertificate(self.certificate))
        signer_message = self.certificate['elements'][3]['message']
        signer_hash = self.certificate['elements'][3]['tweak']
        validate_mock.return_value = {
            "signer": (True, signer_message, signer_hash)
        }

        with patch('builtins.open', mock_open(read_data='')) as file_mock:
            with patch('sys.argv', [
                    'adm.py',
                    '-t', 'certification-path',
                    '-b', 'pubkeys-path',
                    'verify_attestation'
            ]):
                with self.assertRaises(AdminError) as e:
                    main()
        self.assertEqual([call('pubkeys-path', 'r')], file_mock.call_args_list)
        self.assertEqual('Certificate does not contain a UI attestation',
                         str(e.exception))

    @patch("admin.certificate.HSMCertificate.validate_and_get_values")
    @patch("admin.verify_attestation.HSMCertificate")
    @patch("json.loads")
    def test_verify_attestation_invalid_ui_att(self,
                                               loads_mock,
                                               certificate_mock,
                                               validate_mock,
                                               _):
        loads_mock.return_value = self.public_keys
        certificate_mock.from_jsonfile = Mock(
            return_value=HSMCertificate(self.certificate))
        ui_message = self.certificate['elements'][2]['message']
        ui_hash = self.certificate['elements'][2]['tweak']
        signer_message = self.certificate['elements'][3]['message']
        signer_hash = self.certificate['elements'][3]['tweak']
        validate_mock.return_value = {
            "ui": (False, ui_message, ui_hash),
            "signer": (True, signer_message, signer_hash)
        }

        with patch('builtins.open', mock_open(read_data='')) as file_mock:
            with patch('sys.argv', [
                    'adm.py',
                    '-t', 'certification-path',
                    '-b', 'pubkeys-path',
                    'verify_attestation'
            ]):
                with self.assertRaises(AdminError) as e:
                    main()
        self.assertEqual([call('pubkeys-path', 'r')], file_mock.call_args_list)
        self.assertEqual(f"Invalid UI attestation: error validating '{ui_message}'",
                         str(e.exception))

    @patch("admin.certificate.HSMCertificate.validate_and_get_values")
    @patch("admin.verify_attestation.HSMCertificate")
    @patch("json.loads")
    def test_verify_attestation_no_signer_att(self,
                                              loads_mock,
                                              certificate_mock,
                                              validate_mock,
                                              _):
        loads_mock.return_value = self.public_keys
        certificate_mock.from_jsonfile = Mock(
            return_value=HSMCertificate(self.certificate))
        ui_message = self.certificate['elements'][2]['message']
        ui_hash = self.certificate['elements'][2]['tweak']
        validate_mock.return_value = {
            "ui": (True, ui_message, ui_hash)
        }

        with patch('builtins.open', mock_open(read_data='')) as file_mock:
            with patch('sys.argv', [
                    'adm.py',
                    '-t', 'certification-path',
                    '-b', 'pubkeys-path',
                    'verify_attestation'
            ]):
                with self.assertRaises(AdminError) as e:
                    main()
        self.assertEqual([call('pubkeys-path', 'r')], file_mock.call_args_list)
        self.assertEqual('Certificate does not contain a Signer attestation',
                         str(e.exception))

    @patch("admin.certificate.HSMCertificate.validate_and_get_values")
    @patch("admin.verify_attestation.HSMCertificate")
    @patch("json.loads")
    def test_verify_attestation_invalid_signer_att(self,
                                                   loads_mock,
                                                   certificate_mock,
                                                   validate_mock,
                                                   _):
        loads_mock.return_value = self.public_keys
        certificate_mock.from_jsonfile = Mock(
            return_value=HSMCertificate(self.certificate))
        ui_message = self.certificate['elements'][2]['message']
        ui_hash = self.certificate['elements'][2]['tweak']
        signer_message = self.certificate['elements'][3]['message']
        signer_hash = self.certificate['elements'][3]['tweak']
        validate_mock.return_value = {
            "ui": (True, ui_message, ui_hash),
            "signer": (False, signer_message, signer_hash)
        }

        with patch('builtins.open', mock_open(read_data='')) as file_mock:
            with patch('sys.argv', [
                    'adm.py',
                    '-t', 'certification-path',
                    '-b', 'pubkeys-path',
                    'verify_attestation'
            ]):
                with self.assertRaises(AdminError) as e:
                    main()
        self.assertEqual([call('pubkeys-path', 'r')], file_mock.call_args_list)
        self.assertEqual(('Invalid Signer attestation: error validating '
                          f"'{signer_message}'"),
                         str(e.exception))

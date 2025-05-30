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
from unittest.mock import Mock, call, patch
from admin.misc import AdminError
from admin.pubkeys import PATHS
from admin.verify_ledger_attestation import do_verify_attestation
import ecdsa
import secp256k1 as ec
import hashlib
import logging

logging.disable(logging.CRITICAL)

EXPECTED_UI_DERIVATION_PATH = "m/44'/0'/0'/0/0"
LEGACY_SIGNER_HEADER = b"HSM:SIGNER:5.3"
POWHSM_HEADER = b"POWHSM:5.5::"
UI_HEADER = b"HSM:UI:5.5"


@patch("sys.stdout.write")
class TestVerifyLedgerAttestation(TestCase):
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
            self.public_keys[path] = ec.PublicKey(
                pubkey.to_string('compressed'), raw=True)
            pubkeys_hash.update(pubkey.to_string('uncompressed'))
            self.expected_pubkeys_output.append(
                f"{(path + ':').ljust(path_name_padding+1)} "
                f"{pubkey.to_string('compressed').hex()}"
            )
        self.pubkeys_hash = pubkeys_hash.digest()
        self.expected_ui_pubkey = self.public_keys[EXPECTED_UI_DERIVATION_PATH]\
            .serialize(compressed=True).hex()

        self.ui_msg = UI_HEADER + \
            bytes.fromhex("aa"*32) + \
            bytes.fromhex(self.expected_ui_pubkey) + \
            bytes.fromhex("cc"*32) + \
            bytes.fromhex("0123")
        self.ui_hash = bytes.fromhex("ee" * 32)

        self.signer_msg = POWHSM_HEADER + \
            b'plf' + \
            bytes.fromhex('aa'*32) + \
            bytes.fromhex(self.pubkeys_hash.hex()) + \
            bytes.fromhex('bb'*32) + \
            bytes.fromhex('cc'*8) + \
            bytes.fromhex('00'*7 + 'ab')

        self.signer_hash = bytes.fromhex("ff" * 32)

        self.result = {}
        self.result['ui'] = (True, self.ui_msg.hex(), self.ui_hash.hex())
        self.result['signer'] = (True, self.signer_msg.hex(), self.signer_hash.hex())

    @patch("admin.verify_ledger_attestation.head")
    @patch("admin.verify_ledger_attestation.HSMCertificate")
    @patch("admin.verify_ledger_attestation.load_pubkeys")
    def test_verify_attestation_legacy(self,
                                       load_pubkeys_mock,
                                       certificate_mock,
                                       head_mock, _):
        self.signer_msg = LEGACY_SIGNER_HEADER + \
            bytes.fromhex(self.pubkeys_hash.hex())
        self.signer_hash = bytes.fromhex("ff" * 32)
        self.result['signer'] = (True, self.signer_msg.hex(), self.signer_hash.hex())

        load_pubkeys_mock.return_value = self.public_keys
        att_cert = Mock()
        att_cert.validate_and_get_values = Mock(return_value=self.result)
        certificate_mock.from_jsonfile = Mock(return_value=att_cert)

        do_verify_attestation(self.default_options)

        load_pubkeys_mock.assert_called_with(self.pubkeys_path)
        self.assertEqual([call(self.certification_path)],
                         certificate_mock.from_jsonfile.call_args_list)

        expected_call_ui = call(
            [
                "UI verified with:",
                f"UD value: {'aa'*32}",
                f"Derived public key ({EXPECTED_UI_DERIVATION_PATH}): "
                f"{self.expected_ui_pubkey}",
                f"Authorized signer hash: {'cc'*32}",
                "Authorized signer iteration: 291",
                f"Installed UI hash: {'ee'*32}",
                "Installed UI version: 5.5",
            ],
            fill="-",
        )
        self.assertEqual(expected_call_ui, head_mock.call_args_list[1])

        expected_call_signer = call(
            ["Signer verified with public keys:"] + self.expected_pubkeys_output + [
                f"Hash: {self.pubkeys_hash.hex()}",
                "",
                f"Installed Signer hash: {'ff'*32}",
                "Installed Signer version: 5.3",
            ],
            fill="-",
        )
        self.assertEqual(expected_call_signer, head_mock.call_args_list[2])

    @patch("admin.verify_ledger_attestation.head")
    @patch("admin.verify_ledger_attestation.HSMCertificate")
    @patch("admin.verify_ledger_attestation.load_pubkeys")
    def test_verify_attestation(self,
                                load_pubkeys_mock,
                                certificate_mock,
                                head_mock, _):
        load_pubkeys_mock.return_value = self.public_keys
        att_cert = Mock()
        att_cert.validate_and_get_values = Mock(return_value=self.result)
        certificate_mock.from_jsonfile = Mock(return_value=att_cert)

        do_verify_attestation(self.default_options)

        load_pubkeys_mock.assert_called_with(self.pubkeys_path)
        self.assertEqual([call(self.certification_path)],
                         certificate_mock.from_jsonfile.call_args_list)

        expected_call_ui = call(
            [
                "UI verified with:",
                f"UD value: {'aa'*32}",
                f"Derived public key ({EXPECTED_UI_DERIVATION_PATH}): "
                f"{self.expected_ui_pubkey}",
                f"Authorized signer hash: {'cc'*32}",
                "Authorized signer iteration: 291",
                f"Installed UI hash: {'ee'*32}",
                "Installed UI version: 5.5",
            ],
            fill="-",
        )
        self.assertEqual(expected_call_ui, head_mock.call_args_list[1])

        expected_call_signer = call(
            ["Signer verified with public keys:"] + self.expected_pubkeys_output + [
                f"Hash: {self.pubkeys_hash.hex()}",
                "",
                "Installed Signer hash: ffffffffffffffffffffffffffffffffffffffffffff" +
                "ffffffffffffffffffff",
                "Installed Signer version: 5.5",
                "Platform: plf",
                "UD value: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaa",
                "Best block: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" +
                "bbbbbbbbb",
                "Last transaction signed: cccccccccccccccc",
                "Timestamp: 171",
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

    @patch("admin.verify_ledger_attestation.load_pubkeys")
    def test_verify_attestation_no_ui_derivation_key(self, load_pubkeys_mock, _):
        incomplete_pubkeys = self.public_keys
        incomplete_pubkeys.pop(EXPECTED_UI_DERIVATION_PATH, None)
        load_pubkeys_mock.return_value = incomplete_pubkeys

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.default_options)

        load_pubkeys_mock.assert_called_with(self.pubkeys_path)
        self.assertEqual((f'Public key with path {EXPECTED_UI_DERIVATION_PATH} '
                          'not present in public key file'),
                         str(e.exception))

    @patch("admin.verify_ledger_attestation.HSMCertificate")
    @patch("admin.verify_ledger_attestation.load_pubkeys")
    def test_verify_attestation_invalid_certificate(self,
                                                    load_pubkeys_mock,
                                                    certificate_mock,
                                                    _):
        load_pubkeys_mock.return_value = self.public_keys
        certificate_mock.from_jsonfile = Mock(side_effect=Exception('error-msg'))

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.default_options)

        load_pubkeys_mock.assert_called_with(self.pubkeys_path)
        self.assertEqual('While loading the attestation certificate file: error-msg',
                         str(e.exception))

    @patch("admin.verify_ledger_attestation.HSMCertificate")
    @patch("admin.verify_ledger_attestation.load_pubkeys")
    def test_verify_attestation_no_ui_att(self,
                                          load_pubkeys_mock,
                                          certificate_mock,
                                          _):
        load_pubkeys_mock.return_value = self.public_keys

        result = self.result
        result.pop('ui', None)
        att_cert = Mock()
        att_cert.validate_and_get_values = Mock(return_value=self.result)
        certificate_mock.from_jsonfile = Mock(return_value=att_cert)

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.default_options)

        load_pubkeys_mock.assert_called_with(self.pubkeys_path)
        self.assertEqual('Certificate does not contain a UI attestation',
                         str(e.exception))

    @patch("admin.verify_ledger_attestation.HSMCertificate")
    @patch("admin.verify_ledger_attestation.load_pubkeys")
    def test_verify_attestation_invalid_ui_att(self,
                                               load_pubkeys_mock,
                                               certificate_mock,
                                               _):
        load_pubkeys_mock.return_value = self.public_keys
        result = self.result
        result['ui'] = (False, 'ui')
        att_cert = Mock()
        att_cert.validate_and_get_values = Mock(return_value=result)
        certificate_mock.from_jsonfile = Mock(return_value=att_cert)

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.default_options)

        load_pubkeys_mock.assert_called_with(self.pubkeys_path)
        self.assertEqual("Invalid UI attestation: error validating 'ui'",
                         str(e.exception))

    @patch("admin.verify_ledger_attestation.HSMCertificate")
    @patch("admin.verify_ledger_attestation.load_pubkeys")
    def test_verify_attestation_no_signer_att(self,
                                              load_pubkeys_mock,
                                              certificate_mock,
                                              _):
        load_pubkeys_mock.return_value = self.public_keys
        result = self.result
        result.pop('signer', None)
        att_cert = Mock()
        att_cert.validate_and_get_values = Mock(return_value=self.result)
        certificate_mock.from_jsonfile = Mock(return_value=att_cert)

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.default_options)

        load_pubkeys_mock.assert_called_with(self.pubkeys_path)
        self.assertEqual('Certificate does not contain a Signer attestation',
                         str(e.exception))

    @patch("admin.verify_ledger_attestation.HSMCertificate")
    @patch("admin.verify_ledger_attestation.load_pubkeys")
    def test_verify_attestation_invalid_signer_att(self,
                                                   load_pubkeys_mock,
                                                   certificate_mock,
                                                   _):
        load_pubkeys_mock.return_value = self.public_keys
        result = self.result
        result['signer'] = (False, 'signer')
        att_cert = Mock()
        att_cert.validate_and_get_values = Mock(return_value=result)
        certificate_mock.from_jsonfile = Mock(return_value=att_cert)

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.default_options)

        load_pubkeys_mock.assert_called_with(self.pubkeys_path)
        self.assertEqual(("Invalid Signer attestation: error validating 'signer'"),
                         str(e.exception))

    @patch("admin.verify_ledger_attestation.HSMCertificate")
    @patch("admin.verify_ledger_attestation.load_pubkeys")
    def test_verify_attestation_invalid_signer_att_header(self,
                                                          load_pubkeys_mock,
                                                          certificate_mock, _):
        load_pubkeys_mock.return_value = self.public_keys
        signer_header = b"POWHSM:AAA::somerandomstuff".hex()
        self.result["signer"] = (True, signer_header, self.signer_hash.hex())
        att_cert = Mock()
        att_cert.validate_and_get_values = Mock(return_value=self.result)
        certificate_mock.from_jsonfile = Mock(return_value=att_cert)

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.default_options)

        load_pubkeys_mock.assert_called_with(self.pubkeys_path)
        self.assertEqual((f"Invalid Signer attestation message header: {signer_header}"),
                         str(e.exception))

    @patch("admin.verify_ledger_attestation.HSMCertificate")
    @patch("admin.verify_ledger_attestation.load_pubkeys")
    def test_verify_attestation_invalid_signer_att_msg_too_long(self,
                                                                load_pubkeys_mock,
                                                                certificate_mock, _):
        load_pubkeys_mock.return_value = self.public_keys
        signer_header = (b"POWHSM:5.9::" + b"aa"*300).hex()
        self.result["signer"] = (True, signer_header, self.signer_hash.hex())
        att_cert = Mock()
        att_cert.validate_and_get_values = Mock(return_value=self.result)
        certificate_mock.from_jsonfile = Mock(return_value=att_cert)

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.default_options)

        load_pubkeys_mock.assert_called_with(self.pubkeys_path)
        self.assertIn("Signer attestation message length mismatch", str(e.exception))

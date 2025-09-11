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
from unittest.mock import Mock, patch
from parameterized import parameterized
from admin.misc import AdminError
from admin.pubkeys import PATHS
from admin.verify_sgx_attestation import do_verify_attestation, DEFAULT_ROOT_AUTHORITY
import ecdsa
import secp256k1 as ec
import hashlib
import logging

logging.disable(logging.CRITICAL)


@patch("sys.stdout.write")
@patch("admin.verify_sgx_attestation.head")
@patch("admin.verify_sgx_attestation.HSMCertificate")
@patch("admin.verify_sgx_attestation.load_pubkeys")
@patch("admin.verify_sgx_attestation.get_sgx_root_of_trust")
class TestVerifySgxAttestation(TestCase):
    def setUp(self):
        self.certification_path = 'certification-path'
        self.pubkeys_path = 'pubkeys-path'
        self.options = SimpleNamespace(**{
            'attestation_certificate_file_path': self.certification_path,
            'pubkeys_file_path': self.pubkeys_path,
            'root_authority': None
        })

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
        self.expected_pubkeys_hash = pubkeys_hash.digest().hex()

        self.powhsm_msg = \
            b"POWHSM:5.5::" + \
            b'plf' + \
            bytes.fromhex('aa'*32) + \
            bytes.fromhex(self.expected_pubkeys_hash) + \
            bytes.fromhex('bb'*32) + \
            bytes.fromhex('cc'*8) + \
            bytes.fromhex('00'*7 + 'cd')

        self.mock_sgx_quote = SimpleNamespace(**{
            "report_body": SimpleNamespace(**{
                "mrenclave": bytes.fromhex("aabbccdd"),
                "mrsigner": bytes.fromhex("1122334455"),
            })
        })

        self.validate_result = {"quote": (
            True, {
                "sgx_quote": self.mock_sgx_quote,
                "message": self.powhsm_msg.hex()
            }, None)
        }

    def configure_mocks(self, get_sgx_root_of_trust, load_pubkeys,
                        HSMCertificate, head):
        self.root_of_trust = Mock()
        self.root_of_trust.is_valid.return_value = True
        get_sgx_root_of_trust.return_value = self.root_of_trust
        load_pubkeys.return_value = self.public_keys
        self.mock_certificate = Mock()
        self.mock_certificate.validate_and_get_values.return_value = self.validate_result
        HSMCertificate.from_jsonfile.return_value = self.mock_certificate

    @parameterized.expand([
        ("default_root", None),
        ("custom_root", "a-custom-root")
    ])
    def test_verify_attestation(self, get_sgx_root_of_trust, load_pubkeys,
                                HSMCertificate, head, _, __, custom_root):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate, head)
        if custom_root:
            self.options.root_authority = custom_root

        do_verify_attestation(self.options)

        if custom_root:
            get_sgx_root_of_trust.assert_called_with(custom_root)
        else:
            get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_called_with(self.certification_path)
        self.mock_certificate.validate_and_get_values \
            .assert_called_with(self.root_of_trust)
        head.assert_called_with([
            "powHSM verified with public keys:"
        ] + self.expected_pubkeys_output + [
            f"Hash: {self.expected_pubkeys_hash}",
            "",
            "Installed powHSM MRENCLAVE: aabbccdd",
            "Installed powHSM MRSIGNER: 1122334455",
            "Installed powHSM version: 5.5",
            "Platform: plf",
            f"UD value: {"aa"*32}",
            f"Best block: {"bb"*32}",
            f"Last transaction signed: {"cc"*8}",
            "Timestamp: 205",
        ], fill="-")

    def test_verify_attestation_err_get_root(self, get_sgx_root_of_trust, load_pubkeys,
                                             HSMCertificate, head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate, head)
        get_sgx_root_of_trust.side_effect = ValueError("root of trust error")

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("root of trust error", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_not_called()
        load_pubkeys.assert_not_called()
        HSMCertificate.from_jsonfile.assert_not_called()
        self.mock_certificate.validate_and_get_values.assert_not_called()

    def test_verify_attestation_err_root_invalid(self, get_sgx_root_of_trust,
                                                 load_pubkeys, HSMCertificate, head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate, head)
        self.root_of_trust.is_valid.return_value = False

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("self-signed root of trust", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_not_called()
        HSMCertificate.from_jsonfile.assert_not_called()
        self.mock_certificate.validate_and_get_values.assert_not_called()

    def test_verify_attestation_err_load_pubkeys(self, get_sgx_root_of_trust,
                                                 load_pubkeys, HSMCertificate, head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate, head)
        load_pubkeys.side_effect = ValueError("pubkeys error")

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("pubkeys error", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_not_called()
        self.mock_certificate.validate_and_get_values.assert_not_called()

    def test_verify_attestation_err_load_cert(self, get_sgx_root_of_trust, load_pubkeys,
                                              HSMCertificate, head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate, head)
        HSMCertificate.from_jsonfile.side_effect = ValueError("load cert error")

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("load cert error", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_called_with(self.certification_path)
        self.mock_certificate.validate_and_get_values.assert_not_called()

    def test_verify_attestation_validation_noquote(self, get_sgx_root_of_trust,
                                                   load_pubkeys, HSMCertificate, head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate, head)
        self.mock_certificate.validate_and_get_values.return_value = {"something": "else"}

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("does not contain", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_called_with(self.certification_path)
        self.mock_certificate.validate_and_get_values \
            .assert_called_with(self.root_of_trust)

    def test_verify_attestation_validation_failed(self, get_sgx_root_of_trust,
                                                  load_pubkeys, HSMCertificate, head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate, head)
        self.mock_certificate.validate_and_get_values.return_value = {
            "quote": (False, "a validation error")
        }

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("validation error", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_called_with(self.certification_path)
        self.mock_certificate.validate_and_get_values \
            .assert_called_with(self.root_of_trust)

    def test_verify_attestation_invalid_header(self, get_sgx_root_of_trust, load_pubkeys,
                                               HSMCertificate, head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate, head)
        self.validate_result["quote"][1]["message"] = "aabbccdd"

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("message header", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_called_with(self.certification_path)
        self.mock_certificate.validate_and_get_values \
            .assert_called_with(self.root_of_trust)

    def test_verify_attestation_invalid_message(self, get_sgx_root_of_trust, load_pubkeys,
                                                HSMCertificate, head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate, head)
        self.validate_result["quote"][1]["message"] = b"POWHSM:5.5::plf".hex()

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("parsing", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_called_with(self.certification_path)
        self.mock_certificate.validate_and_get_values \
            .assert_called_with(self.root_of_trust)

    def test_verify_attestation_pkh_mismatch(self, get_sgx_root_of_trust, load_pubkeys,
                                             HSMCertificate, head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate, head)
        self.public_keys.popitem()

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("hash mismatch", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_called_with(self.certification_path)
        self.mock_certificate.validate_and_get_values \
            .assert_called_with(self.root_of_trust)

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
from unittest.mock import Mock, patch, call
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
@patch("admin.verify_sgx_attestation.validate_qeid_info")
@patch("admin.verify_sgx_attestation.get_qeid_info")
@patch("admin.verify_sgx_attestation.validate_tcb_info")
@patch("admin.verify_sgx_attestation.get_tcb_info")
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

        self.mock_pck_collateral = {
            "fmspc": "aabbccddeeff",
            "other": "very",
            "important": "stuff",
        }

        self.mock_qe_collateral = "qe-collateral"

        self.validate_result = {"quote": {
            "valid": True,
            "value": {
                "sgx_quote": self.mock_sgx_quote,
                "message": self.powhsm_msg.hex(),
            },
            "tweak": None,
            "collateral": {
                "quoting_enclave": self.mock_pck_collateral,
                "attestation": self.mock_qe_collateral,
            },
        }}

    def configure_mocks(self, get_sgx_root_of_trust, load_pubkeys,
                        HSMCertificate, get_tcb_info, validate_tcb_info,
                        get_qeid_info, validate_qeid_info, head):
        self.root_of_trust = Mock()
        self.root_of_trust.is_valid.return_value = True
        self.root_of_trust.certificate = "rot-certificate"
        get_sgx_root_of_trust.return_value = self.root_of_trust
        load_pubkeys.return_value = self.public_keys
        self.mock_certificate = Mock()
        self.mock_certificate.validate_and_get_values.return_value = self.validate_result
        HSMCertificate.from_jsonfile.return_value = self.mock_certificate
        self.get_tcb_info = get_tcb_info
        get_tcb_info.return_value = {
            "tcb_info": {
                "tcbInfo": "the tcb info",
            },
            "warnings": ["w1", "w2"],
        }
        self.validate_tcb_info = validate_tcb_info
        validate_tcb_info.return_value = {
            "valid": True,
            "status": "the status",
            "date": "a date",
            "advisories": ["adv-1", "adv-2"],
            "edn": 123,
            "svns": ["one: 34", "two: 17", "three: 87"],
        }
        self.get_qeid_info = get_qeid_info
        get_qeid_info.return_value = {
            "qeid_info": {
                "enclaveIdentity": "the enclave identity"
            },
            "warnings": ["w3", "w4"],
        }
        self.validate_qeid_info = validate_qeid_info
        validate_qeid_info.return_value = {
            "valid": True,
            "status": "another status",
            "date": "another date",
            "advisories": ["adv-3", "adv-4"],
            "edn": 456,
            "isvsvn": 789
        }

    @parameterized.expand([
        ("default_root", None),
        ("custom_root", "a-custom-root")
    ])
    def test_verify_attestation(self, get_sgx_root_of_trust, load_pubkeys,
                                HSMCertificate, get_tcb_info, validate_tcb_info,
                                get_qeid_info, validate_qeid_info,
                                head, _, __, custom_root):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate,
                             get_tcb_info, validate_tcb_info,
                             get_qeid_info, validate_qeid_info, head)
        if custom_root:
            self.options.root_authority = custom_root

        with \
                patch("admin.verify_sgx_attestation.HSMCertificateV2ElementX509") as \
                HSMCertificateV2ElementX509, \
                patch("admin.verify_sgx_attestation.X509CertificateValidator") as \
                X509CertificateValidator, \
                patch("admin.verify_sgx_attestation.get_sgx_extensions") as \
                get_sgx_extensions, \
                patch("admin.verify_sgx_attestation.get_intel_pcs_x509_crl") as \
                get_intel_pcs_x509_crl:

            X509CertificateValidator.return_value = "the-cert-validator"

            do_verify_attestation(self.options)

            X509CertificateValidator.assert_called_with(get_intel_pcs_x509_crl)
            HSMCertificateV2ElementX509.set_collateral_getter.assert_called_with(
                get_sgx_extensions)
            HSMCertificateV2ElementX509.set_certificate_validator.assert_called_with(
                "the-cert-validator")

        if custom_root:
            get_sgx_root_of_trust.assert_called_with(custom_root)
        else:
            get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_called_with(self.certification_path)
        self.mock_certificate.validate_and_get_values \
            .assert_called_with(self.root_of_trust)
        self.get_tcb_info.assert_called_with(
            "https://api.trustedservices.intel.com/sgx/certification/v4/tcb",
            "aabbccddeeff",
            "rot-certificate"
        )
        self.validate_tcb_info.assert_called_with(
            self.mock_pck_collateral, "the tcb info")
        self.get_qeid_info.assert_called_with(
            "https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity",
            "rot-certificate"
        )
        self.validate_qeid_info.assert_called_with(
            self.mock_qe_collateral, "the enclave identity")

        self.assertEqual(head.call_args_list[1], call([
            "powHSM verified with public keys:"
        ] + self.expected_pubkeys_output + [
            f"Hash: {self.expected_pubkeys_hash}",
            "",
            "Installed powHSM MRENCLAVE: aabbccdd",
            "Installed powHSM MRSIGNER: 1122334455",
            "Installed powHSM version: 5.5",
            "Platform: plf",
            f"UD value: {'aa'*32}",
            f"Best block: {'bb'*32}",
            f"Last transaction signed: {'cc'*8}",
            "Timestamp: 205",
        ], fill="-"))
        self.assertEqual(head.call_args_list[2], call([
            "TCB Information:",
            "Status: the status",
            "Issued: a date",
            "Advisories: adv-1, adv-2",
            "TCB evaluation data number: 123",
            "SVNs:",
            "  - one: 34",
            "  - two: 17",
            "  - three: 87",
        ], fill="-"))

    def test_verify_attestation_err_get_root(self, get_sgx_root_of_trust, load_pubkeys,
                                             HSMCertificate, get_tcb_info,
                                             validate_tcb_info,
                                             get_qeid_info, validate_qeid_info, head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate,
                             get_tcb_info, validate_tcb_info,
                             get_qeid_info, validate_qeid_info, head)
        get_sgx_root_of_trust.side_effect = ValueError("root of trust error")

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("root of trust error", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_not_called()
        load_pubkeys.assert_not_called()
        HSMCertificate.from_jsonfile.assert_not_called()
        self.mock_certificate.validate_and_get_values.assert_not_called()
        self.get_tcb_info.assert_not_called()
        self.validate_tcb_info.assert_not_called()
        self.get_qeid_info.assert_not_called()
        self.validate_qeid_info.assert_not_called()

    def test_verify_attestation_err_root_invalid(self, get_sgx_root_of_trust,
                                                 load_pubkeys, HSMCertificate,
                                                 get_tcb_info, validate_tcb_info,
                                                 get_qeid_info, validate_qeid_info,
                                                 head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate,
                             get_tcb_info, validate_tcb_info,
                             get_qeid_info, validate_qeid_info, head)
        self.root_of_trust.is_valid.return_value = False

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("self-signed root of trust", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_not_called()
        HSMCertificate.from_jsonfile.assert_not_called()
        self.mock_certificate.validate_and_get_values.assert_not_called()
        self.get_tcb_info.assert_not_called()
        self.validate_tcb_info.assert_not_called()
        self.get_qeid_info.assert_not_called()
        self.validate_qeid_info.assert_not_called()

    def test_verify_attestation_err_load_pubkeys(self, get_sgx_root_of_trust,
                                                 load_pubkeys, HSMCertificate,
                                                 get_tcb_info, validate_tcb_info,
                                                 get_qeid_info, validate_qeid_info,
                                                 head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate,
                             get_tcb_info, validate_tcb_info,
                             get_qeid_info, validate_qeid_info, head)
        load_pubkeys.side_effect = ValueError("pubkeys error")

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("pubkeys error", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_not_called()
        self.mock_certificate.validate_and_get_values.assert_not_called()
        self.get_tcb_info.assert_not_called()
        self.validate_tcb_info.assert_not_called()
        self.get_qeid_info.assert_not_called()
        self.validate_qeid_info.assert_not_called()

    def test_verify_attestation_err_load_cert(self, get_sgx_root_of_trust, load_pubkeys,
                                              HSMCertificate, get_tcb_info,
                                              validate_tcb_info,
                                              get_qeid_info, validate_qeid_info, head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate,
                             get_tcb_info, validate_tcb_info,
                             get_qeid_info, validate_qeid_info, head)
        HSMCertificate.from_jsonfile.side_effect = ValueError("load cert error")

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("load cert error", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_called_with(self.certification_path)
        self.mock_certificate.validate_and_get_values.assert_not_called()
        self.get_tcb_info.assert_not_called()
        self.validate_tcb_info.assert_not_called()
        self.get_qeid_info.assert_not_called()
        self.validate_qeid_info.assert_not_called()

    def test_verify_attestation_validation_noquote(self, get_sgx_root_of_trust,
                                                   load_pubkeys, HSMCertificate,
                                                   get_tcb_info, validate_tcb_info,
                                                   get_qeid_info, validate_qeid_info,
                                                   head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate,
                             get_tcb_info, validate_tcb_info,
                             get_qeid_info, validate_qeid_info, head)
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
        self.get_tcb_info.assert_not_called()
        self.validate_tcb_info.assert_not_called()
        self.get_qeid_info.assert_not_called()
        self.validate_qeid_info.assert_not_called()

    def test_verify_attestation_validation_failed(self, get_sgx_root_of_trust,
                                                  load_pubkeys, HSMCertificate,
                                                  get_tcb_info, validate_tcb_info,
                                                  get_qeid_info, validate_qeid_info,
                                                  head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate,
                             get_tcb_info, validate_tcb_info,
                             get_qeid_info, validate_qeid_info, head)
        self.mock_certificate.validate_and_get_values.return_value = {
            "quote": {
                "valid": False,
                "failed_element": "the failed element",
            }
        }

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("the failed element", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_called_with(self.certification_path)
        self.mock_certificate.validate_and_get_values \
            .assert_called_with(self.root_of_trust)
        self.get_tcb_info.assert_not_called()
        self.validate_tcb_info.assert_not_called()
        self.get_qeid_info.assert_not_called()
        self.validate_qeid_info.assert_not_called()

    def test_verify_attestation_get_tcb_err(self, get_sgx_root_of_trust, load_pubkeys,
                                            HSMCertificate, get_tcb_info,
                                            validate_tcb_info,
                                            get_qeid_info, validate_qeid_info, head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate,
                             get_tcb_info, validate_tcb_info,
                             get_qeid_info, validate_qeid_info, head)
        self.get_tcb_info.side_effect = RuntimeError("oops tcb info")

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("While trying to verify TCB", str(e.exception))
        self.assertIn("oops tcb info", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_called_with(self.certification_path)
        self.mock_certificate.validate_and_get_values \
            .assert_called_with(self.root_of_trust)
        self.get_tcb_info.assert_called_with(
            "https://api.trustedservices.intel.com/sgx/certification/v4/tcb",
            "aabbccddeeff",
            "rot-certificate"
        )
        self.validate_tcb_info.assert_not_called()
        self.get_qeid_info.assert_not_called()
        self.validate_qeid_info.assert_not_called()

    def test_verify_attestation_verify_tcb_err(self, get_sgx_root_of_trust, load_pubkeys,
                                               HSMCertificate, get_tcb_info,
                                               validate_tcb_info,
                                               get_qeid_info, validate_qeid_info,
                                               head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate,
                             get_tcb_info, validate_tcb_info,
                             get_qeid_info, validate_qeid_info, head)
        self.validate_tcb_info.return_value = {
            "valid": False,
            "reason": "This is the verification error",
        }

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("While trying to verify TCB", str(e.exception))
        self.assertIn("the verification error", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_called_with(self.certification_path)
        self.mock_certificate.validate_and_get_values \
            .assert_called_with(self.root_of_trust)
        self.get_tcb_info.assert_called_with(
            "https://api.trustedservices.intel.com/sgx/certification/v4/tcb",
            "aabbccddeeff",
            "rot-certificate"
        )
        self.validate_tcb_info.assert_called_with(
            self.mock_pck_collateral, "the tcb info")
        self.get_qeid_info.assert_not_called()
        self.validate_qeid_info.assert_not_called()

    def test_verify_attestation_get_qeid_err(self, get_sgx_root_of_trust, load_pubkeys,
                                             HSMCertificate, get_tcb_info,
                                             validate_tcb_info,
                                             get_qeid_info, validate_qeid_info, head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate,
                             get_tcb_info, validate_tcb_info,
                             get_qeid_info, validate_qeid_info, head)
        self.get_qeid_info.side_effect = RuntimeError("oops qeid info")

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("While trying to verify QE ID", str(e.exception))
        self.assertIn("oops qeid info", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_called_with(self.certification_path)
        self.mock_certificate.validate_and_get_values \
            .assert_called_with(self.root_of_trust)
        self.get_tcb_info.assert_called_with(
            "https://api.trustedservices.intel.com/sgx/certification/v4/tcb",
            "aabbccddeeff",
            "rot-certificate"
        )
        self.validate_tcb_info.assert_called_with(
            self.mock_pck_collateral, "the tcb info")
        self.get_qeid_info.assert_called_with(
            "https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity",
            "rot-certificate"
        )
        self.validate_qeid_info.assert_not_called()

    def test_verify_attestation_verify_qeid_err(self, get_sgx_root_of_trust, load_pubkeys,
                                                HSMCertificate, get_tcb_info,
                                                validate_tcb_info,
                                                get_qeid_info, validate_qeid_info,
                                                head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate,
                             get_tcb_info, validate_tcb_info,
                             get_qeid_info, validate_qeid_info, head)
        self.validate_qeid_info.return_value = {
            "valid": False,
            "reason": "This is the verification error",
        }

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("While trying to verify QE ID", str(e.exception))
        self.assertIn("the verification error", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_called_with(self.certification_path)
        self.mock_certificate.validate_and_get_values \
            .assert_called_with(self.root_of_trust)
        self.get_tcb_info.assert_called_with(
            "https://api.trustedservices.intel.com/sgx/certification/v4/tcb",
            "aabbccddeeff",
            "rot-certificate"
        )
        self.validate_tcb_info.assert_called_with(
            self.mock_pck_collateral, "the tcb info")
        self.get_qeid_info.assert_called_with(
            "https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity",
            "rot-certificate"
        )
        self.validate_qeid_info.assert_called_with(
            self.mock_qe_collateral, "the enclave identity")

    def test_verify_attestation_invalid_header(self, get_sgx_root_of_trust, load_pubkeys,
                                               HSMCertificate, get_tcb_info,
                                               validate_tcb_info,
                                               get_qeid_info, validate_qeid_info,
                                               head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate,
                             get_tcb_info, validate_tcb_info,
                             get_qeid_info, validate_qeid_info, head)
        self.validate_result["quote"]["value"]["message"] = "aabbccdd"

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("message header", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_called_with(self.certification_path)
        self.mock_certificate.validate_and_get_values \
            .assert_called_with(self.root_of_trust)
        self.get_tcb_info.assert_called_with(
            "https://api.trustedservices.intel.com/sgx/certification/v4/tcb",
            "aabbccddeeff",
            "rot-certificate"
        )
        self.validate_tcb_info.assert_called_with(
            self.mock_pck_collateral, "the tcb info")
        self.get_qeid_info.assert_called_with(
            "https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity",
            "rot-certificate"
        )
        self.validate_qeid_info.assert_called_with(
            self.mock_qe_collateral, "the enclave identity")

    def test_verify_attestation_invalid_message(self, get_sgx_root_of_trust, load_pubkeys,
                                                HSMCertificate, get_tcb_info,
                                                validate_tcb_info,
                                                get_qeid_info, validate_qeid_info,
                                                head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate,
                             get_tcb_info, validate_tcb_info,
                             get_qeid_info, validate_qeid_info, head)
        self.validate_result["quote"]["value"]["message"] = b"POWHSM:5.5::plf".hex()

        with self.assertRaises(AdminError) as e:
            do_verify_attestation(self.options)
        self.assertIn("parsing", str(e.exception))

        get_sgx_root_of_trust.assert_called_with(DEFAULT_ROOT_AUTHORITY)
        self.root_of_trust.is_valid.assert_called_with(self.root_of_trust)
        load_pubkeys.assert_called_with(self.pubkeys_path)
        HSMCertificate.from_jsonfile.assert_called_with(self.certification_path)
        self.mock_certificate.validate_and_get_values \
            .assert_called_with(self.root_of_trust)
        self.get_tcb_info.assert_called_with(
            "https://api.trustedservices.intel.com/sgx/certification/v4/tcb",
            "aabbccddeeff",
            "rot-certificate"
        )
        self.validate_tcb_info.assert_called_with(
            self.mock_pck_collateral, "the tcb info")
        self.get_qeid_info.assert_called_with(
            "https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity",
            "rot-certificate"
        )
        self.validate_qeid_info.assert_called_with(
            self.mock_qe_collateral, "the enclave identity")

    def test_verify_attestation_pkh_mismatch(self, get_sgx_root_of_trust, load_pubkeys,
                                             HSMCertificate, get_tcb_info,
                                             validate_tcb_info,
                                             get_qeid_info, validate_qeid_info, head, _):
        self.configure_mocks(get_sgx_root_of_trust, load_pubkeys, HSMCertificate,
                             get_tcb_info, validate_tcb_info,
                             get_qeid_info, validate_qeid_info, head)
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
        self.get_tcb_info.assert_called_with(
            "https://api.trustedservices.intel.com/sgx/certification/v4/tcb",
            "aabbccddeeff",
            "rot-certificate"
        )
        self.validate_tcb_info.assert_called_with(
            self.mock_pck_collateral, "the tcb info")
        self.get_qeid_info.assert_called_with(
            "https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity",
            "rot-certificate"
        )
        self.validate_qeid_info.assert_called_with(
            self.mock_qe_collateral, "the enclave identity")

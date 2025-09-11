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
import secp256k1 as ec
from unittest import TestCase
from unittest.mock import patch, mock_open
from parameterized import parameterized
from admin.attestation_utils import AdminError, PowHsmAttestationMessage, load_pubkeys, \
                                    compute_pubkeys_hash, compute_pubkeys_output, \
                                    get_sgx_root_of_trust
from .test_attestation_utils_resources import TEST_PUBKEYS_JSON, \
                                              TEST_PUBKEYS_JSON_INVALID
import logging

logging.disable(logging.CRITICAL)


class TestPowHsmAttestationMessage(TestCase):
    @parameterized.expand([
        ("ok_exact", True, b"POWHSM:5.6::"),
        ("ok_longer", True, b"POWHSM:5.3::whatcomesafterwards"),
        ("version_mismatch", False, b"POWHSM:4.3::"),
        ("shorter", False, b"POWHSM:5.3:"),
        ("invalid", False, b"something invalid"),
    ])
    def test_is_header(self, _, expected, header):
        self.assertEqual(expected, PowHsmAttestationMessage.is_header(header))

    def test_parse_ok(self):
        msg = PowHsmAttestationMessage(
            b"POWHSM:5.7::" +
            b"abc" +
            bytes.fromhex("aa"*32) +
            bytes.fromhex("bb"*32) +
            bytes.fromhex("cc"*32) +
            bytes.fromhex("dd"*8) +
            bytes.fromhex("00"*7 + "83")
        )

        self.assertEqual("abc", msg.platform)
        self.assertEqual(bytes.fromhex("aa"*32), msg.ud_value)
        self.assertEqual(bytes.fromhex("bb"*32), msg.public_keys_hash)
        self.assertEqual(bytes.fromhex("cc"*32), msg.best_block)
        self.assertEqual(bytes.fromhex("dd"*8), msg.last_signed_tx)
        self.assertEqual(0x83, msg.timestamp)

    def test_parse_header_mismatch(self):
        with self.assertRaises(ValueError) as e:
            PowHsmAttestationMessage(
                b"POWHSM:3.0::" +
                b"abc" +
                bytes.fromhex("aa"*32) +
                bytes.fromhex("bb"*32) +
                bytes.fromhex("cc"*32) +
                bytes.fromhex("dd"*8) +
                bytes.fromhex("00"*7 + "83") +
                b"0"
            )
        self.assertIn("header", str(e.exception))

    def test_parse_shorter(self):
        with self.assertRaises(ValueError) as e:
            PowHsmAttestationMessage(
                b"POWHSM:5.7::" +
                b"abc" +
                bytes.fromhex("aa"*32) +
                bytes.fromhex("bb"*32) +
                bytes.fromhex("cc"*32) +
                bytes.fromhex("dd"*8) +
                bytes.fromhex("00"*6 + "83")
            )
        self.assertIn("length mismatch", str(e.exception))

    def test_parse_longer(self):
        with self.assertRaises(ValueError) as e:
            PowHsmAttestationMessage(
                b"POWHSM:5.7::" +
                b"abc" +
                bytes.fromhex("aa"*32) +
                bytes.fromhex("bb"*32) +
                bytes.fromhex("cc"*32) +
                bytes.fromhex("dd"*8) +
                bytes.fromhex("00"*7 + "83") +
                b"0"
            )
        self.assertIn("length mismatch", str(e.exception))


class TestLoadPubKeys(TestCase):
    def test_load_pubkeys_ok(self):
        with patch("builtins.open", mock_open()) as file_mock:
            file_mock.return_value.read.return_value = TEST_PUBKEYS_JSON
            pubkeys = load_pubkeys("a-path")

        file_mock.assert_called_with("a-path", "r")
        self.assertEqual([
            "m/44'/1'/0'/0/0",
            "m/44'/1'/1'/0/0",
            "m/44'/1'/2'/0/0",
        ], list(pubkeys.keys()))
        self.assertEqual(bytes.fromhex(
            "03abe31ee7c91976f7a56d8e196d82d5ce75a0fcc2935723bf25610d22bd81e50f"),
            pubkeys["m/44'/1'/0'/0/0"].serialize(compressed=True))
        self.assertEqual(bytes.fromhex(
            "03d44eac557a58be6cd4a40cbdaa9ed22cf4f0322e8c7bb84f6421d5bdda3b99ff"),
            pubkeys["m/44'/1'/1'/0/0"].serialize(compressed=True))
        self.assertEqual(bytes.fromhex(
            "02877a756d2b82ddff342fa327b065326001b204b2f86a24ac36638b5162330141"),
            pubkeys["m/44'/1'/2'/0/0"].serialize(compressed=True))

    def test_load_pubkeys_file_doesnotexist(self):
        with patch("builtins.open", mock_open()) as file_mock:
            file_mock.side_effect = FileNotFoundError("another error")
            with self.assertRaises(AdminError) as e:
                load_pubkeys("a-path")
        file_mock.assert_called_with("a-path", "r")
        self.assertIn("another error", str(e.exception))

    def test_load_pubkeys_invalid_json(self):
        with patch("builtins.open", mock_open()) as file_mock:
            file_mock.return_value.read.return_value = "not json"
            with self.assertRaises(AdminError) as e:
                load_pubkeys("a-path")
        file_mock.assert_called_with("a-path", "r")
        self.assertIn("Unable to read", str(e.exception))

    def test_load_pubkeys_notamap(self):
        with patch("builtins.open", mock_open()) as file_mock:
            file_mock.return_value.read.return_value = "[1,2,3]"
            with self.assertRaises(AdminError) as e:
                load_pubkeys("a-path")
        file_mock.assert_called_with("a-path", "r")
        self.assertIn("top level", str(e.exception))

    def test_load_pubkeys_invalid_pubkey(self):
        with patch("builtins.open", mock_open()) as file_mock:
            file_mock.return_value.read.return_value = TEST_PUBKEYS_JSON_INVALID
            with self.assertRaises(AdminError) as e:
                load_pubkeys("a-path")
        file_mock.assert_called_with("a-path", "r")
        self.assertIn("public key", str(e.exception))


class TestComputePubkeysHash(TestCase):
    def test_ok(self):
        expected_hash = bytes.fromhex(
            "ad33c8be1af2520e2c533d883a2021654102917969816cd1b9dacfcccf4e139e")

        def to_pub(h):
            return ec.PrivateKey(bytes.fromhex(h), raw=True).pubkey

        keys = {
            "1first":  to_pub("11"*32),
            "3third":  to_pub("33"*32),
            "2second": to_pub("22"*32),
        }

        self.assertEqual(expected_hash, compute_pubkeys_hash(keys))

    def test_empty_errors(self):
        with self.assertRaises(AdminError) as e:
            compute_pubkeys_hash({})
        self.assertIn("empty", str(e.exception))


class TestComputePubkeysOutput(TestCase):
    def test_sample_output(self):
        class PubKey:
            def __init__(self, h):
                self.h = h

            def serialize(self, compressed):
                return bytes.fromhex(self.h) if compressed else ""

        keys = {
            "name":  PubKey("11223344"),
            "longer_name":  PubKey("aabbcc"),
            "very_very_long_name": PubKey("6677889900"),
        }

        self.assertEqual([
            "longer_name:         aabbcc",
            "name:                11223344",
            "very_very_long_name: 6677889900",
        ], compute_pubkeys_output(keys))


class TestGetRootOfTrust(TestCase):
    @patch("admin.attestation_utils.HSMCertificateV2ElementX509")
    @patch("admin.attestation_utils.Path")
    def test_file_ok(self, path, HSMCertificateV2ElementX509):
        path.return_value.is_file.return_value = True
        HSMCertificateV2ElementX509.from_pemfile.return_value = "the-result"

        self.assertEqual("the-result", get_sgx_root_of_trust("a-file-path"))

        path.assert_called_with("a-file-path")
        HSMCertificateV2ElementX509.from_pemfile.assert_called_with(
            "a-file-path", "sgx_root", "sgx_root")

    @patch("admin.attestation_utils.HSMCertificateV2ElementX509")
    @patch("admin.attestation_utils.Path")
    def test_file_invalid(self, path, HSMCertificateV2ElementX509):
        path.return_value.is_file.return_value = True
        err = ValueError("something wrong")
        HSMCertificateV2ElementX509.from_pemfile.side_effect = err

        with self.assertRaises(ValueError) as e:
            get_sgx_root_of_trust("a-file-path")
        self.assertEqual(err, e.exception)

        path.assert_called_with("a-file-path")
        HSMCertificateV2ElementX509.from_pemfile.assert_called_with(
            "a-file-path", "sgx_root", "sgx_root")

    @patch("admin.attestation_utils.requests")
    @patch("admin.attestation_utils.HSMCertificateV2ElementX509")
    @patch("admin.attestation_utils.Path")
    def test_url_ok(self, path, HSMCertificateV2ElementX509, requests):
        path.return_value.is_file.return_value = False
        requests.get.return_value = SimpleNamespace(**{
            "status_code": 200,
            "content": b"some-pem",
        })
        HSMCertificateV2ElementX509.from_pem.return_value = "the-result"

        self.assertEqual("the-result", get_sgx_root_of_trust("a-url"))

        path.assert_called_with("a-url")
        requests.get.assert_called_with("a-url")
        HSMCertificateV2ElementX509.from_pem.assert_called_with(
            "some-pem", "sgx_root", "sgx_root")

    @patch("admin.attestation_utils.requests")
    @patch("admin.attestation_utils.HSMCertificateV2ElementX509")
    @patch("admin.attestation_utils.Path")
    def test_url_error_get(self, path, HSMCertificateV2ElementX509, requests):
        path.return_value.is_file.return_value = False
        requests.get.return_value = SimpleNamespace(**{
            "status_code": 123,
        })

        with self.assertRaises(RuntimeError) as e:
            get_sgx_root_of_trust("a-url")
        self.assertIn("fetching root of trust", str(e.exception))

        path.assert_called_with("a-url")
        requests.get.assert_called_with("a-url")
        HSMCertificateV2ElementX509.from_pem.assert_not_called()

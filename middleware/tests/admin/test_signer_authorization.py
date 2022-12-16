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
from unittest.mock import patch, call, mock_open
from admin.signer_authorization import SignerAuthorization, SignerVersion
import sha3
import json

import logging

logging.disable(logging.CRITICAL)


class TestSignerAuthorization(TestCase):
    def setUp(self):
        self.sigs = [
            "3044022039c6785195590cf80a39473a3c74196fb00768b4fa0afa42e542a2cdbf17a09102201f47eb7939da1dded637dfef6911d7c6f2c52943f02f32947620a1c82ecfb1e9", # noqa E501
            "304402206d327be3539bd0187525420554f6087a50a7edab89bf69b001d40936bff41adf02206c46e02c7df30191eddbac780037bd6aed888a0cc09af02dac46afc8cbabe54a", # noqa E501
            "3044022054440c5d33490590c7b75ec7c2f2756cded50796b8e5b984574656e5506cebd302200ac695c65c4b2d43af072fa7068b1119245a5a72ecfa920794f2fa82398f563d", # noqa E501
        ]

        self.sigver = SignerVersion("cc"*32, 123)

        self.sa = SignerAuthorization(self.sigver, self.sigs)

    def test_signer_version_n_signatures(self):
        self.assertEqual(self.sa.signer_version.hash, "cc"*32)
        self.assertEqual(self.sa.signer_version.iteration, 123)
        self.assertEqual(self.sa.signatures, self.sigs)
        self.assertIsNot(self.sa.signatures, self.sigs)

    def test_invalid_signer_version(self):
        with self.assertRaises(ValueError):
            SignerAuthorization("not-a-signer-version", self.sigs)

    def test_invalid_signatures(self):
        with self.assertRaises(ValueError):
            SignerAuthorization(self.sigver, "not-an-array")

    def test_invalid_signature(self):
        with self.assertRaises(ValueError):
            SignerAuthorization(self.sigver, [self.sigs[0], "not-a-valid-signature"])

    def test_to_dict(self):
        self.assertEqual({
            "version": 1,
            "signer": {
                "hash": "cc"*32,
                "iteration": 123,
            },
            "signatures": self.sigs
        }, self.sa.to_dict())

    def test_add_signature(self):
        new_sig = "304402206028c2917d0dfd66b92754750b4e2dbc6459de"\
                  "2dff598f0014470ee02e3c020702202baf9cab552b5021"\
                  "c7f3966fb7051be2ec1d273b3d5d1ce02e1ae73d1d8038ed"
        self.sa.add_signature(new_sig)

        self.assertEqual(self.sa.signatures, self.sigs + [new_sig])

    def test_add_invalid_signature(self):
        with self.assertRaises(ValueError):
            self.sa.add_signature("invalid-signature")

    def test_save_to_jsonfile(self):
        with patch("builtins.open", mock_open()) as open_mock:
            self.sa.save_to_jsonfile("/a/file/path.json")

        self.assertEqual([call("/a/file/path.json", "w")], open_mock.call_args_list)
        self.assertEqual([call(json.dumps(self.sa.to_dict(), indent=2) + "\n")],
                         open_mock.return_value.write.call_args_list)

    def test_from_jsonfile(self):
        jsonsample = """
        {
          "version": 1,
          "signer": {
            "hash": "0123456789012345678901234567890123456789012345678901234567891122",
            "iteration": 345 },
          "signatures": [
              "3044022039e6db716cd2ce9efbd29a01afd50ffb04bae58ac747dc847b5af34bec03a195022060ffa2e7758a92a53093a672f3813d17352212dfab9535fd4927dbbf487d910a",
              "304402201ef9d2a728e86aa3e8a0cf27a1f6afeba84af90f89ea50ea14483c4bd0c17fcd02201b6130ab0aed38128a4637b93ac90484aa2361c014e89c915d061fd27cab6aa6"
          ]
        }
        """

        with patch("builtins.open", mock_open()) as open_mock:
            open_mock.return_value.read.return_value = jsonsample

            sa = SignerAuthorization.from_jsonfile("/an/existing/file.json")

        self.assertEqual([call("/an/existing/file.json", "r")], open_mock.call_args_list)
        self.assertEqual(
            "0123456789012345678901234567890123456789012345678901234567891122",
            sa.signer_version.hash)
        self.assertEqual(345, sa.signer_version.iteration)
        self.assertEqual([
            "3044022039e6db716cd2ce9efbd29a01afd50ffb04bae58ac747dc847b5af34bec03a195022060ffa2e7758a92a53093a672f3813d17352212dfab9535fd4927dbbf487d910a",  # noqa E501
            "304402201ef9d2a728e86aa3e8a0cf27a1f6afeba84af90f89ea50ea14483c4bd0c17fcd02201b6130ab0aed38128a4637b93ac90484aa2361c014e89c915d061fd27cab6aa6",  # noqa E501
        ], sa.signatures)

    def test_from_jsonfile_invalid_json(self):
        jsonsample = """
        { THISISNOTJSON
          "version": 1,
          "signer": {
            "hash": "0123456789012345678901234567890123456789012345678901234567891122",
            "iteration": 345 },
          "signatures": []
        }
        """

        with patch("builtins.open", mock_open()) as open_mock:
            open_mock.return_value.read.return_value = jsonsample

            with self.assertRaises(ValueError):
                SignerAuthorization.from_jsonfile("/an/existing/file.json")

    def test_from_jsonfile_invalid_version(self):
        jsonsample = """
        {
          "version": 2,
          "signer": {
            "hash": "0123456789012345678901234567890123456789012345678901234567891122",
            "iteration": 345 },
          "signatures": [
              "3044022039e6db716cd2ce9efbd29a01afd50ffb04bae58ac747dc847b5af34bec03a195022060ffa2e7758a92a53093a672f3813d17352212dfab9535fd4927dbbf487d910a",
              "304402201ef9d2a728e86aa3e8a0cf27a1f6afeba84af90f89ea50ea14483c4bd0c17fcd02201b6130ab0aed38128a4637b93ac90484aa2361c014e89c915d061fd27cab6aa6"
          ]
        }
        """

        with patch("builtins.open", mock_open()) as open_mock:
            open_mock.return_value.read.return_value = jsonsample

            with self.assertRaises(ValueError):
                SignerAuthorization.from_jsonfile("/an/existing/file.json")

    def test_from_jsonfile_invalid_hash(self):
        jsonsample = """
        {
          "version": 1,
          "signer": {
            "hash": "not-a-hash",
            "iteration": 345 },
          "signatures": [
              "3044022039e6db716cd2ce9efbd29a01afd50ffb04bae58ac747dc847b5af34bec03a195022060ffa2e7758a92a53093a672f3813d17352212dfab9535fd4927dbbf487d910a",
              "304402201ef9d2a728e86aa3e8a0cf27a1f6afeba84af90f89ea50ea14483c4bd0c17fcd02201b6130ab0aed38128a4637b93ac90484aa2361c014e89c915d061fd27cab6aa6"
          ]
        }
        """

        with patch("builtins.open", mock_open()) as open_mock:
            open_mock.return_value.read.return_value = jsonsample

            with self.assertRaises(ValueError):
                SignerAuthorization.from_jsonfile("/an/existing/file.json")

    def test_from_jsonfile_invalid_iteration(self):
        jsonsample = """
        {
          "version": 1,
          "signer": {
            "hash": "0123456789012345678901234567890123456789012345678901234567891122",
            "iteration": "not-an-iteration" },
          "signatures": [
              "3044022039e6db716cd2ce9efbd29a01afd50ffb04bae58ac747dc847b5af34bec03a195022060ffa2e7758a92a53093a672f3813d17352212dfab9535fd4927dbbf487d910a",
              "304402201ef9d2a728e86aa3e8a0cf27a1f6afeba84af90f89ea50ea14483c4bd0c17fcd02201b6130ab0aed38128a4637b93ac90484aa2361c014e89c915d061fd27cab6aa6"
          ]
        }
        """

        with patch("builtins.open", mock_open()) as open_mock:
            open_mock.return_value.read.return_value = jsonsample

            with self.assertRaises(ValueError):
                SignerAuthorization.from_jsonfile("/an/existing/file.json")

    def test_from_jsonfile_invalid_signatures(self):
        jsonsample = """
        {
          "version": 1,
          "signer": {
            "hash": "0123456789012345678901234567890123456789012345678901234567891122",
            "iteration": 345 },
          "signatures": "not-signatures"
        }
        """

        with patch("builtins.open", mock_open()) as open_mock:
            open_mock.return_value.read.return_value = jsonsample

            with self.assertRaises(ValueError):
                SignerAuthorization.from_jsonfile("/an/existing/file.json")

    def test_from_jsonfile_invalid_signature(self):
        jsonsample = """
        {
          "version": 1,
          "signer": {
            "hash": "0123456789012345678901234567890123456789012345678901234567891122",
            "iteration": 345 },
          "signatures": [
              "not-a-signature",
              "304402201ef9d2a728e86aa3e8a0cf27a1f6afeba84af90f89ea50ea14483c4bd0c17fcd02201b6130ab0aed38128a4637b93ac90484aa2361c014e89c915d061fd27cab6aa6"
          ]
        }
        """

        with patch("builtins.open", mock_open()) as open_mock:
            open_mock.return_value.read.return_value = jsonsample

            with self.assertRaises(ValueError):
                SignerAuthorization.from_jsonfile("/an/existing/file.json")


class TestSignerVersion(TestCase):
    def test_hash_iteration(self):
        sv = SignerVersion("AA"*32, "0x2d")

        self.assertEqual(sv.hash, "aa"*32)
        self.assertEqual(sv.iteration, 45)

    def test_invalid_hash(self):
        with self.assertRaises(ValueError):
            SignerVersion("notahash", 45)

    def test_invalid_version(self):
        with self.assertRaises(ValueError):
            SignerVersion("aa"*32, "not-a-number")

    def test_authorization_message(self):
        sv = SignerVersion("aa" + "BB"*30 + "cc", "0x2d")

        self.assertEqual(b"\x19Ethereum Signed Message:\n95RSK_powHSM_signer_aa"
                         b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                         b"bbbbbbbbcc_iteration_45",
                         sv.get_authorization_msg())

    def test_authorization_digest(self):
        sv = SignerVersion("aa" + "BB"*30 + "cc", "0x2d")

        self.assertEqual(
            sha3.keccak_256(b"\x19Ethereum Signed Message:\n95RSK_powHSM_"
                            b"signer_aabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            b"bbbbbbbbbbcc_iteration_45").digest(),
            sv.get_authorization_digest())

    def test_to_dict(self):
        sv = SignerVersion("aa" + "BB"*30 + "cc", "0x2d")

        self.assertEqual({
                "hash": "aabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        "cc",
                "iteration": 45,
            }, sv.to_dict())

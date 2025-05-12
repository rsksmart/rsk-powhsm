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
from admin.sgx_migration_authorization import SGXMigrationAuthorization, SGXMigrationSpec
from comm.utils import keccak_256
import json

import logging

logging.disable(logging.CRITICAL)


class TestSGXAuthorization(TestCase):
    def setUp(self):
        # Sample valid DER signatures
        self.sigs = [
            "3045022100f31ee73e3b10c5d610d9f5501e12ce1f2fd31182d0630c8e0db75fba3f35bbe3022056d0703a27937aec36a0a05bd5b85de6144279ab3a66faf266378ce42a838831",  # noqa E501
            "3046022100d2e039915b4decd3d32d613bdcfc84090560e0e714284ff4c3b454b563d81c7c022100ff0de20f22f75a87cf546a6e3dd9dada082b0bdd01862e1c566e5bdd67f0c3b1",  # noqa E501
        ]

        # Sample mrenclave values (32-byte hex strings)
        self.exporter_mrenclave = "aa" * 32
        self.importer_mrenclave = "bb" * 32

        # Create migration spec
        self.migration_spec = SGXMigrationSpec({
            "exporter": self.exporter_mrenclave,
            "importer": self.importer_mrenclave
        })

        # Create SGX authorization instance
        self.sa = SGXMigrationAuthorization(self.migration_spec, self.sigs)

    def test_migration_spec_n_signatures(self):
        # Test basic property getters and verify signatures list is copied
        self.assertEqual(self.sa.migration_spec.exporter, self.exporter_mrenclave)
        self.assertEqual(self.sa.migration_spec.importer, self.importer_mrenclave)
        self.assertEqual(self.sa.signatures, self.sigs)
        self.assertIsNot(self.sa.signatures, self.sigs)  # Verify list is copied

    def test_invalid_migration_spec(self):
        # Test constructor with invalid migration spec
        with self.assertRaises(ValueError):
            SGXMigrationAuthorization("not-a-migration-spec", self.sigs)

    def test_invalid_signatures(self):
        # Test constructor with invalid signatures (non-list)
        with self.assertRaises(ValueError):
            SGXMigrationAuthorization(self.migration_spec, "not-an-array")

    def test_invalid_signature(self):
        # Test constructor with invalid signature format
        with self.assertRaises(ValueError):
            SGXMigrationAuthorization(
                self.migration_spec,
                [self.sigs[0], "not-a-valid-signature"]
            )

    def test_to_dict(self):
        # Test dictionary conversion
        expected_dict = {
            "version": 1,
            "hashes": {
                "exporter": self.exporter_mrenclave,
                "importer": self.importer_mrenclave,
            },
            "signatures": self.sigs
        }
        self.assertEqual(expected_dict, self.sa.to_dict())

    def test_add_signature(self):
        # Test adding a valid signature
        new_sig = "3045022100d2dac5b641d6a454cacdff045ab428bfc4c86e"\
                  "004ff69728050a33788f6e9e7602207e8b3536a7a50185e2"\
                  "7219237358823b98678fe32aa7a30b31155cbffad3747d"
        self.sa.add_signature(new_sig)
        self.assertEqual(self.sa.signatures, self.sigs + [new_sig])

    def test_add_duplicate_signature_not_allowed(self):
        # Adding the same signature should not be allowed
        with self.assertRaises(ValueError) as e:
            self.sa.add_signature(self.sigs[0])
        self.assertEqual(
            str(e.exception),
            "Signature already exists"
        )

    def test_add_invalid_signature(self):
        # Test signature validation with various invalid formats
        invalid_signatures = [
            "not-a-signature",
            "0x1234",  # Too short
            "0x" + "1" * 100,  # Too long
        ]
        for sig in invalid_signatures:
            with self.assertRaises(ValueError):
                self.sa.add_signature(sig)

    def test_save_to_jsonfile(self):
        # Test saving authorization to JSON file
        with patch("builtins.open", mock_open()) as open_mock:
            self.sa.save_to_jsonfile("/a/file/path.json")

        self.assertEqual([call("/a/file/path.json", "w")], open_mock.call_args_list)
        self.assertEqual([call(json.dumps(self.sa.to_dict(), indent=2))],
                         open_mock.return_value.write.call_args_list)

    def test_from_jsonfile(self):
        # Test loading authorization from valid JSON file
        jsonsample = """
        {
          "version": 1,
          "hashes": {
            "exporter": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "importer": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          },
          "signatures": [
            "3045022100f31ee73e3b10c5d610d9f5501e12ce1f2fd31182d0630c8e0db75fba3f35bbe3022056d0703a27937aec36a0a05bd5b85de6144279ab3a66faf266378ce42a838831",
            "3046022100d2e039915b4decd3d32d613bdcfc84090560e0e714284ff4c3b454b563d81c7c022100ff0de20f22f75a87cf546a6e3dd9dada082b0bdd01862e1c566e5bdd67f0c3b1"
          ]
        }
        """  # noqa E501

        with patch("builtins.open", mock_open()) as open_mock:
            open_mock.return_value.read.return_value = jsonsample
            sa = SGXMigrationAuthorization.from_jsonfile("/an/existing/file.json")

        self.assertEqual([call("/an/existing/file.json", "r")], open_mock.call_args_list)
        self.assertEqual("aa" * 32, sa.migration_spec.exporter)
        self.assertEqual("bb" * 32, sa.migration_spec.importer)
        self.assertEqual(
            [
                "3045022100f31ee73e3b10c5d610d9f5501e12ce1f2fd31182d0630c8e0db75fba3f35bbe3022056d0703a27937aec36a0a05bd5b85de6144279ab3a66faf266378ce42a838831",  # noqa E501
                "3046022100d2e039915b4decd3d32d613bdcfc84090560e0e714284ff4c3b454b563d81c7c022100ff0de20f22f75a87cf546a6e3dd9dada082b0bdd01862e1c566e5bdd67f0c3b1"  # noqa E501
            ],
            sa.signatures)

    def test_from_jsonfile_invalid_json(self):
        # Test loading authorization from invalid JSON file
        jsonsample = """
        { THISISNOTJSON
          "version": 1,
          "hashes": {
            "exporter": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "importer": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          },
          "signatures": []
        }
        """  # noqa E501

        with patch("builtins.open", mock_open()) as open_mock:
            open_mock.return_value.read.return_value = jsonsample

            with self.assertRaises(ValueError):
                SGXMigrationAuthorization.from_jsonfile("/an/existing/file.json")

    def test_from_jsonfile_invalid_version(self):
        # Test loading authorization with invalid version
        jsonsample = """
        {
          "version": 2,
          "hashes": {
            "exporter": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "importer": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          },
          "signatures": []
        }
        """  # noqa E501

        with patch("builtins.open", mock_open()) as open_mock:
            open_mock.return_value.read.return_value = jsonsample

            with self.assertRaises(ValueError):
                SGXMigrationAuthorization.from_jsonfile("/an/existing/file.json")

    def test_from_jsonfile_invalid_migration_spec(self):
        # Test loading authorization with invalid migration spec
        jsonsample = """
        {
          "version": 1,
          "hashes": {
            "exporter": "not-a-mrenclave",
            "importer": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          },
          "signatures": []
        }
        """

        with patch("builtins.open", mock_open()) as open_mock:
            open_mock.return_value.read.return_value = jsonsample

            with self.assertRaises(ValueError):
                SGXMigrationAuthorization.from_jsonfile("/an/existing/file.json")

    def test_from_jsonfile_invalid_signatures(self):
        # Test loading authorization with invalid signatures format
        jsonsample = """
        {
          "version": 1,
          "hashes": {
            "exporter": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "importer": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          },
          "signatures": "not-signatures"
        }
        """  # noqa E501

        with patch("builtins.open", mock_open()) as open_mock:
            open_mock.return_value.read.return_value = jsonsample

            with self.assertRaises(ValueError):
                SGXMigrationAuthorization.from_jsonfile("/an/existing/file.json")

    def test_from_jsonfile_invalid_signature(self):
        # Test loading authorization with invalid signature format
        jsonsample = """
        {
          "version": 1,
          "hashes": {
            "exporter": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "importer": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          },
          "signatures": [
              "not-a-signature",
              "304402201ef9d2a728e86aa3e8a0cf27a1f6afeba84af90f89ea50ea14483c4bd0c17fcd02201b6130ab0aed38128a4637b93ac90484aa2361c014e89c915d061fd27cab6aa6"
          ]
        }
        """  # noqa E501

        with patch("builtins.open", mock_open()) as open_mock:
            open_mock.return_value.read.return_value = jsonsample

            with self.assertRaises(ValueError):
                SGXMigrationAuthorization.from_jsonfile("/an/existing/file.json")

    def test_authorization_message(self):
        # Test authorization message format
        expected_msg = (b"\x19Ethereum Signed Message:\n" +
                        b"160" +
                        b"RSK_powHSM_SGX_upgrade_from_" +
                        self.exporter_mrenclave.encode("ASCII") +
                        b"_to_" + self.importer_mrenclave.encode("ASCII"))
        self.assertEqual(expected_msg, self.sa.migration_spec.get_authorization_msg())


class TestMigrationSpec(TestCase):
    def setUp(self):
        # Sample mrenclave values (32-byte hex strings)
        self.exporter_mrenclave = "aa" * 32
        self.importer_mrenclave = "bb" * 32
        self.migration_spec = SGXMigrationSpec({
            "exporter": self.exporter_mrenclave,
            "importer": self.importer_mrenclave
        })

    def test_mrenclave_getters(self):
        # Test mrenclave getters and normalization
        self.assertEqual(self.migration_spec.exporter, self.exporter_mrenclave.lower())
        self.assertEqual(self.migration_spec.importer, self.importer_mrenclave.lower())

    def test_invalid_exporter_mrenclave(self):
        # Test constructor with invalid exporter mrenclave
        with self.assertRaises(ValueError):
            SGXMigrationSpec({
                "exporter": "not-a-mrenclave",
                "importer": self.importer_mrenclave
            })

    def test_invalid_importer_mrenclave(self):
        # Test constructor with invalid importer mrenclave
        with self.assertRaises(ValueError):
            SGXMigrationSpec({
                "exporter": self.exporter_mrenclave,
                "importer": "not-a-mrenclave"
            })

    def test_mrenclave_normalization(self):
        # Test mrenclave hex string normalization
        spec = SGXMigrationSpec({
            "exporter": "0x" + "aa" * 32,
            "importer": "0x" + "bb" * 32
        })
        self.assertEqual(spec.exporter, "aa" * 32)
        self.assertEqual(spec.importer, "bb" * 32)

    def test_to_dict(self):
        # Test dictionary conversion
        expected_dict = {
            "exporter": self.exporter_mrenclave,
            "importer": self.importer_mrenclave,
        }
        self.assertEqual(expected_dict, self.migration_spec.to_dict())

    def test_msg_generation(self):
        # Test non-prefixed message generation
        expected_msg = (f"RSK_powHSM_SGX_upgrade_from_"
                        f"{'aa' * 32}"
                        f"_to_{'bb' * 32}")
        self.assertEqual(expected_msg, self.migration_spec.msg)

    def test_authorization_message(self):
        # Test authorization message format
        expected_msg = (b"\x19Ethereum Signed Message:\n" +
                        b"160" +
                        b"RSK_powHSM_SGX_upgrade_from_" +
                        self.exporter_mrenclave.encode("ASCII") +
                        b"_to_" + self.importer_mrenclave.encode("ASCII"))
        self.assertEqual(expected_msg, self.migration_spec.get_authorization_msg())

    def test_authorization_digest(self):
        # Test authorization digest generation
        msg = self.migration_spec.get_authorization_msg()
        expected_digest = keccak_256(msg)
        self.assertEqual(expected_digest, self.migration_spec.get_authorization_digest())

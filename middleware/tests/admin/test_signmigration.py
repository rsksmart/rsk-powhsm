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
from signmigration import main
from admin.bip32 import BIP32Path
import ecdsa
from .ecdsa_utils import WEB3_PUBKEY, WEB3_ADDRESS, address
import logging

logging.disable(logging.CRITICAL)

RETURN_SUCCESS = 0
RETURN_ERROR = 1


@patch("signmigration.SGXMigrationAuthorization")
@patch("signmigration.SGXMigrationSpec")
@patch("signmigration.info")
class TestSignMigrationMessage(TestCase):
    def setUp(self):
        self.migration_auth = Mock()
        self.migration_spec = Mock()
        self.migration_spec.msg = "the-message"
        self.migration_spec.get_authorization_msg.return_value = (
            b"the-authorization-message"
        )
        self.migration_spec.get_authorization_digest.return_value = b"the-digest"
        self.migration_auth.for_spec.return_value = self.migration_auth

    def test_ok_to_console(self, info_mock, migration_spec_mock, migration_auth_mock):
        migration_spec_mock.return_value = self.migration_spec
        migration_auth_mock.for_spec.return_value = self.migration_auth

        with patch("sys.argv", ["signmigration.py", "message",
                                "-e", "exporter-hash",
                                "-i", "importer-hash"]), \
             patch("signmigration.format_message_to_sign") as format_mock:
            format_mock.return_value = "the-formatted-message"
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            [call("Computing the SGX migration authorization message..."),
             call("the-formatted-message")], info_mock.call_args_list
        )
        self.assertEqual(
            [call("the-message", b"the-authorization-message", b"the-digest")],
            format_mock.call_args_list
        )
        self.assertEqual(
            [call({"exporter": "exporter-hash", "importer": "importer-hash"})],
            migration_spec_mock.call_args_list
        )
        self.assertEqual(
            [call(self.migration_spec)],
            migration_auth_mock.for_spec.call_args_list
        )

    def test_ok_to_file(self, info_mock, migration_spec_mock, migration_auth_mock):
        migration_spec_mock.return_value = self.migration_spec
        migration_auth_mock.for_spec.return_value = self.migration_auth

        with patch("sys.argv", ["signmigration.py", "message",
                                "-e", "exporter-hash",
                                "-i", "importer-hash",
                                "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            [call("Computing the SGX migration authorization message..."),
             call("SGX migration authorization saved to an-output-path")],
            info_mock.call_args_list
        )
        self.assertEqual(
            [call({"exporter": "exporter-hash", "importer": "importer-hash"})],
            migration_spec_mock.call_args_list
        )
        self.assertEqual(
            [call(self.migration_spec)],
            migration_auth_mock.for_spec.call_args_list
        )
        self.assertEqual(
            [call("an-output-path")],
            self.migration_auth.save_to_jsonfile.call_args_list
        )

    def test_missing_args(self, info_mock, migration_spec_mock, migration_auth_mock):
        with patch("sys.argv", ["signmigration.py", "message"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(len(info_mock.call_args_list), 1)
        self.assertEqual(len(info_mock.call_args_list[0].args), 1)
        self.assertIn("Must provide either:\n", info_mock.call_args_list[0].args[0])
        self.assertIn("importer hash", info_mock.call_args_list[0].args[0])
        self.assertIn("exporter hash", info_mock.call_args_list[0].args[0])
        self.assertIn("authorization file", info_mock.call_args_list[0].args[0])
        migration_spec_mock.assert_not_called()
        migration_auth_mock.for_spec.assert_not_called()

    def test_missing_exporter(self, info_mock, migration_spec_mock, migration_auth_mock):
        with patch("sys.argv", ["signmigration.py", "message",
                                "-i", "importer-hash"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(len(info_mock.call_args_list), 1)
        self.assertEqual(len(info_mock.call_args_list[0].args), 1)
        self.assertIn("Must provide either:\n", info_mock.call_args_list[0].args[0])
        self.assertIn("importer hash", info_mock.call_args_list[0].args[0])
        self.assertIn("exporter hash", info_mock.call_args_list[0].args[0])
        self.assertIn("authorization file", info_mock.call_args_list[0].args[0])
        migration_spec_mock.assert_not_called()
        migration_auth_mock.for_spec.assert_not_called()

    def test_missing_importer(self, info_mock, migration_spec_mock, migration_auth_mock):
        with patch("sys.argv", ["signmigration.py", "message",
                                "-e", "exporter-hash"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(len(info_mock.call_args_list), 1)
        self.assertEqual(len(info_mock.call_args_list[0].args), 1)
        self.assertIn("Must provide either:\n", info_mock.call_args_list[0].args[0])
        self.assertIn("importer hash", info_mock.call_args_list[0].args[0])
        self.assertIn("exporter hash", info_mock.call_args_list[0].args[0])
        self.assertIn("authorization file", info_mock.call_args_list[0].args[0])
        migration_spec_mock.assert_not_called()
        migration_auth_mock.for_spec.assert_not_called()

    def test_ok_from_file(self, info_mock, migration_spec_mock, migration_auth_mock):
        self.migration_auth.migration_spec = self.migration_spec
        migration_auth_mock.from_jsonfile.return_value = self.migration_auth

        with patch("sys.argv", ["signmigration.py", "message",
                                "-f", "an-input-path"]), \
             patch("signmigration.format_message_to_sign") as format_mock:
            format_mock.return_value = "the-formatted-message"
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            [call("Opening SGX migration authorization file an-input-path..."),
             call("the-formatted-message")], info_mock.call_args_list
        )
        self.assertEqual(
            [call("an-input-path")],
            migration_auth_mock.from_jsonfile.call_args_list
        )
        self.assertEqual(
            [call("the-message", b"the-authorization-message", b"the-digest")],
            format_mock.call_args_list
        )
        migration_spec_mock.assert_not_called()
        self.migration_auth.save_to_jsonfile.assert_not_called()

    def test_ok_from_file_to_file(self, info_mock, migration_spec_mock,
                                  migration_auth_mock):
        input_auth = Mock()
        input_auth.migration_spec = self.migration_spec
        migration_auth_mock.from_jsonfile.return_value = input_auth
        migration_auth_mock.for_spec.return_value = self.migration_auth

        with patch("sys.argv", ["signmigration.py", "message",
                                "-f", "an-input-path",
                                "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            [call("Opening SGX migration authorization file an-input-path..."),
             call("SGX migration authorization saved to an-output-path")],
            info_mock.call_args_list
        )
        self.assertEqual(
            [call("an-input-path")],
            migration_auth_mock.from_jsonfile.call_args_list
        )
        # A fresh authorization (without the input file's signatures) is saved
        self.assertEqual(
            [call(self.migration_spec)],
            migration_auth_mock.for_spec.call_args_list
        )
        self.assertEqual(
            [call("an-output-path")],
            self.migration_auth.save_to_jsonfile.call_args_list
        )
        input_auth.save_to_jsonfile.assert_not_called()
        migration_spec_mock.assert_not_called()

    def test_file_and_exporter(self, info_mock, migration_spec_mock,
                               migration_auth_mock):
        with patch("sys.argv", ["signmigration.py", "message",
                                "-f", "an-input-path",
                                "-e", "exporter-hash"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(
            [call("An input file (-f/--file) cannot be provided together with "
                  "an exporter hash (-e/--exporter) or an importer hash "
                  "(-i/--importer)")],
            info_mock.call_args_list
        )
        migration_auth_mock.from_jsonfile.assert_not_called()
        migration_spec_mock.assert_not_called()

    def test_file_and_importer(self, info_mock, migration_spec_mock,
                               migration_auth_mock):
        with patch("sys.argv", ["signmigration.py", "message",
                                "-f", "an-input-path",
                                "-i", "importer-hash"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(
            [call("An input file (-f/--file) cannot be provided together with "
                  "an exporter hash (-e/--exporter) or an importer hash "
                  "(-i/--importer)")],
            info_mock.call_args_list
        )
        migration_auth_mock.from_jsonfile.assert_not_called()
        migration_spec_mock.assert_not_called()

    def test_file_with_other_operation(self, info_mock, migration_spec_mock,
                                       migration_auth_mock):
        with patch("sys.argv", ["signmigration.py", "manual",
                                "-f", "an-input-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(
            [call("An input file (-f/--file) can only be provided for the "
                  "'message' operation")],
            info_mock.call_args_list
        )
        migration_auth_mock.from_jsonfile.assert_not_called()


@patch("signmigration.isfile")
@patch("signmigration.SGXMigrationAuthorization")
@patch("signmigration.info")
class TestSignMigrationManual(TestCase):
    def setUp(self):
        self.migration_auth = Mock()
        self.migration_auth.migration_spec.msg = "the-message"
        self.migration_auth.migration_spec.get_authorization_digest.return_value = \
            b"the-digest"
        self.signature = Mock()
        self.signature.der_signature = "the-der-signature"

    def test_ok(self, info_mock, migration_auth_mock, isfile_mock):
        migration_auth_mock.from_jsonfile.return_value = self.migration_auth
        isfile_mock.return_value = True

        with patch("sys.argv", ["signmigration.py", "manual",
                                "-o", "an-output-path",
                                "-g", "a-signature"]), \
             patch("signmigration.parse_external_signature") as parse_mock, \
             patch("signmigration.describe_external_signature") as describe_mock:
            parse_mock.return_value = self.signature
            describe_mock.return_value = ["line-1", "line-2"]
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            [call("an-output-path")],
            migration_auth_mock.from_jsonfile.call_args_list
        )
        self.assertEqual(
            [call("a-signature", "the-message", b"the-digest", None)],
            parse_mock.call_args_list
        )
        self.assertEqual(
            [call(self.signature, False)],
            describe_mock.call_args_list
        )
        self.assertEqual(
            [call("the-der-signature")],
            self.migration_auth.add_signature.call_args_list
        )
        self.assertEqual(
            [call("an-output-path")],
            self.migration_auth.save_to_jsonfile.call_args_list
        )
        self.assertEqual(
            [
                call("Opening SGX migration authorization file an-output-path..."),
                call("Verifying signature..."),
                call("line-1"),
                call("line-2"),
                call("Adding signature..."),
                call("SGX migration authorization saved to an-output-path")
            ],
            info_mock.call_args_list
        )

    def test_ok_with_expected_signer(self, info_mock, migration_auth_mock, isfile_mock):
        migration_auth_mock.from_jsonfile.return_value = self.migration_auth
        isfile_mock.return_value = True

        with patch("sys.argv", ["signmigration.py", "manual",
                                "-o", "an-output-path",
                                "-g", "a-signature",
                                "-s", "a-signer"]), \
             patch("signmigration.parse_external_signature") as parse_mock, \
             patch("signmigration.describe_external_signature") as describe_mock:
            parse_mock.return_value = self.signature
            describe_mock.return_value = []
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            [call("a-signature", "the-message", b"the-digest", "a-signer")],
            parse_mock.call_args_list
        )
        self.assertEqual(
            [call(self.signature, True)],
            describe_mock.call_args_list
        )
        self.assertEqual(
            [call("the-der-signature")],
            self.migration_auth.add_signature.call_args_list
        )

    def test_invalid_signature(self, info_mock, migration_auth_mock, isfile_mock):
        migration_auth_mock.from_jsonfile.return_value = self.migration_auth
        isfile_mock.return_value = True

        with patch("sys.argv", ["signmigration.py", "manual",
                                "-o", "an-output-path",
                                "-g", "a-signature"]), \
             patch("signmigration.parse_external_signature") as parse_mock:
            parse_mock.side_effect = ValueError("bad signature")
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(call("bad signature"), info_mock.call_args_list[-1])
        self.migration_auth.add_signature.assert_not_called()
        self.migration_auth.save_to_jsonfile.assert_not_called()

    def test_file_not_found(self, info_mock, migration_auth_mock, isfile_mock):
        isfile_mock.return_value = False

        with patch("sys.argv", ["signmigration.py", "manual",
                                "-o", "an-output-path",
                                "-g", "a-signature"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(
            [
                call("Invalid output path: an-output-path")
            ],
            info_mock.call_args_list
        )
        migration_auth_mock.from_jsonfile.assert_not_called()

    def test_missing_signature(self, info_mock, migration_auth_mock, isfile_mock):
        migration_auth = Mock()
        migration_auth_mock.from_jsonfile.return_value = migration_auth
        isfile_mock.return_value = True

        with patch("sys.argv", ["signmigration.py", "manual",
                                "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(
            [
                call("Must provide a signature (-g/--signature)"),
            ],
            info_mock.call_args_list
        )
        migration_auth_mock.from_jsonfile.assert_not_called()
        migration_auth.add_signature.assert_not_called()
        migration_auth.save_to_jsonfile.assert_not_called()

    def test_missing_output_file(self, info_mock, migration_auth_mock, isfile_mock):
        with patch("sys.argv", ["signmigration.py", "manual",
                                "-g", "a-signature"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(
            [
                call("Must provide an output path (-o/--output)"),
            ],
            info_mock.call_args_list
        )
        isfile_mock.assert_not_called()
        migration_auth_mock.from_jsonfile.assert_not_called()
        migration_auth_mock.add_signature.assert_not_called()
        migration_auth_mock.save_to_jsonfile.assert_not_called()

    def test_non_existent_output_file(self, info_mock, migration_auth_mock, isfile_mock):
        isfile_mock.return_value = False

        with patch("sys.argv", ["signmigration.py", "manual",
                                "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        isfile_mock.assert_called_once_with("an-output-path")
        self.assertEqual(
            [
                call("Invalid output path: an-output-path"),
            ],
            info_mock.call_args_list
        )
        migration_auth_mock.from_jsonfile.assert_not_called()
        migration_auth_mock.add_signature.assert_not_called()
        migration_auth_mock.save_to_jsonfile.assert_not_called()


@patch("signmigration.isfile")
@patch("signmigration.SGXMigrationAuthorization")
@patch("signmigration.info")
class TestSignMigrationKey(TestCase):
    def test_ok(self, info_mock, migration_auth_mock, isfile_mock):
        migration_auth = Mock()
        migration_auth_mock.from_jsonfile.return_value = migration_auth
        migration_auth.add_signature.return_value = None
        isfile_mock.return_value = True
        migration_auth.migration_spec.get_authorization_digest.return_value = (
            bytes.fromhex("bb"*32)
        )

        with patch("sys.argv", ["signmigration.py", "key",
                                "-o", "an-output-path",
                                "-k", "aa"*32]):
            with self.assertRaises(SystemExit) as exit:
                main()

        privkey = ecdsa.SigningKey.from_string(
            bytes.fromhex("aa"*32),
            curve=ecdsa.SECP256k1
        )
        pubkey = privkey.get_verifying_key()
        signature = migration_auth.add_signature.call_args_list[0][0][0]
        pubkey.verify_digest(bytes.fromhex(signature), bytes.fromhex("bb"*32),
                             sigdecode=ecdsa.util.sigdecode_der)
        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            [call("an-output-path")],
            migration_auth_mock.from_jsonfile.call_args_list
        )
        self.assertEqual(
            [
                call("Opening SGX migration authorization file an-output-path..."),
                call("Signing with key..."),
                call("SGX migration authorization saved to an-output-path")
            ],
            info_mock.call_args_list
        )

    def test_missing_key(self, info_mock, migration_auth_mock, isfile_mock):
        isfile_mock.return_value = True

        with patch("sys.argv", ["signmigration.py", "key",
                                "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(
            [
                call("Must provide a signing key (-k/--key)"),
            ],
            info_mock.call_args_list
        )
        migration_auth_mock.from_jsonfile.assert_not_called()
        migration_auth_mock.add_signature.assert_not_called()
        migration_auth_mock.save_to_jsonfile.assert_not_called()

    def test_invalid_key(self, info_mock, migration_auth_mock, isfile_mock):
        isfile_mock.return_value = True

        with patch("sys.argv", ["signmigration.py", "key",
                                "-o", "an-output-path",
                                "-k", "invalid-key"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(
            [
                call("Invalid key 'invalid-key'"),
            ],
            info_mock.call_args_list
        )
        migration_auth_mock.from_jsonfile.assert_not_called()
        migration_auth_mock.add_signature.assert_not_called()
        migration_auth_mock.save_to_jsonfile.assert_not_called()

    def test_missing_output_file(self, info_mock, migration_auth_mock, isfile_mock):
        with patch("sys.argv", ["signmigration.py", "key",
                                "-k", "aa"*32]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(
            [
                call("Must provide an output path (-o/--output)"),
            ],
            info_mock.call_args_list
        )
        isfile_mock.assert_not_called()
        migration_auth_mock.from_jsonfile.assert_not_called()

    def test_non_existent_output_file(self, info_mock, migration_auth_mock, isfile_mock):
        isfile_mock.return_value = False

        with patch("sys.argv", ["signmigration.py", "key",
                                "-o", "an-output-path",
                                "-k", "aa"*32]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        isfile_mock.assert_called_once_with("an-output-path")
        self.assertEqual(
            [
                call("Invalid output path: an-output-path"),
            ],
            info_mock.call_args_list
        )
        migration_auth_mock.from_jsonfile.assert_not_called()

    def test_canonical_signature_encoding(self, _, migration_auth_mock, isfile_mock):
        migration_auth = Mock()
        migration_auth_mock.from_jsonfile.return_value = migration_auth
        migration_auth.add_signature.return_value = None
        isfile_mock.return_value = True
        test_digest = bytes.fromhex("bb"*32)
        migration_auth.migration_spec.get_authorization_digest.return_value = test_digest

        with patch("signmigration.ecdsa.util.sigencode_der_canonize") as sigencode_mock:
            known_signature = bytes.fromhex(
                "30440220" + "11" * 32 + "0220" + "22" * 32
            )
            sigencode_mock.return_value = known_signature

            with patch("sys.argv", ["signmigration.py", "key",
                                    "-o", "an-output-path",
                                    "-k", "aa"*32]):
                with self.assertRaises(SystemExit) as exit:
                    main()

            self.assertEqual(sigencode_mock.call_count, 1)
            signature_hex = migration_auth.add_signature.call_args_list[0][0][0]
            self.assertEqual(signature_hex, known_signature.hex())

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)


@patch("signmigration.isfile")
@patch("signmigration.dispose_eth_dongle")
@patch("signmigration.get_eth_dongle")
@patch("signmigration.BIP32Path")
@patch("signmigration.SGXMigrationSpec")
@patch("signmigration.SGXMigrationAuthorization")
@patch("signmigration.info")
class TestSignMigrationEth(TestCase):
    def test_ok_pubkey(
            self,
            info_mock,
            migration_auth_mock,
            migration_spec_mock,
            bip32path_mock,
            get_eth_mock,
            dispose_eth_mock,
            isfile_mock):
        migration_auth = Mock()
        migration_auth_mock.from_jsonfile.return_value = migration_auth
        bip32path_mock.return_value = "bip32-path"
        get_eth_mock.return_value = Mock()
        eth_mock = Mock()
        eth_mock.get_pubkey.return_value = WEB3_PUBKEY
        eth_mock.sign.return_value = bytes.fromhex("bb"*32)
        get_eth_mock.return_value = eth_mock
        isfile_mock.return_value = True

        mock_file = mock_open()
        with patch("builtins.open", mock_file) as open_mock:
            with patch("sys.argv", ["signmigration.py", "eth",
                                    "-o", "an-output-path", "-b"]):
                with self.assertRaises(SystemExit) as exit:
                    main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        get_eth_mock.assert_called_once()
        eth_mock.get_pubkey.assert_called_once_with("bip32-path")
        self.assertEqual(
            [
                call("Retrieving public key for path 'bip32-path'..."),
                call(f"Address: {WEB3_ADDRESS}"),
                call(f"Public key: {WEB3_PUBKEY.hex()}"),
                call("Opening public key file an-output-path..."),
                call("Adding public key..."),
                call("Public key saved to an-output-path")
            ],
            info_mock.call_args_list
        )
        # Verify the file was opened in write mode
        open_mock.assert_called_once_with("an-output-path", "w")
        # Verify the correct content was written
        mock_file.return_value.write.assert_called_once_with(WEB3_PUBKEY.hex() + "\n")

    def test_existingfile_ok(
            self,
            info_mock,
            migration_auth_mock,
            migration_spec_mock,
            bip32path_mock,
            get_eth_mock,
            dispose_eth_mock,
            isfile_mock):
        migration_spec_mock = Mock()
        migration_spec_mock.get_authorization_digest.return_value = bytes.fromhex("aa"*32)
        migration_spec_mock.msg = "RSK_powHSM_SGX_upgrade_from_exporter_to_importer"
        migration_auth = Mock()
        migration_auth.migration_spec = migration_spec_mock
        migration_auth_mock.from_jsonfile.return_value = migration_auth
        bip32path_mock.return_value = BIP32Path("m/44'/60'/0'/0/0")
        privkey = ecdsa.SigningKey.from_string(bytes.fromhex("dd"*32),
                                               curve=ecdsa.SECP256k1)
        pubkey = privkey.get_verifying_key()
        eth_mock = Mock()
        eth_mock.get_pubkey.return_value = pubkey.to_string("uncompressed")
        eth_mock.sign.return_value = privkey.sign_digest(
            bytes.fromhex("aa"*32), sigencode=ecdsa.util.sigencode_der)
        get_eth_mock.return_value = eth_mock
        isfile_mock.return_value = True

        with patch("sys.argv", ["signmigration.py", "eth",
                                "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)

        self.assertEqual([call("an-output-path")], isfile_mock.call_args_list)
        self.assertFalse(migration_spec_mock.called)
        self.assertEqual([call("an-output-path")],
                         migration_auth_mock.from_jsonfile.call_args_list)
        self.assertEqual([call(BIP32Path("m/44'/60'/0'/0/0"))],
                         eth_mock.get_pubkey.call_args_list)
        self.assertEqual([call(BIP32Path("m/44'/60'/0'/0/0"),
                         b"RSK_powHSM_SGX_upgrade_from_exporter_to_importer")],
                         eth_mock.sign.call_args_list)
        self.assertEqual(1, migration_auth.add_signature.call_count)
        signature = migration_auth.add_signature.call_args_list[0][0][0]
        pubkey.verify_digest(bytes.fromhex(signature), bytes.fromhex("aa"*32),
                             sigdecode=ecdsa.util.sigdecode_der)
        self.assertEqual([call("an-output-path")],
                         migration_auth.save_to_jsonfile.call_args_list)

    def test_missing_output_file(
            self,
            info_mock,
            migration_auth_mock,
            migration_spec_mock,
            bip32path_mock,
            get_eth_mock,
            dispose_eth_mock,
            isfile_mock):

        with patch("sys.argv", ["signmigration.py", "eth"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(
            [call("Must provide an output path (-o/--output)")],
            info_mock.call_args_list
        )
        get_eth_mock.assert_not_called()
        dispose_eth_mock.assert_not_called()

    def test_get_eth_dongle_exception(
            self,
            info_mock,
            migration_auth_mock,
            migration_spec_mock,
            bip32path_mock,
            get_eth_mock,
            dispose_eth_mock,
            isfile_mock):

        bip32path_mock.return_value = BIP32Path("m/44'/60'/0'/0/0")
        get_eth_mock.side_effect = Exception("Dongle connection error")

        with patch("sys.argv", ["signmigration.py", "eth",
                                "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        bip32path_mock.assert_called_once_with("m/44'/60'/0'/0/0")
        get_eth_mock.assert_called_once()
        self.assertEqual(
            [call("Error signing with dongle: Dongle connection error")],
            info_mock.call_args_list
        )
        # dispose_eth_dongle should be called even if get_eth_dongle fails
        dispose_eth_mock.assert_called_once_with(None)

    def test_get_pubkey_exception(
            self,
            info_mock,
            migration_auth_mock,
            migration_spec_mock,
            bip32path_mock,
            get_eth_mock,
            dispose_eth_mock,
            isfile_mock):

        bip32path_mock.return_value = BIP32Path("m/44'/60'/0'/0/0")
        eth_mock = Mock()
        eth_mock.get_pubkey.side_effect = Exception("Could not get pubkey")
        get_eth_mock.return_value = eth_mock

        with patch("sys.argv", ["signmigration.py", "eth",
                                "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        bip32path_mock.assert_called_once_with("m/44'/60'/0'/0/0")
        get_eth_mock.assert_called_once()
        eth_mock.get_pubkey.assert_called_once_with(BIP32Path("m/44'/60'/0'/0/0"))
        self.assertEqual(
            [
                call("Retrieving public key for path 'm/44\'/60\'/0\'/0/0'..."),
                call("Error signing with dongle: Could not get pubkey")
            ],
            info_mock.call_args_list
        )
        dispose_eth_mock.assert_called_once_with(eth_mock)

    def test_sign_exception(
            self,
            info_mock,
            migration_auth_mock,
            migration_spec_mock,
            bip32path_mock,
            get_eth_mock,
            dispose_eth_mock,
            isfile_mock):

        migration_spec = Mock()
        migration_spec.msg = "RSK_powHSM_SGX_upgrade_from_exporter_to_importer"
        migration_auth = Mock()
        migration_auth.migration_spec = migration_spec
        migration_auth_mock.from_jsonfile.return_value = migration_auth
        bip32path_mock.return_value = BIP32Path("m/44'/60'/0'/0/0")
        eth_mock = Mock()
        eth_mock.get_pubkey.return_value = WEB3_PUBKEY
        eth_mock.sign.side_effect = Exception("User rejected")
        get_eth_mock.return_value = eth_mock
        isfile_mock.return_value = True

        with patch("sys.argv", ["signmigration.py", "eth",
                                "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        # The original dongle error is reported
        self.assertEqual(
            call("Error signing with dongle: User rejected"),
            info_mock.call_args_list[-1]
        )
        migration_auth.add_signature.assert_not_called()
        migration_auth.save_to_jsonfile.assert_not_called()
        dispose_eth_mock.assert_called_once_with(eth_mock)

    def test_bad_signature(
            self,
            info_mock,
            migration_auth_mock,
            migration_spec_mock,
            bip32path_mock,
            get_eth_mock,
            dispose_eth_mock,
            isfile_mock):

        migration_spec = Mock()
        migration_spec.get_authorization_digest.return_value = bytes.fromhex("aa"*32)
        migration_spec.get_old_eth_digest.return_value = bytes.fromhex("bb"*32)
        migration_spec.msg = "RSK_powHSM_SGX_upgrade_from_exporter_to_importer"
        migration_auth = Mock()
        migration_auth.migration_spec = migration_spec
        migration_auth_mock.from_jsonfile.return_value = migration_auth
        bip32path_mock.return_value = BIP32Path("m/44'/60'/0'/0/0")

        # Generate a valid key pair
        privkey = ecdsa.SigningKey.from_string(bytes.fromhex("dd"*32),
                                               curve=ecdsa.SECP256k1)
        pubkey = privkey.get_verifying_key()

        eth_mock = Mock()
        eth_mock.get_pubkey.return_value = pubkey.to_string("uncompressed")
        signer_address = address("dd"*32)
        # Sign a DIFFERENT digest to create a bad signature for the expected digest
        bad_signature = privkey.sign_digest(
            bytes.fromhex("cc"*32), sigencode=ecdsa.util.sigencode_der)
        eth_mock.sign.return_value = bad_signature
        get_eth_mock.return_value = eth_mock
        isfile_mock.return_value = True

        with patch("sys.argv", ["signmigration.py", "eth",
                                "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        isfile_mock.assert_called_once_with("an-output-path")
        migration_auth_mock.from_jsonfile.assert_called_once_with("an-output-path")
        get_eth_mock.assert_called_once()
        eth_mock.get_pubkey.assert_called_once_with(BIP32Path("m/44'/60'/0'/0/0"))
        eth_mock.sign.assert_called_once_with(
            BIP32Path("m/44'/60'/0'/0/0"),
            b"RSK_powHSM_SGX_upgrade_from_exporter_to_importer"
        )
        self.assertEqual(
            [
                call("Retrieving public key for path 'm/44\'/60\'/0\'/0/0'..."),
                call(f"Address: {signer_address}"),
                call(f"Public key: {pubkey.to_string('uncompressed').hex()}"),
                call("Opening SGX migration authorization file an-output-path..."),
                call("Signing with dongle..."),
                call("Check that the device shows the following message "
                     "(or one of the digests):"),
                call("    Message:\n"),
                call("    RSK_powHSM_SGX_upgrade_from_exporter_to_importer\n"),
                call("    Digest (app >= 1.22.3, if hash display enabled):  "
                     f"0x{'aa'*32}"),
                call("    Digest (app <= 1.9.19):                           "
                     f"{'BB'*32}"),
                call(f"Bad signature from dongle! (got '{bad_signature.hex()}')")
            ],
            info_mock.call_args_list
        )
        migration_auth.add_signature.assert_not_called()
        migration_auth.save_to_jsonfile.assert_not_called()
        dispose_eth_mock.assert_called_once_with(eth_mock)

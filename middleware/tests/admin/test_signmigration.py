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
from unittest.mock import Mock, call, patch
from signmigration import main
from admin.bip32 import BIP32Path
import ecdsa
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
        self.migration_spec.get_authorization_msg.return_value = (
            b"the-authorization-message"
        )
        self.migration_auth.for_spec.return_value = self.migration_auth

    def test_ok_to_console(self, info_mock, migration_spec_mock, migration_auth_mock):
        migration_spec_mock.return_value = self.migration_spec
        migration_auth_mock.for_spec.return_value = self.migration_auth

        with patch("sys.argv", ["signmigration.py", "message",
                                "-e", "exporter-hash",
                                "-i", "importer-hash"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            [call("Computing the SGX migration authorization message..."),
             call("the-authorization-message")], info_mock.call_args_list
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


@patch("signmigration.isfile")
@patch("signmigration.SGXMigrationAuthorization")
@patch("signmigration.info")
class TestSignMigrationManual(TestCase):
    def test_ok(self, info_mock, migration_auth_mock, isfile_mock):
        migration_auth = Mock()
        migration_auth_mock.from_jsonfile.return_value = migration_auth
        isfile_mock.return_value = True

        with patch("sys.argv", ["signmigration.py", "manual",
                                "-o", "an-output-path",
                                "-g", "a-signature"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            [call("an-output-path")],
            migration_auth_mock.from_jsonfile.call_args_list
        )
        self.assertEqual(
            [call("a-signature")],
            migration_auth.add_signature.call_args_list
        )
        self.assertEqual(
            [call("an-output-path")],
            migration_auth.save_to_jsonfile.call_args_list
        )
        self.assertEqual(
            [
                call("Opening SGX migration authorization file an-output-path..."),
                call("Adding signature..."),
                call("SGX migration authorization saved to an-output-path")
            ],
            info_mock.call_args_list
        )

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
        eth_mock.get_pubkey.return_value = bytes.fromhex("aa"*32)
        eth_mock.sign.return_value = bytes.fromhex("bb"*32)
        get_eth_mock.return_value = eth_mock
        isfile_mock.return_value = True

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
                call("Public key: " + "aa"*32),
                call("Opening public key file an-output-path..."),
                call("Adding public key..."),
                call("Public key saved to an-output-path")
            ],
            info_mock.call_args_list
        )

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

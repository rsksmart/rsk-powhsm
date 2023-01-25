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
from signapp import main
from admin.bip32 import BIP32Path
import ecdsa
import logging

logging.disable(logging.CRITICAL)

RETURN_SUCCESS = 0
RETURN_ERROR = 1


@patch("signapp.compute_app_hash")
@patch("signapp.info")
class TestSignAppHash(TestCase):
    def test_ok(self, info_mock, compute_app_hash_mock):
        compute_app_hash_mock.return_value = bytes.fromhex("aabbcc")

        with patch("sys.argv", ["signapp.py", "hash", "-a", "a-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            [call("Computing hash..."),
             call("Computed hash: aabbcc")], info_mock.call_args_list)
        self.assertEqual([call("a-path")], compute_app_hash_mock.call_args_list)


@patch("signapp.SignerAuthorization")
@patch("signapp.SignerVersion")
@patch("signapp.compute_app_hash")
@patch("signapp.info")
class TestSignAppMessage(TestCase):
    def test_ok_to_console(self, info_mock, compute_app_hash_mock,
                           signer_version_mock, signer_authorization_mock):
        compute_app_hash_mock.return_value = bytes.fromhex("aabbcc")
        signer_version = Mock()
        signer_version_mock.return_value = signer_version
        signer_version.get_authorization_msg.return_value = b"the-authorization-message"

        with patch("sys.argv", ["signapp.py", "message", "-a", "a-path",
                                "-i", "an-iteration"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            [call("Computing hash..."),
             call("Computing signer authorization message..."),
             call("the-authorization-message")], info_mock.call_args_list)

        self.assertEqual([call("aabbcc", "an-iteration")],
                         signer_version_mock.call_args_list)

    def test_ok_to_file(self, info_mock, compute_app_hash_mock,
                        signer_version_mock, signer_authorization_mock):
        compute_app_hash_mock.return_value = bytes.fromhex("aabbcc")
        signer_version = Mock()
        signer_version_mock.return_value = signer_version
        signer_version.get_authorization_msg.return_value = b"the-authorization-message"
        signer_authorization = Mock()
        signer_authorization_mock.for_signer_version.return_value = signer_authorization

        with patch("sys.argv", ["signapp.py", "message", "-a", "a-path",
                                "-i", "an-iteration", "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)

        self.assertEqual([call("aabbcc", "an-iteration")],
                         signer_version_mock.call_args_list)
        self.assertEqual([call(signer_version)],
                         signer_authorization_mock.for_signer_version.call_args_list)
        self.assertEqual([call("an-output-path")],
                         signer_authorization.save_to_jsonfile.call_args_list)


@patch("signapp.isfile")
@patch("signapp.SignerAuthorization")
@patch("signapp.SignerVersion")
@patch("signapp.compute_app_hash")
@patch("signapp.info")
class TestSignAppKey(TestCase):
    def test_newfile_ok(self, info_mock, compute_app_hash_mock,
                        signer_version_mock, signer_authorization_mock,
                        isfile_mock):
        compute_app_hash_mock.return_value = bytes.fromhex("aabbcc")
        signer_version = Mock()
        signer_version_mock.return_value = signer_version
        signer_version.get_authorization_digest.return_value = bytes.fromhex("bb"*32)
        signer_authorization = Mock()
        signer_authorization_mock.for_signer_version.return_value = signer_authorization
        isfile_mock.return_value = False

        with patch("sys.argv", ["signapp.py", "key", "-a", "a-path",
                                "-i", "an-iteration", "-o", "an-output-path",
                                "-k", "aa"*32]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)

        self.assertEqual([call("an-output-path")], isfile_mock.call_args_list)
        self.assertEqual([call("aabbcc", "an-iteration")],
                         signer_version_mock.call_args_list)
        self.assertEqual([call(signer_version)],
                         signer_authorization_mock.for_signer_version.call_args_list)
        self.assertEqual(1, signer_authorization.add_signature.call_count)
        signature = signer_authorization.add_signature.call_args_list[0][0][0]
        pk = ecdsa.SigningKey\
            .from_string(bytes.fromhex("aa"*32), curve=ecdsa.SECP256k1)\
            .get_verifying_key()
        pk.verify_digest(bytes.fromhex(signature), bytes.fromhex("bb"*32),
                         sigdecode=ecdsa.util.sigdecode_der)
        self.assertEqual([call("an-output-path")],
                         signer_authorization.save_to_jsonfile.call_args_list)

    def test_existingfile_ok(self, info_mock, compute_app_hash_mock,
                             signer_version_mock, signer_authorization_mock,
                             isfile_mock):
        signer_version = Mock()
        signer_version.get_authorization_digest.return_value = bytes.fromhex("bb"*32)
        signer_authorization = Mock()
        signer_authorization.signer_version = signer_version
        signer_authorization_mock.from_jsonfile.return_value = signer_authorization
        isfile_mock.return_value = True

        with patch("sys.argv", ["signapp.py", "key",
                                "-o", "an-output-path",
                                "-k", "aa"*32]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)

        self.assertEqual([call("an-output-path")], isfile_mock.call_args_list)
        self.assertFalse(signer_version_mock.called)
        self.assertEqual([call("an-output-path")],
                         signer_authorization_mock.from_jsonfile.call_args_list)
        self.assertEqual(1, signer_authorization.add_signature.call_count)
        signature = signer_authorization.add_signature.call_args_list[0][0][0]
        pk = ecdsa.SigningKey\
            .from_string(bytes.fromhex("aa"*32), curve=ecdsa.SECP256k1)\
            .get_verifying_key()
        pk.verify_digest(bytes.fromhex(signature), bytes.fromhex("bb"*32),
                         sigdecode=ecdsa.util.sigdecode_der)
        self.assertEqual([call("an-output-path")],
                         signer_authorization.save_to_jsonfile.call_args_list)


@patch("signapp.dispose_eth_dongle")
@patch("signapp.get_eth_dongle")
@patch("signapp.isfile")
@patch("signapp.SignerAuthorization")
@patch("signapp.SignerVersion")
@patch("signapp.compute_app_hash")
@patch("signapp.info")
class TestSignAppEth(TestCase):
    def test_newfile_ok(self, info_mock, compute_app_hash_mock,
                        signer_version_mock, signer_authorization_mock, isfile_mock,
                        get_eth_mock, dispose_eth_mock):
        compute_app_hash_mock.return_value = bytes.fromhex("aabbcc")
        signer_version = Mock()
        signer_version_mock.return_value = signer_version
        signer_version.get_authorization_digest.return_value = bytes.fromhex("bb"*32)
        signer_version.msg = "RSK_powHSM_signer_aabbcc_iteration_an-iteration"
        signer_authorization = Mock()
        signer_authorization_mock.for_signer_version.return_value = signer_authorization
        privkey = ecdsa.SigningKey.from_string(bytes.fromhex("aa"*32),
                                               curve=ecdsa.SECP256k1)
        pubkey = privkey.get_verifying_key()
        eth_mock = Mock()
        eth_mock.get_pubkey.return_value = pubkey.to_string("uncompressed")
        eth_mock.sign.return_value = privkey.sign_digest(
            bytes.fromhex("bb"*32), sigencode=ecdsa.util.sigencode_der)
        get_eth_mock.return_value = eth_mock
        isfile_mock.return_value = False
        with patch("sys.argv", ["signapp.py", "eth", "-a", "a-path",
                                "-i", "an-iteration", "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual([call("an-output-path")], isfile_mock.call_args_list)
        self.assertEqual([call("aabbcc", "an-iteration")],
                         signer_version_mock.call_args_list)
        self.assertEqual([call(signer_version)],
                         signer_authorization_mock.for_signer_version.call_args_list)
        self.assertEqual([call(BIP32Path("m/44'/60'/0'/0/0"))],
                         eth_mock.get_pubkey.call_args_list)
        self.assertEqual([call(BIP32Path("m/44'/60'/0'/0/0"),
                               b"RSK_powHSM_signer_aabbcc_iteration_an-iteration")],
                         eth_mock.sign.call_args_list)
        self.assertEqual(1, signer_authorization.add_signature.call_count)
        signature = signer_authorization.add_signature.call_args_list[0][0][0]
        pubkey.verify_digest(bytes.fromhex(signature), bytes.fromhex("bb"*32),
                             sigdecode=ecdsa.util.sigdecode_der)
        self.assertEqual([call("an-output-path")],
                         signer_authorization.save_to_jsonfile.call_args_list)

    def test_existingfile_ok(self, info_mock, compute_app_hash_mock,
                             signer_version_mock, signer_authorization_mock, isfile_mock,
                             get_eth_mock, dispose_eth_mock):
        signer_version = Mock()
        signer_version.get_authorization_digest.return_value = bytes.fromhex("bb"*32)
        signer_version.msg = "RSK_powHSM_signer_aabbcc_iteration_an-iteration"
        signer_authorization = Mock()
        signer_authorization.signer_version = signer_version
        signer_authorization_mock.from_jsonfile.return_value = signer_authorization
        privkey = ecdsa.SigningKey.from_string(bytes.fromhex("aa"*32),
                                               curve=ecdsa.SECP256k1)
        pubkey = privkey.get_verifying_key()
        eth_mock = Mock()
        eth_mock.get_pubkey.return_value = pubkey.to_string("uncompressed")
        eth_mock.sign.return_value = privkey.sign_digest(
            bytes.fromhex("bb"*32), sigencode=ecdsa.util.sigencode_der)
        get_eth_mock.return_value = eth_mock
        isfile_mock.return_value = True

        with patch("sys.argv", ["signapp.py", "eth",
                                "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)

        self.assertEqual([call("an-output-path")], isfile_mock.call_args_list)
        self.assertFalse(signer_version_mock.called)
        self.assertEqual([call("an-output-path")],
                         signer_authorization_mock.from_jsonfile.call_args_list)
        self.assertEqual([call(BIP32Path("m/44'/60'/0'/0/0"))],
                         eth_mock.get_pubkey.call_args_list)
        self.assertEqual([call(BIP32Path("m/44'/60'/0'/0/0"),
                               b"RSK_powHSM_signer_aabbcc_iteration_an-iteration")],
                         eth_mock.sign.call_args_list)
        self.assertEqual(1, signer_authorization.add_signature.call_count)
        signature = signer_authorization.add_signature.call_args_list[0][0][0]
        pubkey.verify_digest(bytes.fromhex(signature), bytes.fromhex("bb"*32),
                             sigdecode=ecdsa.util.sigdecode_der)
        self.assertEqual([call("an-output-path")],
                         signer_authorization.save_to_jsonfile.call_args_list)


@patch("signapp.SignerAuthorization")
@patch("signapp.info")
class TestSignAppManual(TestCase):
    def test_ok(self, info_mock, signer_authorization_mock):
        signer_authorization = Mock()
        signer_authorization_mock.from_jsonfile.return_value = signer_authorization

        with patch("sys.argv", ["signapp.py", "manual", "-o", "an-output-path",
                                "-g", "a-signature"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)

        self.assertEqual([call("an-output-path")],
                         signer_authorization_mock.from_jsonfile.call_args_list)
        self.assertEqual([call("a-signature")],
                         signer_authorization.add_signature.call_args_list)
        self.assertEqual([call("an-output-path")],
                         signer_authorization.save_to_jsonfile.call_args_list)

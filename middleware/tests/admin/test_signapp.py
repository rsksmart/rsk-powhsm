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
from .ecdsa_utils import WEB3_PUBKEY
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
        signer_version.msg = "the-message"
        signer_version.get_authorization_msg.return_value = b"the-authorization-message"
        signer_version.get_authorization_digest.return_value = b"the-digest"

        with patch("sys.argv", ["signapp.py", "message", "-a", "a-path",
                                "-i", "an-iteration"]), \
             patch("signapp.format_message_to_sign") as format_mock:
            format_mock.return_value = "the-formatted-message"
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            [call("Computing hash..."),
             call("Computing signer authorization message..."),
             call("the-formatted-message")], info_mock.call_args_list)
        self.assertEqual(
            [call("the-message", b"the-authorization-message", b"the-digest")],
            format_mock.call_args_list)

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

    def test_ok_from_file(self, info_mock, compute_app_hash_mock,
                          signer_version_mock, signer_authorization_mock):
        signer_version = Mock()
        signer_version.msg = "the-message"
        signer_version.get_authorization_msg.return_value = b"the-authorization-message"
        signer_version.get_authorization_digest.return_value = b"the-digest"
        signer_authorization = Mock()
        signer_authorization.signer_version = signer_version
        signer_authorization_mock.from_jsonfile.return_value = signer_authorization

        with patch("sys.argv", ["signapp.py", "message", "-f", "an-input-path"]), \
             patch("signapp.format_message_to_sign") as format_mock:
            format_mock.return_value = "the-formatted-message"
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            [call("Opening signer authorization file an-input-path..."),
             call("the-formatted-message")], info_mock.call_args_list)
        self.assertEqual([call("an-input-path")],
                         signer_authorization_mock.from_jsonfile.call_args_list)
        self.assertEqual(
            [call("the-message", b"the-authorization-message", b"the-digest")],
            format_mock.call_args_list)
        compute_app_hash_mock.assert_not_called()
        signer_version_mock.assert_not_called()
        signer_authorization.save_to_jsonfile.assert_not_called()

    def test_ok_from_file_to_file(self, info_mock, compute_app_hash_mock,
                                  signer_version_mock, signer_authorization_mock):
        signer_version = Mock()
        input_authorization = Mock()
        input_authorization.signer_version = signer_version
        signer_authorization_mock.from_jsonfile.return_value = input_authorization
        output_authorization = Mock()
        signer_authorization_mock.for_signer_version.return_value = output_authorization

        with patch("sys.argv", ["signapp.py", "message", "-f", "an-input-path",
                                "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            [call("Opening signer authorization file an-input-path..."),
             call("Signer authorization saved to an-output-path")],
            info_mock.call_args_list)
        self.assertEqual([call("an-input-path")],
                         signer_authorization_mock.from_jsonfile.call_args_list)
        # A fresh authorization (without the input file's signatures) is saved
        self.assertEqual([call(signer_version)],
                         signer_authorization_mock.for_signer_version.call_args_list)
        self.assertEqual([call("an-output-path")],
                         output_authorization.save_to_jsonfile.call_args_list)
        input_authorization.save_to_jsonfile.assert_not_called()
        compute_app_hash_mock.assert_not_called()
        signer_version_mock.assert_not_called()

    def test_file_and_app_path(self, info_mock, compute_app_hash_mock,
                               signer_version_mock, signer_authorization_mock):
        with patch("sys.argv", ["signapp.py", "message", "-f", "an-input-path",
                                "-a", "a-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(
            [call("An input file (-f/--file) cannot be provided together with "
                  "an app path (-a/--app) or a signer iteration (-i/--iteration)")],
            info_mock.call_args_list)
        signer_authorization_mock.from_jsonfile.assert_not_called()
        compute_app_hash_mock.assert_not_called()

    def test_file_and_iteration(self, info_mock, compute_app_hash_mock,
                                signer_version_mock, signer_authorization_mock):
        with patch("sys.argv", ["signapp.py", "message", "-f", "an-input-path",
                                "-i", "an-iteration"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(
            [call("An input file (-f/--file) cannot be provided together with "
                  "an app path (-a/--app) or a signer iteration (-i/--iteration)")],
            info_mock.call_args_list)
        signer_authorization_mock.from_jsonfile.assert_not_called()
        compute_app_hash_mock.assert_not_called()

    def test_file_with_other_operation(self, info_mock, compute_app_hash_mock,
                                       signer_version_mock, signer_authorization_mock):
        with patch("sys.argv", ["signapp.py", "hash", "-f", "an-input-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(
            [call("An input file (-f/--file) can only be provided for the "
                  "'message' operation")],
            info_mock.call_args_list)
        signer_authorization_mock.from_jsonfile.assert_not_called()
        compute_app_hash_mock.assert_not_called()


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

    def test_get_eth_dongle_exception(self, info_mock, compute_app_hash_mock,
                                      signer_version_mock, signer_authorization_mock,
                                      isfile_mock, get_eth_mock, dispose_eth_mock):
        get_eth_mock.side_effect = Exception("Dongle connection error")

        with patch("sys.argv", ["signapp.py", "eth", "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(
            [call("Error signing with dongle: Dongle connection error")],
            info_mock.call_args_list)
        # dispose_eth_dongle should be called even if get_eth_dongle fails
        dispose_eth_mock.assert_called_once_with(None)

    def test_get_pubkey_exception(self, info_mock, compute_app_hash_mock,
                                  signer_version_mock, signer_authorization_mock,
                                  isfile_mock, get_eth_mock, dispose_eth_mock):
        eth_mock = Mock()
        eth_mock.get_pubkey.side_effect = Exception("Could not get pubkey")
        get_eth_mock.return_value = eth_mock

        with patch("sys.argv", ["signapp.py", "eth", "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(
            [call("Retrieving public key for path 'm/44\'/60\'/0\'/0/0'..."),
             call("Error signing with dongle: Could not get pubkey")],
            info_mock.call_args_list)
        signer_authorization_mock.from_jsonfile.assert_not_called()
        dispose_eth_mock.assert_called_once_with(eth_mock)

    def test_sign_exception(self, info_mock, compute_app_hash_mock,
                            signer_version_mock, signer_authorization_mock,
                            isfile_mock, get_eth_mock, dispose_eth_mock):
        signer_version = Mock()
        signer_version.msg = "RSK_powHSM_signer_aabbcc_iteration_an-iteration"
        signer_authorization = Mock()
        signer_authorization.signer_version = signer_version
        signer_authorization_mock.from_jsonfile.return_value = signer_authorization
        eth_mock = Mock()
        eth_mock.get_pubkey.return_value = WEB3_PUBKEY
        eth_mock.sign.side_effect = Exception("User rejected")
        get_eth_mock.return_value = eth_mock
        isfile_mock.return_value = True

        with patch("sys.argv", ["signapp.py", "eth", "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(call("Error signing with dongle: User rejected"),
                         info_mock.call_args_list[-1])
        signer_authorization.add_signature.assert_not_called()
        signer_authorization.save_to_jsonfile.assert_not_called()
        dispose_eth_mock.assert_called_once_with(eth_mock)

    def test_bad_signature(self, info_mock, compute_app_hash_mock,
                           signer_version_mock, signer_authorization_mock,
                           isfile_mock, get_eth_mock, dispose_eth_mock):
        signer_version = Mock()
        signer_version.get_authorization_digest.return_value = bytes.fromhex("bb"*32)
        signer_version.msg = "RSK_powHSM_signer_aabbcc_iteration_an-iteration"
        signer_authorization = Mock()
        signer_authorization.signer_version = signer_version
        signer_authorization_mock.from_jsonfile.return_value = signer_authorization
        privkey = ecdsa.SigningKey.from_string(bytes.fromhex("aa"*32),
                                               curve=ecdsa.SECP256k1)
        eth_mock = Mock()
        eth_mock.get_pubkey.return_value = \
            privkey.get_verifying_key().to_string("uncompressed")
        # Sign a DIFFERENT digest to create a bad signature for the expected digest
        bad_signature = privkey.sign_digest(
            bytes.fromhex("cc"*32), sigencode=ecdsa.util.sigencode_der)
        eth_mock.sign.return_value = bad_signature
        get_eth_mock.return_value = eth_mock
        isfile_mock.return_value = True

        with patch("sys.argv", ["signapp.py", "eth", "-o", "an-output-path"]):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        # Admin errors are not wrapped
        self.assertEqual(
            call(f"Bad signature from dongle! (got '{bad_signature.hex()}')"),
            info_mock.call_args_list[-1])
        signer_authorization.add_signature.assert_not_called()
        signer_authorization.save_to_jsonfile.assert_not_called()
        dispose_eth_mock.assert_called_once_with(eth_mock)


@patch("signapp.SignerAuthorization")
@patch("signapp.info")
class TestSignAppManual(TestCase):
    def setUp(self):
        self.signer_authorization = Mock()
        self.signer_authorization.signer_version.msg = "the-message"
        self.signer_authorization.signer_version.get_authorization_digest.return_value = \
            b"the-digest"
        self.signature = Mock()
        self.signature.der_signature = "the-der-signature"

    def test_ok(self, info_mock, signer_authorization_mock):
        signer_authorization_mock.from_jsonfile.return_value = self.signer_authorization

        with patch("sys.argv", ["signapp.py", "manual", "-o", "an-output-path",
                                "-g", "a-signature"]), \
             patch("signapp.parse_external_signature") as parse_mock, \
             patch("signapp.describe_external_signature") as describe_mock:
            parse_mock.return_value = self.signature
            describe_mock.return_value = ["line-1", "line-2"]
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)

        self.assertEqual([call("an-output-path")],
                         signer_authorization_mock.from_jsonfile.call_args_list)
        self.assertEqual([call("a-signature", "the-message", b"the-digest", None)],
                         parse_mock.call_args_list)
        self.assertEqual([call(self.signature, False)], describe_mock.call_args_list)
        self.assertEqual([call("the-der-signature")],
                         self.signer_authorization.add_signature.call_args_list)
        self.assertEqual([call("an-output-path")],
                         self.signer_authorization.save_to_jsonfile.call_args_list)
        self.assertEqual(
            [call("Opening signer authorization file an-output-path..."),
             call("Verifying signature..."),
             call("line-1"),
             call("line-2"),
             call("Adding signature..."),
             call("Signer authorization saved to an-output-path")],
            info_mock.call_args_list)

    def test_ok_with_expected_signer(self, info_mock, signer_authorization_mock):
        signer_authorization_mock.from_jsonfile.return_value = self.signer_authorization

        with patch("sys.argv", ["signapp.py", "manual", "-o", "an-output-path",
                                "-g", "a-signature", "-s", "a-signer"]), \
             patch("signapp.parse_external_signature") as parse_mock, \
             patch("signapp.describe_external_signature") as describe_mock:
            parse_mock.return_value = self.signature
            describe_mock.return_value = []
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            [call("a-signature", "the-message", b"the-digest", "a-signer")],
            parse_mock.call_args_list)
        self.assertEqual([call(self.signature, True)], describe_mock.call_args_list)
        self.assertEqual([call("the-der-signature")],
                         self.signer_authorization.add_signature.call_args_list)

    def test_invalid_signature(self, info_mock, signer_authorization_mock):
        signer_authorization_mock.from_jsonfile.return_value = self.signer_authorization

        with patch("sys.argv", ["signapp.py", "manual", "-o", "an-output-path",
                                "-g", "a-signature"]), \
             patch("signapp.parse_external_signature") as parse_mock:
            parse_mock.side_effect = ValueError("bad signature")
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_ERROR)
        self.assertEqual(call("bad signature"), info_mock.call_args_list[-1])
        self.signer_authorization.add_signature.assert_not_called()
        self.signer_authorization.save_to_jsonfile.assert_not_called()

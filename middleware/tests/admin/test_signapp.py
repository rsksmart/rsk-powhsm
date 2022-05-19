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
from unittest.mock import Mock, call, mock_open, patch
from signapp import main, COMMAND_SIGN, DEFAULT_PATH
from thirdparty.sha256 import SHA256
import io

import ecdsa
import logging
import random

logging.disable(logging.CRITICAL)

RETURN_SUCCESS = 0

USAGE = ('usage: signapp.py [-h] -a APP_PATH [-o OUTPUT_PATH] [-p PATH] [-k KEY] [-v]\n'
         '                  {key,ledger,hash}\n')


@patch("signapp.info")
@patch("signapp.IntelHexParser")
class TestSignApp(TestCase):
    def setUp(self):
        app_data = bytearray.fromhex('%032x' % random.randrange(16**32))
        hash = SHA256()
        hash.update(app_data)

        self.app_hash = hash.digest()
        self.area_mock = Mock()
        self.area_mock.data = app_data
        self.priv_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

    def test_hash(self, parser_mock, info_mock):
        parser_mock.return_value.getAreas.return_value = [self.area_mock]
        with patch('sys.argv', ['signapp.py', '-a', 'a-path', 'hash']):
            with self.assertRaises(SystemExit) as exit:
                main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            [call('Computing app hash...'),
             call(f'App hash: {self.app_hash.hex()}')], info_mock.call_args_list)

    @patch("sys.stderr", new_callable=io.StringIO)
    def test_hash_no_app(self, err_mock, parser_mock, _):
        parser_mock.return_value.getAreas.return_value = [self.area_mock]
        with patch('sys.argv', ['signapp.py', 'hash']):
            with self.assertRaises(SystemExit) as exit:
                main()
            self.assertNotEqual(exit.exception.code, RETURN_SUCCESS)

        error_msg = (f'{USAGE}signapp.py: error: the following arguments are required:'
                     ' -a/--app\n')
        self.assertEqual(error_msg, err_mock.getvalue())

    def test_hash_invalid_app(self, parser_mock, info_mock):
        parser_mock.side_effect = Exception("error-message")
        with patch('sys.argv', ['signapp.py', '-a', 'a-path', 'hash']):
            with self.assertRaises(SystemExit) as exit:
                main()
        self.assertNotEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertTrue(info_mock.called)
        self.assertEqual(call("error-message"), info_mock.call_args_list[-1])

    def test_key(self, parser_mock, info_mock):
        parser_mock.return_value.getAreas.return_value = [self.area_mock]
        pub_key = self.priv_key.get_verifying_key()
        out_path = 'out-path'

        with patch('sys.argv', [
                'signapp.py', '-a', 'a-path', '-o', out_path, '-k',
                self.priv_key.to_string().hex(), 'key'
        ]):
            with patch('builtins.open', mock_open()) as file_mock:
                with self.assertRaises(SystemExit) as exit:
                    main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual([call(out_path, 'wb')], file_mock.call_args_list)
        self.assertEqual([
            call('Computing app hash...'),
            call(f'App hash: {self.app_hash.hex()}'),
            call('Signing with key...'),
            call(f'Signature saved to {out_path}')
        ], info_mock.call_args_list)
        retreived_hash = info_mock.call_args_list[1][0][0].split()[-1]
        retreived_sig = file_mock.return_value.write.call_args_list[0][0][0]
        self.assertEqual(self.app_hash.hex(), retreived_hash)
        signature = bytes.fromhex(retreived_sig.decode())
        hash = bytes.fromhex(retreived_hash)
        self.assertTrue(
            pub_key.verify_digest(signature,
                                  hash,
                                  sigdecode=ecdsa.util.sigdecode_der))

    def test_key_default_path(self, parser_mock, info_mock):
        parser_mock.return_value.getAreas.return_value = [self.area_mock]
        pub_key = self.priv_key.get_verifying_key()

        with patch('sys.argv',
                   ['signapp.py', '-a', 'a-path', '-k',
                    self.priv_key.to_string().hex(), 'key']):
            with patch('builtins.open', mock_open()) as file_mock:
                with self.assertRaises(SystemExit) as exit:
                    main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual([call('a-path.sig', 'wb')], file_mock.call_args_list)
        self.assertEqual([
            call('Computing app hash...'),
            call(f'App hash: {self.app_hash.hex()}'),
            call('Signing with key...'),
            call('Signature saved to a-path.sig')
        ], info_mock.call_args_list)
        retreived_hash = info_mock.call_args_list[1][0][0].split()[-1]
        retreived_sig = file_mock.return_value.write.call_args_list[0][0][0]
        self.assertEqual(self.app_hash.hex(), retreived_hash)
        signature = bytes.fromhex(retreived_sig.decode())
        hash = bytes.fromhex(retreived_hash)
        self.assertTrue(pub_key.verify_digest(signature,
                                              hash,
                                              sigdecode=ecdsa.util.sigdecode_der))

    def test_key_no_key(self, parser_mock, info_mock):
        parser_mock.return_value.getAreas.return_value = [self.area_mock]
        with patch('sys.argv', ['signapp.py', '-a', 'a-path', 'key']):
            with self.assertRaises(SystemExit) as exit:
                main()
        self.assertNotEqual(exit.exception.code, RETURN_SUCCESS)
        error_msg = "Must provide a signing key with '-k/--key'"
        self.assertEqual(call(error_msg), info_mock.call_args_list[-1])

    def test_key_invalid_key(self, parser_mock, info_mock):
        parser_mock.return_value.getAreas.return_value = [self.area_mock]
        key = 'aabbccddeeff'
        with patch('sys.argv', ['signapp.py', '-a', 'a-path', '-k', key, 'key']):
            with self.assertRaises(SystemExit) as exit:
                main()
            error_msg = f"Invalid key '{key}'"
            self.assertNotEqual(exit.exception.code, RETURN_SUCCESS)
            self.assertEqual(call(error_msg), info_mock.call_args_list[-1])

    @patch("signapp.get_hsm")
    @patch("admin.misc.info")
    def test_ledger(self, _, get_hsm, parser_mock, info_mock):
        pub_key = self.priv_key.get_verifying_key()
        path = "m/44'/0'/0'/0/0"

        def send_command_mock(command, _):
            if command == COMMAND_SIGN:
                return self.priv_key.sign_digest(self.app_hash,
                                                 sigencode=ecdsa.util.sigencode_der)
            else:
                return pub_key.to_string()

        parser_mock.return_value.getAreas.return_value = [self.area_mock]
        dongle_mock = Mock()
        get_hsm.return_value = dongle_mock
        dongle_mock._send_command = Mock(side_effect=send_command_mock)
        with patch(
            'sys.argv',
                ['signapp.py', '-a', 'a-path', '-p', path, '-o', 'out-path', 'ledger']):
            with patch('builtins.open', mock_open()) as file_mock:
                with self.assertRaises(SystemExit) as exit:
                    main()
        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual([
            call('Computing app hash...'),
            call(f'App hash: {self.app_hash.hex()}'),
            call(f"Retrieving public key for path '{str(path)}'..."),
            call(f"Public key: {pub_key.to_string().hex()}"),
            call("Signing with dongle..."),
            call("Verifying signature..."),
            call("Signature saved to out-path")
        ], info_mock.call_args_list)
        retreived_hash = info_mock.call_args_list[1][0][0].split()[-1]
        retreived_sig = file_mock.return_value.write.call_args_list[0][0][0]
        signature = bytes.fromhex(retreived_sig.decode())
        hash = bytes.fromhex(retreived_hash)
        self.assertTrue(pub_key.verify_digest(signature,
                                              hash,
                                              sigdecode=ecdsa.util.sigdecode_der))

    @patch("signapp.get_hsm")
    @patch("admin.misc.info")
    def test_ledger_default_path(self, _, get_hsm, parser_mock, info_mock):
        pub_key = self.priv_key.get_verifying_key()
        path = DEFAULT_PATH

        def send_command_mock(command, _):
            if command == COMMAND_SIGN:
                return self.priv_key.sign_digest(self.app_hash,
                                                 sigencode=ecdsa.util.sigencode_der)
            else:
                return pub_key.to_string()

        parser_mock.return_value.getAreas.return_value = [self.area_mock]
        dongle_mock = Mock()
        get_hsm.return_value = dongle_mock
        dongle_mock._send_command = Mock(side_effect=send_command_mock)
        with patch('sys.argv',
                   ['signapp.py', '-a', 'a-path', '-o', 'out-path', 'ledger']):
            with patch('builtins.open', mock_open()) as file_mock:
                with self.assertRaises(SystemExit) as exit:
                    main()

        self.assertEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual([
            call('Computing app hash...'),
            call(f'App hash: {self.app_hash.hex()}'),
            call(f"Retrieving public key for path '{str(path)}'..."),
            call(f"Public key: {pub_key.to_string().hex()}"),
            call("Signing with dongle..."),
            call("Verifying signature..."),
            call("Signature saved to out-path")
        ], info_mock.call_args_list)
        retreived_hash = info_mock.call_args_list[1][0][0].split()[-1]
        retreived_sig = file_mock.return_value.write.call_args_list[0][0][0]
        signature = bytes.fromhex(retreived_sig.decode())
        hash = bytes.fromhex(retreived_hash)
        self.assertTrue(pub_key.verify_digest(signature,
                                              hash,
                                              sigdecode=ecdsa.util.sigdecode_der))

    def test_ledger_invalid_bip_path(self, parser_mock, info_mock):
        path = "invalid-path"
        parser_mock.return_value.getAreas.return_value = [self.area_mock]

        with patch(
            'sys.argv',
                ['signapp.py', '-p', path, '-a', 'a-path', '-o', 'out-path', 'ledger']):
            with self.assertRaises(SystemExit) as exit:
                main()
        self.assertNotEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(
            call("BIP32Path spec must start with 'm/', instead got invalid-path"),
            info_mock.call_args_list[-1]
        )

    @patch("signapp.get_hsm")
    @patch("sys.stdout.write")
    def test_ledger_invalid_app(self, _, get_hsm, parser_mock, info_mock):
        parser_mock.side_effect = Exception("error-message")
        get_hsm.return_value = Mock()
        with patch('sys.argv',
                   ['signapp.py', '-a', 'a-path', '-o', 'out-path', 'ledger']):
            with self.assertRaises(SystemExit) as exit:
                main()
        self.assertNotEqual(exit.exception.code, RETURN_SUCCESS)
        self.assertEqual(call("error-message"), info_mock.call_args_list[-1])

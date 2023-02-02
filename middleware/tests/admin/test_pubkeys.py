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
from unittest.mock import Mock, call, patch, mock_open
from admin.misc import AdminError
from admin.pubkeys import do_get_pubkeys, PATHS
from ledger.hsm2dongle import HSM2Dongle

import ecdsa
import json
import logging

logging.disable(logging.CRITICAL)


@patch("sys.stdout.write")
@patch("time.sleep")
@patch("admin.pubkeys.get_hsm")
@patch("admin.pubkeys.do_unlock")
class TestPubkeys(TestCase):
    def setUp(self):
        self.output_file_path = 'outfile'
        options = {
            'no_unlock': False,
            'output_file_path': self.output_file_path,
            'verbose': False
        }
        self.default_options = SimpleNamespace(**options)

        self.dongle = Mock()
        self.invalid_public_key = 'aa' * 65

        self.public_keys = {}
        for path in PATHS:
            pubkey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1).get_verifying_key()
            self.public_keys[path] = pubkey.to_string().hex()

    def test_pubkeys(self, unlock_mock, get_hsm, *_):
        def get_pubkey_mock(path):
            path_name = list(PATHS.keys())[list(PATHS.values()).index(path)]
            return self.public_keys[path_name]

        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.SIGNER)
        self.dongle.get_public_key = Mock(side_effect=get_pubkey_mock)
        self.dongle.is_onboarded = Mock(return_value=True)
        get_hsm.return_value = self.dongle

        with patch('builtins.open', mock_open()) as file_mock:
            do_get_pubkeys(self.default_options)

        self.assertEqual([call(self.output_file_path, 'w'),
                          call(f'{self.output_file_path}.json', 'w')],
                         file_mock.call_args_list)

        json_dict = {}
        path_name_padding = max(map(len, PATHS))
        expected_call_list = [call(f"{'*' * 80}\n"),
                              call('Name \t\t\t Path \t\t\t\t Pubkey\n'),
                              call('==== \t\t\t ==== \t\t\t\t ======\n')]
        for path_name in PATHS.keys():
            pubkey = ecdsa.VerifyingKey.from_string(bytes.fromhex(
                self.public_keys[path_name]), curve=ecdsa.SECP256k1)
            pubkey_compressed = pubkey.to_string("compressed").hex()
            pubkey_uncompressed = pubkey.to_string("uncompressed").hex()
            expected_call_list.append(call(f'{path_name.ljust(path_name_padding)} '
                                           f'\t\t {PATHS[path_name]} '
                                           f'\t\t {pubkey_compressed}\n'))
            json_dict[str(PATHS[path_name])] = pubkey_uncompressed
        expected_call_list.append(call('*' * 80 + '\n'))
        expected_call_list.append(call('%s\n' % json.dumps(json_dict, indent=2)))

        self.assertEqual(expected_call_list, file_mock.return_value.write.call_args_list)
        self.assertTrue(unlock_mock.called)

    def test_pubkeys_no_unlock(self, unlock_mock, get_hsm, *_):
        def get_pubkey_mock(path):
            path_name = list(PATHS.keys())[list(PATHS.values()).index(path)]
            return self.public_keys[path_name]

        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.SIGNER)
        self.dongle.get_public_key = Mock(side_effect=get_pubkey_mock)
        self.dongle.is_onboarded = Mock(return_value=True)
        get_hsm.return_value = self.dongle

        options = self.default_options
        options.no_unlock = True
        with patch('builtins.open', mock_open()) as file_mock:
            do_get_pubkeys(options)

        self.assertEqual([call(self.output_file_path, 'w'),
                          call(f'{self.output_file_path}.json', 'w')],
                         file_mock.call_args_list)

        json_dict = {}
        path_name_padding = max(map(len, PATHS))
        expected_call_list = [call(f"{'*' * 80}\n"),
                              call('Name \t\t\t Path \t\t\t\t Pubkey\n'),
                              call('==== \t\t\t ==== \t\t\t\t ======\n')]
        for path_name in PATHS.keys():
            pubkey = ecdsa.VerifyingKey.from_string(bytes.fromhex(
                self.public_keys[path_name]), curve=ecdsa.SECP256k1)
            pubkey_compressed = pubkey.to_string("compressed").hex()
            pubkey_uncompressed = pubkey.to_string("uncompressed").hex()
            expected_call_list.append(call(f'{path_name.ljust(path_name_padding)} '
                                           f'\t\t {PATHS[path_name]} '
                                           f'\t\t {pubkey_compressed}\n'))
            json_dict[str(PATHS[path_name])] = pubkey_uncompressed
        expected_call_list.append(call('*' * 80 + '\n'))
        expected_call_list.append(call('%s\n' % json.dumps(json_dict, indent=2)))

        self.assertEqual(expected_call_list, file_mock.return_value.write.call_args_list)
        self.assertFalse(unlock_mock.called)

    def test_pubkeys_unlock_error(self, unlock_mock, get_hsm, *_):
        unlock_mock.side_effect = Exception("unlock-error")
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.SIGNER)
        self.dongle.is_onboarded = Mock(return_value=True)
        get_hsm.return_value = self.dongle

        with self.assertRaises(AdminError) as e:
            do_get_pubkeys(self.default_options)

        self.assertTrue(unlock_mock.called)
        self.assertEqual('Failed to unlock device: unlock-error', str(e.exception))

    def test_pubkeys_invalid_pubkey(self, unlock_mock, get_hsm, *_):
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.SIGNER)
        self.dongle.get_public_key = Mock(return_value=self.invalid_public_key)
        self.dongle.is_onboarded = Mock(return_value=True)
        get_hsm.return_value = self.dongle

        with patch('builtins.open', mock_open()) as file_mock:
            with self.assertRaises(AdminError) as e:
                do_get_pubkeys(self.default_options)

        self.assertTrue(unlock_mock.called)
        self.assertEqual('Error writing output: '
                         'Invalid X9.62 encoding of the public point',
                         str(e.exception))
        self.assertTrue(file_mock.return_value.write.called)
        self.assertEqual([call(f"{'*' * 80}\n"),
                          call('Name \t\t\t Path \t\t\t\t Pubkey\n'),
                          call('==== \t\t\t ==== \t\t\t\t ======\n')],
                         file_mock.return_value.write.call_args_list)

    def test_pubkeys_invalid_mode(self, unlock_mock, get_hsm, *_):
        self.dongle.get_current_mode = Mock(return_value=HSM2Dongle.MODE.BOOTLOADER)
        self.dongle.is_onboarded = Mock(return_value=True)
        get_hsm.return_value = self.dongle

        with self.assertRaises(AdminError) as e:
            do_get_pubkeys(self.default_options)

        self.assertTrue(unlock_mock.called)
        self.assertTrue(str(e.exception).startswith('Device not in app mode.'))

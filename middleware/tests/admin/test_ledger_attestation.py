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

import json

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, call, patch, mock_open
from admin.ledger_attestation import do_attestation
from admin.certificate import HSMCertificate
from admin.misc import AdminError


@patch("sys.stdout.write")
@patch("time.sleep")
@patch("admin.ledger_attestation.do_unlock")
@patch("admin.ledger_attestation.get_hsm")
@patch("admin.ledger_attestation.HSMCertificate.from_jsonfile")
class TestAttestation(TestCase):
    def setupMocks(self, from_jsonfile, get_hsm):
        from_jsonfile.return_value = HSMCertificate({
            "version": 1,
            "targets": ["attestation", "device"],
            "elements": [
                {
                    "name": "attestation",
                    "message": '11' * 32,
                    "signature": '22' * 32,
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": '33' * 32,
                    "signature": '44' * 32,
                    "signed_by": "root"
                }]
        })
        get_hsm.return_value = Mock()
        hsm = get_hsm.return_value
        hsm.get_ui_attestation = Mock(return_value={
            'message':   'aa' * 32,
            'signature': 'bb' * 32,
            'app_hash':  'cc' * 32
        })
        hsm.exit_menu = Mock()
        hsm.disconnect = Mock()
        hsm.get_powhsm_attestation = Mock(return_value={
            'envelope':   'dd' * 32,
            'message':   'dd' * 32,
            'signature': 'ee' * 32,
            'app_hash':  'ff' * 32
        })

    def setupDefaultOptions(self):
        options = SimpleNamespace()
        options.output_file_path = 'out-path'
        options.attestation_certificate_file_path = 'att-cert-path'
        options.verbose = False
        options.attestation_ud_source = 'aa' * 32
        return options

    @patch('admin.ledger_attestation.get_ud_value_for_attestation')
    def test_attestation_ok(self, get_ud_value_for_attestation,
                            from_jsonfile, get_hsm, *_):
        self.setupMocks(from_jsonfile, get_hsm)
        get_ud_value_for_attestation.return_value = 'bb'*32

        options = self.setupDefaultOptions()
        options.attestation_ud_source = 'an-url'
        with patch('builtins.open', mock_open()) as file_mock:
            do_attestation(options)

        self.assertEqual([call(options.attestation_certificate_file_path)],
                         from_jsonfile.call_args_list)
        self.assertEqual([call('an-url')], get_ud_value_for_attestation.call_args_list)
        self.assertNotEqual([call(options.attestation_ud_source)],
                            get_hsm.return_value.get_ui_attestation.call_args_list)
        self.assertEqual([call('bb' * 32)],
                         get_hsm.return_value.get_ui_attestation.call_args_list)
        self.assertEqual([call(options.verbose), call(options.verbose)],
                         get_hsm.call_args_list)
        self.assertEqual([call(options.output_file_path, 'w')], file_mock.call_args_list)
        self.assertEqual([call("%s\n" % json.dumps({
            'version': 1,
            'targets': [
                'ui',
                'signer'
            ],
            'elements': [
                {
                    "name": "attestation",
                    "message": '11' * 32,
                    "signature": '22' * 32,
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": '33' * 32,
                    "signature": '44' * 32,
                    "signed_by": "root"
                },
                {
                    'name': 'ui',
                    'message': 'aa' * 32,
                    'signature': 'bb' * 32,
                    'signed_by': 'attestation',
                    'tweak': 'cc' * 32
                },
                {
                    'name': 'signer',
                    'message': 'dd' * 32,
                    'signature': 'ee' * 32,
                    'signed_by': 'attestation',
                    'tweak': 'ff' * 32
                }
            ]
        }, indent=2))],
            file_mock.return_value.write.call_args_list)

    def test_attestation_no_output_file(self, from_jsonfile, get_hsm, *_):
        self.setupMocks(from_jsonfile, get_hsm)
        options = self.setupDefaultOptions()
        options.output_file_path = None
        with patch('builtins.open', mock_open()) as file_mock:
            with self.assertRaises(AdminError):
                do_attestation(options)
        self.assertFalse(from_jsonfile.called)
        self.assertFalse(get_hsm.called)
        self.assertFalse(file_mock.return_value.write.called)

    def test_attestation_no_att_cert_file(self, from_jsonfile, get_hsm, *_):
        self.setupMocks(from_jsonfile, get_hsm)
        options = self.setupDefaultOptions()
        options.attestation_certificate_file_path = None
        with patch('builtins.open', mock_open()) as file_mock:
            with self.assertRaises(AdminError):
                do_attestation(options)
        self.assertFalse(from_jsonfile.called)
        self.assertFalse(get_hsm.called)
        self.assertFalse(file_mock.return_value.write.called)

    def test_attestation_invalid_jsonfile(self, from_jsonfile, get_hsm, *_):
        self.setupMocks(from_jsonfile, get_hsm)
        from_jsonfile.side_effect = AdminError()
        options = self.setupDefaultOptions()
        with patch('builtins.open', mock_open()) as file_mock:
            with self.assertRaises(AdminError):
                do_attestation(options)
        self.assertTrue(from_jsonfile.called)
        self.assertFalse(get_hsm.called)
        self.assertFalse(file_mock.return_value.write.called)

    @patch('admin.ledger_attestation.get_ud_value_for_attestation')
    def test_attestation_get_ud_value_for_attestation_error(self,
                                                            get_ud_value_for_attestation,
                                                            from_jsonfile, get_hsm, *_):
        self.setupMocks(from_jsonfile, get_hsm)
        get_ud_value_for_attestation.side_effect = AdminError('error-msg')
        options = self.setupDefaultOptions()
        options.attestation_ud_source = 'another-url'
        with patch('builtins.open', mock_open()) as file_mock:
            with self.assertRaises(AdminError):
                do_attestation(options)
        self.assertEqual([call('another-url')],
                         get_ud_value_for_attestation.call_args_list)
        self.assertTrue(from_jsonfile.called)
        self.assertFalse(get_hsm.called)
        self.assertFalse(file_mock.return_value.write.called)

    def test_attestation_unlock_error(self, from_jsonfile, get_hsm, do_unlock, *_):
        self.setupMocks(from_jsonfile, get_hsm)
        do_unlock.side_effect = Exception()
        options = self.setupDefaultOptions()
        with patch('builtins.open', mock_open()) as file_mock:
            with self.assertRaises(AdminError):
                do_attestation(options)
        self.assertTrue(from_jsonfile.called)
        self.assertFalse(get_hsm.called)
        self.assertFalse(file_mock.return_value.write.called)

    def test_attestation_get_hsm_error(self, from_jsonfile, get_hsm, *_):
        self.setupMocks(from_jsonfile, get_hsm)
        get_hsm.side_effect = Exception()
        options = self.setupDefaultOptions()
        with patch('builtins.open', mock_open()) as file_mock:
            with self.assertRaises(Exception):
                do_attestation(options)
        self.assertTrue(from_jsonfile.called)
        self.assertTrue(get_hsm.called)
        self.assertFalse(file_mock.return_value.write.called)

    def test_attestation_get_ui_attestation_error(self, from_jsonfile, get_hsm, *_):
        self.setupMocks(from_jsonfile, get_hsm)
        hsm = get_hsm.return_value
        hsm.get_ui_attestation.side_effect = Exception()
        options = self.setupDefaultOptions()
        with patch('builtins.open', mock_open()) as file_mock:
            with self.assertRaises(AdminError):
                do_attestation(options)
        self.assertTrue(from_jsonfile.called)
        self.assertTrue(get_hsm.called)
        self.assertFalse(file_mock.return_value.write.called)

    def test_attestation_get_powhsm_attestation_error(self, from_jsonfile, get_hsm, *_):
        self.setupMocks(from_jsonfile, get_hsm)
        hsm = get_hsm.return_value
        hsm.get_powhsm_attestation.side_effect = Exception()
        options = self.setupDefaultOptions()
        with patch('builtins.open', mock_open()) as file_mock:
            with self.assertRaises(AdminError):
                do_attestation(options)
        self.assertTrue(from_jsonfile.called)
        self.assertTrue(get_hsm.called)
        self.assertFalse(file_mock.return_value.write.called)

    def test_attestation_get_powhsm_attestation_envelope_msg_differ(self, from_jsonfile,
                                                                    get_hsm, *_):
        self.setupMocks(from_jsonfile, get_hsm)
        hsm = get_hsm.return_value
        hsm.get_powhsm_attestation.return_value["envelope"] = "11"*32
        hsm.get_powhsm_attestation.return_value["message"] = "22"*32
        options = self.setupDefaultOptions()
        with patch('builtins.open', mock_open()) as file_mock:
            with self.assertRaises(AdminError):
                do_attestation(options)
        self.assertTrue(from_jsonfile.called)
        self.assertTrue(get_hsm.called)
        self.assertFalse(file_mock.return_value.write.called)

    @patch("admin.ledger_attestation.HSMCertificate.add_element")
    def test_attestation_add_element_error(self, add_element, from_jsonfile, get_hsm, *_):
        self.setupMocks(from_jsonfile, get_hsm)
        add_element.side_effect = Exception()
        options = self.setupDefaultOptions()
        with patch('builtins.open', mock_open()) as file_mock:
            with self.assertRaises(Exception):
                do_attestation(options)
        self.assertTrue(from_jsonfile.called)
        self.assertTrue(get_hsm.called)
        self.assertFalse(file_mock.return_value.write.called)

    @patch("admin.ledger_attestation.HSMCertificate.add_target")
    def test_attestation_add_target_error(self, add_target, from_jsonfile, get_hsm, *_):
        self.setupMocks(from_jsonfile, get_hsm)
        add_target.side_effect = ValueError()
        options = self.setupDefaultOptions()
        with patch('builtins.open', mock_open()) as file_mock:
            with self.assertRaises(ValueError):
                do_attestation(options)
        self.assertTrue(from_jsonfile.called)
        self.assertTrue(get_hsm.called)
        self.assertFalse(file_mock.return_value.write.called)

    @patch("admin.ledger_attestation.HSMCertificate.save_to_jsonfile")
    def test_attestation_save_to_jsonfile_error(self,
                                                save_to_jsonfile,
                                                from_jsonfile,
                                                get_hsm,
                                                *_):
        self.setupMocks(from_jsonfile, get_hsm)
        save_to_jsonfile.side_effect = Exception()
        options = self.setupDefaultOptions()
        with patch('builtins.open', mock_open()) as file_mock:
            with self.assertRaises(Exception):
                do_attestation(options)
        self.assertTrue(from_jsonfile.called)
        self.assertTrue(get_hsm.called)
        self.assertFalse(file_mock.return_value.write.called)

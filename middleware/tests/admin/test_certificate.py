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
import os
import secp256k1 as ec

from unittest import TestCase
from unittest.mock import call, patch, mock_open
from admin.certificate import HSMCertificate, HSMCertificateElement


class TestCertificate(TestCase):
    def test_create_valid_certificate_ok(self):
        cert = HSMCertificate({
            "version": 1,
            "targets": ["attestation", "device"],
            "elements": [
                {
                    "name": "attestation",
                    "message": 'aa',
                    "signature": 'bb',
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": 'cc',
                    "signature": 'dd',
                    "signed_by": "root"
                }]
        })
        self.assertEqual({
            "version": 1,
            "targets": ["attestation", "device"],
            "elements": [
                {
                    "name": "attestation",
                    "message": 'aa',
                    "signature": 'bb',
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": 'cc',
                    "signature": 'dd',
                    "signed_by": "root"
                }]
        }, cert.to_dict())

    def test_create_empty_certificate_ok(self):
        cert = HSMCertificate()
        self.assertEqual({'version': 1, 'targets': [], 'elements': []}, cert.to_dict())

    def test_create_certificate_invalid_version(self):
        with self.assertRaises(ValueError):
            HSMCertificate({
                "version": 99,
                "targets": ["attestation", "device"],
                "elements": [
                    {
                        "name": "attestation",
                        "message": 'aa',
                        "signature": 'bb',
                        "signed_by": "device"
                    },
                    {
                        "name": "device",
                        "message": 'cc',
                        "signature": 'dd',
                        "signed_by": "root"
                    }]
            })

    def test_create_certificate_no_version(self):
        with self.assertRaises(ValueError):
            HSMCertificate({
                "targets": ["attestation", "device"],
                "elements": [
                    {
                        "name": "attestation",
                        "message": 'aa',
                        "signature": 'bb',
                        "signed_by": "device"
                    },
                    {
                        "name": "device",
                        "message": 'cc',
                        "signature": 'dd',
                        "signed_by": "root"
                    }]
            })

    def test_create_certificate_missing_targets(self):
        with self.assertRaises(ValueError):
            HSMCertificate({
                "version": 1,
                "elements": [
                    {
                        "name": "attestation",
                        "message": 'aa',
                        "signature": 'bb',
                        "signed_by": "device"
                    },
                    {
                        "name": "device",
                        "message": 'cc',
                        "signature": 'dd',
                        "signed_by": "root"
                    }]
            })

    def test_create_certificate_invalid_targets(self):
        with self.assertRaises(ValueError):
            HSMCertificate({
                "version": 1,
                "targets": "invalid-targets",
                "elements": [
                    {
                        "name": "attestation",
                        "message": 'aa',
                        "signature": 'bb',
                        "signed_by": "device"
                    },
                    {
                        "name": "device",
                        "message": 'cc',
                        "signature": 'dd',
                        "signed_by": "root"
                    }]
            })

    def test_create_certificate_missing_elements(self):
        with self.assertRaises(ValueError):
            HSMCertificate({
                "version": 1,
                "targets": ["attestation", "device"]
            })

    @patch('admin.certificate.HSMCertificateElement')
    def test_create_certificate_invalid_element(self, certElementMock):
        certElementMock.side_effect = ValueError()
        with self.assertRaises(ValueError):
            HSMCertificate({
                "version": 1,
                "targets": ["attestation", "device"],
                "elements": [
                    {
                        "name": "attestation",
                        "message": 'aa',
                        "signature": 'bb',
                        "signed_by": "device"
                    },
                    {
                        "name": "device",
                        "message": 'cc',
                        "signature": 'dd',
                        "signed_by": "root"
                    }]
            })

    def test_create_certificate_target_not_in_elements(self):
        with self.assertRaises(ValueError):
            HSMCertificate({
                "version": 1,
                "targets": ["attestation", "device", "ui"],
                "elements": [
                    {
                        "name": "attestation",
                        "message": 'aa',
                        "signature": 'bb',
                        "signed_by": "device"
                    },
                    {
                        "name": "device",
                        "message": 'cc',
                        "signature": 'dd',
                        "signed_by": "root"
                    }]
            })

    def test_create_certificate_elements_without_path_to_root(self):
        with self.assertRaises(ValueError):
            HSMCertificate({
                "version": 1,
                "targets": ["attestation", "device"],
                "elements": [
                    {
                        "name": "attestation",
                        "message": 'aa',
                        "signature": 'bb',
                        "signed_by": "attestation"
                    },
                    {
                        "name": "device",
                        "message": 'cc',
                        "signature": 'dd',
                        "signed_by": "root"
                    }]
            })

    def test_create_certificate_signer_not_in_elements(self):
        with self.assertRaises(ValueError):
            HSMCertificate({
                "version": 1,
                "targets": ["attestation", "device"],
                "elements": [
                    {
                        "name": "attestation",
                        "message": 'aa',
                        "signature": 'bb',
                        "signed_by": "signer"
                    },
                    {
                        "name": "device",
                        "message": 'cc',
                        "signature": 'dd',
                        "signed_by": "root"
                    }]
            })

    def test_validate_and_get_values_ok(self):
        root_privkey = ec.PrivateKey()
        root_pubkey = root_privkey.pubkey.serialize(compressed=False).hex()
        device_privkey = ec.PrivateKey()
        device_pubkey = device_privkey.pubkey.serialize(compressed=False).hex()
        att_pubkey = ec.PrivateKey().pubkey.serialize(compressed=False).hex()

        att_msg = 'ff' + att_pubkey
        att_sig = device_privkey.ecdsa_serialize(
            device_privkey.ecdsa_sign(bytes.fromhex(att_msg))).hex()

        device_msg = os.urandom(16).hex() + device_pubkey
        device_sig = root_privkey.ecdsa_serialize(
            root_privkey.ecdsa_sign(bytes.fromhex(device_msg))).hex()

        cert = HSMCertificate({
            "version": 1,
            "targets": ["attestation", "device"],
            "elements": [
                {
                    "name": "attestation",
                    "message": att_msg,
                    "signature": att_sig,
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": device_msg,
                    "signature": device_sig,
                    "signed_by": "root"
                }]
        })

        self.assertEqual({
            'attestation': (True, att_pubkey, None),
            'device': (True, device_pubkey, None)
        }, cert.validate_and_get_values(root_pubkey))

    def test_create_and_get_values_invalid_pubkey(self):
        root_privkey = ec.PrivateKey()
        device_privkey = ec.PrivateKey()
        device_pubkey = device_privkey.pubkey.serialize(compressed=False).hex()
        att_pubkey = ec.PrivateKey().pubkey.serialize(compressed=False).hex()

        att_msg = 'ff' + att_pubkey
        att_sig = device_privkey.ecdsa_serialize(
            device_privkey.ecdsa_sign(bytes.fromhex(att_msg))).hex()

        device_msg = os.urandom(16).hex() + device_pubkey
        device_sig = root_privkey.ecdsa_serialize(
            root_privkey.ecdsa_sign(bytes.fromhex(device_msg))).hex()

        cert = HSMCertificate({
            "version": 1,
            "targets": ["attestation", "device"],
            "elements": [
                {
                    "name": "attestation",
                    "message": att_msg,
                    "signature": att_sig,
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": device_msg,
                    "signature": device_sig,
                    "signed_by": "root"
                }]
        })

        self.assertEqual({
            'attestation': (False, 'root'),
            'device': (False, 'root')
        }, cert.validate_and_get_values('invalid-pubkey'))

    def test_validate_and_get_values_invalid_element(self):
        root_privkey = ec.PrivateKey()
        root_pubkey = root_privkey.pubkey.serialize(compressed=False).hex()
        device_privkey = ec.PrivateKey()
        device_pubkey = device_privkey.pubkey.serialize(compressed=False).hex()
        att_pubkey = ec.PrivateKey().pubkey.serialize(compressed=False).hex()

        att_msg = 'ff' + att_pubkey
        att_sig = 'aa' * 65

        device_msg = os.urandom(16).hex() + device_pubkey
        device_sig = root_privkey.ecdsa_serialize(
            root_privkey.ecdsa_sign(bytes.fromhex(device_msg))).hex()

        cert = HSMCertificate({
            "version": 1,
            "targets": ["attestation", "device"],
            "elements": [
                {
                    "name": "attestation",
                    "message": att_msg,
                    "signature": att_sig,
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": device_msg,
                    "signature": device_sig,
                    "signed_by": "root"
                }]
        })

        self.assertEqual({
            'attestation': (False, 'attestation'),
            'device': (True, device_pubkey, None)
        }, cert.validate_and_get_values(root_pubkey))

    def test_validate_and_get_values_invalid_elements(self):
        att_privkey = ec.PrivateKey()
        att_msg = os.urandom(66).hex()
        att_sig = 'aa' * 65

        device_privkey = ec.PrivateKey()
        device_pubkey = device_privkey.pubkey.serialize(compressed=False).hex()
        device_msg = os.urandom(16).hex() + \
            att_privkey.pubkey.serialize(compressed=False).hex()
        device_sig = 'bb' * 65

        cert = HSMCertificate({
            "version": 1,
            "targets": ["attestation", "device"],
            "elements": [
                {
                    "name": "attestation",
                    "message": att_msg,
                    "signature": att_sig,
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": device_msg,
                    "signature": device_sig,
                    "signed_by": "root"
                }]
        })

        self.assertEqual({
            'attestation': (False, 'device'),
            'device': (False, 'device')
        }, cert.validate_and_get_values(device_pubkey))

    def test_add_element_ok(self):
        cert = HSMCertificate()
        self.assertEqual({'version': 1, 'targets': [], 'elements': []}, cert.to_dict())

        cert.add_element(HSMCertificateElement({
            "name": "device",
            "message": 'cc',
            "signature": 'dd',
            "signed_by": "root"
        }))
        self.assertEqual({'version': 1, 'targets': [], 'elements': [
            {
                "name": "device",
                "message": 'cc',
                "signature": 'dd',
                "signed_by": "root"
            }
        ]}, cert.to_dict())

    def test_add_element_invalid_element(self):
        cert = HSMCertificate()
        self.assertEqual({'version': 1, 'targets': [], 'elements': []}, cert.to_dict())
        with self.assertRaises(ValueError):
            cert.add_element('not-an-element')
        self.assertEqual({'version': 1, 'targets': [], 'elements': []}, cert.to_dict())

    def test_add_target_ok(self):
        cert = HSMCertificate({
            "version": 1,
            "targets": [],
            "elements": [
                {
                    "name": "attestation",
                    "message": 'aa',
                    "signature": 'bb',
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": 'cc',
                    "signature": 'dd',
                    "signed_by": "root"
                }]
        })
        cert.add_target('attestation')
        cert.add_target('device')
        self.assertEqual({
            "version": 1,
            "targets": ["attestation", "device"],
            "elements": [
                {
                    "name": "attestation",
                    "message": 'aa',
                    "signature": 'bb',
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": 'cc',
                    "signature": 'dd',
                    "signed_by": "root"
                }]
        }, cert.to_dict())

    def test_add_target_not_in_elements(self):
        cert = HSMCertificate({
            "version": 1,
            "targets": [],
            "elements": [
                {
                    "name": "attestation",
                    "message": 'aa',
                    "signature": 'bb',
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": 'cc',
                    "signature": 'dd',
                    "signed_by": "root"
                }]
        })
        cert.add_target('attestation')
        with self.assertRaises(ValueError):
            cert.add_target('ui')
        self.assertEqual({
            "version": 1,
            "targets": ["attestation"],
            "elements": [
                {
                    "name": "attestation",
                    "message": 'aa',
                    "signature": 'bb',
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": 'cc',
                    "signature": 'dd',
                    "signed_by": "root"
                }]
        }, cert.to_dict())

    def test_clear_targets(self):
        cert = HSMCertificate({
            "version": 1,
            "targets": ["attestation", "device"],
            "elements": [
                {
                    "name": "attestation",
                    "message": 'aa',
                    "signature": 'bb',
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": 'cc',
                    "signature": 'dd',
                    "signed_by": "root"
                }]
        })
        cert.clear_targets()
        self.assertEqual({
            "version": 1,
            "targets": [],
            "elements": [
                {
                    "name": "attestation",
                    "message": 'aa',
                    "signature": 'bb',
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": 'cc',
                    "signature": 'dd',
                    "signed_by": "root"
                }]
        }, cert.to_dict())

    def test_save_to_jsonfile_ok(self):
        cert = HSMCertificate({
            "version": 1,
            "targets": ["attestation", "device"],
            "elements": [
                {
                    "name": "attestation",
                    "message": 'aa',
                    "signature": 'bb',
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": 'cc',
                    "signature": 'dd',
                    "signed_by": "root"
                }]
        })
        with patch('builtins.open', mock_open()) as file_mock:
            cert.save_to_jsonfile('file-path')
        self.assertEqual([call('file-path', 'w')], file_mock.call_args_list)
        self.assertEqual([call('{\n  "version": 1,\n'
                               '  "targets": [\n'
                               '    "attestation",\n'
                               '    "device"\n  ],\n'
                               '  "elements": [\n'
                               '    {\n'
                               '      "name": "attestation",\n'
                               '      "message": "aa",\n'
                               '      "signature": "bb",\n'
                               '      "signed_by": "device"\n'
                               '    },\n'
                               '    {\n'
                               '      "name": "device",\n'
                               '      "message": "cc",\n'
                               '      "signature": "dd",\n'
                               '      "signed_by": "root"\n'
                               '    }\n'
                               '  ]\n'
                               '}\n')], file_mock.return_value.write.call_args_list)

    def test_save_to_jsonfile_write_error(self):
        cert = HSMCertificate({
            "version": 1,
            "targets": ["attestation", "device"],
            "elements": [
                {
                    "name": "attestation",
                    "message": 'aa',
                    "signature": 'bb',
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": 'cc',
                    "signature": 'dd',
                    "signed_by": "root"
                }]
        })
        with patch('builtins.open', mock_open()) as file_mock:
            file_mock.side_effect = Exception()
            with self.assertRaises(Exception):
                cert.save_to_jsonfile('file-path')
        self.assertEqual([call('file-path', 'w')], file_mock.call_args_list)
        self.assertFalse(file_mock.return_value.write.called)

    def test_from_jsonfile_ok(self):
        cert_dict = {
            "version": 1,
            "targets": ["attestation", "device"],
            "elements": [
                {
                    "name": "attestation",
                    "message": 'aa',
                    "signature": 'bb',
                    "signed_by": "device"
                },
                {
                    "name": "device",
                    "message": 'cc',
                    "signature": 'dd',
                    "signed_by": "root"
                }]
        }
        with patch('builtins.open', mock_open(read_data=json.dumps(cert_dict))) as file:
            certificate = HSMCertificate.from_jsonfile('file-path')
        self.assertEqual([call('file-path', 'r')], file.call_args_list)
        self.assertEqual(cert_dict, certificate.to_dict())

    def test_from_jsonfile_error(self):
        with patch('builtins.open', mock_open(read_data='invalid-data')) as file:
            with self.assertRaises(ValueError):
                HSMCertificate.from_jsonfile('file-path')
        self.assertEqual([call('file-path', 'r')], file.call_args_list)

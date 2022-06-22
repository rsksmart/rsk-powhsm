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

import hashlib
import hmac
import os
from parameterized import parameterized
import secp256k1 as ec

from unittest import TestCase
from admin.certificate import HSMCertificateElement


class TestCertificateElement(TestCase):
    def test_create_certificate_element_ok(self):
        element = HSMCertificateElement({
            "name": "device",
            "message": 'cc',
            "signature": 'dd',
            "signed_by": "root",
            "tweak": 'ee'
        })
        self.assertEqual({
            "name": "device",
            "message": 'cc',
            "signature": 'dd',
            "signed_by": "root",
            "tweak": 'ee'
        }, element.to_dict())

    def test_create_certificate_element_invalid_name(self):
        with self.assertRaises(ValueError):
            HSMCertificateElement({
                "name": "invalid-name",
                "message": 'cc',
                "signature": 'dd',
                "signed_by": "root",
                "tweak": 'ee'
            })

    def test_create_certificate_element_missing_certifier(self):
        with self.assertRaises(ValueError):
            HSMCertificateElement({
                "name": "device",
                "message": 'cc',
                "signature": 'dd',
                "tweak": 'ee'
            })

    def test_create_certificate_element_invalid_tweak(self):
        with self.assertRaises(ValueError):
            HSMCertificateElement({
                "name": "device",
                "message": 'cc',
                "signature": 'dd',
                "signed_by": "root",
                "tweak": 'invalid-tweak'
            })

    def test_create_certificate_element_invalid_message(self):
        with self.assertRaises(ValueError):
            HSMCertificateElement({
                "name": "device",
                "message": 'invalid-message',
                "signature": 'dd',
                "signed_by": "root",
                "tweak": 'ee'
            })

    def test_create_certificate_element_invalid_signature(self):
        with self.assertRaises(ValueError):
            HSMCertificateElement({
                "name": "device",
                "message": 'cc',
                "signature": 'invalid-signature',
                "signed_by": "root",
                "tweak": 'ee'
            })

    def test_certificate_element_is_valid_ok(self):
        privkey = ec.PrivateKey()
        msg = 'aa' * 65
        signature = privkey.ecdsa_serialize(privkey.ecdsa_sign(bytes.fromhex(msg))).hex()

        element = HSMCertificateElement({
            "name": "device",
            "message": msg,
            "signature": signature,
            "signed_by": "root"
        })
        self.assertEqual({
            "name": "device",
            "message": msg,
            "signature": signature,
            "signed_by": "root"
        }, element.to_dict())
        self.assertTrue(element.is_valid(privkey.pubkey))

    def test_certificate_element_is_valid_with_tweak_ok(self):
        privkey = ec.PrivateKey()
        pubkey = privkey.pubkey
        raw_tweak = os.urandom(32).hex()
        tweak = hmac.new(
            bytes.fromhex(raw_tweak),
            pubkey.serialize(compressed=False),
            hashlib.sha256,
        ).digest()

        tweak_privkey = ec.PrivateKey(privkey.tweak_add(tweak), raw=True)
        msg = os.urandom(66).hex()
        signature = tweak_privkey.ecdsa_serialize(
            tweak_privkey.ecdsa_sign(bytes.fromhex(msg))).hex()

        element = HSMCertificateElement({
            "name": "device",
            "message": msg,
            "signature": signature,
            "signed_by": "root",
            "tweak": raw_tweak
        })
        self.assertEqual({
            "name": "device",
            "message": msg,
            "signature": signature,
            "signed_by": "root",
            "tweak": raw_tweak
        }, element.to_dict())
        self.assertTrue(element.is_valid(pubkey))

    def test_certificate_element_is_valid_wrong_signature(self):
        privkey = ec.PrivateKey()
        msg = 'aa' * 65

        element = HSMCertificateElement({
            "name": "device",
            "message": msg,
            "signature": 'bb' * 65,
            "signed_by": "root"
        })
        self.assertEqual({
            "name": "device",
            "message": msg,
            "signature": 'bb' * 65,
            "signed_by": "root"
        }, element.to_dict())
        self.assertFalse(element.is_valid(privkey.pubkey))

    def test_certificate_element_is_valid_wrong_tweak(self):
        privkey = ec.PrivateKey()
        pubkey = privkey.pubkey
        raw_tweak = os.urandom(32).hex()
        tweak = hmac.new(
            bytes.fromhex(raw_tweak),
            pubkey.serialize(compressed=False),
            hashlib.sha256,
        ).digest()

        tweak_privkey = ec.PrivateKey(privkey.tweak_add(tweak), raw=True)
        msg = os.urandom(66).hex()
        signature = tweak_privkey.ecdsa_serialize(
            tweak_privkey.ecdsa_sign(bytes.fromhex(msg))).hex()

        element = HSMCertificateElement({
            "name": "device",
            "message": msg,
            "signature": signature,
            "signed_by": "root",
            "tweak": 'bb' * 32
        })
        self.assertEqual({
            "name": "device",
            "message": msg,
            "signature": signature,
            "signed_by": "root",
            "tweak": 'bb' * 32
        }, element.to_dict())
        self.assertFalse(element.is_valid(pubkey))

    @parameterized.expand([
        ("device", lambda b: b[-65:]),
        ("attestation", lambda b: b[1:]),
        ("ui", lambda b: b[:]),
        ("signer", lambda b: b[:])
    ])
    def test_certificate_element_get_value(self, name, extractor):
        msg = os.urandom(66).hex()
        element = HSMCertificateElement({
            "name": name,
            "message": msg,
            "signature": 'aa' * 70,
            "signed_by": "root",
            "tweak": 'bb' * 32
        })
        self.assertEqual(extractor(bytes.fromhex(msg)).hex(), element.get_value())

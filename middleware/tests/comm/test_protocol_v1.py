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
from comm.protocol_v1 import HSM1Protocol

import logging

logging.disable(logging.CRITICAL)


class TestHSM1Protocol(TestCase):
    def setUp(self):
        self.protocol = HSM1Protocol()

    def test_format_error(self):
        self.assertEqual(self.protocol.format_error(), {"errorcode": -2})

    def test_format_error_type(self):
        self.assertEqual(
            self.protocol.handle_request('"{"not": "json", "only": "astring"}"'),
            {"errorcode": -2},
        )

    def test_invalid_request(self):
        self.assertEqual(self.protocol.handle_request({"any": "thing"}),
                         {"errorcode": -2})

    def test_invalid_request_no_command(self):
        self.assertEqual(self.protocol.handle_request({"version": 1}), {"errorcode": -2})

    def test_invalid_request_no_version(self):
        self.assertEqual(self.protocol.handle_request({"command": "sign"}),
                         {"errorcode": -2})

    def test_wrong_version(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": "somethingelse",
                "command": "whatever"
            }),
            {"errorcode": -666},
        )

    def test_invalid_command(self):
        self.assertEqual(
            self.protocol.handle_request({
                "command": "invalid",
                "version": 1
            }),
            {"errorcode": -2},
        )

    def test_version(self):
        self.assertEqual(
            self.protocol.handle_request({"command": "version"}),
            {
                "errorcode": 0,
                "version": 1
            },
        )

    def test_initialize_device_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.protocol.initialize_device()

    def test_getpubkey_keyId_presence(self):
        self.assertEqual(
            self.protocol.handle_request({
                "command": "getPubKey",
                "version": 1
            }),
            {"errorcode": -2},
        )

    def test_getpubkey_keyId_notastring(self):
        self.assertEqual(
            self.protocol.handle_request({
                "command": "getPubKey",
                "version": 1,
                "keyId": 123
            }),
            {"errorcode": -2},
        )

    def test_getpubkey_keyId_invalid(self):
        self.assertEqual(
            self.protocol.handle_request({
                "command": "getPubKey",
                "version": 1,
                "keyId": "not-a-key-id"
            }),
            {"errorcode": -2},
        )

    def test_getpubkey_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.protocol.handle_request({
                "command": "getPubKey",
                "version": 1,
                "keyId": "m/0/0/0/0/0"
            })

    def test_sign_keyId_presence(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 1,
                "command": "sign"
            }),
            {"errorcode": -2},
        )

    def test_sign_keyId_not_a_string(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": 1234
            }),
            {"errorcode": -2},
        )

    def test_sign_keyId_invalid(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "not-a-key-id"
            }),
            {"errorcode": -2},
        )

    def test_sign_message_presence(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/0/0/0/0/0"
            }),
            {"errorcode": -2},
        )

    def test_sign_message_notstring(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "message": 123
            }),
            {"errorcode": -2},
        )

    def test_sign_message_not_hex(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "message": "not-a-hex",
            }),
            {"errorcode": -2},
        )

    def test_sign_message_not_longenough(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "message": "aabbccddee",
            }),
            {"errorcode": -2},
        )

    def test_sign_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.protocol.handle_request({
                "version": 1,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "message": "bb"*32,
            })

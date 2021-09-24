from unittest import TestCase
from comm.protocol import HSM2Protocol

import logging

logging.disable(logging.CRITICAL)


class TestHSM2Protocol(TestCase):
    def setUp(self):
        self.protocol = HSM2Protocol()

    def test_format_error(self):
        self.assertEqual(self.protocol.format_error(), {"errorcode": -901})

    def test_format_error_type(self):
        self.assertEqual(
            self.protocol.handle_request('"{"not": "json", "only": "astring"}"'),
            {"errorcode": -901},
        )

    def test_invalid_request(self):
        self.assertEqual(self.protocol.handle_request({"any": "thing"}),
                         {"errorcode": -902})

    def test_invalid_request_no_command(self):
        self.assertEqual(self.protocol.handle_request({"version": "2"}),
                         {"errorcode": -902})

    def test_invalid_request_no_version(self):
        self.assertEqual(self.protocol.handle_request({"command": "sign"}),
                         {"errorcode": -902})

    def test_wrong_version(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": "somethingelse",
                "command": "whatever"
            }),
            {"errorcode": -904},
        )

    def test_invalid_command(self):
        self.assertEqual(
            self.protocol.handle_request({
                "command": "invalid",
                "version": 2
            }),
            {"errorcode": -903},
        )

    def test_version(self):
        self.assertEqual(
            self.protocol.handle_request({"command": "version"}),
            {
                "errorcode": 0,
                "version": 2
            },
        )

    def test_initialize_device_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.protocol.initialize_device()

    def test_getpubkey_keyId_presence(self):
        self.assertEqual(
            self.protocol.handle_request({
                "command": "getPubKey",
                "version": 2
            }),
            {"errorcode": -103},
        )

    def test_getpubkey_keyId_notastring(self):
        self.assertEqual(
            self.protocol.handle_request({
                "command": "getPubKey",
                "version": 2,
                "keyId": 123
            }),
            {"errorcode": -103},
        )

    def test_getpubkey_keyId_invalid(self):
        self.assertEqual(
            self.protocol.handle_request({
                "command": "getPubKey",
                "version": 2,
                "keyId": "not-a-key-id"
            }),
            {"errorcode": -103},
        )

    def test_getpubkey_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.protocol.handle_request({
                "command": "getPubKey",
                "version": 2,
                "keyId": "m/0/0/0/0/0"
            })

    def test_sign_keyId_presence(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign"
            }),
            {"errorcode": -103},
        )

    def test_sign_keyId_not_a_string(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": 1234
            }),
            {"errorcode": -103},
        )

    def test_sign_keyId_invalid(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "not-a-key-id"
            }),
            {"errorcode": -103},
        )

    def test_sign_auth_type_components(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": 123
            }),
            {"errorcode": -101},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": ""
            }),
            {"errorcode": -101},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "any": "thing"
                },
            }),
            {"errorcode": -101},
        )

    def test_sign_receipt_presence_type(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt_merkle_proof": []
                },
            }),
            {"errorcode": -101},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": 123,
                    "receipt_merkle_proof": []
                },
            }),
            {"errorcode": -101},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "",
                    "receipt_merkle_proof": []
                },
            }),
            {"errorcode": -101},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "not-a-hex",
                    "receipt_merkle_proof": []
                },
            }),
            {"errorcode": -101},
        )

    def test_sign_receipt_merkle_proof_presence_type(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc"
                },
            }),
            {"errorcode": -101},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": "notalist"
                },
            }),
            {"errorcode": -101},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": [1, 2, 3]
                },
            }),
            {"errorcode": -101},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": ["aa", "", "bb"],
                },
            }),
            {"errorcode": -101},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": ["aa", "not-a-hex", "bb"],
                },
            }),
            {"errorcode": -101},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": []
                },
            }),
            {"errorcode": -101},
        )

    def test_sign_message_presence_type(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": ["aa"]
                },
            }),
            {"errorcode": -102},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": ["aa"]
                },
                "message": "",
            }),
            {"errorcode": -102},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0"
            }),
            {"errorcode": -102},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "message": ""
            }),
            {"errorcode": -102},
        )

    def test_sign_tx_input_hash_presence(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": ["aa"]
                },
                "message": {
                    "any": "thing"
                },
            }),
            {"errorcode": -102},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": ["aa"]
                },
                "message": {
                    "tx": "001122"
                },
            }),
            {"errorcode": -102},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": ["aa"]
                },
                "message": {
                    "input": 123
                },
            }),
            {"errorcode": -102},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": ["aa"]
                },
                "message": {
                    "tx": "001122",
                    "input": "not-an-input"
                },
            }),
            {"errorcode": -102},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": ["aa"]
                },
                "message": {
                    "tx": "",
                    "input": 123
                },
            }),
            {"errorcode": -102},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": ["aa"]
                },
                "message": {
                    "tx": "not-a-hex",
                    "input": 123
                },
            }),
            {"errorcode": -102},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": ["aa"]
                },
                "message": {
                    "hash": 123
                },
            }),
            {"errorcode": -102},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": ["aa"]
                },
                "message": {
                    "hash": ""
                },
            }),
            {"errorcode": -102},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": ["aa"]
                },
                "message": {
                    "hash": "not-a-hex"
                },
            }),
            {"errorcode": -102},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "aabbcc",
                    "receipt_merkle_proof": ["aa"]
                },
                "message": {
                    "hash": "aa"*33
                },
            }),
            {"errorcode": -102},
        )

    def test_sign_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.protocol.handle_request({
                "command": "sign",
                "version": 2,
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "ddeeff",
                    "receipt_merkle_proof": ["aa"]
                },
                "message": {
                    "tx": "001122",
                    "input": 123
                },
            })

        with self.assertRaises(NotImplementedError):
            self.protocol.handle_request({
                "command": "sign",
                "version": 2,
                "keyId": "m/0/0/0/0/0",
                "auth": {
                    "receipt": "ddeeff",
                    "receipt_merkle_proof": ["aa"]
                },
                "message": {
                    "hash": "bb"*32
                },
            })

        with self.assertRaises(NotImplementedError):
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "message": {
                    "tx": "001122",
                    "input": 123
                },
            })

        with self.assertRaises(NotImplementedError):
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "message": {
                    "hash": "bb"*32
                },
            })

    def test_sign_noauth_message_presence(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0"
            }),
            {"errorcode": -102},
        )

    def test_sign_noauth_message_notobject(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "message": 123
            }),
            {"errorcode": -102},
        )

    def test_sign_noauth_message_hash_notpresent(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "message": {
                    "something": "else"
                },
            }),
            {"errorcode": -102},
        )

    def test_sign_noauth_message_hash_invalid(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "message": {
                    "hash": 123
                },
            }),
            {"errorcode": -102},
        )

    def test_sign_noauth_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.protocol.handle_request({
                "version": 2,
                "command": "sign",
                "keyId": "m/0/0/0/0/0",
                "message": {
                    "hash": "bb"*32
                },
            })

    def test_advance_blockchain_blocks_presence(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "advanceBlockchain"
            }),
            {"errorcode": -204},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "advanceBlockchain",
                "blocks": 123
            }),
            {"errorcode": -204},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "advanceBlockchain",
                "blocks": []
            }),
            {"errorcode": -204},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "advanceBlockchain",
                "blocks": ["ok", 333, "another-ok"],
            }),
            {"errorcode": -204},
        )

    def test_advance_blockchain_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.protocol.handle_request({
                "command": "advanceBlockchain",
                "version": 2,
                "blocks": ["fist-block", "second-block"],
            })

    def test_reset_advance_blockchain_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.protocol.handle_request({
                "command": "resetAdvanceBlockchain",
                "version": 2
            })

    def test_blockchain_status_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.protocol.handle_request({"command": "blockchainState", "version": 2})

    def test_update_ancestor_block_blocks_presence(self):
        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "updateAncestorBlock"
            }),
            {"errorcode": -204},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "updateAncestorBlock",
                "blocks": 123
            }),
            {"errorcode": -204},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "updateAncestorBlock",
                "blocks": []
            }),
            {"errorcode": -204},
        )

        self.assertEqual(
            self.protocol.handle_request({
                "version": 2,
                "command": "updateAncestorBlock",
                "blocks": ["ok", 333, "another-ok"],
            }),
            {"errorcode": -204},
        )

    def test_update_ancestor_block_notimplemented(self):
        with self.assertRaises(NotImplementedError):
            self.protocol.handle_request({
                "command": "updateAncestorBlock",
                "version": 2,
                "blocks": ["a-block"]
            })

        with self.assertRaises(NotImplementedError):
            self.protocol.handle_request({
                "command":
                "updateAncestorBlock",
                "version":
                2,
                "blocks": ["first-block", "second-block", "third-block"],
            })

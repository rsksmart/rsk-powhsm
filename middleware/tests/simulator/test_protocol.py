from unittest import TestCase
from unittest.mock import Mock, call, patch
from comm.bip32 import BIP32Path
from simulator.protocol import HSM2ProtocolSimulator

import logging
logging.disable(logging.CRITICAL)

class TestHSM2ProtocolSimulator(TestCase):
    def setUp(self):
        self.emitter_address = "33"*20
        self.wallet = Mock()
        self.blockchain_state = Mock()
        self.network_parameters = Mock()
        self.protocol = HSM2ProtocolSimulator(
            self.wallet, self.blockchain_state,
            self.emitter_address, self.network_parameters,
            999_999_999_999 # Very fast so we don't need to mock 'time.sleep'
        )

    @patch('simulator.protocol.is_authorized_signing_path')
    def test_get_pubkey(self, is_authorized_signing_path_mock):
        is_authorized_signing_path_mock.return_value = True
        the_key = Mock()
        self.wallet.get.return_value = the_key
        the_key.public_key.return_value = "this-is-the-public-key"

        self.assertEqual(
            { "errorcode": 0, "pubKey": "this-is-the-public-key" },
            self.protocol.handle_request({ "version": 2, "command": "getPubKey", "keyId": "m/44'/0'/0'/0/0" }))
        self.assertEqual(is_authorized_signing_path_mock.call_args_list, [call(BIP32Path("m/44'/0'/0'/0/0"))])
        self.assertEqual(self.wallet.get.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertEqual(the_key.public_key.call_args_list, [call()])

    @patch('simulator.protocol.is_authorized_signing_path')
    def test_get_pubkey_unauthorized_keyid(self, is_authorized_signing_path_mock):
        is_authorized_signing_path_mock.return_value = False

        self.assertEqual(
            { "errorcode": -103 },
            self.protocol.handle_request({ "version": 2, "command": "getPubKey", "keyId": "m/44'/0'/0'/0/0" }))
        self.assertEqual(is_authorized_signing_path_mock.call_args_list, [call(BIP32Path("m/44'/0'/0'/0/0"))])
        self.assertFalse(self.wallet.get.called)

    @patch('simulator.protocol.is_authorized_signing_path')
    @patch('simulator.protocol.authorize_signature_and_get_message_to_sign')
    def test_sign_unauthorized_keyid(self, authorize_mock, is_authorized_signing_path_mock):
        is_authorized_signing_path_mock.return_value = False

        self.assertEqual(
            { "errorcode": -103 },
            self.protocol.handle_request({ "version": 2, "command": "sign", "keyId": "m/44'/0'/0'/0/0", "message": {"tx": "11223344", "input": 123}, \
                                            "auth": { "receipt": "aabbcc", "receipt_merkle_proof": ["aa"] } }))
        self.assertEqual(is_authorized_signing_path_mock.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertFalse(authorize_mock.called)
        self.assertFalse(self.wallet.get.called)

    @patch('simulator.protocol.is_auth_requiring_path')
    @patch('simulator.protocol.is_authorized_signing_path')
    @patch('simulator.protocol.authorize_signature_and_get_message_to_sign')
    def test_sign_auth_fields_invalid(self, authorize_mock, is_authorized_signing_path_mock, is_auth_requiring_path_mock):
        is_authorized_signing_path_mock.return_value = True
        is_auth_requiring_path_mock.return_value = True

        self.assertEqual(
            { "errorcode": -101 },
            self.protocol.handle_request({ "version": 2, "command": "sign", "keyId": "m/44'/0'/0'/0/0", "message": {"tx": "11223344", "input": 123}}))
        self.assertEqual(is_authorized_signing_path_mock.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertEqual(is_auth_requiring_path_mock.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertFalse(authorize_mock.called)
        self.assertFalse(self.wallet.get.called)

    @patch('simulator.protocol.is_auth_requiring_path')
    @patch('simulator.protocol.is_authorized_signing_path')
    @patch('simulator.protocol.authorize_signature_and_get_message_to_sign')
    def test_sign_message_fields_invalid(self, authorize_mock, is_authorized_signing_path_mock, is_auth_requiring_path_mock):
        is_authorized_signing_path_mock.return_value = True
        is_auth_requiring_path_mock.return_value = True

        self.assertEqual(
            { "errorcode": -102 },
            self.protocol.handle_request({ "version": 2, "command": "sign", "keyId": "m/44'/0'/0'/0/0", "message": {"hash": "bb"*32}, \
                                            "auth": { "receipt": "aabbcc", "receipt_merkle_proof": ["aa"] } }))
        self.assertEqual(is_authorized_signing_path_mock.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertEqual(is_auth_requiring_path_mock.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertFalse(authorize_mock.called)
        self.assertFalse(self.wallet.get.called)

    @patch('simulator.protocol.is_auth_requiring_path')
    @patch('simulator.protocol.is_authorized_signing_path')
    @patch('simulator.protocol.authorize_signature_and_get_message_to_sign')
    def test_sign_unauthorized(self, authorize_mock, is_authorized_signing_path_mock, is_auth_requiring_path_mock):
        is_authorized_signing_path_mock.return_value = True
        is_auth_requiring_path_mock.return_value = True
        authorize_mock.return_value = (False, -456)

        self.assertEqual(
            { "errorcode": -456 },
            self.protocol.handle_request({ "version": 2, "command": "sign", "keyId": "m/44'/0'/0'/0/0", "message": {"tx": "11223344", "input": 123}, \
                                            "auth": { "receipt": "aabbcc", "receipt_merkle_proof": ["aa"] } }))
        self.assertEqual(is_authorized_signing_path_mock.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertEqual(is_auth_requiring_path_mock.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertEqual(authorize_mock.call_args_list, [call("aabbcc", ["aa"], \
                                                              "11223344", 123, self.emitter_address, \
                                                              self.blockchain_state, \
                                                              self.protocol.logger)])
        self.assertFalse(self.wallet.get.called)

    @patch('simulator.protocol.is_auth_requiring_path')
    @patch('simulator.protocol.is_authorized_signing_path')
    @patch('simulator.protocol.authorize_signature_and_get_message_to_sign')
    def test_sign_ok(self, authorize_mock, is_authorized_signing_path_mock, is_auth_requiring_path_mock):
        is_authorized_signing_path_mock.return_value = True
        is_auth_requiring_path_mock.return_value = True
        authorize_mock.return_value = (True, "message-to-sign")
        the_key = Mock()
        self.wallet.get.return_value = the_key
        the_key.sign.return_value = { "r": "this-is-r", "s": "this-is-s" }

        self.assertEqual(
            { "errorcode": 0, "signature": { "r": "this-is-r", "s": "this-is-s" } },
            self.protocol.handle_request({ "version": 2, "command": "sign", "keyId": "m/44'/0'/0'/0/0", "message": {"tx": "11223344", "input": 123}, \
                                            "auth": { "receipt": "aabbcc", "receipt_merkle_proof": ["aa"] } }))
        self.assertEqual(is_authorized_signing_path_mock.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertEqual(is_auth_requiring_path_mock.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertEqual(authorize_mock.call_args_list, [call("aabbcc", ["aa"], \
                                                              "11223344", 123, self.emitter_address, \
                                                              self.blockchain_state, \
                                                              self.protocol.logger)])
        self.assertEqual(self.wallet.get.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertEqual(the_key.sign.call_args_list, [call("message-to-sign")])

    @patch('simulator.protocol.is_auth_requiring_path')
    @patch('simulator.protocol.is_authorized_signing_path')
    @patch('simulator.protocol.authorize_signature_and_get_message_to_sign')
    def test_sign_signing_wallet_keyget_error(self, authorize_mock, is_authorized_signing_path_mock, is_auth_requiring_path_mock):
        is_authorized_signing_path_mock.return_value = True
        is_auth_requiring_path_mock.return_value = True
        authorize_mock.return_value = (True, "message-to-sign")
        self.wallet.get.side_effect = ValueError()

        self.assertEqual(
            { "errorcode": -905 },
            self.protocol.handle_request({ "version": 2, "command": "sign", "keyId": "m/44'/0'/0'/0/0", "message": {"tx": "11223344", "input": 123}, \
                                            "auth": { "receipt": "aabbcc", "receipt_merkle_proof": ["aa"] } }))
        self.assertEqual(is_authorized_signing_path_mock.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertEqual(is_auth_requiring_path_mock.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertEqual(authorize_mock.call_args_list, [call("aabbcc", ["aa"], \
                                                              "11223344", 123, self.emitter_address, \
                                                              self.blockchain_state, \
                                                              self.protocol.logger)])
        self.assertEqual(self.wallet.get.call_args_list, [call("m/44'/0'/0'/0/0")])

    @patch('simulator.protocol.is_auth_requiring_path')
    @patch('simulator.protocol.is_authorized_signing_path')
    @patch('simulator.protocol.authorize_signature_and_get_message_to_sign')
    def test_sign_signing_wallet_sign_error(self, authorize_mock, is_authorized_signing_path_mock, is_auth_requiring_path_mock):
        is_authorized_signing_path_mock.return_value = True
        is_auth_requiring_path_mock.return_value = True
        authorize_mock.return_value = (True, "message-to-sign")
        the_key = Mock()
        self.wallet.get.return_value = the_key
        the_key.sign.side_effect = ValueError()

        self.assertEqual(
            { "errorcode": -905 },
            self.protocol.handle_request({ "version": 2, "command": "sign", "keyId": "m/44'/0'/0'/0/0", "message": {"tx": "11223344", "input": 123}, \
                                            "auth": { "receipt": "aabbcc", "receipt_merkle_proof": ["aa"] } }))
        self.assertEqual(is_authorized_signing_path_mock.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertEqual(is_auth_requiring_path_mock.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertEqual(authorize_mock.call_args_list, [call("aabbcc", ["aa"], \
                                                              "11223344", 123, self.emitter_address, \
                                                              self.blockchain_state, \
                                                              self.protocol.logger)])
        self.assertEqual(self.wallet.get.call_args_list, [call("m/44'/0'/0'/0/0")])
        self.assertEqual(the_key.sign.call_args_list, [call("message-to-sign")])

    @patch('simulator.protocol.is_auth_requiring_path')
    @patch('simulator.protocol.is_authorized_signing_path')
    @patch('simulator.protocol.authorize_signature_and_get_message_to_sign')
    def test_noauth_sign_ok(self, authorize_mock, is_authorized_signing_path_mock, is_auth_requiring_path_mock):
        is_authorized_signing_path_mock.return_value = True
        is_auth_requiring_path_mock.return_value = False
        the_key = Mock()
        self.wallet.get.return_value = the_key
        the_key.sign.return_value = { "r": "this-is-r", "s": "this-is-s" }

        self.assertEqual(
            { "errorcode": 0, "signature": { "r": "this-is-r", "s": "this-is-s" } },
            self.protocol.handle_request({ "version": 2, "command": "sign", "keyId": "m/44'/137'/0'/0/0", "message": {"hash": "bb"*32} }))

        self.assertEqual(is_authorized_signing_path_mock.call_args_list, [call("m/44'/137'/0'/0/0")])
        self.assertEqual(is_auth_requiring_path_mock.call_args_list, [call("m/44'/137'/0'/0/0")])
        self.assertFalse(authorize_mock.called)
        self.assertEqual(self.wallet.get.call_args_list, [call("m/44'/137'/0'/0/0")])
        self.assertEqual(the_key.sign.call_args_list, [call("bb"*32)])

    @patch('simulator.protocol.is_auth_requiring_path')
    @patch('simulator.protocol.is_authorized_signing_path')
    @patch('simulator.protocol.authorize_signature_and_get_message_to_sign')
    def test_noauth_sign_signing_wallet_keyget_error(self, authorize_mock, is_authorized_signing_path_mock, is_auth_requiring_path_mock):
        is_authorized_signing_path_mock.return_value = True
        is_auth_requiring_path_mock.return_value = False
        self.wallet.get.side_effect = ValueError()

        self.assertEqual(
            { "errorcode": -905 },
            self.protocol.handle_request({ "version": 2, "command": "sign", "keyId": "m/44'/137'/0'/0/0", "message": {"hash": "bb"*32} }))
        self.assertEqual(is_authorized_signing_path_mock.call_args_list, [call("m/44'/137'/0'/0/0")])
        self.assertEqual(is_auth_requiring_path_mock.call_args_list, [call("m/44'/137'/0'/0/0")])
        self.assertFalse(authorize_mock.called)
        self.assertEqual(self.wallet.get.call_args_list, [call("m/44'/137'/0'/0/0")])

    @patch('simulator.protocol.is_auth_requiring_path')
    @patch('simulator.protocol.is_authorized_signing_path')
    @patch('simulator.protocol.authorize_signature_and_get_message_to_sign')
    def test_noauth_sign_signing_wallet_sign_error(self, authorize_mock, is_authorized_signing_path_mock, is_auth_requiring_path_mock):
        is_authorized_signing_path_mock.return_value = True
        is_auth_requiring_path_mock.return_value = False
        the_key = Mock()
        self.wallet.get.return_value = the_key
        the_key.sign.side_effect = ValueError()

        self.assertEqual(
            { "errorcode": -905 },
            self.protocol.handle_request({ "version": 2, "command": "sign", "keyId": "m/44'/137'/0'/0/0", "message": {"hash": "bb"*32} }))
        self.assertEqual(is_authorized_signing_path_mock.call_args_list, [call("m/44'/137'/0'/0/0")])
        self.assertEqual(is_auth_requiring_path_mock.call_args_list, [call("m/44'/137'/0'/0/0")])
        self.assertFalse(authorize_mock.called)
        self.assertEqual(self.wallet.get.call_args_list, [call("m/44'/137'/0'/0/0")])
        self.assertEqual(the_key.sign.call_args_list, [call("bb"*32)])

    @patch('simulator.protocol.is_auth_requiring_path')
    @patch('simulator.protocol.is_authorized_signing_path')
    @patch('simulator.protocol.authorize_signature_and_get_message_to_sign')
    def test_noauth_sign_message_fields_invalid(self, authorize_mock, is_authorized_signing_path_mock, is_auth_requiring_path_mock):
        is_authorized_signing_path_mock.return_value = True
        is_auth_requiring_path_mock.return_value = False

        self.assertEqual(
            { "errorcode": -102 },
            self.protocol.handle_request({ "version": 2, "command": "sign", "keyId": "m/44'/137'/0'/0/0", "message": {"tx": "11223344", "input": 123} }))

        self.assertEqual(is_authorized_signing_path_mock.call_args_list, [call("m/44'/137'/0'/0/0")])
        self.assertEqual(is_auth_requiring_path_mock.call_args_list, [call("m/44'/137'/0'/0/0")])
        self.assertFalse(authorize_mock.called)
        self.assertFalse(self.wallet.get.called)

    def test_blockchain_state(self):
        self.blockchain_state.to_dict.return_value = "this-is-the-state"

        self.assertEqual(
            { "errorcode": 0, "state": "this-is-the-state" },
            self.protocol.handle_request({ "version": 2, "command": "blockchainState" }))
        self.assertEqual(self.blockchain_state.to_dict.call_args_list, [call()])

    def test_reset_advance_blockchain(self):
        self.assertEqual(
            { "errorcode": 0 },
            self.protocol.handle_request({ "version": 2, "command": "resetAdvanceBlockchain" }))
        self.assertEqual(self.blockchain_state.reset_advance.call_args_list, [call()])

    @patch('simulator.protocol.RskBlockHeader')
    def test_advance_blockchain_ok(self, RskBlockHeaderMock):
        RskBlockHeaderMock.side_effect = lambda raw, np, mm_is_mandatory: 'block-%s' % raw
        self.blockchain_state.advance.return_value = 123

        self.assertEqual(
            { "errorcode": 123 },
            self.protocol.handle_request({ "version": 2, "command": "advanceBlockchain",\
                                          "blocks": ["n1", "n2", "n3"] }))
        np = self.network_parameters
        self.assertEqual(RskBlockHeaderMock.call_args_list, [call("n1", np, mm_is_mandatory=True), call("n2", np, mm_is_mandatory=True), call("n3", np, mm_is_mandatory=True)])
        self.assertEqual(self.blockchain_state.advance.call_args_list, [call(["block-n1", "block-n2", "block-n3"])])

    @patch('simulator.protocol.RskBlockHeader')
    def test_advance_blockchain_invalid_header(self, RskBlockHeaderMock):
        def block_header_constructor(raw, np, mm_is_mandatory):
            if raw == "n3":
                raise ValueError()
            return "block-%s" % raw

        RskBlockHeaderMock.side_effect = block_header_constructor
        self.blockchain_state.advance.return_value = 0

        self.assertEqual(
            { "errorcode": -204 },
            self.protocol.handle_request({ "version": 2, "command": "advanceBlockchain",\
                                          "blocks": ["n1", "n2", "n3", "n4"] }))
        np = self.network_parameters
        self.assertEqual(RskBlockHeaderMock.call_args_list, [call("n1", np, mm_is_mandatory=True), call("n2", np, mm_is_mandatory=True), call("n3", np, mm_is_mandatory=True)])
        self.assertFalse(self.blockchain_state.advance.called)

    @patch('simulator.protocol.RskBlockHeader')
    def test_advance_blockchain_advance_error(self, RskBlockHeaderMock):
        RskBlockHeaderMock.side_effect = lambda raw, np, mm_is_mandatory: 'block-%s' % raw
        self.blockchain_state.advance.return_value = -123

        self.assertEqual(
            { "errorcode": -123 },
            self.protocol.handle_request({ "version": 2, "command": "advanceBlockchain",\
                                          "blocks": ["n1", "n2", "n3"] }))
        np = self.network_parameters
        self.assertEqual(RskBlockHeaderMock.call_args_list, [call("n1", np, mm_is_mandatory=True), call("n2", np, mm_is_mandatory=True), call("n3", np, mm_is_mandatory=True)])
        self.assertEqual(self.blockchain_state.advance.call_args_list, [call(["block-n1", "block-n2", "block-n3"])])

    @patch('simulator.protocol.RskBlockHeader')
    def test_advance_blockchain_advance_exception(self, RskBlockHeaderMock):
        RskBlockHeaderMock.side_effect = lambda raw, np, mm_is_mandatory: 'block-%s' % raw
        self.blockchain_state.advance.side_effect = RuntimeError()

        self.assertEqual(
            { "errorcode": -906 },
            self.protocol.handle_request({ "version": 2, "command": "advanceBlockchain",\
                                          "blocks": ["n1", "n2", "n3"] }))
        np = self.network_parameters
        self.assertEqual(RskBlockHeaderMock.call_args_list, [call("n1", np, mm_is_mandatory=True), call("n2", np, mm_is_mandatory=True), call("n3", np, mm_is_mandatory=True)])
        self.assertEqual(self.blockchain_state.advance.call_args_list, [call(["block-n1", "block-n2", "block-n3"])])

    @patch('simulator.protocol.RskBlockHeader')
    def test_update_ancestor_block_ok(self, RskBlockHeaderMock):
        RskBlockHeaderMock.side_effect = lambda raw, np, mm_is_mandatory: 'block-%s' % raw
        self.blockchain_state.update_ancestor.return_value = 123

        self.assertEqual(
            { "errorcode": 123 },
            self.protocol.handle_request({ "version": 2, "command": "updateAncestorBlock",\
                                          "blocks": ["n1", "n2", "n3"] }))
        np = self.network_parameters
        self.assertEqual(RskBlockHeaderMock.call_args_list, [call("n1", np, mm_is_mandatory=False), call("n2", np, mm_is_mandatory=False), call("n3", np, mm_is_mandatory=False)])
        self.assertEqual(self.blockchain_state.update_ancestor.call_args_list, [call(["block-n1", "block-n2", "block-n3"])])

    @patch('simulator.protocol.RskBlockHeader')
    def test_update_ancestor_block_invalid_header(self, RskBlockHeaderMock):
        def block_header_constructor(raw, np, mm_is_mandatory):
            if raw == "n3":
                raise ValueError()
            return "block-%s" % raw

        RskBlockHeaderMock.side_effect = block_header_constructor
        self.blockchain_state.update_ancestor.return_value = 0

        self.assertEqual(
            { "errorcode": -204 },
            self.protocol.handle_request({ "version": 2, "command": "updateAncestorBlock",\
                                          "blocks": ["n1", "n2", "n3", "n4"] }))
        np = self.network_parameters
        self.assertEqual(RskBlockHeaderMock.call_args_list, [call("n1", np, mm_is_mandatory=False), call("n2", np, mm_is_mandatory=False), call("n3", np, mm_is_mandatory=False)])
        self.assertFalse(self.blockchain_state.update_ancestor.called)

    @patch('simulator.protocol.RskBlockHeader')
    def test_update_ancestor_block_advance_error(self, RskBlockHeaderMock):
        RskBlockHeaderMock.side_effect = lambda raw, np, mm_is_mandatory: 'block-%s' % raw
        self.blockchain_state.update_ancestor.return_value = -123

        self.assertEqual(
            { "errorcode": -123 },
            self.protocol.handle_request({ "version": 2, "command": "updateAncestorBlock",\
                                          "blocks": ["n1", "n2", "n3"] }))
        np = self.network_parameters
        self.assertEqual(RskBlockHeaderMock.call_args_list, [call("n1", np, mm_is_mandatory=False), call("n2", np, mm_is_mandatory=False), call("n3", np, mm_is_mandatory=False)])
        self.assertEqual(self.blockchain_state.update_ancestor.call_args_list, [call(["block-n1", "block-n2", "block-n3"])])

    @patch('simulator.protocol.RskBlockHeader')
    def test_update_ancestor_block_advance_exception(self, RskBlockHeaderMock):
        RskBlockHeaderMock.side_effect = lambda raw, np, mm_is_mandatory: 'block-%s' % raw
        self.blockchain_state.update_ancestor.side_effect = RuntimeError()

        self.assertEqual(
            { "errorcode": -906 },
            self.protocol.handle_request({ "version": 2, "command": "updateAncestorBlock",\
                                          "blocks": ["n1", "n2", "n3"] }))
        np = self.network_parameters
        self.assertEqual(RskBlockHeaderMock.call_args_list, [call("n1", np, mm_is_mandatory=False), call("n2", np, mm_is_mandatory=False), call("n3", np, mm_is_mandatory=False)])
        self.assertEqual(self.blockchain_state.update_ancestor.call_args_list, [call(["block-n1", "block-n2", "block-n3"])])

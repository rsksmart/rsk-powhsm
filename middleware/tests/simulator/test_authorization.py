from unittest import TestCase
from unittest.mock import Mock, call, patch
from simulator.authorization import authorize_signature_and_get_message_to_sign

import logging

logging.disable(logging.CRITICAL)


@patch("simulator.authorization.get_tx_version")
@patch("simulator.authorization.RskTransactionReceipt")
@patch("simulator.authorization.RskTrie")
@patch("simulator.authorization.get_tx_hash_for_unsigned_tx")
@patch("simulator.authorization.get_signature_hash_for_p2sh_input")
@patch("simulator.authorization.get_unsigned_tx")
class TestAuthorization(TestCase):
    EXPECTED_SIGNATURE = (
        "7a7c29481528ac8c2b2e93aee658fddd4dc15304fa723a5c2b88514557bcc790")
    EXPECTED_ADDRESS = "an-address"

    def setUp(self):
        self.logger = Mock()
        self.blockchain_state = Mock()
        self.blockchain_state.ancestor_receipts_root = "the-ancestor-receipts-root"

    def test_invalid_receipt(
        self,
        get_unsigned_tx_mock,
        get_signature_hash_for_p2sh_input_mock,
        get_tx_hash_for_unsigned_tx_mock,
        RskTrieMock,
        RskTransactionReceiptMock,
        get_tx_version_mock,
    ):
        RskTransactionReceiptMock.side_effect = ValueError()

        self.assertEqual(
            authorize_signature_and_get_message_to_sign(
                "a-receipt",
                ["a", "b"],
                "a-tx",
                123,
                self.EXPECTED_ADDRESS,
                self.blockchain_state,
                self.logger,
            ),
            (False, -101),
        )
        self.assertEqual(RskTransactionReceiptMock.call_args_list, [call("a-receipt")])
        self.assertFalse(RskTrieMock.from_proof.called)
        self.assertFalse(get_tx_hash_for_unsigned_tx_mock.called)
        self.assertFalse(get_tx_version_mock.called)
        self.assertFalse(get_signature_hash_for_p2sh_input_mock.called)
        self.assertFalse(get_unsigned_tx_mock.called)

    def test_invalid_receipts_trie_proof(
        self,
        get_unsigned_tx_mock,
        get_signature_hash_for_p2sh_input_mock,
        get_tx_hash_for_unsigned_tx_mock,
        RskTrieMock,
        RskTransactionReceiptMock,
        get_tx_version_mock,
    ):
        RskTrieMock.from_proof.side_effect = ValueError()

        self.assertEqual(
            authorize_signature_and_get_message_to_sign(
                "a-receipt",
                ["a", "b"],
                "a-tx",
                123,
                self.EXPECTED_ADDRESS,
                self.blockchain_state,
                self.logger,
            ),
            (False, -101),
        )
        self.assertEqual(RskTransactionReceiptMock.call_args_list, [call("a-receipt")])
        self.assertEqual(RskTrieMock.from_proof.call_args_list, [call(["a", "b"])])
        self.assertFalse(get_tx_hash_for_unsigned_tx_mock.called)
        self.assertFalse(get_tx_version_mock.called)
        self.assertFalse(get_signature_hash_for_p2sh_input_mock.called)
        self.assertFalse(get_unsigned_tx_mock.called)

    def test_receipts_trie_proof_no_leaf(
        self,
        get_unsigned_tx_mock,
        get_signature_hash_for_p2sh_input_mock,
        get_tx_hash_for_unsigned_tx_mock,
        RskTrieMock,
        RskTransactionReceiptMock,
        get_tx_version_mock,
    ):
        trie_root = Mock(**{"get_first_leaf.side_effect": ValueError()})
        RskTrieMock.from_proof.return_value = trie_root

        self.assertEqual(
            authorize_signature_and_get_message_to_sign(
                "a-receipt",
                ["a", "b"],
                "a-tx",
                123,
                self.EXPECTED_ADDRESS,
                self.blockchain_state,
                self.logger,
            ),
            (False, -101),
        )
        self.assertEqual(RskTransactionReceiptMock.call_args_list, [call("a-receipt")])
        self.assertEqual(RskTrieMock.from_proof.call_args_list, [call(["a", "b"])])
        self.assertTrue(trie_root.get_first_leaf.called)
        self.assertFalse(get_tx_hash_for_unsigned_tx_mock.called)
        self.assertFalse(get_tx_version_mock.called)
        self.assertFalse(get_signature_hash_for_p2sh_input_mock.called)
        self.assertFalse(get_unsigned_tx_mock.called)

    def test_receipts_root_no_match(
        self,
        get_unsigned_tx_mock,
        get_signature_hash_for_p2sh_input_mock,
        get_tx_hash_for_unsigned_tx_mock,
        RskTrieMock,
        RskTransactionReceiptMock,
        get_tx_version_mock,
    ):
        trie_leaf = Mock(value_hash="the-receipt-hash")
        trie_root = Mock(**{
            "hash": "a-different-root-hash",
            "get_first_leaf.return_value": trie_leaf
        })
        receipt = Mock(hash=trie_leaf.value_hash)
        RskTrieMock.from_proof.return_value = trie_root
        RskTransactionReceiptMock.return_value = receipt

        self.assertEqual(
            authorize_signature_and_get_message_to_sign(
                "a-receipt",
                ["a", "b"],
                "a-tx",
                123,
                self.EXPECTED_ADDRESS,
                self.blockchain_state,
                self.logger,
            ),
            (False, -101),
        )
        self.assertEqual(RskTransactionReceiptMock.call_args_list, [call("a-receipt")])
        self.assertEqual(RskTrieMock.from_proof.call_args_list, [call(["a", "b"])])
        self.assertFalse(get_tx_hash_for_unsigned_tx_mock.called)
        self.assertFalse(get_tx_version_mock.called)
        self.assertFalse(get_signature_hash_for_p2sh_input_mock.called)
        self.assertFalse(get_unsigned_tx_mock.called)

    def test_receipts_leaf_value_no_match(
        self,
        get_unsigned_tx_mock,
        get_signature_hash_for_p2sh_input_mock,
        get_tx_hash_for_unsigned_tx_mock,
        RskTrieMock,
        RskTransactionReceiptMock,
        get_tx_version_mock,
    ):
        trie_leaf = Mock(value_hash="the-receipt-hash")
        trie_root = Mock(
            **{
                "hash": self.blockchain_state.ancestor_receipts_root,
                "get_first_leaf.return_value": trie_leaf,
            })
        receipt = Mock(hash="another-receipt-hash")
        RskTrieMock.from_proof.return_value = trie_root
        RskTransactionReceiptMock.return_value = receipt

        self.assertEqual(
            authorize_signature_and_get_message_to_sign(
                "a-receipt",
                ["a", "b"],
                "a-tx",
                123,
                self.EXPECTED_ADDRESS,
                self.blockchain_state,
                self.logger,
            ),
            (False, -101),
        )
        self.assertEqual(RskTransactionReceiptMock.call_args_list, [call("a-receipt")])
        self.assertEqual(RskTrieMock.from_proof.call_args_list, [call(["a", "b"])])
        self.assertFalse(get_tx_hash_for_unsigned_tx_mock.called)
        self.assertFalse(get_tx_version_mock.called)
        self.assertFalse(get_signature_hash_for_p2sh_input_mock.called)
        self.assertFalse(get_unsigned_tx_mock.called)

    def test_invalid_transaction(
        self,
        get_unsigned_tx_mock,
        get_signature_hash_for_p2sh_input_mock,
        get_tx_hash_for_unsigned_tx_mock,
        RskTrieMock,
        RskTransactionReceiptMock,
        get_tx_version_mock,
    ):
        trie_leaf = Mock(value_hash="the-receipt-hash")
        trie_root = Mock(
            **{
                "hash": self.blockchain_state.ancestor_receipts_root,
                "get_first_leaf.return_value": trie_leaf,
            })
        receipt = Mock(hash=trie_leaf.value_hash)
        RskTrieMock.from_proof.return_value = trie_root
        RskTransactionReceiptMock.return_value = receipt
        get_tx_hash_for_unsigned_tx_mock.side_effect = ValueError()

        self.assertEqual(
            authorize_signature_and_get_message_to_sign(
                "a-receipt",
                ["a", "b"],
                "a-tx",
                123,
                self.EXPECTED_ADDRESS,
                self.blockchain_state,
                self.logger,
            ),
            (False, -102),
        )
        self.assertEqual(RskTransactionReceiptMock.call_args_list, [call("a-receipt")])
        self.assertEqual(RskTrieMock.from_proof.call_args_list, [call(["a", "b"])])
        self.assertEqual(get_tx_hash_for_unsigned_tx_mock.call_args_list, [call("a-tx")])
        self.assertFalse(get_tx_version_mock.called)
        self.assertFalse(get_signature_hash_for_p2sh_input_mock.called)
        self.assertFalse(get_unsigned_tx_mock.called)

    def test_invalid_transaction_version(
        self,
        get_unsigned_tx_mock,
        get_signature_hash_for_p2sh_input_mock,
        get_tx_hash_for_unsigned_tx_mock,
        RskTrieMock,
        RskTransactionReceiptMock,
        get_tx_version_mock,
    ):
        trie_leaf = Mock(value_hash="the-receipt-hash")
        trie_root = Mock(
            **{
                "hash": self.blockchain_state.ancestor_receipts_root,
                "get_first_leaf.return_value": trie_leaf,
            })
        receipt = Mock(hash=trie_leaf.value_hash)
        RskTrieMock.from_proof.return_value = trie_root
        RskTransactionReceiptMock.return_value = receipt
        get_tx_hash_for_unsigned_tx_mock.return_value = "the-tx-hash"
        get_tx_version_mock.return_value = 456

        self.assertEqual(
            authorize_signature_and_get_message_to_sign(
                "a-receipt",
                ["a", "b"],
                "a-tx",
                123,
                self.EXPECTED_ADDRESS,
                self.blockchain_state,
                self.logger,
            ),
            (False, -102),
        )
        self.assertEqual(RskTransactionReceiptMock.call_args_list, [call("a-receipt")])
        self.assertEqual(RskTrieMock.from_proof.call_args_list, [call(["a", "b"])])
        self.assertEqual(get_tx_hash_for_unsigned_tx_mock.call_args_list, [call("a-tx")])
        self.assertEqual(get_tx_version_mock.call_args_list, [call("a-tx")])
        self.assertFalse(get_signature_hash_for_p2sh_input_mock.called)

    def test_no_logs(
        self,
        get_unsigned_tx_mock,
        get_signature_hash_for_p2sh_input_mock,
        get_tx_hash_for_unsigned_tx_mock,
        RskTrieMock,
        RskTransactionReceiptMock,
        get_tx_version_mock,
    ):
        trie_leaf = Mock(value_hash="the-receipt-hash")
        trie_root = Mock(
            **{
                "hash": self.blockchain_state.ancestor_receipts_root,
                "get_first_leaf.return_value": trie_leaf,
            })
        receipt = Mock(hash=trie_leaf.value_hash)
        RskTrieMock.from_proof.return_value = trie_root
        RskTransactionReceiptMock.return_value = receipt
        get_tx_hash_for_unsigned_tx_mock.return_value = "the-tx-hash"
        get_tx_version_mock.return_value = 1

        receipt.logs = []

        self.assertEqual(
            authorize_signature_and_get_message_to_sign(
                "a-receipt",
                ["a", "b"],
                "a-tx",
                123,
                self.EXPECTED_ADDRESS,
                self.blockchain_state,
                self.logger,
            ),
            (False, -101),
        )
        self.assertEqual(RskTransactionReceiptMock.call_args_list, [call("a-receipt")])
        self.assertEqual(RskTrieMock.from_proof.call_args_list, [call(["a", "b"])])
        self.assertEqual(get_tx_hash_for_unsigned_tx_mock.call_args_list, [call("a-tx")])
        self.assertEqual(get_tx_version_mock.call_args_list, [call("a-tx")])
        self.assertFalse(get_signature_hash_for_p2sh_input_mock.called)
        self.assertFalse(get_unsigned_tx_mock.called)

    def test_no_log_matches(
        self,
        get_unsigned_tx_mock,
        get_signature_hash_for_p2sh_input_mock,
        get_tx_hash_for_unsigned_tx_mock,
        RskTrieMock,
        RskTransactionReceiptMock,
        get_tx_version_mock,
    ):
        trie_leaf = Mock(value_hash="the-receipt-hash")
        trie_root = Mock(
            **{
                "hash": self.blockchain_state.ancestor_receipts_root,
                "get_first_leaf.return_value": trie_leaf,
            })
        receipt = Mock(hash=trie_leaf.value_hash)
        RskTrieMock.from_proof.return_value = trie_root
        RskTransactionReceiptMock.return_value = receipt
        get_tx_hash_for_unsigned_tx_mock.return_value = "the-tx-hash"
        get_tx_version_mock.return_value = 1

        receipt.logs = [
            Mock(
                signature="something-else",
                address="another-address",
                topics=[None, None, "the-tx-hash"],
            ),
            Mock(
                signature=self.EXPECTED_SIGNATURE,
                address="another-address",
                topics=[None, None, "another-tx-hash"],
            ),
            Mock(
                signature="something-else",
                address=self.EXPECTED_ADDRESS,
                topics=[None, None, "different-tx-hash"],
            ),
        ]

        self.assertEqual(
            authorize_signature_and_get_message_to_sign(
                "a-receipt",
                ["a", "b"],
                "a-tx",
                123,
                self.EXPECTED_ADDRESS,
                self.blockchain_state,
                self.logger,
            ),
            (False, -101),
        )
        self.assertEqual(RskTransactionReceiptMock.call_args_list, [call("a-receipt")])
        self.assertEqual(RskTrieMock.from_proof.call_args_list, [call(["a", "b"])])
        self.assertEqual(get_tx_hash_for_unsigned_tx_mock.call_args_list, [call("a-tx")])
        self.assertEqual(get_tx_version_mock.call_args_list, [call("a-tx")])
        self.assertFalse(get_signature_hash_for_p2sh_input_mock.called)
        self.assertFalse(get_unsigned_tx_mock.called)

    def test_authorization_ok(
        self,
        get_unsigned_tx_mock,
        get_signature_hash_for_p2sh_input_mock,
        get_tx_hash_for_unsigned_tx_mock,
        RskTrieMock,
        RskTransactionReceiptMock,
        get_tx_version_mock,
    ):
        trie_leaf = Mock(value_hash="the-receipt-hash")
        trie_root = Mock(
            **{
                "hash": self.blockchain_state.ancestor_receipts_root,
                "get_first_leaf.return_value": trie_leaf,
            })
        receipt = Mock(hash="the-receipt-hash")
        RskTrieMock.from_proof.return_value = trie_root
        RskTransactionReceiptMock.return_value = receipt
        get_tx_hash_for_unsigned_tx_mock.return_value = "the-tx-hash"
        get_signature_hash_for_p2sh_input_mock.return_value = "the-hash-to-sign"
        get_unsigned_tx_mock.return_value = "a-tx-unsigned"
        get_tx_version_mock.return_value = 1

        receipt.logs = [
            Mock(
                signature="something-else",
                address="another-address",
                topics=[None, None, "the-tx-hash"],
            ),
            Mock(
                signature=self.EXPECTED_SIGNATURE,
                address="another-address",
                topics=[None, None, "another-tx-hash"],
            ),
            Mock(
                signature="something-else",
                address=self.EXPECTED_ADDRESS,
                topics=[None, None, "different-tx-hash"],
            ),
            Mock(
                signature=self.EXPECTED_SIGNATURE,
                address=self.EXPECTED_ADDRESS,
                topics=[None, None, "the-tx-hash"],
            ),
        ]

        self.assertEqual(
            authorize_signature_and_get_message_to_sign(
                "a-receipt",
                ["a", "b"],
                "a-tx",
                123,
                self.EXPECTED_ADDRESS,
                self.blockchain_state,
                self.logger,
            ),
            (True, "the-hash-to-sign"),
        )
        self.assertEqual(RskTransactionReceiptMock.call_args_list, [call("a-receipt")])
        self.assertEqual(RskTrieMock.from_proof.call_args_list, [call(["a", "b"])])
        self.assertEqual(get_tx_hash_for_unsigned_tx_mock.call_args_list, [call("a-tx")])
        self.assertEqual(get_tx_version_mock.call_args_list, [call("a-tx")])
        self.assertEqual(
            get_signature_hash_for_p2sh_input_mock.call_args_list,
            [call("a-tx-unsigned", 123)],
        )
        self.assertEqual(get_unsigned_tx_mock.call_args_list, [call("a-tx")])

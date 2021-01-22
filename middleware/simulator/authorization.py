import sha3
from comm.protocol import HSM2Protocol
from comm.bip32 import BIP32Path
from .rsk.receipt import RskTransactionReceipt
from .rsk.trie import RskTrie
from comm.bitcoin import get_tx_hash_for_unsigned_tx, get_signature_hash_for_p2sh_input

# These are all the valid signing paths (key ids)
# Any other key id should be rejected as invalid
# Paths starting with 'dep_' are deprecated and are to be removed
# in a future version
_VALID_BIP32_PATHS = {
    "btc": BIP32Path("m/44'/0'/0'/0/0"),
    "rsk": BIP32Path("m/44'/137'/0'/0/0"),
    "mst": BIP32Path("m/44'/137'/1'/0/0"),
    "dep_mst": BIP32Path("m/44'/137'/0'/0/1"),
    "tbtc": BIP32Path("m/44'/1'/0'/0/0"),
    "trsk": BIP32Path("m/44'/1'/1'/0/0"),
    "dep_trsk": BIP32Path("m/44'/1'/0'/0/1"),
    "tmst": BIP32Path("m/44'/1'/2'/0/0"),
    "dep_tmst": BIP32Path("m/44'/1'/0'/0/2"),
}

# These are the only paths that require an authorization
_AUTH_REQUIRING_BIP32_PATHS = list(map(lambda k: _VALID_BIP32_PATHS[k], ["btc", "tbtc"]))

_EXPECTED_RECEIPT_EVENT_SIGNATURE = sha3.keccak_256(\
    "release_requested(bytes32,bytes32,uint256)".encode('utf-8'))\
    .digest().hex()

_EXPECTED_NUMBER_OF_TOPICS = 3
_EXPECTED_TOPIC_BTC_TX_INDEX = 2

def get_authorized_signing_paths():
    return _VALID_BIP32_PATHS.values()

def is_authorized_signing_path(path):
    return path in get_authorized_signing_paths()

def is_auth_requiring_path(path):
    return path in _AUTH_REQUIRING_BIP32_PATHS

def authorize_signature_and_get_message_to_sign(raw_tx_receipt, \
                                                receipt_merkle_proof, raw_tx, \
                                                input_index, emitter_address, \
                                                blockchain_state, logger):
    # The authorization process is as follows:
    # 1. The transaction receipt is parsed
    # 2. The receipt merkle proof is parsed
    # 3. Inclusion of the receipt in the blockchain is checked
    # (by means of the computed receipts trie root)
    # 4. The hash of the original unsigned tx is computed from the given raw tx
    # (potentially partially signed)
    # 5. The transaction receipt logs are inspected to find a matching log (more on this
    # in the _LogMatcher class)
    # 6. If all the previous verifications are successful, the raw transaction and the given
    # input index are used to compute the hash that needs to be signed, which
    # is then returned as result.

    # Steps 1 & 2
    try:
        tx_receipt = RskTransactionReceipt(raw_tx_receipt)
        rsk_trie_root = RskTrie.from_proof(receipt_merkle_proof)
        rsk_trie_leaf = rsk_trie_root.get_first_leaf()
    except Exception as e:
        logger.info("Error while processing authorization data: %s", str(e))
        return (False, HSM2Protocol.ERROR_CODE_INVALID_AUTH)

    # Step 3
    # 1. Check merkle proof root matches the blockchain state's ancestor receipts root
    if rsk_trie_root.hash != blockchain_state.ancestor_receipts_root:
        logger.info("Blockchain state's ancestor receipts root (%s) doesn't match merkle proof root (%s)",
                    blockchain_state.ancestor_receipts_root, rsk_trie_root.hash)
        return (False, HSM2Protocol.ERROR_CODE_INVALID_AUTH)
    # 2. Check merkle proof leaf value hash matches tx receipt hash
    if rsk_trie_leaf.value_hash != tx_receipt.hash:
        logger.info("Transaction receipt hash (%s) doesn't match merkle proof leaf value hash (%s)",
                    tx_receipt.hash, rsk_trie_leaf.value_hash)
        return (False, HSM2Protocol.ERROR_CODE_INVALID_AUTH)

    # Step 4
    try:
        tx_hash = get_tx_hash_for_unsigned_tx(raw_tx)
    except ValueError as e:
        logger.info("Invalid BTC transaction: %s", str(e))
        return (False, HSM2Protocol.ERROR_CODE_INVALID_MESSAGE)

    log_matcher = _LogMatcher(emitter_address, tx_hash, logger)

    # Step 5. Iterate logs and find the first that matches the conditions
    log_entry = next(filter(log_matcher.matches, tx_receipt.logs), None)

    if log_entry is None:
        logger.info("Transaction receipt contains no log with expected parameters")
        return (False, HSM2Protocol.ERROR_CODE_INVALID_AUTH)

    # Step 6. Generate the hash to sign and return
    try:
        hash_to_sign = get_signature_hash_for_p2sh_input(raw_tx, input_index)
    except ValueError as e:
        logger.info("Error generating hash to sign: %s", str(e))
        return (False, HSM2Protocol.ERROR_CODE_INVALID_MESSAGE)

    return (True, hash_to_sign)

class _LogMatcher:
    def __init__(self, emitter_address, btc_tx_hash, logger):
        self.emitter_address = emitter_address
        self.btc_tx_hash = btc_tx_hash
        self.logger = logger

    def matches(self, log):
        # A log is a _matching_ log iif:
        # 1. Its signature matches the expected event signature _AND_
        # 2. Its emitter contract address matches the expected emitter address _AND_
        # 3. The number of topics matches that of the expected event _AND_
        # 3. Its BTC tx hash (present in the topics) matches the expected BTC tx hash

        if log.signature != _EXPECTED_RECEIPT_EVENT_SIGNATURE:
            self.logger.debug("Log signature mismatch: %s (expected %s)", log.signature, _EXPECTED_RECEIPT_EVENT_SIGNATURE)
            return False

        self.logger.debug("Matched log signature - %s", log.signature)

        if log.address != self.emitter_address:
            self.logger.debug("Log address mismatch: %s (expected %s)", log.address, self.emitter_address)
            return False

        self.logger.debug("Matched log emitter - %s", log.address)

        if len(log.topics) != _EXPECTED_NUMBER_OF_TOPICS:
            self.logger.debug("Log topics mismatch: expected %d entries but got %d", _EXPECTED_NUMBER_OF_TOPICS, len(log.topics))
            return False

        if log.topics[_EXPECTED_TOPIC_BTC_TX_INDEX] != self.btc_tx_hash:
            self.logger.debug("Log BTC tx hash mismatch: %s (expected %s)", log.topics[_EXPECTED_TOPIC_BTC_TX_INDEX], self.btc_tx_hash)
            return False

        self.logger.debug("Matched BTC tx hash - %s", log.topics[_EXPECTED_TOPIC_BTC_TX_INDEX])

        return True

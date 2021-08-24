from unittest import TestCase
from simulator.rsk.trie import RskTrie, RskTrieHash, RskTrieError
import sha3

import logging
logging.disable(logging.CRITICAL)

# Test cases generated using truffle and an RSK node in regtest with a sample
# contract.
class TestRskTrie(TestCase):
    def test_leafnode_1(self):
        trie = RskTrie("7006003e0aeabebb4fee65e5de7d357b3329b8b6b3a1d2d382da1a0fe97fbabb6d2d5300055c", None)
        self.assert_leaf(trie, 'e12aad8318aeac60fb72c2fc6edd4f0beb4e8fc1e2c167f44cf2b99d3ae913f7', \
                         '3e0aeabebb4fee65e5de7d357b3329b8b6b3a1d2d382da1a0fe97fbabb6d2d53', 1372)

    def test_leafnode_2(self):
        trie = RskTrie("700600dd5b448174111ddf9cf0ea013fafa2860e828fdb806c231e618f73450f5762230001ad", None)
        self.assert_leaf(trie, 'e4e116e234d0529341fd05af08de4c9bec33c029c16fc1c12327ec9fcc369e98', \
                         'dd5b448174111ddf9cf0ea013fafa2860e828fdb806c231e618f73450f576223', 429)

    def test_leafnode_3(self):
        trie = RskTrie("700600c6165d1b8bc37d2a92e63392bb7ef6168a20532c1338e73bfba7641b8d51b0320002e8", None)
        self.assert_leaf(trie, 'f1d08d485ef58271953193de4c0d65ed02657e0dd4acbccc290760f50191549f', \
                         'c6165d1b8bc37d2a92e63392bb7ef6168a20532c1338e73bfba7641b8d51b032', 744)

    def test_leafnode_4(self):
        trie = RskTrie("609ee41e621aa694f8d1043a932092a1847d622ac61cb90111548b36fb280672ab000386", None)
        self.assert_leaf(trie, '2d90642c1b27329d56bd2cc74448a791f67c36c11d38a9c17a69a861a8e16289', \
                         '9ee41e621aa694f8d1043a932092a1847d622ac61cb90111548b36fb280672ab', 902)

    def test_innernode_1(self):
        trie = RskTrie("4f26700602264060209505db399ad70eead0819227ea4fe07c87f128678095e7da40a7a97a00010d26700600c6165d1b8bc37d2a92e63392bb7ef6168a20532c1338e73bfba7641b8d51b0320002e8fd4104", None)

        self.assertEqual('8df4ae63539c7fa8f14f4b263eb83ed0812dd7db72f6c0ce89c7499835195076', trie.hash)
        self.assertEqual(None, trie.parent)
        self.assert_children_hashes(trie, '1e549262aa5dfa08aa868df4520ff2ac9874cbf1261a65d1204373687330a98d', 'f1d08d485ef58271953193de4c0d65ed02657e0dd4acbccc290760f50191549f')

    def test_innernode_2(self):
        trie = RskTrie("4f246072fe1f639db776206478851f69e4fe488be402c0197d82588e22b1d01f5156f000010f24609ee41e621aa694f8d1043a932092a1847d622ac61cb90111548b36fb280672ab000386fddd04", None)

        self.assertEqual('c7a69c17f7f0a43630127753b78f0c1ce89b0b5f3ffd27360bf07dbac4bfd5cb', trie.hash)
        self.assertEqual(None, trie.parent)
        self.assert_children_hashes(trie, '4cd0624a9a83d9b798417bbc3b44116d730793a7cb7517fd854d117af8561e0e', '2d90642c1b27329d56bd2cc74448a791f67c36c11d38a9c17a69a861a8e16289')

    def test_innernode_3(self):
        trie = RskTrie("4e26700080c547fd1068dc610c82cb1f0355a736918e91e7f827bbfc25e5462a17622b48f300010fc7a69c17f7f0a43630127753b78f0c1ce89b0b5f3ffd27360bf07dbac4bfd5cbfd6006", None)

        self.assertEqual('148f8bb4d19d9258cec67bf1de9dfeaa8f0e2be3d445da0a2871a0464f273779', trie.hash)
        self.assertEqual(None, trie.parent)
        self.assert_children_hashes(trie, '38886edf178905dc8966e6de1e95d6743308d1b579720811104cc49442b42668', 'c7a69c17f7f0a43630127753b78f0c1ce89b0b5f3ffd27360bf07dbac4bfd5cb')

    def test_proof_1(self):
        self.assert_proof(proof=[\
            '7006008168dcc1f4e9db024c34e286c536cf2f3f6748b09da0ed1dbc67e1e7e724996a0001ad',\
            '4f267006027414b485c2de18fcea386000c837019c792d1bf0e9f86c95ee955f50cc6a97f000010d267006008168dcc1f4e9db024c34e286c536cf2f3f6748b09da0ed1dbc67e1e7e724996a0001adfd0603'\
          ],root_hash='4c00f7846d81046e9ef5f8e25d9216c03f2fbd4ef5011615cfc572e9328d2849',\
            leaf_hash='f937c72488b115dcfa140a4d5509b8e7836b4b9c3739cc2e2376c0e4622d263b',\
            receipt_hash='8168dcc1f4e9db024c34e286c536cf2f3f6748b09da0ed1dbc67e1e7e724996a', \
            receipt_length=429)

    def test_proof_2(self):
        self.assert_proof(proof=[\
            '609ee41e621aa694f8d1043a932092a1847d622ac61cb90111548b36fb280672ab000386',\
            '4f246072fe1f639db776206478851f69e4fe488be402c0197d82588e22b1d01f5156f000010f24609ee41e621aa694f8d1043a932092a1847d622ac61cb90111548b36fb280672ab000386fddd04',\
            '4e26700080c547fd1068dc610c82cb1f0355a736918e91e7f827bbfc25e5462a17622b48f300010fc7a69c17f7f0a43630127753b78f0c1ce89b0b5f3ffd27360bf07dbac4bfd5cbfd6006',\
            '5c0300148f8bb4d19d9258cec67bf1de9dfeaa8f0e2be3d445da0a2871a0464f2737791dca111c62b0a886e6779ff7dbb52f5b55874cd28b82a28a21677fc47be05868fd6109',\
            '4d2595a2cc015ad4069258cfa839073c932eaf42b9991900b4b9440df31b48c4842670060048ee76b19fc451dba9dbee8b3e73084f79ea540d3940b3b36b128e8024e9302500010ffddc0a'\
          ],root_hash='d994ef7b04aa8b34e533c9e58076069572fa5e4b231d84223ba819deff8a9a5a',\
            leaf_hash='2d90642c1b27329d56bd2cc74448a791f67c36c11d38a9c17a69a861a8e16289',\
            receipt_hash='9ee41e621aa694f8d1043a932092a1847d622ac61cb90111548b36fb280672ab', \
            receipt_length=902)

    def test_proof_3(self):
        self.assert_proof(proof=[\
            '7000806d76d62aec1d48c62859bb85ac2fe3e958cec93ea17d26e8143cabf7a43072c6000697',\
            '5e0400267000806d76d62aec1d48c62859bb85ac2fe3e958cec93ea17d26e8143cabf7a43072c6000697da3ca44ce3c56b07533d0cfb6f369d8adc76d7f0da742834508a528328cd7d4bfd7109',\
            '4d7edf0e6d7eeddf88a9edb8bdca8daf05504f419ed3c03c16d55def1afa1af27c2670060048ee76b19fc451dba9dbee8b3e73084f79ea540d3940b3b36b128e8024e9302500010ffdf30a'\
          ],root_hash='c7a4d9519f38904a7d9c37e3231ef416aa1915e4c901c788eb9d6e6580fba5c2',\
            leaf_hash='6773b26a7cb468403db632ba8d672f27784fff8503a619afd5d58825579acd46',\
            receipt_hash='6d76d62aec1d48c62859bb85ac2fe3e958cec93ea17d26e8143cabf7a43072c6', \
            receipt_length=1687)

    def test_invalid_trie_1(self):
        with self.assertRaises(RskTrieError):
            RskTrie("3000806d76d62aec1d48c62859bb85ac2fe3e958cec93ea17d26e8143cabf7a43072c6000697", None)

    def test_invalid_trie_2(self):
        with self.assertRaises(RskTrieError):
            RskTrie("aa", None)

    def test_invalid_trie_no_prefix(self):
        with self.assertRaises(RskTrieError):
            RskTrie("57", None)

    def test_invalid_trie_prefix_invalid_not_enough_bytes(self):
        with self.assertRaises(RskTrieError):
            RskTrie("57aa", None)

    def test_invalid_trie_prefix_invalid_no_size(self):
        with self.assertRaises(RskTrieError):
            RskTrie("57ff", None)

    def test_invalid_trie_prefix_invalid_var_int_3(self):
        with self.assertRaises(RskTrieError):
            RskTrie("57fffd", None)

    def test_invalid_trie_prefix_invalid_var_int_5(self):
        with self.assertRaises(RskTrieError):
            RskTrie("57fffe", None)

    def test_invalid_trie_prefix_invalid_var_int_9(self):
        with self.assertRaises(RskTrieError):
            RskTrie("57ffff", None)

    def test_invalid_trie_no_left_node(self):
        with self.assertRaises(RskTrieError):
            RskTrie("48", None)

    def test_invalid_trie_no_right_node(self):
        with self.assertRaises(RskTrieError):
            RskTrie("44", None)

    def test_invalid_trie_no_left_hash(self):
        with self.assertRaises(RskTrieError):
            RskTrie("48aa", None)

    def test_invalid_trie_no_right_hash(self):
        with self.assertRaises(RskTrieError):
            RskTrie("44aa", None)

    def test_invalid_trie_no_children_size(self):
        with self.assertRaises(RskTrieError):
            RskTrie("4a02aabb", None)

    def test_invalid_trie_invalid_value_hash_longvalue(self):
        with self.assertRaises(RskTrieError):
            RskTrie("60", None)

    def assert_leaf(self, trie, hash, value_hash, value_length, value=None):
        self.assertEqual(hash, trie.hash)
        self.assert_value(trie, value_hash, value_length, value)
        self.assertEqual(None, trie.left)
        self.assertEqual(None, trie.right)

    def assert_children_hashes(self, trie, left, right):
        self.assertEqual(RskTrieHash, type(trie.left))
        self.assertEqual(RskTrieHash, type(trie.right))
        self.assertEqual(left, trie.left.hash)
        self.assertEqual(right, trie.right.hash)

    def assert_value(self, trie, value_hash, value_length, value=None):
        self.assertEqual(value_hash, trie.value_hash)
        self.assertEqual(value, trie.value)
        self.assertEqual(value_length, trie.value_length)

    def assert_proof(self, proof, root_hash, leaf_hash, receipt_hash, receipt_length):
        root = RskTrie.from_proof(proof)

        self.assertEqual(root_hash, root.hash)
        self.assertEqual(None, root.parent)

        leaf = root.get_first_leaf()
        self.assert_leaf(leaf, leaf_hash, \
                         receipt_hash, receipt_length, None)

        self.assert_chaining(leaf, proof)

    def assert_chaining(self, leaf, proof):
        current = leaf
        for i in range(1, len(proof)):
            self.assertEqual(self.keccak256(proof[i]), current.parent.hash)
            if current.parent is not None:
                current = current.parent
        self.assertEqual(self.keccak256(proof[-1]), current.hash)
        self.assertEqual(None, current.parent)

    def keccak256(self, hex):
        return sha3.keccak_256(bytes.fromhex(hex)).digest().hex()

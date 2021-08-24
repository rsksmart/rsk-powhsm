from unittest import TestCase
from unittest.mock import Mock, MagicMock, call, ANY, patch

# The "ecdsa" library is only used for unit testing against the
# "secp256k1" library that the wallet uses.
# This gives library-independent testing for generated keys, public keys and
# signatures.
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string_canonize, sha256

import json
import simulator.wallet

import logging
logging.disable(logging.CRITICAL)

class TestSingleKeyWallet(TestCase):
    ITERATIONS = 100

    def test_public_key_ok(self):
        for i in range(self.ITERATIONS):
            key = SigningKey.generate(curve=SECP256k1)
            expected_public_key = key.verifying_key.to_string("uncompressed").hex()

            wallet = simulator.wallet.SingleKeyWallet(key.to_string().hex())

            self.assertEqual(expected_public_key, wallet.public_key())

    def test_random_keys_constructor(self):
        last_public_key = None
        for i in range(self.ITERATIONS):
            key = simulator.wallet.SingleKeyWallet(None)
            self.assertNotEqual(last_public_key, key.public_key())
            last_public_key = key.public_key()

    def test_random_keys_generate(self):
        last_public_key = None
        for i in range(self.ITERATIONS):
            key = simulator.wallet.SingleKeyWallet.generate()
            self.assertNotEqual(last_public_key, key.public_key())
            last_public_key = key.public_key()

    def test_sign(self):
        for i in range(self.ITERATIONS):
            key = SigningKey.generate(curve=SECP256k1)
            message = sha256(("message #%d" % i).encode('utf-8')).digest()
            sig = key.sign_digest_deterministic(message,
                                                hashfunc=sha256,
                                                sigencode=sigencode_string_canonize)
            expected_signature = {
                "r": sig[:32].hex(),
                "s": sig[32:].hex()
            }

            wallet = simulator.wallet.SingleKeyWallet(key.to_string().hex())
            self.assertEqual(expected_signature, wallet.sign(message.hex()))

    @patch('simulator.wallet.open')
    def test_save(self, mock_open):
        mock_file = MagicMock()
        mock_open.return_value = mock_file

        key = SigningKey.generate(curve=SECP256k1)
        wallet = simulator.wallet.SingleKeyWallet(key.to_string().hex())
        wallet.save("a-path-somewhere")

        self.assertEqual(mock_open.call_args_list, [call("a-path-somewhere", "w")])
        self.assertEqual(mock_file.__enter__().write.call_args_list, [call("%s\n" % key.to_string().hex())])
        self.assertTrue(mock_file.__exit__.called)

    @patch('simulator.wallet.open')
    def test_save_filenotfound(self, mock_open):
        mock_open.side_effect = FileNotFoundError()

        key = SigningKey.generate(curve=SECP256k1)
        wallet = simulator.wallet.SingleKeyWallet(key.to_string().hex())

        with self.assertRaises(FileNotFoundError):
            wallet.save("a-path-somewhere")

        self.assertEqual(mock_open.call_args_list, [call("a-path-somewhere", "w")])

    @patch('simulator.wallet.open')
    def test_from_hexfile(self, mock_open):
        key = SigningKey.generate(curve=SECP256k1)

        mock_file = MagicMock()
        mock_open.return_value = mock_file
        mock_file.__enter__().readline.return_value = "%s\n" % key.to_string().hex()

        wallet = simulator.wallet.SingleKeyWallet.from_hexfile("a-path-to-a-hex-file")

        self.assertEqual(key.verifying_key.to_string("uncompressed").hex(), wallet.public_key())
        self.assertEqual(mock_open.call_args_list, [call("a-path-to-a-hex-file", "r")])
        self.assertEqual(mock_file.__enter__().readline.call_args_list, [call()])
        self.assertTrue(mock_file.__exit__.called)

    @patch('simulator.wallet.open')
    def test_from_hexfile_filenotfound(self, mock_open):
        key = SigningKey.generate(curve=SECP256k1)

        mock_open.side_effect = FileNotFoundError()

        with self.assertRaises(FileNotFoundError):
            simulator.wallet.SingleKeyWallet.from_hexfile("a-path-to-a-hex-file")

        self.assertEqual(mock_open.call_args_list, [call("a-path-to-a-hex-file", "r")])

    @patch('simulator.wallet.open')
    def test_from_hexfile_hextooshort(self, mock_open):
        key = SigningKey.generate(curve=SECP256k1)

        mock_file = MagicMock()
        mock_open.return_value = mock_file
        mock_file.__enter__().readline.return_value = "aabbccdd\n"

        with self.assertRaises(TypeError):
            simulator.wallet.SingleKeyWallet.from_hexfile("a-path-to-a-hex-file")

        self.assertEqual(mock_open.call_args_list, [call("a-path-to-a-hex-file", "r")])
        self.assertEqual(mock_file.__enter__().readline.call_args_list, [call()])
        self.assertTrue(mock_file.__exit__.called)

    @patch('simulator.wallet.open')
    def test_from_hexfile_invalidhex(self, mock_open):
        key = SigningKey.generate(curve=SECP256k1)

        mock_file = MagicMock()
        mock_open.return_value = mock_file
        mock_file.__enter__().readline.return_value = "%s\n" % ("zz" * 32)

        with self.assertRaises(ValueError):
            simulator.wallet.SingleKeyWallet.from_hexfile("a-path-to-a-hex-file")

        self.assertEqual(mock_open.call_args_list, [call("a-path-to-a-hex-file", "r")])
        self.assertEqual(mock_file.__enter__().readline.call_args_list, [call()])
        self.assertTrue(mock_file.__exit__.called)

class TestNamedKeysWallet(TestCase):
    def setUp(self):
        self.wallet = simulator.wallet.NamedKeysWallet({
            "only_as": "aa"*32,
            "only_bs": "bb"*32,
            "only_threes": "33"*32,
            "only_fours": "44"*32
        })

    def test_ids(self):
        self.assertEqual(self.wallet.ids, ["only_as", "only_bs", "only_threes", "only_fours"])

    def test_keys(self):
        for id in self.wallet.ids:
            self.assertEqual(simulator.wallet.SingleKeyWallet, type(self.wallet.get(id)))

    def test_pks(self):
        self.assertEqual(self.wallet.get("only_as").private_key(), "aa"*32)
        self.assertEqual(self.wallet.get("only_bs").private_key(), "bb"*32)
        self.assertEqual(self.wallet.get("only_threes").private_key(), "33"*32)
        self.assertEqual(self.wallet.get("only_fours").private_key(), "44"*32)

    @patch("simulator.wallet.open")
    def test_save_to_jsonfile(self, mock_open):
        mock_file = MagicMock()
        mock_open.return_value = mock_file

        self.wallet.save_to_jsonfile("a-path-somewhere")

        self.assertEqual(mock_open.call_args_list, [call("a-path-somewhere", "w")])
        self.assertEqual(1, len(mock_file.__enter__().write.call_args_list))
        self.assertTrue(mock_file.__exit__.called)

        uniq_call = mock_file.__enter__().write.call_args_list[0]
        self.assertEqual(1, len(uniq_call.args))
        generated_json = uniq_call.args[0]
        self.assertEqual(json.loads(generated_json), {
            "only_as": "aa"*32,
            "only_bs": "bb"*32,
            "only_threes": "33"*32,
            "only_fours": "44"*32
        })

    @patch("simulator.wallet.open")
    def test_save_filenotfound(self, mock_open):
        mock_open.side_effect = FileNotFoundError()

        with self.assertRaises(FileNotFoundError):
            self.wallet.save_to_jsonfile("a-path-somewhere")

        self.assertEqual(mock_open.call_args_list, [call("a-path-somewhere", "w")])

    @patch("simulator.wallet.open")
    def test_from_jsonfile(self, mock_open):
        mock_file = MagicMock()
        mock_open.return_value = mock_file
        mock_file.__enter__().read.return_value = '{"ones": "'+("11"*32)+'", "twos": "'+("22"*32)+'", "threes": "'+("33"*32)+'"}'

        wallet = simulator.wallet.NamedKeysWallet.from_jsonfile("a-path-to-a-json-file")

        self.assertEqual(wallet.ids, ["ones", "twos", "threes"])
        self.assertEqual(wallet.get("ones").private_key(), "11"*32)
        self.assertEqual(wallet.get("twos").private_key(), "22"*32)
        self.assertEqual(wallet.get("threes").private_key(), "33"*32)
        self.assertEqual(mock_open.call_args_list, [call("a-path-to-a-json-file", "r")])
        self.assertEqual(mock_file.__enter__().read.call_args_list, [call()])
        self.assertTrue(mock_file.__exit__.called)

    @patch("simulator.wallet.open")
    def test_from_jsonfile_filenotfound(self, mock_open):
        mock_open.side_effect = FileNotFoundError()

        with self.assertRaises(FileNotFoundError):
            simulator.wallet.NamedKeysWallet.from_jsonfile("a-path-to-a-json-file")

        self.assertEqual(mock_open.call_args_list, [call("a-path-to-a-json-file", "r")])

    @patch("simulator.wallet.open")
    def test_from_jsonfile_invalidjson(self, mock_open):
        mock_file = MagicMock()
        mock_open.return_value = mock_file
        mock_file.__enter__().read.return_value = "im-not-json\n"

        with self.assertRaises(ValueError):
            simulator.wallet.NamedKeysWallet.from_jsonfile("a-path-to-a-json-file")

        self.assertEqual(mock_open.call_args_list, [call("a-path-to-a-json-file", "r")])
        self.assertEqual(mock_file.__enter__().read.call_args_list, [call()])
        self.assertTrue(mock_file.__exit__.called)

    @patch("simulator.wallet.open")
    def test_from_jsonfile_root_not_object(self, mock_open):
        mock_file = MagicMock()
        mock_open.return_value = mock_file
        mock_file.__enter__().read.return_value = json.dumps("im-just-a-string")

        with self.assertRaises(ValueError):
            simulator.wallet.NamedKeysWallet.from_jsonfile("a-path-to-a-json-file")

        self.assertEqual(mock_open.call_args_list, [call("a-path-to-a-json-file", "r")])
        self.assertEqual(mock_file.__enter__().read.call_args_list, [call()])
        self.assertTrue(mock_file.__exit__.called)

class TestLoadOrCreateWallet(TestCase):
    @patch("simulator.wallet.NamedKeysWallet")
    def test_file_exists(self, NamedKeysWalletMock):
        wallet = Mock()
        wallet.ids = [1,2,3]
        NamedKeysWalletMock.from_jsonfile.return_value = wallet

        self.assertEqual(simulator.wallet.load_or_create_wallet("an-existing-path", "doesnt-matter"), wallet)
        self.assertEqual(NamedKeysWalletMock.from_jsonfile.call_args_list, [call("an-existing-path")])
        self.assertFalse(NamedKeysWalletMock.generate.called)
        self.assertFalse(wallet.save_to_jsonfile.called)

    @patch("simulator.wallet.NamedKeysWallet")
    def test_file_does_not_exist(self, NamedKeysWalletMock):
        NamedKeysWalletMock.from_jsonfile.side_effect = FileNotFoundError()
        wallet = Mock()
        wallet.ids = [1,2,3]
        NamedKeysWalletMock.generate.return_value = wallet

        self.assertEqual(simulator.wallet.load_or_create_wallet("a-non-existing-path", \
            "the-ids"), wallet)
        self.assertEqual(NamedKeysWalletMock.from_jsonfile.call_args_list, [call("a-non-existing-path")])
        self.assertEqual(NamedKeysWalletMock.generate.call_args_list, [call("the-ids")])
        self.assertEqual(wallet.save_to_jsonfile.call_args_list, [call("a-non-existing-path")])

    @patch("simulator.wallet.NamedKeysWallet")
    def test_file_format_incorrect(self, NamedKeysWalletMock):
        NamedKeysWalletMock.from_jsonfile.side_effect = ValueError()
        wallet = Mock()
        wallet.ids = [1,2,3]
        NamedKeysWalletMock.generate.return_value = wallet

        self.assertEqual(simulator.wallet.load_or_create_wallet("an-incorrect-file", \
            "the-ids"), wallet)
        self.assertEqual(NamedKeysWalletMock.from_jsonfile.call_args_list, [call("an-incorrect-file")])
        self.assertEqual(NamedKeysWalletMock.generate.call_args_list, [call("the-ids")])
        self.assertEqual(wallet.save_to_jsonfile.call_args_list, [call("an-incorrect-file")])

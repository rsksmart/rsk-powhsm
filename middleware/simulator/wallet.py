import json
import secp256k1
import logging


class SingleKeyWallet:
    @staticmethod
    def from_hexfile(path):
        with open(path, "r") as file:
            key_hex = file.readline().strip()

        return SingleKeyWallet(key_hex)

    @staticmethod
    def generate():
        return SingleKeyWallet(None)

    def __init__(self, private_key):
        key_bytes = None
        if private_key is not None:
            key_bytes = bytes.fromhex(private_key)
        self._key = secp256k1.PrivateKey(privkey=key_bytes, raw=True)

    def public_key(self, compressed=False):
        return self._key.pubkey.serialize(compressed=compressed).hex()

    def private_key(self):
        return self._key.private_key.hex()

    def sign(self, message):
        signature = self._key.ecdsa_sign(bytes.fromhex(message), raw=True)
        serialized_signature = self._key.ecdsa_serialize_compact(signature)
        return {
            "r": serialized_signature[0:32].hex(),
            "s": serialized_signature[32:].hex(),
        }

    def save(self, path):
        with open(path, "w") as file:
            file.write("%s\n" % self.private_key())


class NamedKeysWallet:
    @staticmethod
    def from_jsonfile(path):
        try:
            with open(path, "r") as file:
                keys_map = json.loads(file.read())

            if type(keys_map) != dict:
                raise ValueError(
                    "JSON file must contain an object as a top level element")

            return NamedKeysWallet(keys_map)
        except (ValueError, json.JSONDecodeError) as e:
            raise ValueError("Unable to read named keys wallet from '%s': %s" %
                             (path, str(e)))

    @staticmethod
    def generate(key_ids):
        keys_map = {}
        for id in key_ids:
            keys_map[id] = SingleKeyWallet.generate().private_key()

        return NamedKeysWallet(keys_map)

    def __init__(self, keys_map):
        self._keys = {}

        for (id, private_key) in keys_map.items():
            self._keys[id] = SingleKeyWallet(private_key)

    @property
    def ids(self):
        return list(self._keys.keys())

    def get(self, id):
        return self._keys[id]

    def to_dict(self):
        result = {}
        for (id, key) in self._keys.items():
            result[id] = key.private_key()
        return result

    def save_to_jsonfile(self, path):
        with open(path, "w") as file:
            file.write("%s\n" % json.dumps(self.to_dict(), indent=2))


def load_or_create_wallet(keyfile_path, key_ids):
    logger = logging.getLogger("wallet")
    try:
        logger.info("Loading keyfile '%s'", keyfile_path)
        wallet = NamedKeysWallet.from_jsonfile(keyfile_path)
    except (FileNotFoundError, ValueError):
        logger.info("Keyfile not found or file format incorrect. Creating a new "
                    "random set of keys")
        wallet = NamedKeysWallet.generate(key_ids)
        wallet.save_to_jsonfile(keyfile_path)
        logger.info("Keys created and saved to '%s'", keyfile_path)
    finally:
        logger.info("Loaded keys:")
        for id in wallet.ids:
            logger.info("%s: %s", id, wallet.get(id).public_key(compressed=True))
        return wallet

from .case import TestCase, TestCaseError
from .sign_helpers import assert_signature
from comm.bip32 import BIP32Path

class SignUnauthorized(TestCase):

    PATHS = {
        "rsk": BIP32Path("m/44'/137'/0'/0/0"),
        "mst": BIP32Path("m/44'/137'/1'/0/0"),
        "dep_mst": BIP32Path("m/44'/137'/0'/0/1"),
        "trsk": BIP32Path("m/44'/1'/1'/0/0"),
        "dep_trsk": BIP32Path("m/44'/1'/0'/0/1"),
        "tmst": BIP32Path("m/44'/1'/2'/0/0"),
        "dep_tmst": BIP32Path("m/44'/1'/0'/0/2"),
    }
    
    @classmethod
    def op_name(cls):
        return "signUnauthorized"

    def __init__(self, spec):
        self.hash = spec['hash']
        return super().__init__(spec)

    def run(self, dongle, version, debug):
        try:
            # Attempt the signature with each of the valid paths
            for pkey in self.paths:
                path = self.paths[pkey]

                # Grab the public key
                try:
                    pubkey = dongle.get_public_key(path)
                    debug(f"Got public key for {path}: {pubkey}")
                except RuntimeError as e:
                    pubkey = None

                # Sign
                debug(f"Signing with {path}")
                signature = dongle.sign_unauthorized(path, self.hash)
                debug(f"Dongle replied with {signature}")
                if not(signature[0]):
                    error_code = dongle.last_comm_exception.sw if dongle.last_comm_exception is not None else signature[1]
                    if self.expected == True:
                        raise TestCaseError(f"Expected success signing but got error code {error_code}")
                    elif self.expected != error_code:
                        raise TestCaseError(f"Expected error code {self.expected} but got {error_code}")
                    # All good, expected failure
                    continue
                elif self.expected != True:
                    raise TestCaseError(f"Expected error code {self.expected} signing but got a successful signature")

                # Validate the signature
                assert_signature(pubkey, self.hash, signature[1])
        except RuntimeError as e:
            raise TestCaseError(str(e))

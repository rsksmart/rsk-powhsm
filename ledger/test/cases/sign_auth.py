from .case import TestCase, TestCaseError
from .sign_helpers import assert_signature
from comm.bip32 import BIP32Path
from comm.bitcoin import get_signature_hash_for_p2sh_input


class SignAuthorized(TestCase):

    PATHS = {
        "btc": BIP32Path("m/44'/0'/0'/0/0"),
        "tbtc": BIP32Path("m/44'/1'/0'/0/0"),
    }

    @classmethod
    def op_name(cls):
        return "signAuthorized"

    def __init__(self, spec):
        self.btc_tx = spec["btcTx"]
        self.btc_tx_input = spec["btcTxInput"]
        self.receipt = spec["receipt"]
        self.receipt_mp = spec["receiptMp"]

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
                except RuntimeError:
                    pubkey = None

                # Sign
                debug(f"Signing with {path}")
                signature = dongle.sign_authorized(path, self.receipt, self.receipt_mp,
                                                   self.btc_tx, self.btc_tx_input)
                debug(f"Dongle replied with {signature}")
                if not (signature[0]):
                    error_code = (dongle.last_comm_exception.sw
                                  if dongle.last_comm_exception is not None else
                                  signature[1])
                    if self.expected is True:
                        raise TestCaseError(
                            f"Expected success signing but got error code {error_code}")
                    elif self.expected != error_code:
                        raise TestCaseError(
                            f"Expected error code {self.expected} but got {error_code}")
                    # All good, expected failure
                    continue
                elif self.expected is not True:
                    raise TestCaseError(f"Expected error code {self.expected} signing "
                                        "but got a successful signature")

                # Validate the signature
                sighash = get_signature_hash_for_p2sh_input(self.btc_tx,
                                                            self.btc_tx_input)
                assert_signature(pubkey, sighash, signature[1])
        except RuntimeError as e:
            raise TestCaseError(str(e))

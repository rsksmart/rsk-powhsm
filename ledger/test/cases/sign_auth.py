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

from ledgerblue.comm import CommException
from .case import TestCase, TestCaseError
from .sign_helpers import assert_signature
from comm.bip32 import BIP32Path
from comm.bitcoin import get_signature_hash_for_p2sh_input
from misc.tcpsigner_admin import TcpSignerAdmin


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
        self.fake_ancestor_receipts_root = spec.get("fake_ancestor_receipts_root", None)

        super().__init__(spec)

    def run(self, dongle, debug, run_args):
        try:
            # Do we need to fake the ancestor receipts root?
            # (TCPSigner feature only, it will fail with a physical dongle)
            if self.fake_ancestor_receipts_root:
                try:
                    dongle.dongle.exchange(
                        bytes([TcpSignerAdmin.CLA,
                               TcpSignerAdmin.CMD_SET_ARR,
                               TcpSignerAdmin.OP_NONE]) +
                        bytes.fromhex(self.fake_ancestor_receipts_root))
                except CommException as e:
                    if self.expected != e.sw:
                        raise TestCaseError("Expected error code "
                                            f"{self.expected_desc} but got {hex(e.sw)}")
                    # This was expected, return implying success
                    return

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
                if not signature[0]:
                    if dongle.last_comm_exception is not None:
                        error_code = dongle.last_comm_exception.sw
                        error_code_desc = hex(error_code)
                    else:
                        error_code = signature[1]
                        error_code_desc = error_code

                    if self.expected is True:
                        raise TestCaseError("Expected success signing but got error "
                                            f"code {error_code_desc}")
                    elif self.expected != error_code:
                        raise TestCaseError(f"Expected error code {self.expected_desc} "
                                            f"but got {error_code_desc}")
                    # All good, expected failure
                    continue
                elif self.expected is not True:
                    raise TestCaseError(f"Expected error code {self.expected_desc} "
                                        "signing but got a successful signature")

                # Validate the signature
                sighash = get_signature_hash_for_p2sh_input(self.btc_tx,
                                                            self.btc_tx_input)
                assert_signature(pubkey, sighash, signature[1])

            # Did we fake the ancestor receipts root? Reset it
            # (TCPSigner feature only, it will fail with a physical dongle)
            if self.fake_ancestor_receipts_root:
                dongle.dongle.exchange(bytes([
                    TcpSignerAdmin.CLA,
                    TcpSignerAdmin.CMD_RESET_ARR,
                    TcpSignerAdmin.OP_NONE]))
        except RuntimeError as e:
            raise TestCaseError(str(e))

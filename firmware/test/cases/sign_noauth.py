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

from .case import TestCase, TestCaseError
from .sign_helpers import assert_signature
from comm.bip32 import BIP32Path


class SignUnauthorized(TestCase):

    PATHS = {
        "rsk": BIP32Path("m/44'/137'/0'/0/0"),
        "mst": BIP32Path("m/44'/137'/1'/0/0"),
        "trsk": BIP32Path("m/44'/1'/1'/0/0"),
        "tmst": BIP32Path("m/44'/1'/2'/0/0"),
    }

    @classmethod
    def op_name(cls):
        return "signUnauthorized"

    def __init__(self, spec):
        self.hash = spec["hash"]

        super().__init__(spec)

    def run(self, dongle, debug, run_args):
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
                signature = dongle.sign_unauthorized(path, self.hash)
                debug(f"Dongle replied with {signature}")
                if not signature[0]:
                    if dongle.last_comm_exception is not None:
                        error_code = dongle.last_comm_exception.sw
                        error_code_desc = hex(error_code)
                    else:
                        error_code = signature[1]
                        error_code_desc = error_code

                    if self.expected is True:
                        raise TestCaseError("Expected success signing but got "
                                            f"error code {error_code_desc}")
                    elif self.expected != error_code:
                        raise TestCaseError("Expected error code "
                                            f"{self.expected_desc} but got "
                                            f"{error_code_desc}")
                    # All good, expected failure
                    continue
                elif self.expected is not True:
                    raise TestCaseError(f"Expected error code {self.expected_desc} "
                                        "signing but got a successful signature")

                # Validate the signature
                assert_signature(pubkey, self.hash, signature[1])
        except RuntimeError as e:
            raise TestCaseError(str(e))

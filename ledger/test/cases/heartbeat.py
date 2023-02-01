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
import secp256k1 as ec
import hmac
import hashlib


class Heartbeat(TestCase):
    EXPECTED_HEADER = "HSM:SIGNER:HB:4.0:"
    EHL = len(EXPECTED_HEADER)

    @classmethod
    def op_name(cls):
        return "heartbeat"

    def __init__(self, spec):
        self.ud_value = spec["udValue"]

        super().__init__(spec)

    def run(self, dongle, debug, run_args):
        def normalize_hex_sig_component(h):
            h = bytes.fromhex(h)
            h = int.from_bytes(h, byteorder="big", signed=False)
            return h.to_bytes(32, byteorder="big", signed=False)

        def get_message_part(msg, part):
            try:
                return ({
                    "best_block": lambda m: m[self.EHL*2:(self.EHL+32)*2],
                    "last_tx": lambda m: m[(self.EHL+32)*2:(self.EHL+32+8)*2],
                })[part](msg)
            except KeyError:
                raise TestCaseError(f"Unknown message part \"{part}\"")
            except Exception as e:
                raise TestCaseError(str(e))

        try:
            heartbeat = dongle.get_signer_heartbeat(self.ud_value)
            debug(f"Heartbeat: {heartbeat}")

            if not heartbeat[0]:
                error_code = heartbeat[1]
                raise TestCaseError("Expected success getting the heartbeat "
                                    f"but got error code {error_code}")
            heartbeat = heartbeat[1]

            # Validate signature
            message = bytes.fromhex(heartbeat["message"])
            pubkey = ec.PublicKey(bytes.fromhex(heartbeat["pubKey"]), raw=True)
            norm_r = normalize_hex_sig_component(heartbeat["signature"].r)
            norm_s = normalize_hex_sig_component(heartbeat["signature"].s)
            sig = pubkey.ecdsa_deserialize_compact(norm_r + norm_s)
            tweak = hmac.new(
                    bytes.fromhex(heartbeat["tweak"]),
                    pubkey.serialize(compressed=False),
                    hashlib.sha256,
                ).digest()
            pubkey = pubkey.tweak_add(tweak)

            if not pubkey.ecdsa_verify(message, sig):
                raise TestCaseError("Expected signature to be valid but it wasn't")

            # Validate header
            header_msg = message[:self.EHL].decode('ascii')
            if header_msg != self.EXPECTED_HEADER:
                raise TestCaseError(f"Expected header to be {self.EXPECTED_HEADER} but"
                                    f" got {header_msg}")

            # Validate UD value
            ud_msg = message[-16:].hex()
            if ud_msg != self.ud_value:
                raise TestCaseError(f"Expected UD value to be {self.ud_value} but"
                                    f" got {ud_msg}")

            # Expectations on the heartbeat message (optional)
            if type(self.expected) == dict:
                message = message.hex()
                for key in self.expected:
                    val = get_message_part(message, key)
                    if val != self.expected[key]:
                        raise TestCaseError(f"Expected {key} to be {self.expected[key]} "
                                            f"but got {val}")
        except RuntimeError as e:
            raise TestCaseError(str(e))

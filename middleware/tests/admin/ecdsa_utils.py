# The MIT License (MIT)
#
# Copyright (c) 2026 RSK Labs Ltd
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

# ECDSA (secp256k1) helpers for tests

import ecdsa
from admin.ledger_utils import encode_eth_message, pubkey_to_address, to_checksum_address
from admin.utils import keccak_256

SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Test vector from the web3.js documentation (web3.eth.accounts.sign)
WEB3_PRIVATE_KEY = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
WEB3_PUBKEY = ecdsa.SigningKey.from_string(
    bytes.fromhex(WEB3_PRIVATE_KEY),
    curve=ecdsa.SECP256k1).get_verifying_key().to_string("uncompressed")
WEB3_ADDRESS = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
WEB3_MESSAGE = "Some data"
WEB3_DIGEST = keccak_256(encode_eth_message(WEB3_MESSAGE))
WEB3_R = 0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd
WEB3_S = 0x6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a029
WEB3_RECOVERY_ID = 1


def sign(private_key, digest, k=None):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    if k is None:
        return sk.sign_digest_deterministic(
            digest, sigencode=ecdsa.util.sigencode_der_canonize).hex()
    return sk.sign_digest(digest, k=k, sigencode=ecdsa.util.sigencode_der_canonize).hex()


def address(private_key):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    return to_checksum_address(
        pubkey_to_address(sk.get_verifying_key().to_string("uncompressed")))


def to_high_s(der_signature):
    r, s = ecdsa.util.sigdecode_der(bytes.fromhex(der_signature), SECP256K1_N)
    return der_encode(r, SECP256K1_N - s)


def der_encode(r, s):
    return ecdsa.util.sigencode_der(r, s, SECP256K1_N).hex()


def unrecoverable_r():
    # An r that is not the x coordinate of any curve point,
    # so that no signer can be recovered from a signature with it
    r = 1
    while pow(r**3 + 7, (SECP256K1_P - 1) // 2, SECP256K1_P) == 1:
        r += 1
    return r


def unrecoverable_signature():
    # A valid DER signature from which no signer can be recovered
    return der_encode(unrecoverable_r(), 1)

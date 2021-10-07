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

from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
from .case import TestCaseError


def assert_signature(pubkey, message, signature):
    if pubkey is None:
        raise TestCaseError("Could not determine the public key")

    # Validate the signature
    vkey = VerifyingKey.from_string(bytes.fromhex(pubkey), curve=SECP256k1)
    try:
        tuple_sig = to_tuple(signature)
        vkey.verify_digest(tuple_sig, bytes.fromhex(message), sigdecode=lambda x, _: x)
    except BadSignatureError:
        raise TestCaseError(
            f"Got bad signature {tuple_sig} for message {message} and public key {pubkey}"
        )


def to_tuple(signature):
    return (
        int.from_bytes(bytes.fromhex(signature.r), byteorder="big", signed=False),
        int.from_bytes(bytes.fromhex(signature.s), byteorder="big", signed=False),
    )

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

import json
import secp256k1 as ec
import sha3
from .utils import is_hex_string_of_length, hex_or_decimal_string_to_int
from .ledger_utils import encode_eth_message


class SignerAuthorization:
    VERSION = 1  # Only supported version

    @staticmethod
    def from_jsonfile(path):
        try:
            with open(path, "r") as file:
                signer_auth_map = json.loads(file.read())

            if type(signer_auth_map) != dict:
                raise ValueError(
                    "JSON file must contain an object as a top level element")

            if signer_auth_map["version"] != SignerAuthorization.VERSION:
                raise ValueError("Unsupported file format version "
                                 f"{signer_auth_map['version']}")

            return SignerAuthorization(
                    SignerVersion(signer_auth_map["signer"]["hash"],
                                  signer_auth_map["signer"]["iteration"]),
                    signer_auth_map["signatures"])
        except (ValueError, json.JSONDecodeError) as e:
            raise ValueError('Unable to read Signer Authorization from "%s": %s' %
                             (path, str(e)))

    @staticmethod
    def for_signer_version(signer_version):
        return SignerAuthorization(signer_version, [])

    def __init__(self, signer_version, signatures):
        self._signer_version = signer_version
        self._signatures = signatures[:]

        if type(self._signer_version) != SignerVersion:
            raise ValueError(f"Invalid signer version given: {signer_version}")

        if type(signatures) != list:
            raise ValueError("Signatures must be a list")

        for signature in signatures:
            self._assert_signature_valid(signature)

    @property
    def signer_version(self):
        return self._signer_version

    @property
    def signatures(self):
        return self._signatures[:]

    def add_signature(self, signature):
        self._assert_signature_valid(signature)
        self._signatures.append(signature)

    def to_dict(self):
        return {
            "version": self.VERSION,
            "signer": self._signer_version.to_dict(),
            "signatures": self._signatures[:],
        }

    def save_to_jsonfile(self, path):
        with open(path, "w") as file:
            file.write("%s\n" % json.dumps(self.to_dict(), indent=2))

    def _assert_signature_valid(self, signature):
        try:
            ec.PrivateKey().ecdsa_deserialize(bytes.fromhex(signature))
        except Exception as e:
            raise ValueError(f"Invalid DER signature: {signature}: {e}")


class SignerVersion:
    def __init__(self, hash, iteration):
        if not(is_hex_string_of_length(hash, 32)):
            raise ValueError("Hash must be a 32-byte hex string")

        if type(iteration) == str:
            iteration = hex_or_decimal_string_to_int(iteration)

        if type(iteration) != int or iteration < 0 or iteration >= (2**16):
            raise ValueError("Invalid iteration (must be a 16-bit unsigned int)")

        self._hash = hash.lower()
        self._iteration = iteration

    @property
    def hash(self):
        return self._hash

    @property
    def iteration(self):
        return self._iteration

    @property
    def msg(self):
        return f"RSK_powHSM_signer_{self._hash}_iteration_{str(self._iteration)}"

    def get_authorization_msg(self):
        return encode_eth_message(self.msg)

    def get_authorization_digest(self):
        return sha3.keccak_256(self.get_authorization_msg()).digest()

    def to_dict(self):
        return {
            "hash": self.hash,
            "iteration": self.iteration,
        }

    def __repr__(self):
        return f"SignerVersion(hash=0x{self.hash}, iteration={self.iteration})"

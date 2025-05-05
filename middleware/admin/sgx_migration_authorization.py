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
from .utils import is_hex_string_of_length, normalize_hex_string, keccak_256
from .ledger_utils import encode_eth_message


class SGXMigrationAuthorization:
    VERSION = 1  # Only supported version

    @staticmethod
    def from_jsonfile(path):
        try:
            with open(path, "r") as file:
                spec_auth_map = json.loads(file.read())

            if type(spec_auth_map) != dict:
                raise ValueError(
                    "JSON file must contain an object as a top level element")
            if spec_auth_map["version"] != SGXMigrationAuthorization.VERSION:
                raise ValueError("Unsupported file format version "
                                 f"{spec_auth_map['version']}")

            migration_spec = SGXMigrationSpec(spec_auth_map["hashes"])
            signatures = spec_auth_map["signatures"]
            return SGXMigrationAuthorization(migration_spec, signatures)
        except (ValueError, json.JSONDecodeError) as e:
            raise ValueError("Unable to read SGX Migration Authorization from "
                             f"{path}: {str(e)}")

    @staticmethod
    def for_spec(migration_spec):
        return SGXMigrationAuthorization(migration_spec, [])

    def __init__(self, migration_spec, signatures):
        self._migration_spec = migration_spec
        self._signatures = signatures[:]

        if type(self._migration_spec) != SGXMigrationSpec:
            raise ValueError(f"Invalid migration spec given: {migration_spec}")

        if type(signatures) != list:
            raise ValueError("Signatures must be a list")

        for signature in signatures:
            self._assert_signature_valid(signature)

    @property
    def migration_spec(self):
        return self._migration_spec

    @property
    def signatures(self):
        return self._signatures[:]

    def add_signature(self, signature):
        self._assert_signature_valid(signature)
        self._signatures.append(signature)

    def to_dict(self):
        return {
            "version": self.VERSION,
            "hashes": self._migration_spec.to_dict(),
            "signatures": self._signatures[:],
        }

    def save_to_jsonfile(self, path):
        with open(path, "w") as file:
            file.write(json.dumps(self.to_dict(), indent=2))

    def _assert_signature_valid(self, signature):
        try:
            ec.PrivateKey().ecdsa_deserialize(bytes.fromhex(signature))
        except Exception as e:
            raise ValueError(f"Invalid DER signature: {signature}: {e}")


class SGXMigrationSpec:
    def __init__(self, hashes):
        if type(hashes) != dict:
            raise ValueError("Hashes must be a dict")
        if not is_hex_string_of_length(hashes["exporter"], 32, allow_prefix=True):
            raise ValueError("Exporter hash must be a 32-byte hex string")
        if not is_hex_string_of_length(hashes["importer"], 32, allow_prefix=True):
            raise ValueError("Importer hash must be a 32-byte hex string")
        self._exporter_hash = normalize_hex_string(hashes["exporter"])
        self._importer_hash = normalize_hex_string(hashes["importer"])

    @property
    def exporter(self):
        return self._exporter_hash

    @property
    def importer(self):
        return self._importer_hash

    @property
    def msg(self):
        return f"RSK_powHSM_SGX_upgrade_from_{self.exporter}_to_{self.importer}"

    def get_authorization_msg(self):
        return encode_eth_message(self.msg)

    def get_authorization_digest(self):
        return keccak_256(self.get_authorization_msg())

    def to_dict(self):
        return {
            "exporter": self.exporter,
            "importer": self.importer,
        }

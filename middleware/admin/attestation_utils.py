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

import hashlib
import json
import re
import secp256k1 as ec
import requests
from pathlib import Path
from comm.cstruct import CStruct
from .misc import AdminError
from .certificate_v2 import HSMCertificateV2, HSMCertificateV2ElementX509


class PowHsmAttestationMessage(CStruct):
    """
    pow_hsm_message_header

    uint8_t platform 3
    uint8_t ud_value 32
    uint8_t public_keys_hash 32
    uint8_t best_block 32
    uint8_t last_signed_tx 8
    uint8_t timestamp 8
    """

    HEADER_REGEX = re.compile(b"^POWHSM:(5.[0-9])::")

    @classmethod
    def is_header(cls, value):
        return cls.HEADER_REGEX.match(value) is not None

    def __init__(self, value, offset=0, little=True, name="powHSM"):
        self.name = name
        # Parse header
        match = self.HEADER_REGEX.match(value)
        if match is None:
            raise ValueError(
                f"Invalid {self.name} attestation message header: {value.hex()}")

        # Validate total length
        header_length = len(match.group(0))
        expected_length = header_length + self.get_bytelength()
        if len(value[offset:]) != expected_length:
            raise ValueError(f"{self.name} attestation message length "
                             f"mismatch: {value[offset:].hex()}")

        # Grab version
        self.version = match.group(1).decode("ASCII")

        # Parse the rest
        super().__init__(value, offset+header_length, little)

        # Conversions
        self.platform = self.platform.decode("ASCII")
        self.timestamp = int.from_bytes(self.timestamp, byteorder="big", signed=False)


def load_pubkeys(pubkeys_file_path):
    # Load the given public keys file into a map
    try:
        with open(pubkeys_file_path, "r") as file:
            pubkeys_map = json.loads(file.read())

        if type(pubkeys_map) != dict:
            raise AdminError(
                "Public keys file must contain an object as a top level element")

        result = {}
        for path in pubkeys_map.keys():
            pubkey = pubkeys_map[path]
            try:
                pubkey = ec.PublicKey(bytes.fromhex(pubkey), raw=True)
            except Exception:
                raise AdminError(f"Invalid public key for path {path}: {pubkey}")
            result[path] = pubkey
        return result
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        raise AdminError('Unable to read public keys from "%s": %s' %
                         (pubkeys_file_path, str(e)))


def compute_pubkeys_hash(pubkeys_map):
    # Compute the given public keys hash
    # (sha256sum of the uncompressed public keys in
    # lexicographical path order)
    if len(pubkeys_map) == 0:
        raise AdminError("Can't compute the hash of an empty public keys map")

    pubkeys_hash = hashlib.sha256()
    for path in sorted(pubkeys_map.keys()):
        pubkey = pubkeys_map[path]
        pubkeys_hash.update(pubkey.serialize(compressed=False))
    return pubkeys_hash.digest()


def compute_pubkeys_output(pubkeys_map):
    pubkeys_output = []
    path_name_padding = max(map(len, pubkeys_map.keys()))
    for path in sorted(pubkeys_map.keys()):
        pubkey = pubkeys_map[path]
        pubkeys_output.append(
                f"{(path + ':').ljust(path_name_padding+1)} "
                f"{pubkey.serialize(compressed=True).hex()}"
            )
    return pubkeys_output


def get_sgx_root_of_trust(path):
    # From file
    if Path(path).is_file():
        return HSMCertificateV2ElementX509.from_pemfile(
            path,
            HSMCertificateV2.ROOT_ELEMENT,
            HSMCertificateV2.ROOT_ELEMENT)

    # Assume URL and try to grab it
    ra_res = requests.get(path)
    if ra_res.status_code != 200:
        raise RuntimeError(f"Error fetching root of trust from {path}")

    return HSMCertificateV2ElementX509.from_pem(
        ra_res.content.decode(),
        HSMCertificateV2.ROOT_ELEMENT,
        HSMCertificateV2.ROOT_ELEMENT)

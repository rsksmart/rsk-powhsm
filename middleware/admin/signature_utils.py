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

import secp256k1 as ec
from .ledger_utils import pubkey_to_address, to_checksum_address


_ECDSA = ec.ECDSA()


class ECDSASignature:
    """
    An ECDSA secp256k1 signature, internally kept as a libsecp256k1 signature
    """

    @staticmethod
    def from_der(der_signature):
        """
        Parses the given (strictly) DER-encoded signature (bytes)
        """
        try:
            return ECDSASignature(_ECDSA.ecdsa_deserialize(der_signature))
        except Exception:
            raise ValueError(f"Invalid DER signature: {der_signature.hex()}")

    @staticmethod
    def from_compact(compact_signature):
        """
        Parses the given compact (64-byte r||s) signature (bytes)
        """
        try:
            return ECDSASignature(_ECDSA.ecdsa_deserialize_compact(compact_signature))
        except Exception:
            raise ValueError("Invalid compact signature: "
                             f"{compact_signature.hex()}")

    def __init__(self, raw_signature):
        self._raw_signature = raw_signature

    def to_der(self):
        return _ECDSA.ecdsa_serialize(self._raw_signature)

    def to_compact(self):
        return _ECDSA.ecdsa_serialize_compact(self._raw_signature)

    def normalized(self):
        _, raw_signature = _ECDSA.ecdsa_signature_normalize(self._raw_signature)
        return ECDSASignature(raw_signature)

    def recover_signer_address(self, recovery_id, digest):
        try:
            recoverable_signature = _ECDSA.ecdsa_recoverable_deserialize(
                self.to_compact(), recovery_id)
            pubkey = ec.PublicKey(_ECDSA.ecdsa_recover(
                digest, recoverable_signature, raw=True))
        except Exception as e:
            raise ValueError(f"Unable to recover signer: {e}")
        return pubkey_to_address(pubkey.serialize(compressed=False))

    def recover_signer_addresses(self, digest):
        """
        Recovers the possible signer addresses of the given digest when the
        recovery id is unknown. This yields up to two candidates, and an
        empty list if no signer can be recovered.
        """
        addresses = []
        for recovery_id in [0, 1]:
            try:
                addresses.append(self.recover_signer_address(recovery_id, digest))
            except ValueError:
                pass
        return addresses

    def __eq__(self, other):
        return isinstance(other, ECDSASignature) and \
            self.to_compact() == other.to_compact()

    def __hash__(self):
        return hash(self.to_compact())

    def __repr__(self):
        return f"ECDSASignature({self.to_der().hex()})"


def assert_signer_not_present(signatures, new_signature, digest):
    """
    Makes sure the signer of the given new signature hasn't already signed
    the given digest in any of the given signatures. Authorizers are counted
    at most once, so a second signature by the same signer (whether an exact
    copy, a different encoding or a new signature) is useless.
    """
    new_addresses = set(new_signature.recover_signer_addresses(digest))
    if len(new_addresses) == 0:
        raise ValueError("Invalid signature: unable to recover any signer")

    for signature in signatures:
        common_addresses = new_addresses & set(signature.recover_signer_addresses(digest))
        if len(common_addresses) == 1:
            raise ValueError("A signature by signer "
                             f"{to_checksum_address(common_addresses.pop())} "
                             "already exists")
        if len(common_addresses) > 1:
            # E.g., an exact copy of a DER signature, for which
            # the actual signer is one of the (shared) candidates
            addresses = sorted(to_checksum_address(a) for a in common_addresses)
            raise ValueError("A signature by the same signer (one of "
                             f"{' or '.join(addresses)}) already exists")

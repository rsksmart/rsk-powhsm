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

import json
from os.path import isfile
from .utils import parse_hex_string
from .ledger_utils import pubkey_to_address, to_checksum_address
from .signature_utils import ECDSASignature

SUPPORTED_FORMATS_DESCRIPTION = "\n".join([
    "Supported signature formats:",
    "    - DER, hex-encoded",
    "    - 65-byte r||s||v, hex-encoded, with v either 27/28 or 0/1 "
    "(e.g., MetaMask, MyEtherWallet, Ledger)",
    "    - Signed message JSON, given either inline or as a path to a file "
    "(e.g., MyEtherWallet, MyCrypto, Etherscan)",
])

FORMAT_DER = "DER"
FORMAT_RSV = "r||s||v"
FORMAT_JSON = "Signed message JSON"


class ExternalSignature:
    def __init__(self, format, der_signature, signer_addresses):
        self._format = format
        self._der_signature = der_signature
        self._signer_addresses = signer_addresses[:]

    @property
    def format(self):
        return self._format

    @property
    def der_signature(self):
        return self._der_signature

    @property
    def signer_addresses(self):
        return self._signer_addresses[:]


def parse_external_signature(value, message, digest, expected_signer=None):
    """
    Parses an externally generated signature of the given message (whose
    Ethereum-style digest is given) in any of the supported formats, and
    verifies it. If an expected signer (address or public key) is given,
    it must match the signature's signer.

    Returns an ExternalSignature, which contains the canonical (low-S)
    hex-encoded DER signature and the possible signer address(es).
    """
    value = value.strip()
    if isfile(value):
        with open(value, "r") as file:
            value = file.read().strip()

    if value.startswith("{"):
        signature = _parse_json_signature(value, message, digest)
    else:
        signature = _parse_hex_signature(value, digest)

    if expected_signer is not None:
        expected_address = _parse_signer(expected_signer)
        if expected_address not in signature.signer_addresses:
            raise ValueError(f"Signature was not produced by the expected signer "
                             f"{to_checksum_address(expected_address)}")

    return signature


def describe_external_signature(signature, signer_checked):
    addresses = [to_checksum_address(a) for a in signature.signer_addresses]
    lines = [f"Signature format: {signature.format}"]
    if len(addresses) == 1:
        lines.append(f"Signer address: {addresses[0]}")
    else:
        lines.append(f"Signer address: one of {' or '.join(addresses)} "
                     "(a DER signature does not identify a single signer)")
    if signer_checked:
        lines.append("Signer matches the expected signer")
    else:
        lines.append("WARNING: no expected signer given (-s/--signer). "
                     "Make sure the signer address above is the expected one.")
    return lines


def _parse_hex_signature(value, digest):
    try:
        signature_bytes = parse_hex_string(value)
    except ValueError:
        raise ValueError(f"Invalid signature: {value}\n{SUPPORTED_FORMATS_DESCRIPTION}")

    try:
        signature = ECDSASignature.from_der(signature_bytes)
    except ValueError:
        signature = None
    if signature is not None:
        addresses = signature.recover_signer_addresses(digest)
        if len(addresses) == 0:
            raise ValueError("Invalid signature: unable to recover any signer")
        return ExternalSignature(FORMAT_DER, signature.normalized().to_der().hex(),
                                 addresses)

    if len(signature_bytes) == 65:
        return _parse_rsv(signature_bytes, digest, FORMAT_RSV)

    raise ValueError(f"Invalid signature: {value}\n{SUPPORTED_FORMATS_DESCRIPTION}")


def _parse_json_signature(value, message, digest):
    try:
        signed_message = json.loads(value)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid signed message JSON: {e}")

    for field in ["msg", "sig"]:
        if type(signed_message) != dict or type(signed_message.get(field)) != str:
            raise ValueError(f"Invalid signed message JSON: missing '{field}' field")

    # Depending on the tool, the signed message is given either as plain
    # text (e.g., MyCrypto, Etherscan) or hex-encoded (e.g., MyEtherWallet).
    # Since the expected message is known, accept either form
    signed_msg = signed_message["msg"]
    decoded_msg = _decode_utf8_hex_message(signed_msg)
    if message not in [signed_msg, decoded_msg]:
        raise ValueError("Signed message does not match the expected message:\n"
                         f"    Expected: {message}\n"
                         f"    Signed:   {decoded_msg or signed_msg}")

    try:
        signature_bytes = parse_hex_string(signed_message["sig"])
    except ValueError:
        signature_bytes = None
    if signature_bytes is None or len(signature_bytes) != 65:
        raise ValueError("Invalid signed message JSON: 'sig' must be a 65-byte "
                         "hex-encoded signature")
    signature = _parse_rsv(signature_bytes, digest, FORMAT_JSON)

    if "address" in signed_message:
        claimed_address = _parse_signer(str(signed_message["address"]))
        if claimed_address not in signature.signer_addresses:
            actual_address = to_checksum_address(signature.signer_addresses[0])
            raise ValueError(
                "Signer address in signed message JSON "
                f"({signed_message['address']}) does not match the "
                f"signature's signer ({actual_address})")

    return signature


def _decode_utf8_hex_message(value):
    # Returns None if the given value is not a hex-encoded UTF-8 message
    try:
        return parse_hex_string(value).decode("utf-8")
    except ValueError:
        return None


def _parse_rsv(signature_bytes, digest, format):
    v = signature_bytes[64]
    if v in [27, 28]:
        recovery_id = v - 27
    elif v in [0, 1]:
        recovery_id = v
    else:
        raise ValueError(f"Invalid signature v value: {v} (expected 27, 28, 0 or 1)")

    try:
        signature = ECDSASignature.from_compact(signature_bytes[:64])
        address = signature.recover_signer_address(recovery_id, digest)
    except ValueError as e:
        raise ValueError(f"Invalid signature: {e}")
    return ExternalSignature(format, signature.normalized().to_der().hex(), [address])


def _parse_signer(signer):
    try:
        signer_bytes = parse_hex_string(signer.strip())
        if len(signer_bytes) == 20:
            return "0x" + signer_bytes.hex()
        return pubkey_to_address(signer_bytes)
    except Exception:
        raise ValueError(f"Invalid signer '{signer}': must be a hex-encoded "
                         "address or public key")

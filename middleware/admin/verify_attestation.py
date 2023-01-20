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
import hashlib
import secp256k1 as ec
from .misc import info, head, AdminError
from .utils import is_nonempty_hex_string
from .certificate import HSMCertificate


UI_MESSAGE_HEADER = b"HSM:UI:4.0"
SIGNER_MESSAGE_HEADER = b"HSM:SIGNER:4.0"
UI_DERIVATION_PATH = "m/44'/0'/0'/0/0"
UD_VALUE_LENGTH = 32
PUBKEY_COMPRESSED_LENGTH = 33
SIGNER_HASH_LENGTH = 32
SIGNER_ITERATION_LENGTH = 2

# Ledger's root authority
# (according to
# https://github.com/LedgerHQ/blue-loader-python/blob/master/ledgerblue/
# endorsementSetup.py#L138)
DEFAULT_ROOT_AUTHORITY = "0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f8"\
                         "18057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75"\
                         "dad609"


def do_verify_attestation(options):
    head("### -> Verify UI and Signer attestations", fill="#")

    if options.attestation_certificate_file_path is None:
        raise AdminError("No attestation certificate file given")

    if options.pubkeys_file_path is None:
        raise AdminError("No public keys file given")

    root_authority = DEFAULT_ROOT_AUTHORITY
    if options.root_authority is not None:
        if not is_nonempty_hex_string(options.root_authority):
            raise AdminError("Invalid root authority")
        root_authority = options.root_authority
    info(f"Using {root_authority} as root authority")

    # Load the given public keys and compute
    # their hash (sha256sum of the uncompressed
    # public keys in lexicographical path order)
    # Also find and save the public key corresponding
    # to the expected derivation path for the UI
    # attestation
    expected_ui_public_key = None
    try:
        with open(options.pubkeys_file_path, "r") as file:
            pubkeys_map = json.loads(file.read())

        if type(pubkeys_map) != dict:
            raise ValueError(
                "Public keys file must contain an object as a top level element")

        pubkeys_hash = hashlib.sha256()
        pubkeys_output = []
        path_name_padding = max(map(len, pubkeys_map.keys()))
        for path in sorted(pubkeys_map.keys()):
            pubkey = pubkeys_map[path]
            if not is_nonempty_hex_string(pubkey):
                raise AdminError(f"Invalid public key for path {path}: {pubkey}")
            pubkey = ec.PublicKey(bytes.fromhex(pubkey), raw=True)
            pubkeys_hash.update(pubkey.serialize(compressed=False))
            pubkeys_output.append(
                f"{(path + ':').ljust(path_name_padding+1)} "
                f"{pubkey.serialize(compressed=True).hex()}"
            )
            if path == UI_DERIVATION_PATH:
                expected_ui_public_key = pubkey.serialize(compressed=True).hex()
        pubkeys_hash = pubkeys_hash.digest()

    except (ValueError, json.JSONDecodeError) as e:
        raise ValueError('Unable to read public keys from "%s": %s' %
                         (options.pubkeys_file_path, str(e)))

    if expected_ui_public_key is None:
        raise AdminError(
            f"Public key with path {UI_DERIVATION_PATH} not present in public key file")

    # Load the given attestation key certificate
    try:
        att_cert = HSMCertificate.from_jsonfile(options.attestation_certificate_file_path)
    except Exception as e:
        raise AdminError(f"While loading the attestation certificate file: {str(e)}")

    # Validate the certificate using the given root authority
    # (this should be *one of* Ledger's public keys)
    result = att_cert.validate_and_get_values(root_authority)

    # UI
    if "ui" not in result:
        raise AdminError("Certificate does not contain a UI attestation")

    ui_result = result["ui"]
    if not ui_result[0]:
        raise AdminError(f"Invalid UI attestation: error validating '{ui_result[1]}'")

    ui_message = bytes.fromhex(ui_result[1])
    ui_hash = bytes.fromhex(ui_result[2])
    mh_len = len(UI_MESSAGE_HEADER)
    if ui_message[:mh_len] != UI_MESSAGE_HEADER:
        raise AdminError(
            f"Invalid UI attestation message header: {ui_message[:mh_len].hex()}")

    # Extract UD value, UI public key and signer version from message
    ud_value = ui_message[mh_len:mh_len + UD_VALUE_LENGTH].hex()
    ui_public_key = ui_message[mh_len + UD_VALUE_LENGTH:mh_len + UD_VALUE_LENGTH +
                               PUBKEY_COMPRESSED_LENGTH].hex()
    signer_hash = ui_message[mh_len + UD_VALUE_LENGTH + PUBKEY_COMPRESSED_LENGTH:
                             mh_len + UD_VALUE_LENGTH + PUBKEY_COMPRESSED_LENGTH +
                             SIGNER_HASH_LENGTH].hex()
    signer_iteration = ui_message[mh_len + UD_VALUE_LENGTH + PUBKEY_COMPRESSED_LENGTH +
                                  SIGNER_HASH_LENGTH:
                                  mh_len + UD_VALUE_LENGTH + PUBKEY_COMPRESSED_LENGTH +
                                  SIGNER_HASH_LENGTH + SIGNER_ITERATION_LENGTH]
    signer_iteration = int.from_bytes(signer_iteration, byteorder='big', signed=False)

    head(
        [
            "UI verified with:",
            f"UD value: {ud_value}",
            f"Derived public key ({UI_DERIVATION_PATH}): {ui_public_key}",
            f"Authorized signer hash: {signer_hash}",
            f"Authorized signer iteration: {signer_iteration}",
            f"Installed UI hash: {ui_hash.hex()}",
        ],
        fill="-",
    )

    # Signer
    if "signer" not in result:
        raise AdminError("Certificate does not contain a Signer attestation")

    signer_result = result["signer"]
    if not signer_result[0]:
        raise AdminError(
            f"Invalid Signer attestation: error validating '{signer_result[1]}'")

    signer_message = bytes.fromhex(signer_result[1])
    signer_hash = bytes.fromhex(signer_result[2])
    mh_len = len(SIGNER_MESSAGE_HEADER)
    if signer_message[:mh_len] != SIGNER_MESSAGE_HEADER:
        raise AdminError(
            f"Invalid Signer attestation message header: {signer_message[:mh_len].hex()}")

    if signer_message[mh_len:] != pubkeys_hash:
        reported = signer_message[mh_len:].hex()
        raise AdminError(
            f"Signer attestation public keys hash mismatch: expected {pubkeys_hash.hex()}"
            f" but attestation reports {reported}"
        )

    head(
        ["Signer verified with public keys:"] + pubkeys_output + [
            "",
            f"Hash: {signer_message[mh_len:].hex()}",
            f"Installed Signer hash: {signer_hash.hex()}",
        ],
        fill="-",
    )

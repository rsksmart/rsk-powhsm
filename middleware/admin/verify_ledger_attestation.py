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

import re
from .misc import info, head, AdminError
from .attestation_utils import PowHsmAttestationMessage, load_pubkeys, \
                               compute_pubkeys_hash, compute_pubkeys_output
from .utils import is_nonempty_hex_string
from .certificate import HSMCertificate, HSMCertificateRoot


UI_MESSAGE_HEADER_REGEX = re.compile(b"^HSM:UI:([2345].[0-9])")
SIGNER_LEGACY_MESSAGE_HEADER_REGEX = re.compile(b"^HSM:SIGNER:([2345].[0-9])")
UI_DERIVATION_PATH = "m/44'/0'/0'/0/0"
UD_VALUE_LENGTH = 32
PUBLIC_KEYS_HASH_LENGTH = 32
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
    try:
        root_authority = HSMCertificateRoot(root_authority)
    except ValueError:
        raise AdminError("Invalid root authority")
    info(f"Using {root_authority} as root authority")

    # Load public keys, compute their hash and format them for output
    pubkeys_map = load_pubkeys(options.pubkeys_file_path)
    pubkeys_hash = compute_pubkeys_hash(pubkeys_map)
    pubkeys_output = compute_pubkeys_output(pubkeys_map)

    # Find the expected UI public key
    expected_ui_public_key = next(filter(
        lambda pair: pair[0] == UI_DERIVATION_PATH, pubkeys_map.items()), (None, None))[1]
    if expected_ui_public_key is None:
        raise AdminError(
            f"Public key with path {UI_DERIVATION_PATH} not present in public key file")
    expected_ui_public_key = expected_ui_public_key.serialize(compressed=True).hex()

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
    mh_match = UI_MESSAGE_HEADER_REGEX.match(ui_message)
    if mh_match is None:
        raise AdminError(
            f"Invalid UI attestation message header: {ui_message.hex()}")
    mh_len = len(mh_match.group(0))

    # Extract UI version, UD value, UI public key and signer version from message
    ui_version = mh_match.group(1)
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

    if ui_public_key != expected_ui_public_key:
        raise AdminError("Invalid UI attestation: unexpected public key reported. "
                         f"Expected {expected_ui_public_key} but got {ui_public_key}")

    head(
        [
            "UI verified with:",
            f"UD value: {ud_value}",
            f"Derived public key ({UI_DERIVATION_PATH}): {ui_public_key}",
            f"Authorized signer hash: {signer_hash}",
            f"Authorized signer iteration: {signer_iteration}",
            f"Installed UI hash: {ui_hash.hex()}",
            f"Installed UI version: {ui_version.decode()}",
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
    lmh_match = SIGNER_LEGACY_MESSAGE_HEADER_REGEX.match(signer_message)
    if lmh_match is None and not PowHsmAttestationMessage.is_header(signer_message):
        raise AdminError(
            f"Invalid Signer attestation message header: {signer_message.hex()}")

    if lmh_match is not None:
        # Legacy header
        powhsm_message = None
        hlen = len(lmh_match.group(0))
        signer_version = lmh_match.group(1).decode()
        offset = hlen
        reported_pubkeys_hash = signer_message[offset:]
        offset += PUBLIC_KEYS_HASH_LENGTH
        if signer_message[offset:] != b'':
            raise AdminError(f"Signer attestation message longer "
                             f"than expected: {signer_message.hex()}")
    else:
        # New header
        try:
            powhsm_message = PowHsmAttestationMessage(signer_message, name="Signer")
        except ValueError as e:
            raise AdminError(str(e))
        signer_version = powhsm_message.version
        reported_pubkeys_hash = powhsm_message.public_keys_hash

    # Validations on extracted values
    if reported_pubkeys_hash != pubkeys_hash:
        raise AdminError(
            f"Signer attestation public keys hash mismatch: expected {pubkeys_hash.hex()}"
            f" but attestation reports {reported_pubkeys_hash.hex()}"
        )

    signer_info = [
        f"Hash: {pubkeys_hash.hex()}",
        "",
        f"Installed Signer hash: {signer_hash.hex()}",
        f"Installed Signer version: {signer_version}",
    ]

    if powhsm_message is not None:
        signer_info += [
            f"Platform: {powhsm_message.platform}",
            f"UD value: {powhsm_message.ud_value.hex()}",
            f"Best block: {powhsm_message.best_block.hex()}",
            f"Last transaction signed: {powhsm_message.last_signed_tx.hex()}",
            f"Timestamp: {powhsm_message.timestamp}",
        ]

    head(
        ["Signer verified with public keys:"] + pubkeys_output + signer_info,
        fill="-",
    )

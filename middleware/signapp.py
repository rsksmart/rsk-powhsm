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

import sys
from os.path import isfile
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import ecdsa
from admin.misc import (
    get_eth_dongle,
    dispose_eth_dongle,
    info,
    AdminError
)
from comm.utils import is_hex_string_of_length, parse_hex_string
from comm.bip32 import BIP32Path
from admin.signer_authorization import SignerAuthorization, SignerVersion
from admin.ledger_utils import (
    DEFAULT_ETH_PATH,
    format_message_to_sign,
    compute_app_hash,
    pubkey_to_address,
    to_checksum_address
)
from admin.external_signature import (
    parse_external_signature,
    describe_external_signature
)


def _require_output_path(options):
    if options.output_path is None:
        raise AdminError("Must provide an output path (-o/--output)")


def _require_app_path(options):
    if options.app_path is None:
        raise AdminError("Must provide an app path with '-a/--app'")


def _compute_signer_version(options):
    _require_app_path(options)
    if options.iteration is None:
        raise AdminError("Must provide a signer iteration with '-i/--iteration'")

    info("Computing hash...")
    app_hash = compute_app_hash(options.app_path).hex()
    info("Computing signer authorization message...")
    return SignerVersion(app_hash, options.iteration)


def _load_or_create_authorization(options):
    # Is there an existing signer authorization? Read it
    if isfile(options.output_path):
        info(f"Opening signer authorization file {options.output_path}...")
        signer_authorization = SignerAuthorization.from_jsonfile(options.output_path)
        return signer_authorization, signer_authorization.signer_version

    # Otherwise, compute a new one from the given app and iteration
    signer_version = _compute_signer_version(options)
    return SignerAuthorization.for_signer_version(signer_version), signer_version


def _add_signature_and_save(options, signer_authorization, signature):
    # Add the signature to the authorization and save it to disk
    signer_authorization.add_signature(signature.hex())
    signer_authorization.save_to_jsonfile(options.output_path)
    info(f"Signer authorization saved to {options.output_path}")


def do_hash(options):
    _require_app_path(options)

    info("Computing hash...")
    app_hash = compute_app_hash(options.app_path).hex()
    info(f"Computed hash: {app_hash}")


def do_message(options):
    if options.input_path is not None:
        if options.app_path is not None or options.iteration is not None:
            raise AdminError("An input file (-f/--file) cannot be provided "
                             "together with an app path (-a/--app) or a "
                             "signer iteration (-i/--iteration)")

        info(f"Opening signer authorization file {options.input_path}...")
        signer_version = SignerAuthorization.from_jsonfile(
            options.input_path).signer_version
    else:
        if options.app_path is None or options.iteration is None:
            err_msg = "\n".join([
                "Must provide either:",
                "    - An app path (-a/--app) and iteration (-i/--iteration), or",
                "    - An authorization file (-f/--file)"
            ])
            raise AdminError(err_msg)

        signer_version = _compute_signer_version(options)

    signer_authorization = SignerAuthorization.for_signer_version(signer_version)
    if options.output_path is None:
        info(format_message_to_sign(
            signer_version.msg,
            signer_version.get_authorization_msg(),
            signer_version.get_authorization_digest()))
    else:
        signer_authorization.save_to_jsonfile(options.output_path)
        info(f"Signer authorization saved to {options.output_path}")


def do_manual_sign(options):
    _require_output_path(options)
    if options.signature is None:
        raise AdminError("Must provide a signature (-g/--signature)")

    info(f"Opening signer authorization file {options.output_path}...")
    signer_authorization = SignerAuthorization.from_jsonfile(options.output_path)
    signer_version = signer_authorization.signer_version
    info("Verifying signature...")
    signature = parse_external_signature(
        options.signature,
        signer_version.msg,
        signer_version.get_authorization_digest(),
        options.signer)
    for line in describe_external_signature(signature, options.signer is not None):
        info(line)
    info("Adding signature...")
    signer_authorization.add_signature(signature.der_signature)
    signer_authorization.save_to_jsonfile(options.output_path)
    info(f"Signer authorization saved to {options.output_path}")


def do_key(options):
    _require_output_path(options)
    if options.key is None:
        raise AdminError("Must provide a signing key with '-k/--key'")
    if not is_hex_string_of_length(options.key, 32, allow_prefix=True):
        raise AdminError(f"Invalid key '{options.key}'")

    signer_authorization, signer_version = _load_or_create_authorization(options)
    info("Signing with key...")
    sk = ecdsa.SigningKey.from_string(
        parse_hex_string(options.key),
        curve=ecdsa.SECP256k1
    )
    signature = sk.sign_digest(
        signer_version.get_authorization_digest(),
        sigencode=ecdsa.util.sigencode_der
    )
    _add_signature_and_save(options, signer_authorization, signature)


def do_eth(options):
    _require_output_path(options)
    if options.path is None:
        options.path = DEFAULT_ETH_PATH
    # Parse path
    path = BIP32Path(options.path)
    eth = None
    try:
        # Get dongle access (must have ethereum app open)
        eth = get_eth_dongle(options.verbose)
        # Retrieve public key
        info(f"Retrieving public key for path '{str(path)}'...")
        pubkey = eth.get_pubkey(path)
        info(f"Address: {to_checksum_address(pubkey_to_address(pubkey))}")
        info(f"Public key: {pubkey.hex()}")

        # If options.pubkey is True, we just want to retrieve the public key
        if options.pubkey:
            info(f"Opening public key file {options.output_path}...")
            info("Adding public key...")
            with open(options.output_path, "w") as file:
                file.write("%s\n" % pubkey.hex())
            info(f"Public key saved to {options.output_path}")
            return

        signer_authorization, signer_version = _load_or_create_authorization(options)
        # Show what is being signed, so that it can be checked on the device
        info("Signing with dongle...")
        info("Check that the device shows the following message "
             "(or one of the digests) before approval:")
        info("    Message:                                          "
             f"{signer_version.msg}")
        info("    Digest (app >= 1.22.3, if hash display enabled):  "
             f"0x{signer_version.get_authorization_digest().hex()}")
        info("    Digest (app <= 1.9.19):                           "
             f"{signer_version.get_old_eth_digest().hex().upper()}")
        signature = eth.sign(path, signer_version.msg.encode('ascii'))
        vkey = ecdsa.VerifyingKey.from_string(pubkey, curve=ecdsa.SECP256k1)
        try:
            if not vkey.verify_digest(
                signature, signer_version.get_authorization_digest(),
                sigdecode=ecdsa.util.sigdecode_der
            ):
                raise Exception()
        except Exception:
            raise AdminError(f"Bad signature from dongle! (got '{signature.hex()}')")
        _add_signature_and_save(options, signer_authorization, signature)
    except AdminError:
        raise
    except Exception as e:
        raise AdminError(f"Error signing with dongle: {e}")
    finally:
        dispose_eth_dongle(eth)


def main():
    parser = ArgumentParser(
        description="powHSM Signer Authorization Generator",
        formatter_class=RawDescriptionHelpFormatter,
        epilog="""operations:
  hash      Compute and print the hash of the signer app (-a).
  message   Print the authorization message to sign for the given signer app
            (-a) and iteration (-i), or for an existing signer authorization
            file (-f). This is the message to paste into a third-party wallet
            (e.g., MyEtherWallet, MetaMask). If an output path (-o) is given,
            a new, unsigned signer authorization file is written there instead.
  eth       Sign the authorization with a Ledger device running the Ethereum
            app and add the signature to the signer authorization file (-o),
            using the default derivation path (or the one specified with -p).
            If the file does not exist, it is created from the signer app (-a)
            and iteration (-i). With -b, only retrieve the device's public key
            and save it to -o instead.
  manual    Add an externally generated signature (-g), e.g., one obtained
            from a third-party wallet, to an existing signer authorization
            file (-o). The signature can be given as hex-encoded DER, as a
            hex-encoded 65-byte r||s||v signature (e.g., MetaMask, MyEtherWallet,
            Ledger), or as a signed message JSON (e.g., MyEtherWallet, MyCrypto,
            Etherscan), either inline or as a path to a file. The message from the
            authorization file is used in combination with the given signature to
            recover the signer address, which is shown for verification purposes.
            If an expected signer (-s) is given, the signature must have been
            produced by it.
  key       *****************NOT FOR PRODUCTION USE*****************
            Sign the authorization with a private key (-k) and add the
            signature to the signer authorization file (-o). If the file does
            not exist, it is created from the signer app (-a) and iteration (-i).""",
    )
    parser.add_argument("operation", choices=["hash", "message", "key", "eth", "manual"],
                        help="Operation to perform (see 'operations' below).")
    parser.add_argument(
        "-a",
        "--app",
        dest="app_path",
        help="App path (used to compute the app hash and authorization message).",
    )
    parser.add_argument(
        "-i",
        "--iteration",
        dest="iteration",
        help="Signer iteration (used to compute the authorization message).",
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="input_path",
        help="Existing signer authorization file from which to compute the "
        "authorization message (only for 'message' option).",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_path",
        help="Destination file for the authorization.",
    )
    parser.add_argument(
        "-k",
        "--key",
        dest="key",
        help="Private key used for signing (only for 'key' option). "
        "Must be a 32-byte hex-encoded string.",
    )
    parser.add_argument(
        "-p",
        "--path",
        dest="path",
        help="Path used for signing (only for 'eth' option). "
        f"Default \"{DEFAULT_ETH_PATH}\""
    )
    parser.add_argument(
        "-g",
        "--signature",
        dest="signature",
        help="Signature to add to the signer authorization "
        "(only for 'manual' option). "
        "Accepts DER, 65-byte r||s||v (hex-encoded) or signed message JSON "
        "(inline or a path to a file).",
    )
    parser.add_argument(
        "-s",
        "--signer",
        dest="signer",
        help="Expected signer of the signature (only for 'manual' option). "
        "Either an address or a public key, hex-encoded. If given, the "
        "signature must have been produced by this signer.",
    )
    parser.add_argument(
        "-b",
        "--pubkey",
        dest="pubkey",
        action="store_true",
        help="Retrieve public key (only for 'eth' option)."
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_const",
        help="Enable verbose mode",
        default=False,
        const=True,
    )
    options = parser.parse_args()

    try:
        if options.input_path is not None and options.operation != "message":
            raise AdminError("An input file (-f/--file) can only be "
                             "provided for the 'message' operation")

        if options.operation == "hash":
            do_hash(options)
        elif options.operation == "message":
            do_message(options)
        elif options.operation == "key":
            do_key(options)
        elif options.operation == "eth":
            do_eth(options)
        elif options.operation == "manual":
            do_manual_sign(options)
        else:
            raise AdminError(f"Invalid operation: {options.operation}")
        sys.exit(0)
    except Exception as e:
        info(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()

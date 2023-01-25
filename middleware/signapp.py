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
from argparse import ArgumentParser
import logging
import ecdsa
from admin.misc import (
    get_eth_dongle,
    dispose_eth_dongle,
    info,
    AdminError
)
from comm.utils import is_hex_string_of_length
from comm.bip32 import BIP32Path
from admin.signer_authorization import SignerAuthorization, SignerVersion
from admin.ledger_utils import eth_message_to_printable, compute_app_hash

# Default signing path
DEFAULT_ETH_PATH = "m/44'/60'/0'/0/0"

# Legacy dongle constants
COMMAND_SIGN = 0x02
COMMAND_PUBKEY = 0x04
OP_SIGN_MSG_PATH = bytes.fromhex("70")
OP_SIGN_MSG_HASH = bytes.fromhex("800000")


def main():
    logging.disable(logging.CRITICAL)

    parser = ArgumentParser(description="powHSM Signer Authorization Generator")
    parser.add_argument("operation", choices=["hash", "message", "key", "eth", "manual"])
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
        "-o",
        "--output",
        dest="output_path",
        help="Destination file for the authorization.",
    )
    parser.add_argument(
        "-k",
        "--key",
        dest="key",
        help="Private key used for signing (only for 'key' option)."
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
        help="Signature to add to signer authorization (only for 'manual' option)."
        "Must be a hex-encoded, der-encoded SECP256k1 signature.",
    )
    parser.add_argument(
        "-b",
        "--pubkey",
        dest="pubkey",
        action="store_true",
        help="Retrieve pubkic key (only for 'eth' option)."
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
        eth = None

        if options.path is None:
            options.path = DEFAULT_ETH_PATH

        # Require an output path for certain operations
        if options.operation not in ["hash", "message"] and \
           options.output_path is None:
            raise AdminError("Must provide an output path (-o/--output)")

        # Manual addition of signatures is radically different from the rest
        if options.operation == "manual":
            if options.signature is None:
                raise AdminError("Must provide a signature (-g/--signature)")
            info(f"Opening signer authorization file {options.output_path}...")
            signer_authorization = SignerAuthorization.from_jsonfile(options.output_path)
            info("Adding signature...")
            signer_authorization.add_signature(options.signature)
            signer_authorization.save_to_jsonfile(options.output_path)
            info(f"Signer authorization saved to {options.output_path}")
            sys.exit(0)

        if options.operation == "key":
            # Validate key
            if options.key is None:
                raise AdminError("Must provide a signing key with '-k/--key'")
            if not is_hex_string_of_length(options.key, 32, allow_prefix=True):
                raise AdminError(f"Invalid key '{options.key}'")
        elif options.operation == "eth":
            # Parse path
            path = BIP32Path(options.path)

            # Get dongle access (must have ethereum app open)
            eth = get_eth_dongle(options.verbose)

            # Retrieve public key
            info(f"Retrieving public key for path '{str(path)}'...")
            pubkey = eth.get_pubkey(path)
            info(f"Public key: {pubkey.hex()}")

            # If options.pubkey is True, we just want to retrieve the public key
            if options.pubkey:
                info(f"Opening public key file {options.output_path}...")
                info("Adding public key...")
                with open(options.output_path, "w") as file:
                    file.write("%s\n" % pubkey.hex())
                info(f"Public key saved to {options.output_path}")
                sys.exit(0)

        # Is there an existing signer authorization? Read it
        signer_authorization = None
        if options.operation not in ["message", "hash"] and \
           options.output_path is not None and \
           isfile(options.output_path):
            info(f"Opening signer authorization file {options.output_path}...")
            signer_authorization = SignerAuthorization.from_jsonfile(options.output_path)
            signer_version = signer_authorization.signer_version
        else:
            if options.app_path is None:
                raise AdminError("Must provide an app path with '-a/--app'")

            if options.operation != "hash" and options.iteration is None:
                raise AdminError("Must provide a signer iteration with '-i/--iteration'")

            info("Computing hash...")
            app_hash = compute_app_hash(options.app_path).hex()
            if options.operation == "hash":
                info(f"Computed hash: {app_hash}")
                sys.exit(0)

            info("Computing signer authorization message...")
            signer_version = SignerVersion(app_hash, options.iteration)
            signer_authorization = SignerAuthorization.for_signer_version(signer_version)

        if options.operation == "message":
            signer_authorization_msg = signer_version.get_authorization_msg()
            if options.output_path is None:
                info(eth_message_to_printable(signer_authorization_msg))
            else:
                signer_authorization.save_to_jsonfile(options.output_path)
                info(f"Signer authorization saved to {options.output_path}")
            sys.exit(0)

        # Sign the app hash
        if options.operation == "key":
            info("Signing with key...")
            sk = ecdsa.SigningKey.from_string(bytes.fromhex(options.key),
                                              curve=ecdsa.SECP256k1)
            signature = sk.sign_digest(signer_version.get_authorization_digest(),
                                       sigencode=ecdsa.util.sigencode_der)
        elif options.operation == "eth":
            info("Signing with dongle...")
            signature = eth.sign(path, signer_version.msg.encode('ascii'))
            vkey = ecdsa.VerifyingKey.from_string(pubkey, curve=ecdsa.SECP256k1)

            try:
                if not vkey.verify_digest(
                        signature, signer_version.get_authorization_digest(),
                        sigdecode=ecdsa.util.sigdecode_der):
                    raise Exception()
            except Exception:
                raise AdminError(f"Bad signature from dongle! (got '{signature.hex()}')")
        else:
            raise AdminError("Unexpected state reached! "
                             "Expected operation to be either 'eth' or 'key', "
                             f"but was {options.operation}")

        # Add the signature to the authorization and save it to disk
        signer_authorization.add_signature(signature.hex())
        signer_authorization.save_to_jsonfile(options.output_path)
        info(f"Signer authorization saved to {options.output_path}")
        sys.exit(0)
    except Exception as e:
        info(str(e))
        sys.exit(1)
    finally:
        dispose_eth_dongle(eth)


if __name__ == "__main__":
    main()

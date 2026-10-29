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
from comm.utils import is_hex_string_of_length
from comm.bip32 import BIP32Path
from admin.sgx_migration_authorization import SGXMigrationAuthorization, SGXMigrationSpec
from admin.ledger_utils import (
    DEFAULT_ETH_PATH,
    format_message_to_sign,
    pubkey_to_address,
    to_checksum_address
)
from admin.external_signature import (
    parse_external_signature,
    describe_external_signature
)


def _require_output_path(options, require_existing=False):
    if options.output_path is None:
        raise AdminError("Must provide an output path (-o/--output)")
    if require_existing and not isfile(options.output_path):
        raise AdminError(f"Invalid output path: {options.output_path}")


def do_message(options):
    if options.input_path is not None:
        if options.exporter_hash is not None or options.importer_hash is not None:
            raise AdminError("An input file (-f/--file) cannot be provided "
                             "together with an exporter hash (-e/--exporter) or an "
                             "importer hash (-i/--importer)")

        info(f"Opening SGX migration authorization file {options.input_path}...")
        migration_spec = SGXMigrationAuthorization.from_jsonfile(
            options.input_path).migration_spec
    else:
        if options.exporter_hash is None or options.importer_hash is None:
            err_msg = "\n".join([
                "Must provide either:",
                "    - An exporter hash (-e/--exporter) and "
                "importer hash (-i/--importer), or",
                "    - An authorization file (-f/--file)"
            ])
            raise AdminError(err_msg)

        info("Computing the SGX migration authorization message...")
        migration_spec = SGXMigrationSpec({
            "exporter": options.exporter_hash,
            "importer": options.importer_hash
        })

    sgx_authorization = SGXMigrationAuthorization.for_spec(migration_spec)
    if options.output_path is None:
        info(format_message_to_sign(
            migration_spec.msg,
            migration_spec.get_authorization_msg(),
            migration_spec.get_authorization_digest()))
    else:
        sgx_authorization.save_to_jsonfile(options.output_path)
        info(f"SGX migration authorization saved to {options.output_path}")


def do_manual_sign(options):
    _require_output_path(options, require_existing=True)
    if options.signature is None:
        raise AdminError("Must provide a signature (-g/--signature)")

    info(f"Opening SGX migration authorization file {options.output_path}...")
    sgx_authorization = SGXMigrationAuthorization.from_jsonfile(options.output_path)
    migration_spec = sgx_authorization.migration_spec
    info("Verifying signature...")
    signature = parse_external_signature(
        options.signature,
        migration_spec.msg,
        migration_spec.get_authorization_digest(),
        options.signer)
    for line in describe_external_signature(signature, options.signer is not None):
        info(line)
    info("Adding signature...")
    sgx_authorization.add_signature(signature.der_signature)
    sgx_authorization.save_to_jsonfile(options.output_path)
    info(f"SGX migration authorization saved to {options.output_path}")


def do_key(options):
    _require_output_path(options, require_existing=True)
    if options.key is None:
        raise AdminError("Must provide a signing key (-k/--key)")
    if not is_hex_string_of_length(options.key, 32, allow_prefix=True):
        raise AdminError(f"Invalid key '{options.key}'")

    info(f"Opening SGX migration authorization file {options.output_path}...")
    sgx_authorization = SGXMigrationAuthorization.from_jsonfile(options.output_path)
    migration_spec = sgx_authorization.migration_spec
    info("Signing with key...")
    sk = ecdsa.SigningKey.from_string(
        bytes.fromhex(options.key),
        curve=ecdsa.SECP256k1
    )
    signature = sk.sign_digest(
        migration_spec.get_authorization_digest(),
        sigencode=ecdsa.util.sigencode_der_canonize
    )
    # Add the signature to the authorization and save it to disk
    sgx_authorization.add_signature(signature.hex())
    sgx_authorization.save_to_jsonfile(options.output_path)
    info(f"SGX migration authorization saved to {options.output_path}")


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

        # Is there an existing migration authorization? Read it
        sgx_authorization = None
        _require_output_path(options, require_existing=True)

        info(f"Opening SGX migration authorization file {options.output_path}...")
        sgx_authorization = SGXMigrationAuthorization.from_jsonfile(options.output_path)
        migration_spec = sgx_authorization.migration_spec
        # Show what is being signed, so that it can be checked on the device
        info("Signing with dongle...")
        info("Check that the device shows the following message (or one of the digests):")
        info("    Message:\n")
        info(f"    {migration_spec.msg}\n")
        info("    Digest (app >= 1.22.3, if hash display enabled):  "
             f"0x{migration_spec.get_authorization_digest().hex()}")
        info("    Digest (app <= 1.9.19):                           "
             f"{migration_spec.get_old_eth_digest().hex().upper()}")
        signature = eth.sign(path, migration_spec.msg.encode('ascii'))
        vkey = ecdsa.VerifyingKey.from_string(pubkey, curve=ecdsa.SECP256k1)
        try:
            if not vkey.verify_digest(
                signature, migration_spec.get_authorization_digest(),
                sigdecode=ecdsa.util.sigdecode_der
            ):
                raise Exception()
        except Exception:
            raise AdminError(f"Bad signature from dongle! (got '{signature.hex()}')")
        # Add the signature to the authorization and save it to disk
        sgx_authorization.add_signature(signature.hex())
        sgx_authorization.save_to_jsonfile(options.output_path)
        info(f"SGX migration authorization saved to {options.output_path}")
    except AdminError:
        raise
    except Exception as e:
        raise AdminError(f"Error signing with dongle: {e}")
    finally:
        dispose_eth_dongle(eth)


def main():
    parser = ArgumentParser(
        description="powHSM SGX migration authorization generation and signing tool",
        formatter_class=RawDescriptionHelpFormatter,
        epilog="""operations:
  message   Print the authorization message to sign for the given exporter (-e)
            and importer (-i) enclave hashes, or for an existing SGX migration
            authorization file (-f). This is the message to paste into a
            third-party wallet (e.g., MyEtherWallet, MetaMask). If an output
            path (-o) is given, a new, unsigned SGX migration authorization
            file is written there instead.
  eth       Sign the authorization with a Ledger device running the Ethereum
            app and add the signature to an existing SGX migration
            authorization file (-o), using the default derivation path (or the
            one specified with -p). With -b, only retrieve the device's public
            key and save it to -o instead.
  manual    Add an externally generated signature (-g), e.g., one obtained
            from a third-party wallet, to an existing SGX migration
            authorization file (-o). The signature can be given as hex-encoded
            DER, as a hex-encoded 65-byte r||s||v signature (e.g., MetaMask,
            MyEtherWallet, Ledger), or as a signed message JSON (e.g.,
            MyEtherWallet, MyCrypto, Etherscan), either inline or as a path to
            a file. The message from the authorization file is used in combination
            with the given signature to recover the signer address, which is shown
            for verification purposes. If an expected signer (-s) is given, the
            signature must have been produced by it.
  key       *****************NOT FOR PRODUCTION USE*****************
            Sign the authorization with a private key (-k) and add the
            signature to an existing SGX migration authorization file (-o).""",
    )
    parser.add_argument("operation", choices=["message", "key", "eth", "manual"],
                        help="Operation to perform (see 'operations' below).")
    parser.add_argument(
        "-o",
        "--output",
        dest="output_path",
        help="Destination file for SGX migration authorization.",
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
        help="Signature to add to the SGX migration authorization "
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
        "-e",
        "--exporter",
        dest="exporter_hash",
        help="The hash of the exporter enclave (only for 'message' option)."
    )
    parser.add_argument(
        "-i",
        "--importer",
        dest="importer_hash",
        help="The hash of the importer enclave (only for 'message' option)."
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="input_path",
        help="Existing SGX migration authorization file from which to compute the "
        "authorization message (only for 'message' option). "
        "Mutually exclusive with '-e/--exporter' and '-i/--importer'.",
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

        if options.operation == "message":
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

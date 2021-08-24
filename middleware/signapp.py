import sys
from argparse import ArgumentParser
import logging
from hashlib import sha256
import ecdsa
from ledgerblue.hexParser import IntelHexParser
from admin.misc import get_hsm, dispose_hsm, info, AdminError
from comm.utils import is_hex_string_of_length
from comm.bip32 import BIP32Path

# Default signing path
DEFAULT_PATH="m/44'/137'/0'/31/32"

# Legacy dongle constants
COMMAND_SIGN=0x02
COMMAND_PUBKEY=0x04
OP_SIGN_MSG_PATH=bytes.fromhex("70")
OP_SIGN_MSG_HASH=bytes.fromhex("800000")

def compute_app_hash(path):
    # Taken from https://github.com/LedgerHQ/blue-loader-python/blob/0.1.31/ledgerblue/hashApp.py
    parser = IntelHexParser(options.app_path)
    digest = sha256()
    for a in parser.getAreas():
        digest.update(a.data)
    return digest.digest()

if __name__ == '__main__':
    logging.disable(logging.CRITICAL)

    parser = ArgumentParser(description="HSM 2 App Signer")
    parser.add_argument('operation', choices=['key', 'ledger', 'hash'])
    parser.add_argument("-a","--app", dest="app_path", \
                        help=f"Path to the app to be signed.", required=True)
    parser.add_argument("-o","--output", dest="output_path", \
                        help=f"Destination file for the signature (defaults to the app path with a '.sig' extension).")
    parser.add_argument("-p","--path", dest="path", \
                        help=f"Path used for signing (only for 'ledger' option). Default \"{DEFAULT_PATH}\"", \
                        default=DEFAULT_PATH)
    parser.add_argument("-k","--key", dest="key", \
                        help=f"Private key used for signing (only for 'key' option). Must be a 32-byte hex-encoded string.")
    parser.add_argument("-v","--verbose", dest="verbose", action="store_const", \
                        help="Enable verbose mode", default=False, const=True)
    options = parser.parse_args()

    try:
        hsm = None

        if options.operation == 'key':
            # Validate key
            if options.key is None:
                raise AdminError("Must provide a signing key with '-k/--key'")
            if not is_hex_string_of_length(options.key, 32, allow_prefix=True):
                raise AdminError(f"Invalid key '{options.key}'")
        elif options.operation == 'ledger':
            # Parse path
            path = BIP32Path(options.path)

            # Get dongle access (must be opened in the signer)
            hsm = get_hsm(options.verbose)

        info("Computing app hash...")
        app_hash = compute_app_hash(options.app_path)
        info(f"App hash: {app_hash.hex()}")

        # If we only need to compute the hash, then that's it
        if options.operation == 'hash':
            sys.exit(0)

        # Sign the app hash
        if options.operation == 'key':
            info("Signing with key...")
            sk = ecdsa.SigningKey.from_string(bytes.fromhex(options.key), curve=ecdsa.SECP256k1)
            signature = sk.sign_digest(app_hash, sigencode=ecdsa.util.sigencode_der)
        else:
            # We use private dongle methods to do this, since we don't want
            # to implement legacy signing (i.e., 1.0/1.1) in the HSM2Dongle class
            # Essentially we send 2 messages. The first one with the path and the
            # second with the hash to sign. On the second, we obtain the der-encoded
            # signature
            info(f"Retrieving public key for path '{str(path)}'...")
            pubkey = hsm._send_command(COMMAND_PUBKEY, path.to_binary())
            info(f"Public key: {pubkey.hex()}")

            info("Signing with dongle...")
            hsm._send_command(COMMAND_SIGN, OP_SIGN_MSG_PATH + path.to_binary())
            signature = hsm._send_command(COMMAND_SIGN, OP_SIGN_MSG_HASH + app_hash)
            info("Verifying signature...")
            vkey = ecdsa.VerifyingKey.from_string(pubkey, curve=ecdsa.SECP256k1)
            try:
                if not vkey.verify_digest(signature, app_hash, sigdecode=ecdsa.util.sigdecode_der):
                    raise Exception()
            except Exception as e:
                raise AdminError(f"Bad signature from dongle! (got '{signature.hex}')")

        # Save the signature to disk
        output_path = options.output_path if options.output_path is not None else f"{options.app_path}.sig"
        with open(output_path, "wb") as file:
            file.write(signature.hex().encode())
            info(f"Signature saved to {output_path}")

        sys.exit(0)
    except Exception as e:
        info(str(e))
        sys.exit(1)
    finally:
        dispose_hsm(hsm)

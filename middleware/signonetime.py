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
from argparse import ArgumentParser
import logging
import ecdsa
from admin.misc import info
from admin.ledger_utils import compute_app_hash


def main():
    logging.disable(logging.CRITICAL)

    parser = ArgumentParser(description="powHSM OneTime Key App Signer")
    parser.add_argument(
        "-a",
        "--app",
        dest="app_path",
        help="Path to the app(s) to be signed (comma-separated).",
        required=True,
    )
    parser.add_argument(
        "-p",
        "--publickey",
        dest="publickey_path",
        help="Destination file for the public key.",
        required=True,
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
        # Generate the signing key
        sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

        # Save the public key to disk
        with open(options.publickey_path.strip(), "wb") as file:
            file.write(sk.get_verifying_key().to_string("uncompressed").hex().encode())
            info(f"Public key saved to {options.publickey_path}")

        # Sign apps
        for app_path in options.app_path.split(","):
            app_path = app_path.strip()
            info(f"Computing hash for '{app_path}'...")
            app_hash = compute_app_hash(app_path)
            info(f"App hash: {app_hash.hex()}")

            # Sign the app hash with a random key
            info("Signing with key...")
            signature = sk.sign_digest(app_hash, sigencode=ecdsa.util.sigencode_der)

            # Save the signature to disk
            signature_path = f"{app_path}.sig"
            with open(signature_path, "wb") as file:
                file.write(signature.hex().encode())
                info(f"Signature saved to {signature_path}")

        sys.exit(0)
    except Exception as e:
        info(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()

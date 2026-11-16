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

from ledgerblue.hexParser import IntelHexParser
from hashlib import sha256
import ecdsa
from .utils import keccak_256


# Default signing path for Ethereum accounts
DEFAULT_ETH_PATH = "m/44'/60'/0'/0/0"


def compute_app_hash(path):
    # Taken from
    # https://github.com/LedgerHQ/blue-loader-python/blob/0.1.31/ledgerblue/hashApp.py
    parser = IntelHexParser(path)
    digest = sha256()
    for a in parser.getAreas():
        digest.update(a.data)
    return digest.digest()


def encode_eth_message(msg):
    return f"\x19Ethereum Signed Message:\n{str(len(msg))}{msg}".encode("ascii")


def eth_message_to_printable(msg):
    return repr(msg.decode("ascii"))[1:-1]


def pubkey_to_address(pubkey):
    # Ethereum address for the given (compressed or uncompressed) public key
    raw_pubkey = ecdsa.VerifyingKey.from_string(
        pubkey, curve=ecdsa.SECP256k1).to_string("raw")
    return "0x" + keccak_256(raw_pubkey)[-20:].hex()


def to_checksum_address(address):
    # EIP-55 mixed-case checksum encoding
    address = address.lower().replace("0x", "")
    address_hash = keccak_256(address.encode("ascii")).hex()
    return "0x" + "".join(c.upper() if int(address_hash[i], 16) >= 8 else c
                          for i, c in enumerate(address))


def format_message_to_sign(msg, authorization_msg, authorization_digest):
    INDENT = " " * 4
    return "\n".join([
        "",
        "Message to sign: copy and paste exactly, as a single line, into your",
        "wallet's 'sign message' feature - e.g., MyEtherWallet, MetaMask:",
        "",
        f"{INDENT}{msg}",
        "",
        "Your wallet automatically adds the standard Ethereum signed message prefix.",
        "Do NOT include it yourself.",
        "",
        "",
        "For reference only (do NOT paste these into your wallet):",
        "",
        f"{INDENT}Full message: {eth_message_to_printable(authorization_msg)}",
        f"{INDENT}Digest (keccak256):        0x{authorization_digest.hex()}",
        "",
    ])

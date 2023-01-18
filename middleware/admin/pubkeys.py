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

import os
import json
import ecdsa
from ledger.hsm2dongle import HSM2Dongle
from .misc import info, get_hsm, dispose_hsm, AdminError, wait_for_reconnection
from .unlock import do_unlock
from comm.bip32 import BIP32Path

SIGNER_WAIT_TIME = 1  # second

PATHS = {
    "btc": BIP32Path("m/44'/0'/0'/0/0"),
    "rsk": BIP32Path("m/44'/137'/0'/0/0"),
    "mst": BIP32Path("m/44'/137'/1'/0/0"),
    "tbtc": BIP32Path("m/44'/1'/0'/0/0"),
    "trsk": BIP32Path("m/44'/1'/1'/0/0"),
    "tmst": BIP32Path("m/44'/1'/2'/0/0"),
}


def do_get_pubkeys(options):
    info("### -> Get public keys")
    hsm = None

    # Attempt to unlock and open the signing app
    if not options.no_unlock:
        try:
            do_unlock(options, label=False)
        except Exception as e:
            raise AdminError(f"Failed to unlock device: {str(e)}")

    # Wait for the signer
    wait_for_reconnection()

    # Connection
    hsm = get_hsm(options.verbose)

    # Mode check
    info("Finding mode... ", options.verbose)
    mode = hsm.get_current_mode()
    info(f"Mode: {mode.name.capitalize()}")

    # Modes for which we can't get the public keys
    if mode in [HSM2Dongle.MODE.UNKNOWN, HSM2Dongle.MODE.BOOTLOADER]:
        raise AdminError(
            "Device not in app mode. Disconnect and re-connect the ledger and try again")

    # Gather public keys
    pubkeys = {}
    for path_name in PATHS:
        info(f"Getting public key for path '{path_name}'... ", options.verbose)
        path = PATHS[path_name]
        pubkeys[path_name] = hsm.get_public_key(path)
        info("OK")

    try:
        output_file = None
        save_to_json = False
        if options.output_file_path is not None:
            output_file = open(options.output_file_path, "w")

            def do_output(s):
                return output_file.write(f"{s}\n")

            save_to_json = True
            json_dict = {}
        else:

            def do_output(s):
                return info(s)

        do_output("*" * 80)
        do_output("Name \t\t\t Path \t\t\t\t Pubkey")
        do_output("==== \t\t\t ==== \t\t\t\t ======")
        path_name_padding = max(map(len, PATHS))
        for path_name in PATHS:
            path = PATHS[path_name]
            # Compress public key
            pk = ecdsa.VerifyingKey.from_string(bytes.fromhex(pubkeys[path_name]),
                                                curve=ecdsa.SECP256k1)
            pubkey = pk.to_string("compressed").hex()
            do_output(f"{path_name.ljust(path_name_padding)} \t\t {path} \t\t {pubkey}")
            if save_to_json:
                json_dict[str(path)] = pk.to_string("uncompressed").hex()
        do_output("*" * 80)

        if output_file is not None:
            output_file.close()
            info(f"Public keys saved to {options.output_file_path}")

        if save_to_json:
            json_output_file_path = (os.path.splitext(options.output_file_path)[0] +
                                     ".json")
            output_file = open(json_output_file_path, "w")
            output_file.write("%s\n" % json.dumps(json_dict, indent=2))
            output_file.close()
            info(f"JSON-formatted public keys saved to {json_output_file_path}")
    except Exception as e:
        raise AdminError(f"Error writing output: {str(e)}")

    dispose_hsm(hsm)

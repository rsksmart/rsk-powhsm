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
import time
from getpass import getpass
from ledger.hsm2dongle import HSM2Dongle
from sgx.hsm2dongle import HSM2DongleSGX
from ledger.pin import BasePin
from .dongle_admin import DongleAdmin
from .dongle_eth import DongleEth
from comm.platform import Platform
from .utils import is_hex_string_of_length, normalize_hex_string
from .rsk_client import RskClient, RskClientError


PIN_ERROR_MESSAGE = ("Invalid pin given. It must be exactly 8 alphanumeric "
                     "characters with at least one alphabetic character.")
PIN_ERROR_MESSAGE_ANYCHARS = (
    "Invalid pin given. It must be composed only of alphanumeric characters.")

SIGNER_WAIT_TIME = 3  # seconds

ATTESTATION_UD_VALUE_LENGTH = 32  # bytes
DEFAULT_ATT_UD_SOURCE = "https://public-node.rsk.co"


class AdminError(RuntimeError):
    pass


def info(s, nl=True):
    newline = "\n" if nl else ""
    sys.stdout.write(f"{s}{newline}")
    sys.stdout.flush()


def head(ss, fill="*", nl=True):
    if type(ss) == str:
        ss = [ss]

    maxl = max(map(len, ss))
    info(fill*maxl)
    for s in ss:
        info(s)
    info(fill*maxl, nl=nl)


def bls(b):
    return "Yes" if b else "No"


def not_implemented(options):
    info(f"Operation {options.operation} not yet implemented")
    return 1


def get_hsm(debug):
    info("Connecting to HSM... ", False)
    if Platform.is_ledger():
        hsm = HSM2Dongle(debug)
    elif Platform.is_sgx():
        hsm = HSM2DongleSGX(Platform.options("sgx_host"),
                            Platform.options("sgx_port"), debug)
    else:
        raise AdminError("Platform not set or unknown platform")
    hsm.connect()
    info("OK")
    return hsm


def get_admin_hsm(debug):
    info("Connecting to HSM... ", False)
    hsm = DongleAdmin(debug)
    hsm.connect()
    info("OK")
    return hsm


def dispose_hsm(hsm):
    if hsm is None:
        return

    info("Disconnecting from HSM... ", False)
    hsm.disconnect()
    info("OK")


def get_eth_dongle(debug):
    info("Connecting to Ethereum App... ", False)
    eth = DongleEth(debug)
    eth.connect()
    info("OK")
    return eth


def dispose_eth_dongle(eth):
    if eth is None:
        return

    info("Disconnecting from Ethereum App... ", False)
    eth.disconnect()
    info("OK")


def ask_for_pin(any_pin):
    pin = None
    while pin is None or not BasePin.is_valid(pin, any_pin):
        pin = getpass("> ").encode()
        if not BasePin.is_valid(pin, any_pin):
            info(PIN_ERROR_MESSAGE if not any_pin else PIN_ERROR_MESSAGE_ANYCHARS)
    return pin


def wait_for_reconnection():
    time.sleep(SIGNER_WAIT_TIME)


def get_ud_value_for_attestation(user_provided_ud_source):
    if is_hex_string_of_length(user_provided_ud_source,
                               ATTESTATION_UD_VALUE_LENGTH,
                               allow_prefix=True):
        # Final value provided by user
        ud_value = normalize_hex_string(user_provided_ud_source)
    else:
        # Final value taken from a specific Rootstock node
        try:
            rsk_client = RskClient(user_provided_ud_source)
            best_block = rsk_client.get_block_by_number(
                rsk_client.get_best_block_number())
            ud_value = best_block["hash"][2:]
            if not is_hex_string_of_length(ud_value, ATTESTATION_UD_VALUE_LENGTH):
                raise ValueError("Got invalid best block from "
                                 f"Rootstock server: {ud_value}")
        except RskClientError as e:
            raise AdminError(f"While fetching the best Rootstock block hash: {str(e)}")

    return ud_value

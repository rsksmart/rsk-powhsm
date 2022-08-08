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
from ledger.pin import BasePin
from .dongle_admin import DongleAdmin
from .dongle_eth import DongleEth

PIN_ERROR_MESSAGE = ("Invalid pin given. It must be exactly 8 alphanumeric "
                     "characters with at least one alphabetic character.")
PIN_ERROR_MESSAGE_ANYCHARS = (
    "Invalid pin given. It must be composed only of alphanumeric characters.")

SIGNER_WAIT_TIME = 3  # seconds


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
    hsm = HSM2Dongle(debug)
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

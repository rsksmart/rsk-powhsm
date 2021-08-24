import sys
from getpass import getpass
from ledger.hsm2dongle import HSM2Dongle
from ledger.pin import BasePin

PIN_ERROR_MESSAGE = "Invalid pin given. It must be exactly 8 alphanumeric characters with at least one alphabetic character."
PIN_ERROR_MESSAGE_ANYCHARS = "Invalid pin given. It must be exactly 8 alphanumeric characters."

class AdminError(RuntimeError):
    pass

def info(s, nl=True):
    newline = "\n" if nl else ""
    sys.stdout.write(f"{s}{newline}")

def bls(b):
    return "Yes" if b else "No"

def not_implemented(options):
    info(f"Operation {options.operation} not yet implemented")
    return(1)

def get_hsm(debug):
    info("Connecting to HSM... ", False)
    hsm = HSM2Dongle(debug)
    hsm.connect()
    info("OK")
    return hsm

def dispose_hsm(hsm):
    if hsm is None:
        return

    info("Disconnecting from HSM... ", False)
    hsm.disconnect()
    info("OK")

def ask_for_pin(require_alpha):
    pin = None
    while pin is None or not BasePin.is_valid(pin, require_alpha=require_alpha):
        pin = getpass("> ").encode()
        if not BasePin.is_valid(pin, require_alpha=require_alpha):
            info(PIN_ERROR_MESSAGE if require_alpha else PIN_ERROR_MESSAGE_ANYCHARS)
    return pin

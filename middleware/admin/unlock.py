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

from ledger.hsm2dongle import HSM2Dongle
from ledger.pin import BasePin
from .misc import (
    info,
    head,
    bls,
    get_hsm,
    dispose_hsm,
    PIN_ERROR_MESSAGE_ANYCHARS,
    AdminError,
    ask_for_pin,
)


def do_unlock(options, exit=True, no_exec=False, label=True):
    if label:
        head("### -> Unlock", fill="#")

    hsm = None

    # Validate pin (if given)
    pin = None
    if options.pin is not None:
        if not BasePin.is_valid(options.pin.encode(), options.any_pin):
            raise AdminError(PIN_ERROR_MESSAGE_ANYCHARS)
        pin = options.pin.encode()

    # Connection
    hsm = get_hsm(options.verbose)

    # Mode check
    info("Finding mode... ", options.verbose)
    mode = hsm.get_current_mode()
    info(f"Mode: {mode.name.capitalize()}")

    # Onboard check
    if mode in [HSM2Dongle.MODE.BOOTLOADER, HSM2Dongle.MODE.SIGNER]:
        info("Is device onboarded? ... ", options.verbose)
        is_onboarded = hsm.is_onboarded()
        info(f"Onboarded: {bls(is_onboarded)}")
        if not is_onboarded:
            raise AdminError("Device not onboarded")

    # Modes for which we can't unlock
    if mode == HSM2Dongle.MODE.UNKNOWN:
        raise AdminError("Device mode unknown. Already unlocked? Otherwise disconnect "
                         "and re-connect the ledger and try again")
    if mode == HSM2Dongle.MODE.SIGNER or mode == HSM2Dongle.MODE.UI_HEARTBEAT:
        raise AdminError("Device already unlocked")

    # Echo check
    info("Sending echo... ", options.verbose)
    if not hsm.echo():
        raise AdminError("Echo error")
    info("Echo OK")

    # Ask the user for a pin if one not given
    if pin is None:
        info("Please enter the pin.")
        pin = ask_for_pin(any_pin=True)

    # Unlock device with PIN
    info("Unlocking with PIN... ", options.verbose)
    if not hsm.unlock(pin):
        raise AdminError("Unable to unlock: PIN mismatch")
    info("PIN accepted")

    # Exit the bootloader, go into menu (or, if app is properly signed, into
    # the app)
    if exit:
        autoexec = not (options.no_exec or no_exec)
        info(f"Exiting to menu/app (execute signer: {bls(autoexec)})... ",
             options.verbose)
        try:
            hsm.exit_menu(autoexec=autoexec)
        except Exception:
            # exit_menu() always throws due to USB disconnection. we don't care
            pass
        info("Exit OK")

    dispose_hsm(hsm)

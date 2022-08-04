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
    get_hsm,
    dispose_hsm,
    ask_for_pin,
    PIN_ERROR_MESSAGE,
    PIN_ERROR_MESSAGE_ANYCHARS,
    AdminError,
)
from .unlock import do_unlock


def do_changepin(options):
    info("### -> Change pin")
    hsm = None

    # Validate new pin (if given)
    new_pin = None
    if options.new_pin is not None:
        if not BasePin.is_valid(options.new_pin.encode(),
                                any_pin=options.any_pin):
            raise AdminError(
                PIN_ERROR_MESSAGE if not options.any_pin else PIN_ERROR_MESSAGE_ANYCHARS)
        new_pin = options.new_pin.encode()

    # Attempt to unlock without exiting to menu/app
    if not options.no_unlock:
        try:
            do_unlock(options, exit=False, label=False)
        except Exception as e:
            raise AdminError(f"Failed to unlock device: {str(e)}")

    # Connection
    hsm = get_hsm(options.verbose)

    # Mode check
    info("Finding mode... ", options.verbose)
    mode = hsm.get_current_mode()
    info(f"Mode: {mode.name.capitalize()}")

    # We can only change the pin while in bootloader mode
    if mode != HSM2Dongle.MODE.BOOTLOADER:
        raise AdminError("Device not in bootloader mode. Disconnect and re-connect the "
                         "ledger and try again")

    # Ask the user for a new pin if one has not been given
    if new_pin is None:
        info("Please select a pin for the device.")
        new_pin = ask_for_pin(any_pin=options.any_pin)

    # Attempt to change the pin
    info("Changing pin... ", options.verbose)
    if not hsm.new_pin(new_pin):
        raise AdminError("Failed to change pin")
    info("Pin changed. Please disconnect and re-connect the ledger.")

    dispose_hsm(hsm)

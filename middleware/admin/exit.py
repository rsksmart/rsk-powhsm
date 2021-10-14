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
from .misc import info, bls, get_hsm, dispose_hsm, AdminError


def do_exit(options, label=True):
    if label:
        info("### -> Exit")
    # Connection
    hsm = None
    hsm = get_hsm(options.verbose)

    # Mode check
    info("Finding mode... ", options.verbose)
    mode = hsm.get_current_mode()
    info(f"Mode: {mode.name.capitalize()}")

    # Mode
    if mode != HSM2Dongle.MODE.APP:
        raise AdminError("Device not in App mode")

    # Get version (this feature is version-dependent)
    version = hsm.get_version()
    info(f"Signer version: {version}")
    if version >= HSM2Dongle.MAX_VERSION_SIGNER_EXIT:
        raise AdminError(
            f"Exit command not supported from {HSM2Dongle.MAX_VERSION_SIGNER_EXIT} "
            "onwards"
        )

    # Onboard check
    info("Is device onboarded? ... ", options.verbose)
    is_onboarded = hsm.is_onboarded()
    info(f"Onboarded: {bls(is_onboarded)}")
    if not is_onboarded:
        raise AdminError("Device not onboarded")

    # Exit the app, go into menu
    info("Exiting app... ", options.verbose)
    try:
        hsm.exit_menu()
    except Exception:
        pass
    info("Exit OK")

    dispose_hsm(hsm)

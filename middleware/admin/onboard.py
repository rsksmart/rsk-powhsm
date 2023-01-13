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
import os
from ledger.hsm2dongle import HSM2Dongle
from ledger.pin import BasePin
from .misc import (
    info,
    head,
    bls,
    get_hsm,
    get_admin_hsm,
    dispose_hsm,
    PIN_ERROR_MESSAGE,
    AdminError,
    ask_for_pin,
    wait_for_reconnection,
)
from .dongle_admin import DongleAdmin
from .unlock import do_unlock
from .certificate import HSMCertificate, HSMCertificateElement

# TODO: this could perhaps be done with a different value.
# Currently unused but necessary for the attestation setup process.
ENDORSEMENT_CERTIFICATE = b"RSK_ENDORSEMENT_OK"
SEED_SIZE = 32


def do_onboard(options):
    head("### -> Onboarding and attestation setup", fill="#")
    hsm = None

    # Require an output file
    if options.output_file_path is None:
        raise AdminError("No output file path given")

    # Validate pin (if given)
    pin = None
    if options.pin is not None:
        if not BasePin.is_valid(options.pin.encode()):
            raise AdminError(PIN_ERROR_MESSAGE)
        pin = options.pin.encode()

    # Connection
    hsm = get_hsm(options.verbose)

    # Mode check
    info("Finding mode... ", options.verbose)
    mode = hsm.get_current_mode()
    info(f"Mode: {mode.name.capitalize()}")

    # Require bootloader mode for onboarding
    if mode != HSM2Dongle.MODE.BOOTLOADER:
        raise AdminError("Device not in bootloader mode. Disconnect and re-connect the "
                         "ledger and try again")

    # Echo check
    info("Sending echo... ", options.verbose)
    if not hsm.echo():
        raise AdminError("Echo error")
    info("Echo OK")

    info("Is device onboarded? ... ", options.verbose)
    is_onboarded = hsm.is_onboarded()
    info(f"Onboarded: {bls(is_onboarded)}")

    if is_onboarded:
        raise AdminError("Device already onboarded")

    message = "The following operation will onboard the device."
    head([
        message,
        "Do you want to proceed? Yes/No",
    ])
    while True:
        info("> ", False)
        answer = sys.stdin.readline().rstrip()
        if answer.lower() in ["n", "no"]:
            raise AdminError("Cancelled by user")
        if answer.lower() == "yes":
            break
        info("Please answer 'Yes' or 'No'")

    # If we get here, then it means we need to onboard

    # Ask the user for a pin if one not given
    if pin is None:
        info("Please select a pin for the device.")
        pin = ask_for_pin(any_pin=options.any_pin)

    # Generate a random seed
    info("Generating a random seed... ", options.verbose)
    seed = gen_seed()
    info("Seed generated")

    # Onboard
    info("Onboarding... ", options.verbose)
    hsm.onboard(seed, pin)
    info("Onboarded")

    dispose_hsm(hsm)

    head(
        [
            "Onboarding done",
            "Please disconnect and re-connect the ledger to proceed with the attestation setup",  # noqa E501
            "Press [Enter] to continue",
        ],
        nl=False,
    )
    sys.stdin.readline()

    # Wait for the dongle
    wait_for_reconnection()

    # Unlock without executing the signer
    try:
        do_unlock(options, no_exec=True, label=False)
    except Exception as e:
        raise AdminError(f"Failed to unlock device: {str(e)}")

    # Wait for the UI
    wait_for_reconnection()

    # Connection for admin operations
    hsm = get_admin_hsm(options.verbose)

    # Attestation setup
    info("Handshaking... ", options.verbose)
    hsm.handshake()
    info("Handshaking done")

    info("Gathering device key... ", options.verbose)
    device_key_info = hsm.get_device_key()
    info("Device key gathered")

    info("Setting up the attestation key... ", options.verbose)
    attestation_key_info = hsm.setup_endorsement_key(
        DongleAdmin.ENDORSEMENT_SCHEME.SCHEME_TWO, ENDORSEMENT_CERTIFICATE)
    info("Attestation key setup complete")

    dispose_hsm(hsm)

    # Generate and save the attestation certificate
    info("Generating the attestation certificate... ", options.verbose)

    att_cert = HSMCertificate()
    att_cert.add_element(
        HSMCertificateElement({
            "name": "attestation",
            "message": attestation_key_info["message"],
            "signature": attestation_key_info["signature"],
            "signed_by": "device",
        }))
    att_cert.add_element(
        HSMCertificateElement({
            "name": "device",
            "message": device_key_info["message"],
            "signature": device_key_info["signature"],
            "signed_by": "root",
        }))
    att_cert.add_target("attestation")
    att_cert.save_to_jsonfile(options.output_file_path)

    info(f"Attestation certificate saved to {options.output_file_path}")

    head([
        "Onboarding and attestation setup done",
        "Please disconnect and re-connect the ledger before the first use",
    ])


def gen_seed():
    return os.urandom(SEED_SIZE)
